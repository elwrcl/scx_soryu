/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_soryu — BMQ policy on sched_ext.
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * BMQ compresses (nice + boost) by two, so adjacent nice levels share a queue.
 * That halves nice resolution and in exchange gives boost twice the leverage
 * per step. Keeping the compression is the point of porting BMQ rather than
 * inventing a lookalike.
 *
 *   BMQ:      25 + (prio + boost - 128) / 2, where prio = 160 + nice
 *   0-based:       (32  + nice  + boost) / 2
 *   mainline:      (static_prio - 88 + boost) / 2, nice = static_prio - 120
 */
#define BOOST_RANGE 12			   /* BMQ MAX_PRIORITY_ADJ */
#define NORMAL_LEVELS 32		   /* (12 + 40 + 12) / 2 */
#define LEVELS (NORMAL_LEVELS + 1) /* last level is SCHED_IDLE */
#define IDLE_LEVEL (LEVELS - 1)

#define MAX_CPUS 1024

/*
 * BMQ's RESCHED_NS (alt_core.c:94). A remainder below this is treated as spent:
 * handing back a sliver just makes the task come straight back, so BMQ refills
 * instead. Same threshold, same reason.
 */
#define RESCHED_NS (100 << 10) /* ~102 us */

/* uapi/linux/sched.h; vmlinux.h carries the enum but not these defines. */
#define SCHED_NORMAL 0
#define SCHED_BATCH 3
#define SCHED_IDLE 5

#define DSQ_BASE 0x736f7279UL /* "sory" */
#define dsq_id(lvl) (DSQ_BASE + (lvl))

const volatile u64 slice_ns = 4194304ULL; /* 4 << 20, BMQ sysctl_sched_base_slice */
const volatile u32 nr_cpu_ids = 1;		  /* filled in by the loader */

/*
 * BMQ's sched_task_ttwu() boosts on wakeup in proportion to how long the task
 * slept, which is what makes sleeping for 1us worth nothing and closes the
 * sleep-gaming hole. Except the line reads
 *
 *     s64 delta = this_rq()->clock_task > p->last_ran;
 *
 * -- a comparison, not a subtraction. delta is always 0 or 1, the shift makes
 * it 0, and the whole function is dead code in every BMQ build shipped.
 *
 * Fixing it means running behaviour nobody has field-tested; leaving it means
 * reproducing a typo. So it is a knob, measured both ways in stage 2.
 */
const volatile bool boost_on_wake = true;

/*
 * Anti-starvation, and a deliberate deviation from BMQ.
 *
 * BMQ has none. bmq.h is forty lines: boost comes from sleeping, deboost from
 * burning a slice, and nothing whatsoever happens to a task that is merely
 * waiting. Strict priority, no aging, no deadline. On mainline that is
 * survivable -- a nice-19 thread stuck behind a compile is just slow, and no
 * one dies. Under sched_ext the watchdog calls it a fatal stall and ejects the
 * whole scheduler, which is what happened on 1 Sep: helium:disk$2 (nice 19,
 * level 25) waited 7.115s behind seven compilers at level 22 and took us down
 * with it. See docs/stage6-stall.md.
 *
 * So: a level that has held tasks this long without being served gets a turn,
 * once, ahead of better levels. One task per level per starve_ns, which works
 * out to roughly 3% of a CPU for a starving band -- close to what nice 19 is
 * worth under CFS anyway (weight 15/1024). Strict priority is preserved
 * everywhere else.
 *
 * 0 disables it and restores BMQ's semantics exactly.
 */
const volatile u64 starve_ns = 128ULL << 20; /* ~134 ms */
u64 lvl_bitmap;

/* Level each CPU is currently running, LEVELS when idle. Used by stage 4. */
static u8 cpu_level[MAX_CPUS];

u64 max_wait_jiffies;
u64 lvl_max_wait[LEVELS];
u64 lvl_last_run[LEVELS];
u32 starve_cursor;
u32 probe_seq;

/*
 * How many times each boost value was seen at ops.running. The single most
 * useful stage 2 number: it says whether boost is actually moving, and in which
 * direction the workload pushes it. Index is boost + BOOST_RANGE.
 */
u64 boost_hist[2 * BOOST_RANGE + 1];

#define LAT_CLASSES 3  /* 0 boosted, 1 neutral, 2 deboosted */
#define LAT_BUCKETS 32 /* log2(ns): bucket 10 is ~1us, 30 is ~1s */

u64 lat_hist[LAT_CLASSES * LAT_BUCKETS];

struct task_ctx
{
	s32 boost;		 /* [-BOOST_RANGE, +BOOST_RANGE], negative = better */
	u64 sleep_at;	 /* scx_bpf_now() when the task went to sleep */
	u64 run_at;		 /* scx_bpf_now() when it last started running */
	u64 wake_at;	 /* scx_bpf_now() at ops.runnable, for lat_hist */
	u64 slice_given; /* what p->scx.slice held at ops.running */
	u64 slice_left;
};

struct
{
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctxs SEC(".maps");

enum soryu_stat_idx
{
	SORYU_STAT_ENQ_SHARED,
	SORYU_STAT_ENQ_LOCAL,
	SORYU_STAT_ENQ_REENQ,
	SORYU_STAT_ENQ_PINNED,
	SORYU_STAT_DISPATCH,
	SORYU_STAT_INSERT_FAIL,
	SORYU_STAT_CPU_RELEASE,
	SORYU_STAT_BOOST_SLEEP,
	SORYU_STAT_BOOST_WAKE,
	SORYU_STAT_DEBOOST,
	SORYU_STAT_SLICE_CARRY,
	SORYU_STAT_FORK_SPLIT,
	SORYU_STAT_PREEMPT_KICK,
	SORYU_STAT_STARVE_SERVE,
	SORYU_STAT_PREEMPT_NONE,
	SORYU_STAT_PREEMPT_IDLE,
	SORYU_NR_STATS,
};

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, SORYU_NR_STATS);
} stats SEC(".maps");

static void stat_inc(enum soryu_stat_idx idx)
{
	u32 key = idx;
	u64 *cnt = bpf_map_lookup_elem(&stats, &key);

	if (cnt)
		(*cnt)++;
}

static struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctxs, p, 0, 0);
}

/*
 * BMQ boost_task(): the floor depends on policy. SCHED_NORMAL may go all the
 * way to -12; SCHED_BATCH may only climb back to 0, so a batch task can recover
 * from a deboost but never outrank a neutral one; anything else (SCHED_IDLE)
 * never boosts at all.
 */
static void boost_task(struct task_struct *p, struct task_ctx *tctx, u32 n)
{
	s32 limit, want;

	switch (p->policy)
	{
	case SCHED_NORMAL:
		limit = -BOOST_RANGE;
		break;
	case SCHED_BATCH:
		limit = 0;
		break;
	default:
		return;
	}

	want = (s32)tctx->boost - (s32)n;
	tctx->boost = want < limit ? limit : want;
}

/* BMQ deboost_task(): NORMAL and BATCH both decay, SCHED_IDLE does not. */
static void deboost_task(struct task_struct *p, struct task_ctx *tctx)
{
	if ((p->policy == SCHED_NORMAL || p->policy == SCHED_BATCH) &&
		tctx->boost < BOOST_RANGE)
		tctx->boost++;
}

static u32 task_level(struct task_struct *p, struct task_ctx *tctx)
{
	s32 v;

	if (p->policy == SCHED_IDLE)
		return IDLE_LEVEL;

	/*
	 * static_prio in [100, 139], boost in [-12, 12], so v lands in [0, 63]
	 * and never goes negative — no clamp needed, and >> 1 == / 2.
	 *
	 * static_prio rather than p->scx.weight on purpose: weight is a
	 * logarithmic thing derived from nice, and the level math wants nice
	 * itself. ops.set_weight is deliberately not implemented.
	 */
	v = (s32)p->static_prio - 88 + (tctx ? tctx->boost : 0);

	return (u32)v >> 1;
}

static u64 task_slice(struct task_ctx *tctx)
{
	if (tctx && tctx->slice_left >= RESCHED_NS)
		return tctx->slice_left;

	return slice_ns;
}

/*
 * Kick the CPU running the worst thing this task could displace.
 *
 * BMQ does this on every wakeup: if the woken task outranks what some CPU is
 * running, send a resched IPI. With a shared queue there is no single "target
 * CPU", so we track what level each CPU is running (cpu_level[]) and search.
 *
 * Two deliberate differences from LFBMQ (alt_core.c:4225):
 *
 *  - It kicks *every* eligible CPU; we kick only the worst one. Broadcasting
 *    costs an IPI per CPU per wakeup, and stage 1 measured the shared queue
 *    taking 82% of wakeups under game load -- that is a lot of wakeups to
 *    multiply. One kick is enough: the preempted CPU re-enters dispatch and
 *    pulls the lowest level from the bitmap anyway.
 *
 *  - It respects p->cpus_ptr and so do we. The spec originally dropped this;
 *    kicking a CPU the task cannot run on wastes the IPI and hands the slot to
 *    somebody else.
 */
static void try_preempt(struct task_struct *p, u32 lvl, u64 enq_flags)
{
	const struct cpumask *allowed = p->cpus_ptr;
	s32 worst_cpu = -1;
	u32 worst = lvl + 1; /* never IPI an equal or better level */
	u32 nr = scx_bpf_nr_cpu_ids();
	u32 cpu;

	if (!allowed)
		return;

	/*
	 * Wakeups only. BMQ checks for preemption in wakeup_srq_task()
	 * (alt_core.c:4211) -- on the wakeup path, not on every enqueue.
	 *
	 * Running it on every enqueue closes a loop: the task we preempt is
	 * re-enqueued, that re-enqueue runs the check again, which preempts
	 * somebody else, and so on. Measured at 3.2M kicks in 32s (~100k
	 * IPIs/sec) on four spinners plus one 100Hz waker -- three orders of
	 * magnitude more than the wakeups that caused it.
	 */
	if (!(enq_flags & SCX_ENQ_WAKEUP))
		return;

	bpf_for(cpu, 0, nr)
	{
		u32 cl;

		if (cpu >= MAX_CPUS)
			break;
		if (!bpf_cpumask_test_cpu(cpu, allowed))
			continue;

		cl = cpu_level[cpu];
		if (cl > worst)
		{
			worst = cl;
			worst_cpu = cpu;
		}
	}

	if (worst_cpu >= 0)
	{
		scx_bpf_kick_cpu(worst_cpu, SCX_KICK_PREEMPT);

		/*
		 * Two very different events were hiding behind one counter.
		 *
		 * cpu_level is set to LEVELS when a CPU stops running an scx
		 * task, so an idle CPU always looks "worse" than any level and
		 * always wins the search. Most of what preempt_kick counted was
		 * therefore *waking an idle CPU*, not preempting anybody --
		 * measured in the VM at 11:1 against real preemption with eight
		 * sleepers. Necessary work, but it says nothing about
		 * preemption pressure, and the two must not share a number.
		 */
		if (worst >= LEVELS)
			stat_inc(SORYU_STAT_PREEMPT_IDLE);
		else
			stat_inc(SORYU_STAT_PREEMPT_KICK);
		return;
	}

	/*
	 * Nobody worse to kick, so this wakeup waits for a slice to end on its
	 * own -- up to slice_ns.
	 *
	 * This is the measurement behind the slice question. When the boost
	 * range saturates, every task sits at the same level, `worst` never
	 * exceeds `lvl`, and preemption switches itself off: the scheduler
	 * silently degrades to FIFO-with-a-4ms-quantum exactly in the workload
	 * (gaming, 97% at the floor) where responsiveness is the whole point.
	 * If this counter dwarfs preempt_kick there, the tail is a slice-length
	 * problem and no amount of boost tuning will touch it.
	 */
	stat_inc(SORYU_STAT_PREEMPT_NONE);
}

s32 BPF_STRUCT_OPS(soryu_select_cpu, struct task_struct *p, s32 prev_cpu,
				   u64 wake_flags)
{
	struct task_ctx *tctx;
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (!is_idle)
		return cpu;

	/*
	 * Hot path: an idle CPU was found, so skip the shared queue entirely.
	 * ops.enqueue is not called for tasks inserted from here.
	 */
	tctx = lookup_task_ctx(p);
	if (scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(tctx), 0))
		stat_inc(SORYU_STAT_ENQ_LOCAL);
	else
		stat_inc(SORYU_STAT_INSERT_FAIL);

	return cpu;
}

void BPF_STRUCT_OPS(soryu_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	u32 lvl = task_level(p, tctx);

	/*
	 * Tasks bounced back by ops.cpu_release did not stop through any fault
	 * of their own; stage 2 must not read this as a scheduling signal.
	 */
	if (enq_flags & SCX_ENQ_REENQ)
		stat_inc(SORYU_STAT_ENQ_REENQ);

	/*
	 * Single-CPU tasks gain nothing from a shared queue, and they make every
	 * other CPU pay: consume_dispatch_q() walks the whole DSQ list under
	 * dsq->lock skipping tasks it cannot migrate, so a pile of pinned tasks
	 * turns each remote dispatch into a futile scan. Measured at 64 pinned
	 * tasks: 6x slower than EEVDF before this, and it is exactly the
	 * live-lock the kernel comments about. Per-CPU kthreads are in this
	 * class too, so it is not an exotic case.
	 *
	 * Restricted-but-multi-CPU masks still go to the shared queue; they are
	 * rarer and the fix for them is per-CPU DSQs, which is a bigger change.
	 */
	if (p->nr_cpus_allowed == 1)
	{
		s32 cpu = scx_bpf_task_cpu(p);

		if (scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
							   task_slice(tctx), enq_flags))
		{
			stat_inc(SORYU_STAT_ENQ_PINNED);

			/* Only one CPU can ever run it, so the search above is
			 * pointless -- just check that one. Wakeups only, same
			 * reason as try_preempt(). */
			if ((enq_flags & SCX_ENQ_WAKEUP) &&
				cpu >= 0 && cpu < MAX_CPUS &&
				cpu_level[cpu] > lvl)
			{
				scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
				stat_inc(SORYU_STAT_PREEMPT_KICK);
			}
		}
		else
		{
			stat_inc(SORYU_STAT_INSERT_FAIL);
		}
		return;
	}

	if (!scx_bpf_dsq_insert(p, dsq_id(lvl), task_slice(tctx), enq_flags))
	{
		stat_inc(SORYU_STAT_INSERT_FAIL);
		return;
	}
	stat_inc(SORYU_STAT_ENQ_SHARED);

	/* Insert first, then advertise: a bit set late is a missed dispatch
	 * round, a bit set early is a dispatch that finds nothing. */
	__sync_fetch_and_or(&lvl_bitmap, 1ULL << lvl);

	try_preempt(p, lvl, enq_flags);
}

static void sample_head_wait(u32 lvl)
{
	struct task_struct *p;
	u64 now = bpf_jiffies64();

	if (lvl >= LEVELS)
		return;

	bpf_for_each(scx_dsq, p, dsq_id(lvl), 0)
	{
		u64 runnable_at = p->scx.runnable_at;

		if (runnable_at)
		{
			u64 waited = time_delta(now, runnable_at);

			if (waited > READ_ONCE(max_wait_jiffies))
				WRITE_ONCE(max_wait_jiffies, waited);
			if (waited > READ_ONCE(lvl_max_wait[lvl]))
				WRITE_ONCE(lvl_max_wait[lvl], waited);
		}
		break;
	}
}

void BPF_STRUCT_OPS(soryu_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 mask = READ_ONCE(lvl_bitmap);
	u64 now = scx_bpf_now();
	if (starve_ns)
	{
		u32 probe = READ_ONCE(starve_cursor);

		probe = probe < LEVELS - 1 ? probe + 1 : 0;
		WRITE_ONCE(starve_cursor, probe);

		/*
		 * Telemetry, once every 1024 dispatches -- tens of times a
		 * second, which is three orders of magnitude finer than a
		 * multi-second watchdog needs, and cheap enough to ignore.
		 * (1024 mod 33 = 1, so consecutive samples walk every level.)
		 */
		if (!(probe_seq++ & 1023) && (mask & (1ULL << probe)))
			sample_head_wait(probe);

		if ((mask & (1ULL << probe)) &&
			now - READ_ONCE(lvl_last_run[probe]) > starve_ns)
		{
			if (scx_bpf_dsq_move_to_local(dsq_id(probe), 0))
			{
				WRITE_ONCE(lvl_last_run[probe], now);
				stat_inc(SORYU_STAT_DISPATCH);
				stat_inc(SORYU_STAT_STARVE_SERVE);
				return;
			}

			/*
			 * Empty, or nothing here can run on this CPU. Either
			 * way it is not starving -- it was offered a turn and
			 * had nothing to take. Stamping it keeps a level that
			 * has been idle for hours (the bitmap is set-only, so
			 * its bit stays lit forever) from claiming a free pass
			 * on every probe.
			 */
			WRITE_ONCE(lvl_last_run[probe], now);
		}
	}

	bpf_repeat(LEVELS)
	{
		u32 lvl;
		u64 bit;

		if (!mask)
			break;

		lvl = __builtin_ctzll(mask);
		bit = 1ULL << lvl;

		if (scx_bpf_dsq_move_to_local(dsq_id(lvl), 0))
		{
			WRITE_ONCE(lvl_last_run[lvl], now);
			stat_inc(SORYU_STAT_DISPATCH);
			return;
		}

		mask &= ~bit;
	}
}

void BPF_STRUCT_OPS(soryu_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 now, slept, steps;

	if (enq_flags & SCX_ENQ_REENQ)
		return;

	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	now = scx_bpf_now();

	tctx->wake_at = now;

	if (!boost_on_wake || !tctx->sleep_at || !slice_ns)
		return;
	slept = now > tctx->sleep_at ? now - tctx->sleep_at : 0;
	tctx->sleep_at = 0;

	steps = slept / slice_ns;
	if (!steps)
		return;

	if (steps > 2 * BOOST_RANGE)
		steps = 2 * BOOST_RANGE;

	boost_task(p, tctx, (u32)steps);
	stat_inc(SORYU_STAT_BOOST_WAKE);
}

void BPF_STRUCT_OPS(soryu_running, struct task_struct *p)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	s32 cpu = scx_bpf_task_cpu(p);
	u64 runnable_at, waited;

	if (cpu >= 0 && cpu < MAX_CPUS)
		cpu_level[cpu] = task_level(p, tctx);

	if (tctx)
	{
		u32 idx = (u32)(tctx->boost + BOOST_RANGE);

		if (idx < 2 * BOOST_RANGE + 1)
			boost_hist[idx]++;

		tctx->run_at = scx_bpf_now();
		tctx->slice_given = p->scx.slice;

		if (tctx->wake_at)
		{
			u64 lat = tctx->run_at > tctx->wake_at
						  ? tctx->run_at - tctx->wake_at
						  : 0;
			u32 cls = tctx->boost < 0 ? 0 : (tctx->boost ? 2 : 1);
			u32 b = lat ? 63 - __builtin_clzll(lat) : 0;
			u32 slot;

			if (b >= LAT_BUCKETS)
				b = LAT_BUCKETS - 1;

			slot = cls * LAT_BUCKETS + b;
			if (slot < LAT_CLASSES * LAT_BUCKETS)
				lat_hist[slot]++;

			tctx->wake_at = 0;
		}
	}

	runnable_at = p->scx.runnable_at;
	if (runnable_at)
	{
		u32 lvl = task_level(p, tctx);

		waited = time_delta(bpf_jiffies64(), runnable_at);
		if (waited > READ_ONCE(max_wait_jiffies))
			WRITE_ONCE(max_wait_jiffies, waited);

		if (lvl < LEVELS && waited > READ_ONCE(lvl_max_wait[lvl]))
			WRITE_ONCE(lvl_max_wait[lvl], waited);
	}
}

void BPF_STRUCT_OPS(soryu_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	s32 cpu = scx_bpf_task_cpu(p);
	u64 now, ran, left;

	if (cpu >= 0 && cpu < MAX_CPUS)
		cpu_level[cpu] = LEVELS;

	if (!tctx)
		return;

	if (!runnable)
	{
		boost_task(p, tctx, 1);
		tctx->sleep_at = scx_bpf_now();
		tctx->slice_left = 0; /* sleeping earns a fresh slice */
		stat_inc(SORYU_STAT_BOOST_SLEEP);
		return;
	}

	now = scx_bpf_now();
	ran = now > tctx->run_at ? now - tctx->run_at : 0;
	left = tctx->slice_given > ran ? tctx->slice_given - ran : 0;

	if (left < RESCHED_NS)
	{
		deboost_task(p, tctx);
		tctx->slice_left = 0;
		stat_inc(SORYU_STAT_DEBOOST);
	}
	else
	{
		tctx->slice_left = left;
		stat_inc(SORYU_STAT_SLICE_CARRY);
	}
}

void BPF_STRUCT_OPS(soryu_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	scx_bpf_reenqueue_local();

	if (cpu >= 0 && cpu < MAX_CPUS)
		cpu_level[cpu] = LEVELS;

	stat_inc(SORYU_STAT_CPU_RELEASE);
}

s32 BPF_STRUCT_OPS(soryu_init_task, struct task_struct *p,
				   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctxs, p, 0,
								BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	tctx->boost = 0;
	tctx->sleep_at = 0;
	tctx->run_at = 0;
	tctx->wake_at = 0;
	tctx->slice_given = 0;
	tctx->slice_left = 0;

	/*
	 * BMQ (alt_core.c:2874, sched_cgroup_fork):
	 *
	 *	rq->curr->time_slice /= 2;
	 *	p->time_slice = rq->curr->time_slice;
	 *
	 * with the comment "the total amount of pending timeslices in the
	 * system doesn't change". Without it every fork mints a fresh full
	 * slice out of nothing, so anything that forks in a loop -- a build,
	 * most obviously -- gains CPU share against everything else simply by
	 * forking. Splitting closes that.
	 *
	 */
	if (args->fork)
	{
		struct task_struct *parent = bpf_get_current_task_btf();
		struct task_ctx *pctx;
		u64 half;

		if (parent)
		{
			half = parent->scx.slice / 2;

			scx_bpf_task_set_slice(parent, half);

			pctx = bpf_task_storage_get(&task_ctxs, parent, 0, 0);
			if (pctx)
				pctx->slice_left = half;

			tctx->slice_left = half >= RESCHED_NS ? half : 0;
			stat_inc(SORYU_STAT_FORK_SPLIT);
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(soryu_dump, struct scx_dump_ctx *dctx)
{
	u64 mask = READ_ONCE(lvl_bitmap);
	u32 lvl;

	scx_bpf_dump_header();
	scx_bpf_dump("soryu: bitmap=0x%llx max_wait=%llu jiffies\n",
				 mask, READ_ONCE(max_wait_jiffies));

	bpf_for(lvl, 0, LEVELS)
	{
		s32 nr = scx_bpf_dsq_nr_queued(dsq_id(lvl));

		/* [BIT CLEAR!] is an invariant violation: a level holding tasks
		 * whose bit is unset can never be dispatched. Must never fire
		 * now that bits are set-only. */
		if (nr > 0)
			scx_bpf_dump("  lvl %2u: %d queued%s\n", lvl, nr,
						 (mask & (1ULL << lvl)) ? "" : "  [BIT CLEAR!]");
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(soryu_init)
{
	u32 lvl;
	s32 ret;

	bpf_for(lvl, 0, LEVELS)
	{
		ret = scx_bpf_create_dsq(dsq_id(lvl), -1);
		if (ret)
			return ret;
	}

	bpf_for(lvl, 0, MAX_CPUS)
		cpu_level[lvl] = LEVELS;

	return 0;
}

void BPF_STRUCT_OPS(soryu_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(soryu_ops,
			   .select_cpu = (void *)soryu_select_cpu,
			   .enqueue = (void *)soryu_enqueue,
			   .dispatch = (void *)soryu_dispatch,
			   .runnable = (void *)soryu_runnable,
			   .running = (void *)soryu_running,
			   .stopping = (void *)soryu_stopping,
			   .cpu_release = (void *)soryu_cpu_release,
			   .init_task = (void *)soryu_init_task,
			   .dump = (void *)soryu_dump,
			   .init = (void *)soryu_init,
			   .exit = (void *)soryu_exit,
			   .flags = SCX_OPS_KEEP_BUILTIN_IDLE,
			   .timeout_ms = 5000,
			   .name = "soryu");
