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

/*
 * Always overwritten by the loader, whose default is 1000 us. BMQ's own 4 ms
 * base slice measured worse here: the same compile took 4m49s at 4194 us
 * against 4m39s at both 1000 and 500, so 1000 was hardcoded. The value below
 * is only what a hand-loaded object would get.
 *
 * Note this shifts what RESCHED_NS means: at 4 ms it was a 2.4% remainder,
 * at 1 ms it is 10%. The carry/deboost threshold is coarser than BMQ's by
 * that factor.
 */
const volatile u64 slice_ns = 4194304ULL; /* 4 << 20, BMQ sysctl_sched_base_slice */

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
 * reproducing a typo. So it was made a knob and measured both ways.
 *
 * The typo wins. Two paired runs of the same compile, 68 ten-second intervals
 * (docs/boost-on-wake.md): with the wake boost off the interactive tail past
 * 1 ms is roughly half, in 63 of 68 intervals, sign test p = 8e-14. Compile
 * time is unchanged -- the two configurations traded places between rounds.
 *
 * So the default is off: BMQ as shipped, typo intact. That is both what the
 * measurement says and what a decade of field use already ran. The knob stays
 * because the mechanism behind the difference is not understood -- see the
 * open question at the end of that doc.
 */
const volatile bool boost_on_wake = false;

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
 * with it.
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

/*
 * Whether ops.dispatch clears bitmap bits, and with them runs the repair
 * sweep that makes clearing survivable. Both or neither: with the clear off,
 * no bit can be lost, so the sweep has nothing to repair and its per-dispatch
 * nr_queued call is pure cost.
 *
 * This is a knob and not a decision because the measurement is unresolved.
 * Clearing does what it was meant to do -- 55 DSQ probes per dispatch down to
 * 0.52 -- but the same build measured a worse interactive tail than the runs
 * before it (0.114% past 1 ms against 0.075%, 28 of 34 paired intervals), and
 * disabling anti-starvation entirely did not move that number, so the cost is
 * not the priority inversions it was first blamed on.
 *
 * The remaining suspect is this: set-only left lvl_bitmap effectively
 * read-only after warmup, and the scan touched 25 different DSQ cache lines
 * with unlocked reads that every CPU can hold shared. Clearing turns one u64
 * into a write-hot line -- ~595k atomic RMWs on top of the ~1.1M the enqueue
 * side already does -- that four threads must take exclusive turns owning.
 * Trading 25 shared reads for one contended line is not obviously a win.
 *
 * They did. Two rounds, back to back, order reversed between them: clearing
 * loses 46 of 69 paired intervals, p = 0.008, a median tail ratio of 0.84 and
 * one bucket on p99. Default off.
 *
 * The asymmetry is what settles it. Clearing buys 37x fewer DSQ probes per
 * dispatch -- and that scan never had a measurable latency cost to begin with,
 * because consume_dispatch_q() tests list_empty() unlocked (ext.c:2517) and 25
 * shared cache lines are cheaper to touch than one exclusively owned u64.
 * Paying a measured cost for an unmeasured saving is the wrong trade.
 *
 * What clearing looked like it also bought -- a working starvation probe --
 * turned out to be a separate thing that was only accidentally coupled to it.
 * See the probe below.
 */
const volatile bool clear_bitmap = false;

/*
 * Whether ops.cpu_release throws the local DSQ back through ops.enqueue.
 *
 * scx_bpf_reenqueue_local() is the conventional thing to do here, and it is
 * right when the CPU is about to be busy for a while: the tasks queued on it
 * should go find another one rather than wait. It is waste when the higher
 * class is a short burst, because the task pays a full re-enqueue -- level
 * recomputed, DSQ reinserted, possibly migrated -- to avoid a wait it would
 * have finished sooner than the trip.
 *
 * Measured: on a desktop, 38916 releases over five minutes, 99.6% of them RT,
 * about 130 a second, each bouncing 0.98 tasks. Those bounces then take twice
 * as long to reach a CPU as an ordinary wakeup does (p99 1.3 ms against 655
 * us). The RT in question is an audio callback, tens of microseconds.
 *
 * Risk, stated plainly: with this off, tasks sitting in the local DSQ of a CPU
 * that a long-running RT or DL task has taken cannot migrate away. Nothing in
 * this scheduler covers that -- starve_ns walks the shared level DSQs, not
 * local ones. The backstop is the 5 s watchdog, which ejects rather than
 * hangs. Short audio bursts are safe; an RT hog is not.
 */
const volatile bool reenqueue_on_release = true;

/*
 * cgroup cpu.weight, in levels.
 *
 * Until now this scheduler was completely deaf to it. ops.cgroup_set_weight
 * was not implemented, so systemd's CPUWeight=, and with it the whole
 * system.slice / user.slice / app.slice arrangement every desktop already has,
 * did nothing at all. nice worked; cgroups did not.
 *
 * cpu.weight is [1, 10000] with 100 the default, and it is a geometric scale:
 * one nice step is a factor of 1.25, so an octave of weight is log(2)/log(1.25)
 * = 3.1 nice steps. Rounded to 3, which keeps the arithmetic integer and errs
 * toward giving cgroups slightly less authority than nice rather than more.
 *
 * cgrp_weight_levels caps how far that may move a task in each direction; 0
 * disables it. Unlike nice, this is a knob without a measurement behind it
 * yet -- and note that what it changes is fairness between groups, not
 * latency. Do not expect the interactive tail to move. It is here because a
 * desktop scheduler ignoring cpu.weight is a gap, not because it is expected
 * to win an A/B.
 */
const volatile s32 cgrp_weight_levels = 0;

/*
 * Wake-chain priority donation.
 *
 * XNU propagates priority through blocking chains with turnstiles; Linux does
 * the same for rt_mutex, but only inside the RT class. From BPF the lock graph
 * is not visible -- but the wake graph is, and it is a decent proxy: if A
 * wakes B, B is usually about to do something on A's behalf, so B inheriting
 * some of A's urgency is closer to right than B keeping its own.
 *
 * This is deliberately the opposite kind of idea from the ULE ratio, which
 * failed. ULE graded more finely and the tail did not move, which said the
 * problem is not priority resolution. Donation does not grade at all; it
 * changes *who* is urgent. That question has not been tested.
 *
 * wake_donate is how many boost steps a waker may hand down, capped by the gap
 * between them so a wakee is never pushed past its waker. 0 disables it.
 */
const volatile s32 wake_donate = 0;

/*
 * Order each level DSQ by virtual time instead of FIFO.
 *
 * Every mature sched_ext scheduler does this -- bpfland, flash, lavd, p2dq,
 * cake, mitosis, beerland, forge all insert with a vtime. soryu was the
 * outlier, inserting plain FIFO.
 *
 * It is worth trying here specifically because it is not another grading
 * scheme. The ULE ratio graded more finely, reached the level arithmetic, and
 * moved the tail by nothing (p = 1.0), which said the problem is not priority
 * resolution. This changes ordering *within* a band, an axis nothing has
 * touched yet.
 *
 * And FIFO's worst case has exactly the shape of the tail that is left. Arrive
 * at a level behind k tasks and wait k slices; at slice_ns = 1 ms, k = 5 is
 * 5 ms, which is the >4.2 ms band. Roughly half of all events sit on the boost
 * floor, so that queue is the deep one and FIFO is at its worst there.
 *
 * Unweighted on purpose. Priority already lives in the level -- tasks sharing
 * a level share a (nice + boost) by construction -- so within one, vtime means
 * only "who has used least CPU goes first". BMQ's strict priority between
 * levels is untouched.
 *
 * A DSQ must be used consistently as FIFO or vtime, never both. This knob is
 * read-only after load, and the built-in DSQs the other paths use
 * (SCX_DSQ_LOCAL, LOCAL_ON, GLOBAL) are separate, so the level DSQs stay
 * consistent either way.
 */
const volatile bool vtime_within_level = false;

/*
 * The clock vtime is measured against: the largest vtime seen at ops.running.
 * A sleeping task's vtime stands still while this advances, which is the
 * credit that lets it jump the queue on waking -- bounded to one slice by the
 * clamp in ops.enqueue, or a task that slept for a minute would own the level.
 */
u64 vtime_now;

/*
 * FreeBSD ULE's interactivity score, bolted alongside BMQ's boost rather than
 * replacing it.
 *
 * BMQ grades a task with a counter: +1 better per sleep, +1 worse per burnt
 * slice. Measured under compile load, that counter is not a grade at all --
 * it is a one-bit classifier. The distribution sits bimodal at roughly 54% on
 * the -12 floor and 39% on the +12 ceiling, with about 5% spread across the
 * twenty-five values in between. A task that both sleeps a lot and burns a lot
 * -- a render thread, a compositor, a decoder -- oscillates around the middle
 * and never settles anywhere useful.
 *
 * ULE asks a different question. Not "how many times did you sleep" but "what
 * fraction of your recent life was sleep", over a decaying window:
 *
 *   sched_ule.c, sched_interact_score()
 *     runtime > slptime:  50 + (50 - slptime / (runtime / 50))   -> (50, 100]
 *     slptime > runtime:       runtime / (slptime / 50)          -> [0, 50)
 *     equal:                   50
 *
 * 0 is a pure sleeper, 100 a pure hog. That is a continuum by construction,
 * which is the point: it can put the render thread somewhere, and BMQ's
 * counter cannot.
 *
 * ule_weight is the level adjustment in each direction, so the score moves a
 * task by at most +/- ule_weight levels on top of whatever boost did. 0
 * disables it entirely and restores BMQ, which is the default -- this is an
 * experiment with a knob, not a decision, and every decision on this branch so
 * far was made by running the knob both ways back to back.
 */
#define ULE_MAX 100
#define ULE_HALF (ULE_MAX / 2)

const volatile s32 ule_weight = 0;

/* ULE's SCHED_SLP_RUN_MAX: how much combined history is kept before halving. */
const volatile u64 ule_window_ns = 5000000000ULL; /* 5 s */
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

#define LAT_CLASSES 3 /* 0 boosted, 1 neutral, 2 deboosted */

/*
 * Latency histogram, log2 with a mantissa.
 *
 * Plain log2 buckets step by a factor of two, which turned out to be too
 * coarse to answer any of the questions the histogram exists for. Measured
 * 1000 us against 500 us of slice: the compile differed by 0 s and every
 * printed percentile was bit-identical, because a real 20-40% change in
 * latency does not move a value across a 2x boundary. The instrument could
 * only ever say "same".
 *
 * So keep the octave and add the top two mantissa bits: buckets land on
 * 1.00, 1.25, 1.50 and 1.75 times each power of two, a ~19% step. Same
 * unbounded range, 384 u64 of .bss instead of 96.
 */
#define LAT_OCTAVES 32
#define LAT_SUBS 4 /* mantissa buckets per octave */
#define LAT_BUCKETS (LAT_OCTAVES * LAT_SUBS)

u64 lat_hist[LAT_CLASSES * LAT_BUCKETS];

/*
 * ULE score at ops.running, in buckets of 5, split by what BMQ's boost thinks
 * of the same task at the same moment. Kept even when ule_weight is 0: the
 * first thing worth knowing is whether the score separates tasks that boost
 * cannot, and that is answerable without letting it touch a decision.
 *
 * Split, because the flat version produced a contradiction. On the same
 * compile, boost put 43.6% of events at its +12 ceiling -- fully deboosted,
 * hogs by BMQ's reckoning -- while ULE put 1.9% at score >= 75. Two metrics
 * over one population disagreeing that sharply about who the hogs are means
 * one of them is wrong, or they measure different things, and an A/B on
 * ule_weight is uninterpretable until that is settled.
 *
 * Classes match lat_hist: 0 boosted (boost < 0), 1 neutral, 2 deboosted.
 */
#define ULE_BUCKETS 20
u64 ule_hist[LAT_CLASSES * ULE_BUCKETS];

/*
 * Time from being bounced by ops.cpu_release to running again, same buckets
 * as lat_hist.
 *
 * This exists because the tail everything else is measured against cannot see
 * this population at all. scx_bpf_reenqueue_local() throws the local DSQ back
 * through ops.enqueue with SCX_ENQ_REENQ; ops.runnable is not part of that
 * path, so wake_at is never stamped, and ops.running records a latency sample
 * only when wake_at is set. Every task bounced by a higher sched class spends
 * that trip invisible.
 *
 * Measured at ~110 bounces per second on a desktop against ~3 during a
 * compile, while the desktop tail was three times worse. That is a
 * correlation across two different workloads and proves nothing, but it is
 * the one concrete lead in a day of nulls, and the instrument that would have
 * settled it was blind by construction.
 */
u64 bounce_hist[LAT_BUCKETS];

/*
 * Which sched class took the CPU, indexed by enum scx_cpu_preempt_reason:
 * 0 RT, 1 DL, 2 stop, 3 unknown.
 */
#define RELEASE_REASONS 4
u64 release_reason[RELEASE_REASONS];

/*
 * GPU feeders: tasks that submitted GPU work within the last GPU_FEEDER_NS,
 * as seen by the i915_request_add hook at the bottom of this file.
 *
 * The thread that hands work to the GPU (a game's render thread, the
 * compositor, Xwayland) is the one whose lateness costs a frame: if it runs
 * late, the batch reaches the ring late, and on Gen7 there is no GPU-side
 * scheduling to make that back up -- legacy ringbuffer submission, no
 * preemption. Infinity v4.8 coupled CPU and GPU accounting for this reason.
 *
 * Three populations, all against lat_hist's buckets:
 *
 *   0  feeder: wake->run of a feeder
 *   1  feeder requeue, boosted: stopped still runnable (slice end, kick,
 *      bounce) with boost < 0, until it runs again
 *   2  feeder requeue, not boosted: same, boost >= 0
 *
 * 1 and 2 are the population wake->run cannot see. A render thread that burns
 * its slice mid-frame does not sleep, so it never passes ops.runnable and
 * never gets a wake_at; the wait it pays to get the CPU back was invisible.
 * The split is by boost at the moment it stopped, because the question was
 * whether being deboosted is what makes that wait long. It was -- see
 * gpu_boost_cap below and docs/gpu-feeder.md.
 *
 * Feeders waking out of a GPU wait were measured too, through the i915 and
 * dma_fence wait tracepoints, and dropped: 1251 such wakeups in 20 minutes of
 * play. Mesa's crocus does not block in the kernel for its fences, so there
 * was no population there to schedule.
 *
 * 100 ms is three frames at 30 fps: generous on purpose, so the population is
 * every thread that is plausibly feeding a frame and not only the ones caught
 * mid-burst.
 */
#define GPU_FEEDER_NS (100ULL * 1000 * 1000)
#define GPU_POPS 3

/*
 * A recent feeder is not deboosted past gpu_boost_cap. BOOST_RANGE (12) turns
 * it off, since boost never exceeds it anyway.
 *
 * BMQ deboosts a render thread for doing exactly what a heavy frame needs,
 * burning whole slices, and strict priority then queues it behind every
 * better level. One 60 s camera pan in Half-Life 2, no background load: a
 * feeder that stopped still runnable while boosted got the CPU back within
 * 3.1 ms at p99.9 in every second of the run. Deboosted, it passed 4 ms in 6
 * of 61 seconds and reached 25 ms -- two frames at 85 fps. -1 keeps feeders
 * in the boosted class, where that wait never went long.
 *
 * Measured both ways, same binary, alternating (docs/gpu-feeder.md):
 *
 *   idle desktop, two rounds each   frames > 25 ms  26-27 -> 6-8
 *                                   p99.9 frametime 44 ms -> 26 ms
 *   under stress-ng --cpu 4         average fps     60.8 -> 73.3
 *                                   1% low          30.0 -> 46.6
 *
 * The cost is that anything submitting to the GPU keeps its standing however
 * much CPU it burns -- an OpenCL render included -- and outranks nice-0 hogs
 * while it does. Measured: stress-ng lost 27% of its throughput to the game,
 * at unchanged ops per CPU-second, so it ran less rather than slower, and the
 * worst wait stayed at the starve_ns bound either way. That is the trade a
 * desktop scheduler should make, so it is the default.
 */
const volatile s32 gpu_boost_cap = -1;

u64 gpu_lat_hist[GPU_POPS * LAT_BUCKETS];

/* boost_hist, restricted to feeders. */
u64 gpu_boost_hist[2 * BOOST_RANGE + 1];

/*
 * Bucket index for @ns: octave * LAT_SUBS + the two bits below the leading
 * one. Values under 4 ns have no mantissa bits to take and all land in
 * bucket 0, which is fine -- nothing real is measured there.
 */
static u32 lat_bucket(u64 ns)
{
	u32 oct, sub;

	if (!ns)
		return 0;

	oct = 63 - __builtin_clzll(ns);
	sub = oct >= 2 ? (u32)(ns >> (oct - 2)) & (LAT_SUBS - 1) : 0;

	if (oct >= LAT_OCTAVES)
		return LAT_BUCKETS - 1;

	return oct * LAT_SUBS + sub;
}

struct task_ctx
{
	s32 boost;		 /* [-BOOST_RANGE, +BOOST_RANGE], negative = better */
	u64 sleep_at;	 /* scx_bpf_now() when the task went to sleep */
	u64 run_at;		 /* scx_bpf_now() when it last started running */
	u64 wake_at;	 /* scx_bpf_now() at ops.runnable, for lat_hist */
	u64 slice_given; /* what p->scx.slice held at ops.running */
	u64 slice_left;
	u64 runtime;   /* ns run, decaying -- ULE ts_runtime */
	u64 slptime;   /* ns slept, decaying -- ULE ts_slptime */
	u64 bounce_at; /* scx_bpf_now() when ops.cpu_release threw it back */
	s32 cgrp_adj;  /* cached level adjustment from cpu.weight */
	u64 cgrp_seen; /* cgrp_gen this adjustment was computed against */
	u64 gpu_submit_at; /* scx_bpf_now() at its last i915_request_add */
	u64 requeue_at;	   /* scx_bpf_now() when a feeder stopped still runnable */
	bool requeue_boosted; /* its boost was < 0 at that moment */
};

struct cgrp_ctx
{
	u32 weight;
};

struct
{
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cgrp_ctx);
} cgrp_ctxs SEC(".maps");

/*
 * Bumped whenever any cgroup's weight changes. Tasks cache their own
 * adjustment and recheck it against this, because ops.cgroup_set_weight
 * affects every task in a cgroup and there is no way to walk them.
 */
u64 cgrp_gen;

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
	SORYU_STAT_DISPATCH_MISS,
	SORYU_STAT_STARVE_BLOCKED,
	SORYU_STAT_BITMAP_REPAIR,
	SORYU_STAT_WAKE_DONATE,
	SORYU_STAT_GPU_SUBMIT,
	SORYU_STAT_GPU_CAP,
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
 * Signed, so a submit stamped on another CPU a hair ahead of this one's clock
 * still reads as recent rather than as 2^64 ns ago.
 */
static bool gpu_feeder(struct task_ctx *tctx, u64 now)
{
	return tctx->gpu_submit_at &&
		   (s64)(now - tctx->gpu_submit_at) < (s64)GPU_FEEDER_NS;
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

/*
 * sched_ule.c, sched_interact_score(). Integer division by a value derived
 * from the larger term, so the result stays in [0, 100] without a clamp:
 * in each branch the numerator is the smaller of the two.
 *
 * BPF division by zero yields zero rather than faulting, but div is forced to
 * at least 1 anyway so the arithmetic matches ULE's max(1, ...).
 */
static u32 ule_score(struct task_ctx *tctx)
{
	u64 r = tctx->runtime, sl = tctx->slptime, div;

	if (r > sl)
	{
		div = r / ULE_HALF;
		if (!div)
			div = 1;
		return ULE_HALF + (ULE_HALF - (u32)(sl / div));
	}

	if (sl > r)
	{
		div = sl / ULE_HALF;
		if (!div)
			div = 1;
		return (u32)(r / div);
	}

	return ULE_HALF;
}

/*
 * sched_ule.c, sched_interact_update(). Halve both terms once their sum
 * outgrows the window, so the score describes recent behaviour rather than
 * everything since fork. A task that has been away for much longer than the
 * window is pinned to whichever extreme it was at instead of decayed -- ULE
 * does this so a thread that slept for a minute wakes up interactive rather
 * than gradually earning it back.
 */
static void ule_decay(struct task_ctx *tctx)
{
	u64 sum = tctx->runtime + tctx->slptime;

	if (sum < ule_window_ns)
		return;

	if (sum > ule_window_ns * 2)
	{
		if (tctx->runtime > tctx->slptime)
		{
			tctx->runtime = ule_window_ns;
			tctx->slptime = 1;
		}
		else
		{
			tctx->slptime = ule_window_ns;
			tctx->runtime = 1;
		}
		return;
	}

	tctx->runtime >>= 1;
	tctx->slptime >>= 1;
}

/* [-ule_weight, +ule_weight] levels: negative for sleepers, positive for hogs. */
static s32 ule_adjust(struct task_ctx *tctx)
{
	if (!ule_weight || !tctx)
		return 0;

	return ((s32)ule_score(tctx) - ULE_HALF) * ule_weight / ULE_HALF;
}

/*
 * cpu.weight -> level adjustment. Geometric in, linear out: an octave of
 * weight is worth 3 nice steps (log 2 / log 1.25 = 3.106, rounded down), and
 * 100 is the neutral point because that is cpu.weight's default.
 *
 * Negative is better, matching boost: a heavier cgroup should outrank a
 * lighter one.
 */
static s32 cgrp_weight_adj(u32 weight)
{
	s32 oct, adj;

	if (!cgrp_weight_levels || !weight)
		return 0;

	/* ilog2(weight) - ilog2(100); 100 lands on 6. */
	oct = (s32)(31 - __builtin_clz(weight)) - 6;
	adj = -oct * 3;

	if (adj > cgrp_weight_levels)
		adj = cgrp_weight_levels;
	if (adj < -cgrp_weight_levels)
		adj = -cgrp_weight_levels;

	return adj;
}

/*
 * Refresh the cached cgroup adjustment if any weight has changed since it was
 * computed. Called from ops.enqueue rather than from task_level(), which runs
 * on several hot paths and would otherwise pay an acquire/release per call for
 * a value that changes when someone edits a systemd unit.
 */
static void cgrp_refresh(struct task_struct *p, struct task_ctx *tctx)
{
	struct cgroup *cgrp;
	struct cgrp_ctx *cgc;
	u64 gen = READ_ONCE(cgrp_gen);

	if (!cgrp_weight_levels || !tctx || tctx->cgrp_seen == gen)
		return;

	tctx->cgrp_seen = gen;
	tctx->cgrp_adj = 0;

	cgrp = scx_bpf_task_cgroup(p);
	if (!cgrp)
		return;

	cgc = bpf_cgrp_storage_get(&cgrp_ctxs, cgrp, 0, 0);
	if (cgc)
		tctx->cgrp_adj = cgrp_weight_adj(cgc->weight);

	bpf_cgroup_release(cgrp);
}

static u32 task_level(struct task_struct *p, struct task_ctx *tctx)
{
	s32 v;

	if (p->policy == SCHED_IDLE)
		return IDLE_LEVEL;

	/*
	 * static_prio in [100, 139], boost in [-12, 12], so v lands in [0, 63]
	 * and >> 1 == / 2.
	 *
	 * static_prio rather than p->scx.weight on purpose: weight is a
	 * logarithmic thing derived from nice, and the level math wants nice
	 * itself. ops.set_weight is deliberately not implemented.
	 *
	 * The clamp is cheap insurance, not arithmetic we expect to need. It
	 * only matters if scx ever hands us a task with static_prio < 100 (an
	 * RT prio), and there the unclamped path is genuinely dangerous: v goes
	 * negative, (u32)v >> 1 is enormous, dsq_id(lvl) names a DSQ that was
	 * never created, and the insert fails -- which used to mean a lost task
	 * and an ejection. Two instructions to not depend on that.
	 */
	v = (s32)p->static_prio - 88 + (tctx ? tctx->boost : 0) + ule_adjust(tctx) +
		(tctx ? tctx->cgrp_adj : 0);

	if (v < 0)
		v = 0;
	if (v > 2 * (IDLE_LEVEL - 1) + 1)
		v = 2 * (IDLE_LEVEL - 1) + 1;

	return (u32)v >> 1;
}

static u64 task_slice(struct task_ctx *tctx)
{
	if (tctx && tctx->slice_left >= RESCHED_NS)
		return tctx->slice_left;

	return slice_ns;
}

/*
 * A failed insert used to be counted and dropped. That is not a lost sample,
 * it is a lost task: it sits in no DSQ, ops.dispatch has nothing to find it
 * by, and the watchdog calls that a runnable task stall and ejects us. So
 * insert_fail > 0 meant "ejection in at most timeout_ms", which is a strange
 * thing for a counter to mean.
 *
 * SCX_DSQ_GLOBAL is the escape hatch: the core consumes it before entering
 * ops.dispatch and again inside the dispatch loop (ext.c, consume_global_dsq),
 * so a task parked there runs without soryu having to know about it. The cost
 * is that it runs out of level order -- one priority inversion instead of the
 * whole scheduler.
 */
static void insert_fallback(struct task_struct *p, u64 slice, u64 enq_flags)
{
	stat_inc(SORYU_STAT_INSERT_FAIL);
	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, slice, enq_flags);
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
	/*
	 * Seed with @lvl so the `cl > worst` test below means "strictly worse
	 * than the waker" -- an equal or better level is never IPIed. Seeding
	 * with lvl + 1 instead skipped CPUs running exactly one level worse,
	 * and one level is two nice steps under BMQ's compression, so a nice 0
	 * wakeup would not preempt a nice 4 hog. The pinned path below always
	 * used the correct test (cpu_level[cpu] > lvl); the two now agree.
	 */
	u32 worst = lvl;
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
		insert_fallback(p, task_slice(tctx), 0);

	return cpu;
}

void BPF_STRUCT_OPS(soryu_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	u32 lvl;

	cgrp_refresh(p, tctx);
	lvl = task_level(p, tctx);

	/*
	 * Tasks bounced back by ops.cpu_release did not stop through any fault
	 * of their own; stage 2 must not read this as a scheduling signal.
	 */
	if (enq_flags & SCX_ENQ_REENQ)
	{
		stat_inc(SORYU_STAT_ENQ_REENQ);

		/* Start of the trip nothing else measures. Stamped here rather
		 * than in ops.cpu_release because that callback does not know
		 * which tasks scx_bpf_reenqueue_local() will hand back. */
		if (tctx)
			tctx->bounce_at = scx_bpf_now();
	}

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
			insert_fallback(p, task_slice(tctx), enq_flags);
		}
		return;
	}

	if (vtime_within_level)
	{
		u64 now_v = READ_ONCE(vtime_now);
		u64 floor_v = now_v - slice_ns;
		u64 v = p->scx.dsq_vtime;

		/* One slice of credit, no more. time_before() handles the wrap
		 * that a plain `<` would get wrong once vtime_now passes 2^63. */
		if (time_before(v, floor_v))
		{
			v = floor_v;
			scx_bpf_task_set_dsq_vtime(p, v);
		}

		if (!scx_bpf_dsq_insert_vtime(p, dsq_id(lvl), task_slice(tctx),
									  v, enq_flags))
		{
			insert_fallback(p, task_slice(tctx), enq_flags);
			return;
		}
	}
	else if (!scx_bpf_dsq_insert(p, dsq_id(lvl), task_slice(tctx), enq_flags))
	{
		insert_fallback(p, task_slice(tctx), enq_flags);
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

	/*
	 * One level per dispatch, round robin. Two jobs share this cursor: the
	 * starvation probe below, and the bitmap repair sweep here.
	 *
	 * Repair is what makes clearing bits survivable. The clear in the scan
	 * below races against ops.enqueue, and while the handshake there is
	 * ordered correctly on x86, a bit lost anyway would strand its tasks
	 * forever -- which is the LFBMQ failure exactly. So: if a level has
	 * queued tasks but no bit, light it. The cursor covers all 33 levels
	 * every 33 dispatches, which at the measured ~100k dispatches/s is
	 * well under a millisecond, against a 5 s watchdog. A lost bit becomes
	 * a delayed dispatch instead of a stalled task.
	 *
	 * Cost is one unlocked nr_queued read per dispatch, and only when the
	 * bit is already clear. Against the 55 probes per dispatch this scan
	 * used to cost, that is not a trade worth thinking about.
	 */
	u32 probe = READ_ONCE(starve_cursor);

	probe = probe < LEVELS - 1 ? probe + 1 : 0;
	WRITE_ONCE(starve_cursor, probe);

	if (clear_bitmap && !(mask & (1ULL << probe)) &&
		scx_bpf_dsq_nr_queued(dsq_id(probe)) > 0)
	{
		__sync_fetch_and_or(&lvl_bitmap, 1ULL << probe);
		mask |= 1ULL << probe;
		stat_inc(SORYU_STAT_BITMAP_REPAIR);
	}

	if (starve_ns)
	{
		/*
		 * Telemetry, once every 1024 dispatches -- tens of times a
		 * second, which is three orders of magnitude finer than a
		 * multi-second watchdog needs, and cheap enough to ignore.
		 * (1024 mod 33 = 1, so consecutive samples walk every level.)
		 */
		if (!(probe_seq++ & 1023) && scx_bpf_dsq_nr_queued(dsq_id(probe)) > 0)
			sample_head_wait(probe);

		/*
		 * Deliberately not gated on lvl_bitmap.
		 *
		 * It used to be, and that quietly made the whole mechanism
		 * depend on the bitmap being accurate: with set-only bits most
		 * probes landed on levels that had been empty for minutes,
		 * failed the move, stamped lvl_last_run and moved on. Measured
		 * 27 serves against 244 for the same workload with bits being
		 * cleared -- the stall protection was mostly spending itself on
		 * stale bits.
		 *
		 * That looked like an argument for clearing. It was not; it was
		 * an argument for not asking the bitmap. nr_queued answers the
		 * question directly with one unlocked read, and clearing turned
		 * out to cost ~16% of the interactive tail (46 of 69 paired
		 * intervals over two rounds, p = 0.008) by making one u64 a
		 * write-hot line four threads take turns owning.
		 *
		 * Cheap test first: the timestamp compare is free and passing
		 * it is rare, so nr_queued only runs when a level really has
		 * gone starve_ns without service.
		 */
		if (now - READ_ONCE(lvl_last_run[probe]) > starve_ns &&
			scx_bpf_dsq_nr_queued(dsq_id(probe)) > 0)
		{
			if (scx_bpf_dsq_move_to_local(dsq_id(probe), 0))
			{
				WRITE_ONCE(lvl_last_run[probe], now);
				stat_inc(SORYU_STAT_DISPATCH);
				stat_inc(SORYU_STAT_STARVE_SERVE);
				return;
			}

			/*
			 * The move failed, and the two reasons it can fail are
			 * not the same thing.
			 *
			 * Empty: the level really was offered a turn and had
			 * nothing to take. Stamp it -- the bitmap is set-only,
			 * so a level idle for hours keeps its bit lit forever
			 * and would otherwise claim a free pass on every probe.
			 *
			 * Not empty, but nothing here can run on this CPU: the
			 * level IS starving, this CPU just cannot help. Stamping
			 * it here was a silent hole in the only stall protection
			 * this scheduler has. Probes land on a given level about
			 * every 8 ms under load (measured: ~1.4M dispatches over
			 * 33 levels in 5.5 min), so a level reset every 8 ms can
			 * never reach a 128 ms starve_ns -- the protection was
			 * permanently off for any task whose cpumask excludes the
			 * probing CPU. Reachable: nr_cpus_allowed == 1 goes to
			 * LOCAL_ON, but restricted-and-multi-CPU masks land here,
			 * which is exactly the class ops.enqueue documents as
			 * still using the shared queue.
			 *
			 * So leave the clock running and let a CPU that can
			 * actually take the task find it starving.
			 */
			if (!scx_bpf_dsq_nr_queued(dsq_id(probe)))
				WRITE_ONCE(lvl_last_run[probe], now);
			else
				stat_inc(SORYU_STAT_STARVE_BLOCKED);
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

		/*
		 * A miss on a lit-but-empty level.
		 *
		 * Measured before this clear existed: a median of 55 probes to
		 * place one task, peaking at 279, against 33 levels. Higher
		 * than the level count because most of the scanning happens on
		 * dispatch calls that find nothing at all -- those walk every
		 * lit level and never increment `dispatch`. A CPU going idle
		 * was touching 25 DSQs to learn it had no work.
		 *
		 * So clear the bit. This is the handshake LFBMQ gets wrong at
		 * alt_core.c:4260, and getting it wrong strands tasks forever,
		 * so it is written out in full:
		 *
		 *   enqueue:   insert into the DSQ, THEN set the bit
		 *   dispatch:  observe empty, clear the bit, THEN re-check
		 *
		 * Both orders matter, and both need the store to land before
		 * the following load. LFBMQ uses smp_rmb() for the second one,
		 * which orders loads against loads and cannot order a store
		 * against a later load -- and store/load is precisely the one
		 * reordering x86 permits. Here __sync_fetch_and_and() is a
		 * seq_cst builtin and JITs to a lock-prefixed RMW on x86, so
		 * the clear is a full barrier and the re-check cannot float
		 * above it.
		 *
		 * Every interleaving is then covered:
		 *
		 *   insert lands before our first nr_queued read  -> we see it,
		 *                                                    no clear
		 *   insert lands between clear and re-check       -> re-check
		 *                                                    sees it,
		 *                                                    we re-set
		 *   insert lands after re-check                   -> enqueue's
		 *                                                    own set
		 *
		 * That argument holds on x86. It is thinner on a weakly ordered
		 * arch, where a BPF atomic without a fetch may not imply a full
		 * barrier. The repair sweep at the top of this function is the
		 * reason that is survivable rather than fatal: a bit lost to any
		 * hole in the reasoning above is relit within 33 dispatches.
		 */
		stat_inc(SORYU_STAT_DISPATCH_MISS);

		if (clear_bitmap && !scx_bpf_dsq_nr_queued(dsq_id(lvl)))
		{
			__sync_fetch_and_and(&lvl_bitmap, ~bit);

			if (scx_bpf_dsq_nr_queued(dsq_id(lvl)) > 0)
				__sync_fetch_and_or(&lvl_bitmap, bit);
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

	/*
	 * Donate down the wake chain. ops.runnable runs in the waker's context
	 * for a synchronous wakeup, so bpf_get_current_task_btf() is the waker.
	 * Not true for every wakeup path -- a remote IPI delivers elsewhere --
	 * which makes this an approximation, and the same approximation
	 * scx_lavd works from.
	 *
	 * Capped by the gap: a wakee is pulled toward its waker, never past it.
	 * Without that a chain of wakeups would ratchet everyone to the floor,
	 * which is the saturation that boost already suffers from and the last
	 * thing worth adding more of.
	 */
	if (wake_donate && (enq_flags & SCX_ENQ_WAKEUP))
	{
		struct task_struct *waker = bpf_get_current_task_btf();

		if (waker && waker != p)
		{
			struct task_ctx *wtctx = lookup_task_ctx(waker);

			if (wtctx && wtctx->boost < tctx->boost)
			{
				s32 gap = tctx->boost - wtctx->boost;
				s32 give = gap < wake_donate ? gap : wake_donate;

				boost_task(p, tctx, (u32)give);
				stat_inc(SORYU_STAT_WAKE_DONATE);
			}
		}
	}

	/*
	 * slptime accounting is deliberately outside the boost_on_wake gate.
	 * The ULE score has to see every sleep whether or not BMQ's wake boost
	 * is enabled, or the two knobs would not be independent and the A/B
	 * would measure their product.
	 */
	if (tctx->sleep_at)
	{
		slept = now > tctx->sleep_at ? now - tctx->sleep_at : 0;
		tctx->sleep_at = 0;
		tctx->slptime += slept;
		ule_decay(tctx);
	}
	else
	{
		slept = 0;
	}

	if (!boost_on_wake || !slept || !slice_ns)
		return;

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
		u64 now = scx_bpf_now();
		bool feeder = gpu_feeder(tctx, now);

		if (idx < 2 * BOOST_RANGE + 1)
		{
			boost_hist[idx]++;
			if (feeder)
				gpu_boost_hist[idx]++;
		}

		/*
		 * Clamp, do not drop. ule_score() returns a closed [0, 100],
		 * and 100 is not a rounding artifact -- it is the score of a
		 * task with slptime == 0, i.e. every pure CPU hog. Dividing by
		 * the bucket width puts those at index 20 in a 20-wide array,
		 * and the obvious `if (sc < ULE_BUCKETS)` guard then discarded
		 * them silently: 46.5% of events by boost's own count, the
		 * entire compiler population, missing from the histogram.
		 *
		 * It read as ULE and BMQ disagreeing about who the hogs were.
		 * They did not; the top bucket was on the floor. lat_bucket()
		 * clamps for the same reason.
		 */
		u32 sc = ule_score(tctx) / (ULE_MAX / ULE_BUCKETS);
		u32 ucls = tctx->boost < 0 ? 0 : (tctx->boost ? 2 : 1);

		if (sc >= ULE_BUCKETS)
			sc = ULE_BUCKETS - 1;

		ule_hist[ucls * ULE_BUCKETS + sc]++;

		/* Advance the reference clock. Racy across CPUs and benign:
		 * the worst case is a slightly stale floor for one enqueue. */
		if (vtime_within_level && time_before(READ_ONCE(vtime_now), p->scx.dsq_vtime))
			WRITE_ONCE(vtime_now, p->scx.dsq_vtime);

		tctx->run_at = now;
		tctx->slice_given = p->scx.slice;

		if (tctx->wake_at)
		{
			u64 lat = tctx->run_at > tctx->wake_at
						  ? tctx->run_at - tctx->wake_at
						  : 0;
			u32 cls = tctx->boost < 0 ? 0 : (tctx->boost ? 2 : 1);
			u32 b = lat_bucket(lat);
			u32 slot = cls * LAT_BUCKETS + b;
			if (slot < LAT_CLASSES * LAT_BUCKETS)
				lat_hist[slot]++;

			/* Every sample here is also in lat_hist above; this is a
			 * subset of it, not a separate measurement. */
			if (feeder && b < LAT_BUCKETS)
				gpu_lat_hist[b]++;

			tctx->wake_at = 0;
		}

		if (tctx->requeue_at)
		{
			u64 rl = now > tctx->requeue_at ? now - tctx->requeue_at : 0;
			u32 pop = tctx->requeue_boosted ? 1 : 2;
			u32 slot = pop * LAT_BUCKETS + lat_bucket(rl);

			if (slot < GPU_POPS * LAT_BUCKETS)
				gpu_lat_hist[slot]++;
			tctx->requeue_at = 0;
		}

		/*
		 * Recorded independently of wake_at, not instead of it. A task
		 * that woke and was then bounced belongs in both: wake->run is
		 * what the workload experiences, bounce->run is what the bounce
		 * added to it.
		 */
		if (tctx->bounce_at)
		{
			u64 bl = tctx->run_at > tctx->bounce_at
						 ? tctx->run_at - tctx->bounce_at
						 : 0;

			bounce_hist[lat_bucket(bl)]++;
			tctx->bounce_at = 0;
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

	now = scx_bpf_now();
	ran = now > tctx->run_at ? now - tctx->run_at : 0;

	/* Same reasoning as slptime in ops.runnable: every scrap of CPU counts
	 * toward the score, on the sleeping path as much as the preempted one. */
	tctx->runtime += ran;
	ule_decay(tctx);

	/* Unweighted: the level already carries priority, so inside one this is
	 * only "who has used least CPU goes first". */
	if (vtime_within_level)
		scx_bpf_task_set_dsq_vtime(p, p->scx.dsq_vtime + ran);

	if (!runnable)
	{
		boost_task(p, tctx, 1);
		tctx->sleep_at = now;
		tctx->slice_left = 0; /* sleeping earns a fresh slice */
		stat_inc(SORYU_STAT_BOOST_SLEEP);
		return;
	}

	/* Boost as it was while running, before the deboost below can move it. */
	if (gpu_feeder(tctx, now))
	{
		tctx->requeue_at = now;
		tctx->requeue_boosted = tctx->boost < 0;
	}

	left = tctx->slice_given > ran ? tctx->slice_given - ran : 0;

	if (left < RESCHED_NS)
	{
		/* The first test keeps gpu_cap at zero when the knob is off,
		 * rather than counting deboosts that were no-ops at +12. */
		if (gpu_boost_cap < BOOST_RANGE && tctx->boost >= gpu_boost_cap &&
			gpu_feeder(tctx, now))
			stat_inc(SORYU_STAT_GPU_CAP);
		else
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
	u32 reason = args ? (u32)args->reason : RELEASE_REASONS - 1;

	if (reenqueue_on_release)
		scx_bpf_reenqueue_local();

	if (cpu >= 0 && cpu < MAX_CPUS)
		cpu_level[cpu] = LEVELS;

	if (reason < RELEASE_REASONS)
		release_reason[reason]++;

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
	tctx->runtime = 0;
	tctx->slptime = 0;
	tctx->bounce_at = 0;
	tctx->cgrp_adj = 0;
	tctx->cgrp_seen = 0; /* forces a refresh on the first enqueue */
	tctx->gpu_submit_at = 0;
	tctx->requeue_at = 0;
	tctx->requeue_boosted = false;

	/* Starting at 0 would read as an enormous credit against vtime_now and
	 * hand every new task the head of its level. */
	if (vtime_within_level)
		scx_bpf_task_set_dsq_vtime(p, READ_ONCE(vtime_now));

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

s32 BPF_STRUCT_OPS(soryu_cgroup_init, struct cgroup *cgrp,
				   struct scx_cgroup_init_args *args)
{
	struct cgrp_ctx *cgc;

	cgc = bpf_cgrp_storage_get(&cgrp_ctxs, cgrp, 0,
							   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cgc)
		return -ENOMEM;

	cgc->weight = args->weight;
	__sync_fetch_and_add(&cgrp_gen, 1);

	return 0;
}

void BPF_STRUCT_OPS(soryu_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	struct cgrp_ctx *cgc = bpf_cgrp_storage_get(&cgrp_ctxs, cgrp, 0, 0);

	if (cgc)
		cgc->weight = weight;

	/*
	 * Every task in @cgrp now has a stale cached adjustment and there is no
	 * way to walk them, so invalidate everyone's. Weights change when
	 * somebody edits a unit file, so the refresh this triggers is a handful
	 * of lookups spread over the next enqueue of each running task.
	 */
	__sync_fetch_and_add(&cgrp_gen, 1);
}

void BPF_STRUCT_OPS(soryu_cgroup_move, struct task_struct *p,
					struct cgroup *from, struct cgroup *to)
{
	struct task_ctx *tctx = lookup_task_ctx(p);

	/* Same effect, one task: force a refresh on its next enqueue. */
	if (tctx)
		tctx->cgrp_seen = 0;
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

		/* [BIT CLEAR!] is a level holding tasks whose bit is unset --
		 * it cannot be dispatched by the scan until the repair sweep
		 * relights it. Transient and self-healing within 33 dispatches;
		 * seeing it in a crash dump means the clear handshake lost a
		 * race, which is worth knowing about even though the sweep
		 * covers it. */
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

/*
 * The feeder hook. i915_request_add fires in the context of the task doing
 * the submitting, so current is the task we want.
 *
 * Kernel threads are skipped: i915 submits its own requests from workers
 * (heartbeats, retires, display), and a kworker that once touched the ring is
 * not a frame feeder. A task scx has not initialised yet has no tctx and is
 * skipped too.
 *
 * The tracepoint lives in i915's module BTF. The loader turns this program
 * off when /sys/kernel/btf/i915 is absent -- the test VM, the AMD machines --
 * so the scheduler still loads there, with no feeders and gpu_boost_cap
 * inert. The request pointer is never dereferenced, which is also why it is
 * typed void: nothing here depends on i915's layout.
 */
SEC("tp_btf/i915_request_add")
int BPF_PROG(soryu_i915_request_add, void *rq)
{
	struct task_struct *p = bpf_get_current_task_btf();
	struct task_ctx *tctx;

	if (!p || (p->flags & PF_KTHREAD))
		return 0;

	tctx = lookup_task_ctx(p);
	if (tctx)
	{
		tctx->gpu_submit_at = scx_bpf_now();
		stat_inc(SORYU_STAT_GPU_SUBMIT);
	}
	return 0;
}

SCX_OPS_DEFINE(soryu_ops,
			   .select_cpu = (void *)soryu_select_cpu,
			   .enqueue = (void *)soryu_enqueue,
			   .dispatch = (void *)soryu_dispatch,
			   .runnable = (void *)soryu_runnable,
			   .running = (void *)soryu_running,
			   .stopping = (void *)soryu_stopping,
			   .cpu_release = (void *)soryu_cpu_release,
			   .cgroup_init = (void *)soryu_cgroup_init,
			   .cgroup_set_weight = (void *)soryu_cgroup_set_weight,
			   .cgroup_move = (void *)soryu_cgroup_move,
			   .init_task = (void *)soryu_init_task,
			   .dump = (void *)soryu_dump,
			   .init = (void *)soryu_init,
			   .exit = (void *)soryu_exit,
			   .flags = SCX_OPS_KEEP_BUILTIN_IDLE,
			   .timeout_ms = 5000,
			   .name = "soryu");
