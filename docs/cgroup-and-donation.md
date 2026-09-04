# cgroup weights, and priority donation down the wake chain

Two additions, both knobs, both default off. One closes a functional gap, the
other tested an idea and came back null.

## cgroup cpu.weight

Until now the scheduler was completely deaf to it. `ops.cgroup_set_weight` was
not implemented, so systemd's `CPUWeight=`, and with it the whole
`system.slice` / `user.slice` / `app.slice` arrangement every desktop already
has, did nothing. nice worked; cgroups did not.

`ops.cgroup_init`, `ops.cgroup_set_weight` and `ops.cgroup_move` are now
implemented, with weight held in `BPF_MAP_TYPE_CGRP_STORAGE` keyed by the
cgroup pointer.

`cpu.weight` is `[1, 10000]` with 100 the default and it is geometric: one nice
step is a factor of 1.25, so an octave of weight is `log(2)/log(1.25)` = 3.1
nice steps. Rounded down to 3, which errs toward giving cgroups slightly less
authority than nice rather than more.

The awkward part is caching. `ops.cgroup_set_weight` affects every task in a
cgroup and there is no way to walk them, so a generation counter is bumped on
any weight change; each task compares its own `cgrp_seen` against it and
refreshes once, in `ops.enqueue`. `task_level()` only reads the cached value,
so the hot paths never pay for `scx_bpf_task_cgroup()`'s acquire/release.

`--cgrp-weight-levels` caps the movement in each direction. 0 is the default.

It works, and what it does is not what `cpu.weight` means anywhere else.

### Measured

`tools/cgroup-share.sh`: two cgroups at `cpu.weight` 1000 and 10, N spinners in
each, on a 4-CPU machine. CPU time each group actually got over 30 s.

| spinners per group | ratio hi:lo |
| --- | --- |
| knob off, 4 | **1.00 : 1** |
| 2 (half the CPUs) | 1.36 : 1 |
| 4 (exactly the CPUs) | 3.83 : 1 |
| 8 (twice the CPUs) | **497 : 1** |

The first line is the gap this closed: `cpu.weight` had precisely no effect
before.

The rest is the shape of the thing. At 4 spinners per group the ratio looks
almost reasonable, and it is an artifact of the test: a hi task whose slice
expires is not yet back in its DSQ when that CPU calls `ops.dispatch`, and the
other three are on CPUs, so its level is momentarily empty and dispatch falls
through to lo. Nothing is violated -- hi genuinely was not queued.

Oversubscribe the group and that window closes. At 8 per group, lo got 200 ms
out of 30 s. The scheduler log says why: `enq_local` 0 throughout, so no idle
fast path, and `starve_serve` at up to 30/s. That 200 ms *is* the
anti-starvation crumb and nothing else.

### It is a switch, not a dial

BMQ is strict priority. Once two groups land on different levels, the better
one wins whenever it has anything queued -- and the size of the weight
difference does not enter into it, only whether it crossed a level boundary.

Lowering `--cgrp-weight-levels` does not soften that. It only raises the weight
ratio needed to cross a boundary. 1000-against-100 at `levels 2` is still one
level apart and still 497:1.

CFS gives a 100:1 weight ratio a 100:1 share. Here a 100:1 weight ratio means
the lighter group is off.

### The number that decides the default

`max_wait` reached **1067 jiffies -- 1.07 seconds** -- during the 8-spinner run,
with `l25` (the lo group) as the level waiting. The watchdog ejects at 5 s.

So this knob, at 6, on an oversubscribed machine, runs at a fifth of the stall
threshold, and the only thing between it and an ejection is the anti-starvation
mechanism. That is a real dependency and it is worth stating: `starve_ns = 0`
together with `cgrp_weight_levels > 0` is a combination that will eject.

Default stays 0. Anyone enabling it should know they are getting a priority
band, not a share. Proportional behaviour is not reachable from a level
adjustment at all -- it would need a second mechanism underneath the levels,
which is a different scheduler.

## Wake-chain donation: null

XNU propagates priority through blocking chains with turnstiles; Linux does the
same for `rt_mutex` but only inside the RT class. From BPF the lock graph is
invisible, but the wake graph is not, and it is a decent proxy: if A wakes B, B
is usually about to do something for A.

`ops.runnable` runs in the waker's context for a synchronous wakeup, so
`bpf_get_current_task_btf()` is the waker. If the waker's boost is better, the
wakee is pulled toward it, capped by the gap so it never overtakes -- without
that cap a chain of wakeups ratchets everyone to the floor, which is the
saturation boost already suffers from.

This was deliberately the opposite kind of idea from the ULE ratio. ULE graded
more finely and the tail did not move, which said the problem is not priority
resolution. Donation does not grade; it changes *who* is urgent.

`--wake-donate 4` against 0, back to back on the same compile:

| | intervals | wake_donate | tail >1 ms | p99 | p99.9 | boost floor |
| --- | --- | --- | --- | --- | --- | --- |
| 4 | 37 | 5035 | 0.155% | 655 us | 1.00 ms | 50.9% |
| 0 | 38 | 0 | 0.142% | 655 us | 1.00 ms | 50.8% |

Paired: donate better in 14 intervals, off in 22, sign test p = 0.24. p99 and
p99.9 bit-identical.

## Why it did nothing, which is the useful part

Donation fired 5035 times, roughly 0.6% of wakeups, and the boost floor came
out at 50.9% against 50.8% -- it did not move the population at all.

The condition needs the waker to be strictly better than the wakee, and half
the population is already pinned at -12. Waker at the floor, wakee at the
floor, no gap, no donation.

So saturation kills both ideas from opposite ends: ULE produces a gradient and
grading turns out not to help, while donation needs a gradient and boost does
not have one. Feeding ULE's gradient into donation is the obvious next chain,
and it is built on the half of the pair that was already measured not to
matter, so it was not attempted.

A larger dose is the one cheap variant left. Moving 0.6% of the population
further is not going to move a p99 computed over all of it, so the expectation
is another null.

## Defaults

Both 0. The cgroup path is a gap worth having closed and awaits a share
measurement; donation is a tested null kept for the knob and the record.
