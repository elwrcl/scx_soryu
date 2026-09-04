# cpu_release: a blind spot, an answer, and a knob that changed nothing

The interactive tail on an idle-ish desktop is consistently worse than during a
full compile -- 0.29% past 1 ms against 0.15% -- which is backwards, and the
one number that tracked it was `cpu_release`: about 130 a second on the desktop
against 3 during a compile.

## The instrument was blind to it

`scx_bpf_reenqueue_local()` throws the local DSQ back through `ops.enqueue`
with `SCX_ENQ_REENQ`. `ops.runnable` is not part of that path, so `wake_at` is
never stamped, and `ops.running` records a latency sample only when `wake_at`
is set.

So every task bounced by a higher sched class spent that trip invisible. The
tail that every decision on this branch was measured against excluded exactly
the population under suspicion. `bounce_hist` was added to close that, stamped
at `SCX_ENQ_REENQ` in `ops.enqueue` and read at `ops.running`, recorded
alongside the wake sample rather than instead of it.

## What takes the CPU

`ops.cpu_release` now splits by `enum scx_cpu_preempt_reason`.

| | releases | rt | stop | dl |
| --- | --- | --- | --- | --- |
| compile, 6 min | 662 | 307 | 355 | 0 |
| desktop, 5 min | 38916 | 38775 | 141 | 0 |

Desktop is **99.6% RT**, at roughly 130 releases a second, each bouncing 0.98
tasks. No deadline tasks at all.

## Bounced tasks wait about twice as long

| | wake->run p99 | bounce->run p99 | bounce share |
| --- | --- | --- | --- |
| compile | 655 us | 786 us | 0.1% |
| desktop | 655 us | 1.3 ms | 1.8% |

Real, and too small to matter. At 1.8% of samples with a p99 of 1.3 ms,
bounces contribute roughly 18 events past 1 ms per interval against 193 from
the wake population -- about 9% more tail, not the doubling that needed
explaining.

## So the answer is the boring one

The desktop's *non-bounced* population is already worse: `wake->run` p99.9 of
1.45 ms against 1.00 ms during a compile. RT preemption at 130 a second does
not mainly hurt the task it bounces, it steals CPU from everyone and raises
queueing delay across the board.

That is RT working as designed. The scheduler has no move here.

## The knob, and its null

If the RT burst is short -- an audio callback is tens of microseconds -- then
re-enqueueing is waste: the task pays a full trip through `ops.enqueue`, level
recomputed and DSQ reinserted, to avoid a wait it would have outlasted.
`--reenqueue-on-release=false` tests that.

| | intervals | cpu_release/iv | enq_reenq | tail >1 ms | p99 | p99.9 | max_wait |
| --- | --- | --- | --- | --- | --- | --- | --- |
| true | 14 | 1138 | 15580 | 0.368% | 655 us | 1.60 ms | 32 j |
| false | 30 | 897 | 0 | 0.410% | 655 us | 1.60 ms | 22 j |

Paired: `false` better in 4 intervals, `true` in 10, sign test p = 0.18.

The knob works -- `enq_reenq` and the bounce histogram both go to zero -- and
changes nothing measurable. p99 and p99.9 are bit-identical. This was predicted
before the run, on the arithmetic above, and the prediction is recorded here
because on this branch it is the third or fourth hypothesis to be tested and
the first to survive.

The comparison is weak on its own terms: the two runs differ by 27% in release
rate and by more than double in length, because desktop activity is not
reproducible the way a compile is. It is not worth strengthening. The prior and
the data agree, and they agree on "no effect".

## Default

`reenqueue_on_release = true`. It is the conventional behaviour, it is what the
paired direction leans toward, and it is the safe side of a risk this test did
not exercise: with it off, tasks in the local DSQ of a CPU taken by a *long*
RT or DL task cannot migrate away, and `starve_ns` walks the shared level DSQs,
not local ones. Short audio bursts are fine. An RT hog would be a 5 s watchdog
ejection.

`bounce_hist` and the reason split stay regardless. They cost nothing and they
closed a hole in the instrument that had been open the whole time.
