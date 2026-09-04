# `--boost-on-wake`: the typo wins

BMQ's `sched_task_ttwu()` is meant to boost a waking task in proportion to how
long it slept. That is what makes sleeping for 1 us worth nothing and closes
the sleep-gaming hole. The line reads

```c
s64 delta = this_rq()->clock_task > p->last_ran;
```

A comparison, not a subtraction. `delta` is 0 or 1, the shift takes it to 0,
and the function has been dead code in every shipped BMQ build. `soryu` made it
a knob rather than silently picking a side: `--boost-on-wake=true` is what BMQ
meant to do, `false` is what BMQ actually does.

**Result: off is better, and it is not close.**

## What was run

The scheduler compiling itself, twice per configuration, on the Ivy Bridge
target (i5-3210M, 2c/4t, kernel 7.1.6). Each run logged one report every 10 s
with `--report-sec 10`, giving ~34 intervals per run. Rounds 1 and 2 were run
in separate working trees.

Every number below is per-interval, not cumulative. That matters: before the
histograms were differenced, a run printed one figure blended across every
phase the build went through, which described none of them.

## Latency

Interactive (`boosted` class) wake->run, median across intervals:

| | p99 | p99.9 | tail >1 ms |
| --- | --- | --- | --- |
| on, round 1 | 524 us | 1.30 ms | 0.152% |
| on, round 2 | 524 us | 1.80 ms | 0.168% |
| **off, round 1** | **459 us** | **0.92 ms** | **0.075%** |
| **off, round 2** | **459 us** | **0.92 ms** | **0.077%** |

The two `off` runs agree to the last digit on all three columns.

Pairing the runs interval by interval on the >1 ms tail:

| | intervals | off better | on better | sign test | median ratio |
| --- | --- | --- | --- | --- | --- |
| round 1 | 34 | 31 | 3 | p = 7.7e-07 | 0.53 |
| round 2 | 34 | 32 | 2 | p = 6.9e-08 | 0.45 |
| pooled | 68 | 63 | 5 | p = 7.7e-14 | 0.47 |

Worst single interval, which is the number a stutter would live in:

| | worst tail >1 ms | worst p99.9 | worst `max_wait` |
| --- | --- | --- | --- |
| on, round 1 | 0.299% | 4.2 ms | 21 j |
| on, round 2 | 1.787% | 21.0 ms | 38 j |
| off, round 1 | 0.656% | 7.3 ms | 22 j |
| off, round 2 | 0.129% | 0.92 ms | 21 j |

Each configuration produced one bad round, and `on`'s was worse: two
consecutive intervals at 21 ms p99.9.

## Throughput

| | round 1 | round 2 |
| --- | --- | --- |
| on | 5 m 34 s | 5 m 45 s |
| off | 5 m 39 s | 5 m 32 s |

The ordering flips between rounds. With n = 2 per configuration and a ~10 s
spread already known from earlier runs, there is no throughput difference to
report in either direction. The latency result stands on 68 paired intervals;
the timing result stands on nothing, and is not claimed.

## Health

`insert_fail = 0`, `starve_serve` 22-26 across all four runs, `max_wait` 21-22
jiffies except the one 38 j interval noted above. No stalls, no ejections.

## Why the default flipped

Two independent arguments point the same way. The measurement says off. And
off is BMQ as actually shipped -- the behaviour a decade of field use already
ran, rather than a resurrection nobody has tested. The knob stays so the
question can be reopened on other hardware.

## Open question

The mechanism is not understood. The wake boost grants up to 24 steps at once,
so a waking task is slammed to the floor rather than climbing at +1 per sleep,
and the guess is that this makes a task's level change often enough that
`cpu_level[]` is stale when `try_preempt()` reads it. That is a guess. It would
be tested with a per-task counter of how often the level computed at enqueue
differs from the one seen at `ops.running`.

Note this is not the boost distribution collapsing. Under compile load both
configurations sit bimodal at roughly 54% on the -12 floor and 39% on the +12
ceiling, with about 5% spread across the twenty-three values between, and
`preempt_none` stays near 1.2% in both.

That bimodality was expected to disable preemption -- if everything sits at one
level, nothing outranks anything and `try_preempt()` finds nobody worth an IPI.
It does not, because the range saturates at *both* ends rather than one: the
crowd on the floor always has a ceiling hog to displace. Saturation at one end
would have killed preemption; saturation at both preserves it.
