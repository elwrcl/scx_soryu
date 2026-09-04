# `--clear-bitmap`: measured worse, default off

`lvl_bitmap` advertises which levels hold tasks. Bits were originally set-only
-- never cleared -- because clearing one needs a store/load barrier that LFBMQ
gets wrong at `alt_core.c:4260`, and getting it wrong strands tasks forever.

The cost of not clearing is that `ops.dispatch` walks every level ever used on
every call. Measured before any change: a median of **55 DSQ probes to place
one task**, peaking at 279, against 33 levels. Higher than the level count
because most scanning happens on dispatch calls that find nothing and never
increment `dispatch` -- a CPU going idle was touching 25 DSQs to learn it had
no work.

So clearing was implemented, correctly, with a repair sweep as a safety net.
It works: probes per dispatch fall from ~19.5 to 0.53 under compile load.

**And it is off by default, because it costs interactive latency.**

## The measurement

Same binary, same instrument, same source tree, one flag. Two rounds run back
to back, with the order reversed between them so session drift could not align
with the result.

| round | order | n | clear=false better | clear=true better | sign test | median ratio |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | true then false | 35 | 23 | 11 | p = 0.058 | 0.84 |
| 2 | false then true | 35 | 24 | 10 | p = 0.024 | 0.81 |
| **pooled** | | **70** | **46** | **23** | **p = 0.008** | **0.84** |

Round 1 is the more trustworthy of the two: `false` ran second there, so drift
worked against the result and it still won. Round 2 has order and result
aligned, so it likely overstates. The pooled figure is the honest middle.

Corroborating and drift-independent, the p99 bucket median:

| | p99 | p99.9 |
| --- | --- | --- |
| clear=true (both rounds) | 524 us | 1.00 ms |
| clear=false (both rounds) | 459 us | 0.92 / 1.00 ms |

One bucket, consistent across rounds, while absolute tail percentages moved
between 0.098 and 0.160.

## Why

The likely mechanism, unproven: set-only left `lvl_bitmap` effectively
read-only after warmup, and the scan touched 25 different DSQ cache lines with
unlocked reads every CPU can hold shared. Clearing turns one u64 into a
write-hot line -- roughly 600k atomic RMWs on top of the ~1.1M the enqueue side
already does -- that four threads must take exclusive turns owning.

Twenty-five shared reads are cheaper than one contended line. That is a
statement about a 2c/4t Ivy Bridge and may not survive a wider machine.

## The asymmetry that decides it

Clearing buys 37x fewer probes per dispatch. That scan never had a *measured*
latency cost: `consume_dispatch_q()` tests `list_empty()` unlocked and returns
before taking `dsq->lock` (`ext.c:2517`), so a miss is a cache read and a kfunc
call. Paying a measured cost for an unmeasured saving is the wrong trade.

The knob stays. On a machine with more cores, more cache, or a longer level
scan, the arithmetic could invert.

## What clearing did not buy

It looked like clearing was also required for anti-starvation to work:
`starve_serve` was 27 with bits set-only against 244 with them cleared, because
the probe was gated on `lvl_bitmap` and most probes landed on levels that had
been empty for minutes.

That was an argument for not asking the bitmap, not for clearing it. The probe
now calls `scx_bpf_dsq_nr_queued()` directly -- one unlocked read, and only
after the free timestamp compare has already shown the level is past
`starve_ns`. With bits set-only and the probe decoupled, `starve_serve` is 268:
the protection works without paying for the clear.

## Open

`p99` tracks `starve_serve` rather than `clear_bitmap` across all five runs:
459 us when starvation is quiet (27, 32 serves), 524 us when it is active (244,
268, 283). That suggests clearing and active anti-starvation are two
independent causes of the same one-bucket loss, which would also explain why
disabling anti-starvation entirely while clearing was still on changed nothing
(17 of 35 intervals, p = 1.0) -- the bucket was already spent.

If that holds, a working stall protection costs about one p99 bucket, and that
is a policy price worth paying rather than a bug. It is built on cross-run
comparisons, which this project has already been burned by once, so it is
recorded as a hypothesis and not a result. Deciding it needs a knob for the
probe gating and another back-to-back pair.
