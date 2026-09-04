# ULE's interactivity ratio: it separates, and separating does not help

BMQ grades a task with a saturating counter: one step better per sleep, one
step worse per burnt slice. Measured under compile load, that counter is not a
grade -- it is a one-bit classifier. The distribution sits bimodal at roughly
50% on the -12 floor and 44% on the +12 ceiling, with about 6% spread across
the twenty-three values between.

FreeBSD ULE asks a different question: not how many times you slept, but what
fraction of your recent life was sleep, over a decaying window. That is a
continuum by construction. The hypothesis was that it would place the tasks
BMQ cannot -- a render thread, a compositor, a decoder, things that both sleep
a lot and burn a lot and so oscillate around the middle under a counter.

**The hypothesis was half right, and the useful half was the wrong half.**

## The score does separate

`ule_weight = 0`, so the score was computed and histogrammed without being
allowed to touch a scheduling decision. Split by what BMQ's boost thought of
the same task at the same moment:

| class | share of events | ULE mean | off both extremes |
| --- | --- | --- | --- |
| boosted (boost < 0) | 52.8% | 4.7 | 18.5% |
| neutral (boost == 0) | 0.7% | 58.7 | 72.5% |
| deboosted (boost > 0) | 46.4% | 94.8 | 2.7% |

On the hog end the two metrics agree completely: 95.3% of the deboosted class
scores 95-99. ULE adds nothing there and is exactly as saturated as boost.

On the interactive end it adds a lot. Boost puts 50.4% of all events at
precisely -12, which is about 95% of the boosted class on a single value. ULE
splits that same population:

```
  0-4    67.9%
  5-9    14.6%
 10-14   16.5%
```

Three populations where boost sees one.

## Letting it decide changes nothing

`--ule-weight 12`, the largest setting that keeps ULE's authority comparable to
nice's, run back to back against `--ule-weight 0` on the same tree.

| | intervals | tail >1 ms | p50 | p99 | p99.9 | distinct levels | max_wait |
| --- | --- | --- | --- | --- | --- | --- | --- |
| W=12 | 34 | 0.108% | 16.4 us | 393 us | 1.00 ms | 26 (span 0-28) | 21 j |
| W=0 | 34 | 0.106% | 16.4 us | 459 us | 1.00 ms | 15 (span 0-22) | 20 j |

Paired: W=12 better in 16 intervals, W=0 in 17. **Sign test p = 1.0.**

The mechanism engaged -- distinct levels in use went from 15 to 26 and the
span from 0-22 to 0-28, so the score really did reach the level arithmetic and
stretch the distribution. It simply did not move the interactive tail.

p99 came out one bucket better, on one pair. This project has already been
burned once by trusting a single-run bucket comparison, so that is recorded as
a hint and not a result.

No harm either: `insert_fail` 0, `max_wait` 21 j against 20 j, and the deeper
level span was absorbed by anti-starvation (392 serves against 281).

## What this rules out

The interactive tail is not limited by priority resolution. Grading more
finely, carrying the grade into the level, and roughly doubling the width of
the priority distribution all failed to move it.

That is worth knowing because it was the premise behind the whole ULE detour.

## Default

`ule_weight = 0`. The score is still computed and reported, because measuring
it is free and it may answer a different question later.

## Caveat on the mapping

`adj = (score - 50) * weight / 50`, and the level is `(... + adj) / 2`, so the
0-14 band that holds 99% of the interactive population maps to only `0.28 *
weight` units and then halves again. At W=12 that is three distinct adjustments
(-11, -10, -9) and one or two distinct levels. A mapping fitted to the observed
distribution would extract more separation -- and would be fitted to one
workload on one machine, which is why it was not done.
