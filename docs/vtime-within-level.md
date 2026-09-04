# vtime ordering inside a level: null, because the target was already gone

Every mature sched_ext scheduler orders its DSQs by virtual time --
`scx_bpf_dsq_insert_vtime` is used by bpfland, flash, lavd, p2dq, cake,
mitosis, beerland and forge. soryu inserted plain FIFO, and was the outlier.

It was worth trying here for a specific reason. The ULE ratio had already shown
that grading more finely does nothing (p = 1.0), so priority *resolution* is
not the problem. vtime is a different axis: it changes ordering *within* a
band, which nothing had touched.

And FIFO's worst case had the shape of the tail that was left. Arrive at a
level behind k tasks and wait k slices; at 1 ms slices, k = 5 is 5 ms, which
was the >4.2 ms band. Roughly half of all events sit on the boost floor, so
that queue is the deep one and FIFO is at its worst there.

## Design

Unweighted, on purpose. Tasks sharing a level share a `(nice + boost)` by
construction, so priority already lives in the level and vtime inside one means
only "who has used least CPU goes first". BMQ's strict priority between levels
is untouched.

- `ops.stopping` charges `dsq_vtime += ran`, actual runtime
- `ops.running` advances `vtime_now`, the reference clock
- `ops.enqueue` clamps a sleeper's credit to one slice, then inserts by vtime
- `init_task` starts a task at `vtime_now`; starting at 0 would read as an
  enormous credit and hand every new task the head of its level

`time_before()` rather than `<`, so the comparison survives `vtime_now` passing
2^63. A DSQ must be used consistently as FIFO or vtime and never both; the knob
is read-only after load and the other paths use built-in DSQs, so the level
DSQs stay consistent either way.

## Measured

Back to back, same tree, `cargo clean` before each build:

| | intervals | >1 ms | >4.2 ms | >16.8 ms | p50 | p99 | p99.9 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| vtime | 40 | 0.170% | 0.002% | 0.0000% | 16.4 us | 655 us | 1.00 ms |
| FIFO | 41 | 0.161% | 0.000% | 0.0000% | 16.4 us | 655 us | 1.00 ms |

Paired: >1 ms, 22 to 18, p = 0.64. >4.2 ms, 9 to 14 with 17 ties, p = 0.40.
>16.8 ms, 33 of 40 intervals tied at zero. p50, p99 and p99.9 bit-identical.

## Why it is null

The band it was written to fix is empty. Across the day:

| | >1 ms | >4.2 ms |
| --- | --- | --- |
| boost_on_wake on (original) | 0.156% | 0.057% |
| boost_on_wake off | 0.075% | 0.004% |
| vtime on | 0.170% | 0.002% |
| vtime off | 0.161% | 0.000% |

Flipping `boost_on_wake` took the far tail from 0.057% to 0.004%, and it now
sits at 0.000-0.002%, which is the measurement floor. FIFO depth is not
producing a far tail because there is no far tail left.

The prediction was not wrong so much as unemployed. There was no way to know
without measuring: that the >4.2 ms band had bottomed out only became visible
with every run of the day lined up side by side.

The >1 ms tail that remains, ~0.16% and identical in both configurations, is
most likely irreducible -- four saturated threads and real work queued ahead.
vtime never claimed to change average wait, only worst-case wait, and the
worst case is gone.

## Kept, default off

The mechanism is sound and the rest of the ecosystem relies on it. What failed
was not the idea but its applicability to a 4-thread machine with a single LLC,
where level queues do not get deep enough for ordering within one to matter.

On the 6c/12t targets the queues are deeper and this is worth re-running before
concluding anything. The knob is there for that.
