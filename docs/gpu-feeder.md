# `--gpu-boost-cap`: don't deboost the render thread

A GPU feeder is a task that submitted GPU work within the last 100 ms, as seen
by a `tp_btf/i915_request_add` hook: a game's render thread, the compositor,
Xwayland. BMQ deboosts a task for burning whole slices, which is exactly what a
render thread does on a heavy frame, and strict priority then queues it behind
every better level. `--gpu-boost-cap` stops a recent feeder from being
deboosted past the given boost.

**Result: `-1` removes most of the stutter, and is the default.**

The idea came from reading the Infinity scheduler (galpt/infinity-scheduler),
whose v4.8 couples CPU and GPU accounting. Its GPU half patches `drm_sched`,
which i915 does not use, so none of that applies to Ivy Bridge. What carried
over was the question of whether the CPU side lets the GPU's feeders wait.

## What was run

Half-Life 2 (native GL, Mesa crocus), the same 60 s camera pan each round, on
the Ivy Bridge target (i5-3210M, 2c/4t, HD 4000, kernel 7.2.8). Frame times
from MangoHud's CSV log; scheduler numbers from `SORYU_LOG` at one report per
second. Both settings ran from the same binary, alternating off, on, off, on,
so the knob is the only thing that differs.

## Finding the cause

The first instrument only saw wake->run, and feeders looked fine there: p99
around 0.5-0.8 ms with or without load. The render thread's problem is not
waking up. It rarely sleeps mid-frame; it burns its slice, stops still
runnable, and waits to get the CPU back -- a path that never passes
`ops.runnable` and so was invisible.

Measuring that requeue wait, split by the feeder's boost at the moment it
stopped (one 60 s pan, knob off):

| | p99, median second | p99.9, worst second | seconds with p99.9 > 4 ms |
| --- | --- | --- | --- |
| boosted (boost < 0) | 0.92 ms | 3.1 ms | 0 of 72 |
| deboosted (boost >= 0) | 1.0 ms | **25.2 ms** | **6 of 61** |

Boosted, the wait never went past a few slices. Deboosted, it reached two
frames at 85 fps. Feeder boost spent that run at a median of -7.6, so the
render thread was crossing into the deboosted class constantly.

## Frames, idle desktop

| | median frame | p99.9 frame | frames > 2x median | frames > 25 ms | 0.1% low |
| --- | --- | --- | --- | --- | --- |
| off, round 1 | 13.2 ms | 44.0 ms | 15 | 27 | 22.6 fps |
| **-1, round 1** | **12.5 ms** | **26.1 ms** | **6** | **6** | **37.8 fps** |
| off, round 2 | 12.7 ms | 43.2 ms | 23 | 26 | 21.7 fps |
| **-1, round 2** | **12.5 ms** | **25.7 ms** | **8** | **8** | **37.9 fps** |

The two rounds of each setting agree closely. Frames over 25 ms fell by about
70%.

On the scheduler side, deboosted feeder requeues went from ~785/s to ~1/s,
while the cap itself fired only ~35 times a second -- a small intervention.

## Under load

The same pan with `stress-ng --cpu 4 --timeout 60s` running alongside:

| | avg fps | 1% low | 0.1% low | stress-ng ops/s (real) | ops/s (usr+sys) |
| --- | --- | --- | --- | --- | --- |
| off | 60.8 | 30.0 | 21.2 | 1026 | 778 |
| **-1** | **73.3** | **46.6** | **36.8** | 750 | 753 |

## The cost

stress-ng lost 27% of its throughput. Its ops per CPU-second barely moved (778
against 753), so it did not run slower -- it got less CPU, 60 CPU-seconds
instead of 79 over the minute, and the game took the difference. That is the
trade the knob exists to make.

Nothing starved. The worst wait was ~130 jiffies in both rounds, which is the
`starve_ns` bound itself, and `starve_serve` moved from 1.2/s to 1.5/s.

On an idle desktop the other side of the trade shows up in the `deboosted`
class: its wake->run p99 went from ~0.5 ms to 1.0-1.3 ms.

The cap applies to anything that submits GPU work, including an OpenCL render
(DaVinci, beignet/pocl). A build running alongside one will lose a similar
share. That was judged acceptable for a desktop; `--gpu-boost-cap=12` turns it
off.

## Dropped: waking out of a GPU wait

The first version also hooked `i915_request_wait_begin/end` and
`dma_fence_wait_start/end`, to time feeders waking from a GPU wait. Over 20
minutes of play that saw 1251 such wakeups against 434k submissions: crocus
does not block in the kernel for its fences, so there was nothing there to
schedule. The hooks were removed.

## For reference: EEVDF

With soryu unloaded, the same game under `stress-ng --cpu 4` ran at 8-11 fps
(read off the overlay, one run), against 40-50 for soryu without the cap. On an
idle desktop EEVDF's 1% low was 47.7 against 43.2 for soryu without the cap,
which is the stutter this change removes; with it, soryu's 1% low is 46.6-47.3.

## Open

- One game. A Vulkan title through hasvk, and a game whose render thread
  rarely burns a full slice, would say whether -1 is right in general or only
  for this workload.
- No AMD numbers. Without `/sys/kernel/btf/i915` the hook does not load and the
  cap has no feeders to act on; an amdgpu equivalent would need its own
  tracepoint.
