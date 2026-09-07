// SPDX-License-Identifier: GPL-2.0
//
// Live telemetry, readable from a second terminal with `scx_soryu --monitor`
// while the scheduler runs.

use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Wakeups that found an idle CPU and skipped the shared queue")]
    pub enq_local: u64,
    #[stat(desc = "Enqueues onto a shared level DSQ")]
    pub enq_shared: u64,
    #[stat(desc = "Enqueues of single-CPU tasks, sent straight to that CPU")]
    pub enq_pinned: u64,
    #[stat(desc = "Tasks bounced back by ops.cpu_release")]
    pub enq_reenq: u64,
    #[stat(desc = "Tasks moved from a level DSQ to a local one")]
    pub dispatch: u64,
    #[stat(desc = "DSQ inserts that failed and fell back to the global DSQ")]
    pub insert_fail: u64,
    #[stat(desc = "CPUs taken by a higher sched class (PipeWire RT, i915)")]
    pub cpu_release: u64,

    #[stat(desc = "Boosts from going to sleep")]
    pub boost_sleep: u64,
    #[stat(desc = "Boosts from waking after sleeping at least one slice")]
    pub boost_wake: u64,
    #[stat(desc = "Deboosts from burning a whole slice")]
    pub deboost: u64,
    #[stat(desc = "Preemptions that banked an unused slice remainder")]
    pub slice_carry: u64,
    #[stat(desc = "Forks that split the parent's remaining slice")]
    pub fork_split: u64,
    #[stat(desc = "Preemption IPIs sent")]
    pub preempt_kick: u64,
    #[stat(desc = "Dispatches that jumped priority to unstarve a level")]
    pub starve_serve: u64,
    #[stat(desc = "Wakeups with nobody worse to preempt -- they wait out a slice")]
    pub preempt_none: u64,
    #[stat(desc = "Wakeups that kicked an idle CPU rather than preempting anyone")]
    pub preempt_idle: u64,

    #[stat(desc = "Lit-but-empty level DSQs touched while placing a task")]
    pub dispatch_miss: u64,
    #[stat(desc = "Starving levels this CPU could not serve (affinity)")]
    pub starve_blocked: u64,
    #[stat(desc = "Bits relit after a level was found occupied but unadvertised")]
    pub bitmap_repair: u64,
    #[stat(desc = "Wakeups where the waker handed the wakee some of its boost")]
    pub wake_donate: u64,

    #[stat(desc = "Mean boost, x100 (negative is more interactive)")]
    pub boost_mean_x100: i64,
    #[stat(desc = "Percent of scheduling events at the -12 boost floor")]
    pub boost_floor_pct: u64,
    #[stat(desc = "Percent at the +12 ceiling")]
    pub boost_ceil_pct: u64,

    #[stat(desc = "Interactive wakeup->run p50, ns")]
    pub lat_boosted_p50: u64,
    #[stat(desc = "Interactive wakeup->run p99, ns -- the number that matters")]
    pub lat_boosted_p99: u64,
    #[stat(desc = "Interactive wakeup->run p99.9, ns")]
    pub lat_boosted_p999: u64,
    #[stat(desc = "Interactive wakeup samples")]
    pub lat_boosted_n: u64,

    #[stat(desc = "Worst wait by any runnable task since load, jiffies")]
    pub max_wait_j: u64,
    /// Meaning depends on --clear-bitmap, which defaults to false: set-only,
    /// so "levels used since load" rather than a live occupancy map. Clearing
    /// makes it live and measured worse (docs/bitmap-clear.md). With clearing
    /// on, watch `bitmap_repair` -- a nonzero rate means the clear is racing
    /// more than the argument in main.bpf.c predicts.
    #[stat(desc = "Levels holding tasks (set-only unless --clear-bitmap)")]
    pub lvl_bitmap: u64,
}

/// Single copy, shared with the loader's own report.
///
/// One significant decimal below 100, because the histogram now resolves ~19%
/// steps and truncating to whole units threw that away again -- 1.25 ms and
/// 1.75 ms both printed as "1ms", which is the exact resolution problem the
/// finer buckets were added to fix.
pub fn fmt_ns(ns: u64) -> String {
    let (v, unit) = if ns >= 1_000_000_000 {
        (ns as f64 / 1e9, "s")
    } else if ns >= 1_000_000 {
        (ns as f64 / 1e6, "ms")
    } else if ns >= 1_000 {
        (ns as f64 / 1e3, "us")
    } else {
        return format!("{ns}ns");
    };

    if v >= 100.0 {
        format!("{v:.0}{unit}")
    } else {
        format!("{v:.1}{unit}")
    }
}

impl Metrics {
    pub fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "wake->run interactive  p50 {:>7}  p99 {:>7}  p99.9 {:>7}  (n={})",
            fmt_ns(self.lat_boosted_p50),
            fmt_ns(self.lat_boosted_p99),
            fmt_ns(self.lat_boosted_p999),
            self.lat_boosted_n,
        )?;
        writeln!(
            w,
            "boost      mean {:+.2}  floor {}%  ceiling {}%   max_wait {}j  bitmap 0x{:x}",
            self.boost_mean_x100 as f64 / 100.0,
            self.boost_floor_pct,
            self.boost_ceil_pct,
            self.max_wait_j,
            self.lvl_bitmap,
        )?;
        writeln!(
            w,
            "enqueue    local {} shared {} pinned {} reenq {} dispatch {} fail {}",
            self.enq_local,
            self.enq_shared,
            self.enq_pinned,
            self.enq_reenq,
            self.dispatch,
            self.insert_fail,
        )?;
        writeln!(
            w,
            "signal     boost_sleep {} boost_wake {} deboost {} carry {} fork_split {}",
            self.boost_sleep,
            self.boost_wake,
            self.deboost,
            self.slice_carry,
            self.fork_split,
        )?;
        writeln!(
            w,
            "preempt    kick {}  idle {}  none {}  cpu_release {}",
            self.preempt_kick, self.preempt_idle, self.preempt_none, self.cpu_release,
        )?;
        writeln!(
            w,
            "scan       dispatch_miss {} ({:.1} per dispatch)  repair {}  starve_serve {}  starve_blocked {}",
            self.dispatch_miss,
            if self.dispatch > 0 {
                self.dispatch_miss as f64 / self.dispatch as f64
            } else {
                0.0
            },
            self.bitmap_repair,
            self.starve_serve,
            self.starve_blocked,
        )?;
        writeln!(w, "donate     wake_donate {}", self.wake_donate)?;
        Ok(())
    }

    /// Counters are monotonic *within one attach*. They are not monotonic
    /// across one: a hotplug reload rebuilds the maps from zero while a
    /// `--monitor` client is still connected and still holding the old
    /// snapshot as `prev`. Plain `-` wraps there (release builds have
    /// overflow checks off), so a reload printed deltas near 1.8e19 rather
    /// than the restart it actually was. saturating_sub prints 0 instead.
    fn delta(&self, rhs: &Self) -> Self {
        Self {
            enq_local: self.enq_local.saturating_sub(rhs.enq_local),
            enq_shared: self.enq_shared.saturating_sub(rhs.enq_shared),
            enq_pinned: self.enq_pinned.saturating_sub(rhs.enq_pinned),
            enq_reenq: self.enq_reenq.saturating_sub(rhs.enq_reenq),
            dispatch: self.dispatch.saturating_sub(rhs.dispatch),
            insert_fail: self.insert_fail.saturating_sub(rhs.insert_fail),
            cpu_release: self.cpu_release.saturating_sub(rhs.cpu_release),
            boost_sleep: self.boost_sleep.saturating_sub(rhs.boost_sleep),
            boost_wake: self.boost_wake.saturating_sub(rhs.boost_wake),
            deboost: self.deboost.saturating_sub(rhs.deboost),
            slice_carry: self.slice_carry.saturating_sub(rhs.slice_carry),
            fork_split: self.fork_split.saturating_sub(rhs.fork_split),
            preempt_kick: self.preempt_kick.saturating_sub(rhs.preempt_kick),
            starve_serve: self.starve_serve.saturating_sub(rhs.starve_serve),
            preempt_none: self.preempt_none.saturating_sub(rhs.preempt_none),
            preempt_idle: self.preempt_idle.saturating_sub(rhs.preempt_idle),
            dispatch_miss: self.dispatch_miss.saturating_sub(rhs.dispatch_miss),
            starve_blocked: self.starve_blocked.saturating_sub(rhs.starve_blocked),
            bitmap_repair: self.bitmap_repair.saturating_sub(rhs.bitmap_repair),
            wake_donate: self.wake_donate.saturating_sub(rhs.wake_donate),
            // lat_boosted_* are already per-interval: the loader computes them
            // from a differenced histogram, since percentiles cannot be
            // subtracted. Differencing the count here too would zero it.
            ..self.clone()
        }
    }
}

pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;

        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur = res_ch.recv()?;
            let delta = cur.delta(&prev);
            prev = cur;
            delta.to_json()
        });

        Ok(read)
    });

    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
    .with_context(|| {
        format!(
            "cannot reach the {} stats socket \
             (/var/run/scx/root/stats); is it running, and did you use sudo?",
            crate::SCHEDULER_NAME
        )
    })
}
