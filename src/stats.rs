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
    #[stat(desc = "DSQ inserts that failed")]
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
    #[stat(desc = "Levels currently holding tasks")]
    pub lvl_bitmap: u64,
}

impl Metrics {
    fn fmt_ns(ns: u64) -> String {
        if ns >= 1_000_000_000 {
            format!("{:.1}s", ns as f64 / 1e9)
        } else if ns >= 1_000_000 {
            format!("{}ms", ns / 1_000_000)
        } else if ns >= 1_000 {
            format!("{}us", ns / 1_000)
        } else {
            format!("{ns}ns")
        }
    }

    pub fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "wake->run interactive  p50 {:>7}  p99 {:>7}  p99.9 {:>7}  (n={})",
            Self::fmt_ns(self.lat_boosted_p50),
            Self::fmt_ns(self.lat_boosted_p99),
            Self::fmt_ns(self.lat_boosted_p999),
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
            "enqueue    local {} shared {} pinned {} reenq {} fail {}",
            self.enq_local,
            self.enq_shared,
            self.enq_pinned,
            self.enq_reenq,
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
            "preempt    kick {}  idle {}  none {}  cpu_release {}  starve_serve {}",
            self.preempt_kick,
            self.preempt_idle,
            self.preempt_none,
            self.cpu_release,
            self.starve_serve,
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            enq_local: self.enq_local - rhs.enq_local,
            enq_shared: self.enq_shared - rhs.enq_shared,
            enq_pinned: self.enq_pinned - rhs.enq_pinned,
            enq_reenq: self.enq_reenq - rhs.enq_reenq,
            insert_fail: self.insert_fail - rhs.insert_fail,
            cpu_release: self.cpu_release - rhs.cpu_release,
            boost_sleep: self.boost_sleep - rhs.boost_sleep,
            boost_wake: self.boost_wake - rhs.boost_wake,
            deboost: self.deboost - rhs.deboost,
            slice_carry: self.slice_carry - rhs.slice_carry,
            fork_split: self.fork_split - rhs.fork_split,
            preempt_kick: self.preempt_kick - rhs.preempt_kick,
            starve_serve: self.starve_serve - rhs.starve_serve,
            preempt_none: self.preempt_none - rhs.preempt_none,
            preempt_idle: self.preempt_idle - rhs.preempt_idle,
            lat_boosted_n: self.lat_boosted_n - rhs.lat_boosted_n,
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
