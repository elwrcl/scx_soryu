// SPDX-License-Identifier: GPL-2.0
//
//
// scx_soryu loader.
//
// runs in the foreground and holds no state of its own: dropping
// the struct_ops link is what unloads the scheduler, so Ctrl-C is the emergency
// exit during development.

mod bpf_skel;
mod stats;
use bpf_skel::*;
use stats::fmt_ns;
use stats::Metrics;

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use scx_stats::prelude::*;
use libbpf_rs::OpenObject;
use libbpf_rs::MapCore;
use log::error;
use log::info;
use log::warn;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;

const SCHEDULER_NAME: &str = "scx_soryu";

/// mirrors `enum soryu_stat_idx` in main.bpf.c, in order.
///
/// The names and the indices come from the same list on purpose. They used to
/// be a `STAT_NAMES` array plus hand-written `g(0)`..`g(15)` calls in
/// `metrics()`, with nothing tying the two together: inserting one counter in
/// the middle of the BPF enum would have silently shifted every metric after
/// it, and the numbers would still have looked plausible.
macro_rules! soryu_stats {
    ($($name:ident),+ $(,)?) => {
        const STAT_NAMES: &[&str] = &[$(stringify!($name)),+];

        #[allow(non_upper_case_globals)]
        mod stat {
            soryu_stats!(@idx 0usize; $($name),+);
        }
    };
    (@idx $n:expr; $head:ident $(, $tail:ident)*) => {
        pub const $head: usize = $n;
        soryu_stats!(@idx $n + 1; $($tail),*);
    };
    (@idx $n:expr;) => {};
}

soryu_stats!(
    enq_shared,
    enq_local,
    enq_reenq,
    enq_pinned,
    dispatch,
    insert_fail,
    cpu_release,
    boost_sleep,
    boost_wake,
    deboost,
    slice_carry,
    fork_split,
    preempt_kick,
    starve_serve,
    preempt_none,
    preempt_idle,
    dispatch_miss,
    starve_blocked,
    bitmap_repair,
    wake_donate,
);

/// mirrors BOOST_RANGE in main.bpf.c.
const BOOST_RANGE: i32 = 12;

/// mirrors ULE_BUCKETS / ULE_MAX in main.bpf.c.
const ULE_BUCKETS: usize = 20;
const ULE_MAX: usize = 100;

/// mirrors LAT_CLASSES / LAT_OCTAVES / LAT_SUBS in main.bpf.c.
const LAT_CLASSES: usize = 3;
const LAT_OCTAVES: usize = 32;
const LAT_SUBS: usize = 4;
const LAT_BUCKETS: usize = LAT_OCTAVES * LAT_SUBS;
const LAT_CLASS_NAMES: [&str; LAT_CLASSES] = ["boosted", "neutral", "deboosted"];

/// Lower edge of bucket @i in ns: mantissa (4 + sub) / 4, scaled by 2^octave.
/// Inverse of lat_bucket() in main.bpf.c.
fn bucket_ns(i: usize) -> u64 {
    let oct = (i / LAT_SUBS) as u32;
    let sub = (i % LAT_SUBS) as u64;

    ((4 + sub) << oct) >> 2
}

/// First bucket whose lower edge is at or above @ns, for the tail report.
fn bucket_at_least(ns: u64) -> usize {
    (0..LAT_BUCKETS)
        .find(|&i| bucket_ns(i) >= ns)
        .unwrap_or(LAT_BUCKETS - 1)
}

/// Elementwise cur - prev, so a report describes its own interval rather than
/// everything since load.
fn hist_delta(cur: &[u64], prev: &[u64]) -> Vec<u64> {
    cur.iter()
        .enumerate()
        .map(|(i, &c)| c.saturating_sub(prev.get(i).copied().unwrap_or(0)))
        .collect()
}

#[derive(Parser, Debug, Clone)]
#[command(about = "BMQ policy port for sched_ext", version)]
struct Opts {
    #[arg(long, default_value_t = 5000, env = "SORYU_TIMEOUT_MS")]
    timeout_ms: u32,
    /// Boost on wakeup in proportion to time slept. Off by default: measured
    /// worse (docs/boost-on-wake.md). Takes a value -- `--boost-on-wake=true`.
    #[arg(long, default_value_t = false, env = "SORYU_BOOST_ON_WAKE",
          action = clap::ArgAction::Set)]
    boost_on_wake: bool,
    /// Clear bitmap bits in ops.dispatch, with the repair sweep that makes it
    /// safe. Off by default: measured worse (docs/bitmap-clear.md). Takes a
    /// value -- `--clear-bitmap=true`.
    #[arg(long, default_value_t = false, env = "SORYU_CLEAR_BITMAP",
          action = clap::ArgAction::Set)]
    clear_bitmap: bool,
    /// Throw the local DSQ back through ops.enqueue when a higher sched class
    /// takes the CPU. On by default. See main.bpf.c for the risk. Takes a
    /// value -- `--reenqueue-on-release=false`.
    #[arg(long, default_value_t = true, env = "SORYU_REENQUEUE_ON_RELEASE",
          action = clap::ArgAction::Set)]
    reenqueue_on_release: bool,
    #[arg(long, default_value_t = 1000, env = "SORYU_SLICE_US")]
    slice_us: u64,
    #[arg(long, default_value_t = 128, env = "SORYU_STARVE_MS")]
    starve_ms: u64,

    /// Levels the FreeBSD ULE interactivity score may move a task, in each
    /// direction, on top of BMQ's boost. 0 disables it and restores BMQ.
    /// The score is measured either way -- see the ule line in the report.
    #[arg(long, default_value_t = 0, env = "SORYU_ULE_WEIGHT")]
    ule_weight: i32,

    /// Combined run+sleep history the ULE score keeps before halving both.
    /// ULE's SCHED_SLP_RUN_MAX.
    #[arg(long, default_value_t = 5000, env = "SORYU_ULE_WINDOW_MS")]
    ule_window_ms: u64,

    /// Levels a cgroup's cpu.weight may move its tasks, in each direction.
    /// 0 disables it, which is what this scheduler did until now -- systemd's
    /// CPUWeight= had no effect at all. Changes fairness between groups, not
    /// latency.
    #[arg(long, default_value_t = 0, env = "SORYU_CGRP_WEIGHT_LEVELS")]
    cgrp_weight_levels: i32,

    /// Boost steps a waker may hand down to the task it wakes, capped by the
    /// gap between them. 0 disables it.
    #[arg(long, default_value_t = 0, env = "SORYU_WAKE_DONATE")]
    wake_donate: i32,

    /// Order each level DSQ by virtual time rather than FIFO -- within a level
    /// only, so BMQ's strict priority between levels is untouched. Off by
    /// default. Takes a value -- `--vtime-within-level=true`.
    #[arg(long, default_value_t = false, env = "SORYU_VTIME_WITHIN_LEVEL",
          action = clap::ArgAction::Set)]
    vtime_within_level: bool,
    #[arg(long, default_value_t = 1, env = "SORYU_REPORT_SEC")]
    report_sec: u64,
    #[arg(long, env = "SORYU_LOG")]
    log: Option<String>,

    /// Print libbpf's output, including the verifier log on a load failure.
    #[arg(long, default_value_t = false, env = "SORYU_DEBUG")]
    debug: bool,

    /// Bytes of scheduler state captured when the kernel ejects us.
    #[arg(long, default_value_t = 65536)]
    exit_dump_len: u32,

    /// Attach to a running scx_soryu and print its telemetry every N seconds.
    /// Starts no scheduler of its own.
    #[arg(long)]
    monitor: Option<f64>,
}
fn percentiles(buckets: &[u64]) -> Option<(u64, u64, u64)> {
    let total: u64 = buckets.iter().sum();
    if total == 0 {
        return None;
    }

    let at = |frac: f64| -> u64 {
        // ceil, and never zero: truncating gave target = 0 for small n, and
        // `seen >= 0` is true before any bucket has been added, so p50 of a
        // single sample reported bucket 0 (1ns) no matter where the sample
        // actually landed.
        let target = ((total as f64 * frac).ceil() as u64).max(1);
        let mut seen = 0u64;
        for (i, &c) in buckets.iter().enumerate() {
            seen += c;
            if seen >= target {
                return bucket_ns(i);
            }
        }
        bucket_ns(buckets.len() - 1)
    };

    Some((at(0.50), at(0.99), at(0.999)))
}

struct Scheduler<'a> {
    opts: Opts,
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    prev_waits: Vec<u64>,

    /// Histogram snapshots from the previous report, so each line describes
    /// its own interval.
    ///
    /// lat_hist and boost_hist accumulate from load and were printed raw, so a
    /// report was the average of every phase the machine had been through. A
    /// run that idled for 5 s and then got busy for 10 s printed one blended
    /// p50 that described neither -- and it moved 16us -> 8us, which reads
    /// like an improvement and is really just the mixture shifting. The
    /// counters were already deltaed for `--monitor`; the histograms were not
    /// deltaed anywhere.
    prev_lat: Vec<u64>,
    prev_boost: Vec<u64>,
    prev_ule: Vec<u64>,
    prev_bounce: Vec<u64>,
    prev_release: Vec<u64>,

    /// Separate snapshots for the stats server: it samples on its own schedule
    /// and must not consume the report's intervals, or vice versa.
    stats_prev_lat: Vec<u64>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let mut skel_builder = BpfSkelBuilder::default();
        // SORYU_DEBUG=1 turns on libbpf's output, which is the only way to see
        // the verifier's rejection log when a program fails to load.
        skel_builder.obj_builder.debug(opts.debug);

        let open_opts = scx_utils::libbpf_clap_opts::LibbpfOpts::default().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, soryu_ops, open_opts)?;

        // Dump the scheduler's own state when we get ejected; ops.dump fills it.
        skel.struct_ops.soryu_ops_mut().exit_dump_len = opts.exit_dump_len;
        skel.struct_ops.soryu_ops_mut().timeout_ms = opts.timeout_ms;

        let rodata = skel
            .maps
            .rodata_data
            .as_mut()
            .context("no rodata section in skeleton")?;

        // The default reproduces BMQ as shipped, whose wake boost is dead
        // code. SORYU_BOOST_ON_WAKE=1 turns on what BMQ meant to do, which
        // measured worse -- see docs/boost-on-wake.md.
        rodata.boost_on_wake = opts.boost_on_wake;
        rodata.starve_ns = opts.starve_ms * 1_000_000;
        rodata.clear_bitmap = opts.clear_bitmap;
        rodata.reenqueue_on_release = opts.reenqueue_on_release;
        rodata.ule_weight = opts.ule_weight;
        rodata.ule_window_ns = opts.ule_window_ms * 1_000_000;
        rodata.cgrp_weight_levels = opts.cgrp_weight_levels;
        rodata.wake_donate = opts.wake_donate;
        rodata.vtime_within_level = opts.vtime_within_level;

        rodata.slice_ns = opts.slice_us * 1_000;

        let mut skel = scx_ops_load!(skel, soryu_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, soryu_ops)?);

        let rd = skel.maps.rodata_data.as_ref().unwrap();
        info!(
            "{} attached: {} CPUs, slice {} us, boost_on_wake={}, \
             starve {} ms, clear_bitmap={}, ule_weight={} (window {} ms), \
             vtime_within_level={}, timeout {} ms",
            SCHEDULER_NAME,
            *scx_utils::NR_CPU_IDS,
            rd.slice_ns / 1000,
            rd.boost_on_wake,
            rd.starve_ns / 1_000_000,
            rd.clear_bitmap,
            rd.ule_weight,
            rd.ule_window_ns / 1_000_000,
            rd.vtime_within_level,
            opts.timeout_ms
        );

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            opts,
            skel,
            struct_ops,
            stats_server,
            prev_waits: Vec::new(),
            prev_lat: Vec::new(),
            prev_boost: Vec::new(),
            prev_ule: Vec::new(),
            prev_bounce: Vec::new(),
            prev_release: Vec::new(),
            stats_prev_lat: Vec::new(),
        })
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    /// Per-CPU counters summed across CPUs.
    fn read_stats(&self) -> Result<Vec<u64>> {
        let nr_cpus = *scx_utils::NR_CPU_IDS;
        let mut out = vec![0u64; STAT_NAMES.len()];

        for (idx, slot) in out.iter_mut().enumerate() {
            let key = (idx as u32).to_ne_bytes();
            let per_cpu = self
                .skel
                .maps
                .stats
                .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)?
                .unwrap_or_default();

            *slot = per_cpu
                .iter()
                .take(nr_cpus)
                .map(|v| u64::from_ne_bytes(v[..8].try_into().unwrap_or([0; 8])))
                .sum();
        }

        Ok(out)
    }

    /// One snapshot for the stats server.
    ///
    /// The counters go out cumulative and `Metrics::delta` differences them at
    /// the far end; the latency percentiles cannot be differenced that way, so
    /// they are computed here from the interval histogram directly.
    fn metrics(&mut self) -> Metrics {
        let c = self.read_stats().unwrap_or_default();
        let g = |i: usize| c.get(i).copied().unwrap_or(0);

        let mut m = Metrics {
            enq_shared: g(stat::enq_shared),
            enq_local: g(stat::enq_local),
            enq_reenq: g(stat::enq_reenq),
            enq_pinned: g(stat::enq_pinned),
            dispatch: g(stat::dispatch),
            insert_fail: g(stat::insert_fail),
            cpu_release: g(stat::cpu_release),
            boost_sleep: g(stat::boost_sleep),
            boost_wake: g(stat::boost_wake),
            deboost: g(stat::deboost),
            slice_carry: g(stat::slice_carry),
            fork_split: g(stat::fork_split),
            preempt_kick: g(stat::preempt_kick),
            starve_serve: g(stat::starve_serve),
            preempt_none: g(stat::preempt_none),
            preempt_idle: g(stat::preempt_idle),
            dispatch_miss: g(stat::dispatch_miss),
            starve_blocked: g(stat::starve_blocked),
            bitmap_repair: g(stat::bitmap_repair),
            wake_donate: g(stat::wake_donate),
            ..Default::default()
        };

        let Some(bss) = self.skel.maps.bss_data.as_ref() else {
            return m;
        };

        m.max_wait_j = bss.max_wait_jiffies;
        m.lvl_bitmap = bss.lvl_bitmap;

        let hist = &bss.boost_hist;
        let total: u64 = hist.iter().sum();
        if total > 0 {
            let weighted: i64 = hist
                .iter()
                .enumerate()
                .map(|(i, &n)| (i as i64 - BOOST_RANGE as i64) * n as i64)
                .sum();
            m.boost_mean_x100 = weighted * 100 / total as i64;
            m.boost_floor_pct = hist[0] * 100 / total;
            m.boost_ceil_pct = hist[hist.len() - 1] * 100 / total;
        }

        // Class 0 is "boosted" -- the interactive tail, and the only class
        // with enough samples to mean anything (hogs barely ever wake).
        let cur = bss.lat_hist[0..LAT_BUCKETS].to_vec();
        let interval = hist_delta(&cur, &self.stats_prev_lat);
        self.stats_prev_lat = cur;

        m.lat_boosted_n = interval.iter().sum();
        if let Some((p50, p99, p999)) = percentiles(&interval) {
            m.lat_boosted_p50 = p50;
            m.lat_boosted_p99 = p99;
            m.lat_boosted_p999 = p999;
        }

        m
    }

    fn report(&mut self) {
        let stats = match self.read_stats() {
            Ok(s) => s,
            Err(e) => {
                warn!("stat read failed: {e}");
                return;
            }
        };

        let bss = self.skel.maps.bss_data.as_ref();
        let (bitmap, max_wait) = bss
            .map(|b| (b.lvl_bitmap, b.max_wait_jiffies))
            .unwrap_or((0, 0));

        let raw: Vec<u64> = self
            .skel
            .maps
            .bss_data
            .as_ref()
            .map(|b| b.lvl_max_wait.to_vec())
            .unwrap_or_default();

        let waits: Vec<String> = raw
            .iter()
            .enumerate()
            .filter(|(_, &w)| w > 0)
            .map(|(lvl, &w)| {
                let rising = self.prev_waits.get(lvl).map(|&p| w > p).unwrap_or(false);
                let mark = if rising { "*" } else { "" };
                match lvl {
                    32 => format!("idle:{w}j{mark}"),
                    10 => format!("l10*n0boosted:{w}j{mark}"),
                    16 => format!("l16*n0neutral:{w}j{mark}"),
                    22 => format!("l22*n0hog:{w}j{mark}"),
                    _ => format!("l{lvl}:{w}j{mark}"),
                }
            })
            .collect();

        if !raw.is_empty() {
            self.prev_waits = raw;
        }

        let line = STAT_NAMES
            .iter()
            .zip(stats.iter())
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join(" ");

        info!("{line} bitmap=0x{bitmap:x} max_wait={max_wait}j");
        if !waits.is_empty() {
            info!("  per-level worst wait: {}", waits.join(" "));
        }

        let Some(bss) = self.skel.maps.bss_data.as_ref() else {
            return;
        };

        // Everything below describes this interval only. The cumulative view
        // is still available -- max_wait and lvl_max_wait above are running
        // maxima, and the counters on the first line are totals since load.
        let boost_cur = bss.boost_hist.to_vec();
        let lat_cur = bss.lat_hist.to_vec();
        let ule_cur = bss.ule_hist.to_vec();
        let bounce_cur = bss.bounce_hist.to_vec();
        let release_cur = bss.release_reason.to_vec();

        let boost = hist_delta(&boost_cur, &self.prev_boost);
        let lat = hist_delta(&lat_cur, &self.prev_lat);
        let ule = hist_delta(&ule_cur, &self.prev_ule);
        let bounce = hist_delta(&bounce_cur, &self.prev_bounce);
        let release = hist_delta(&release_cur, &self.prev_release);

        self.prev_boost = boost_cur;
        self.prev_lat = lat_cur;
        self.prev_ule = ule_cur;
        self.prev_bounce = bounce_cur;
        self.prev_release = release_cur;

        let total: u64 = boost.iter().sum();
        if total > 0 {
            let occupied: Vec<String> = boost
                .iter()
                .enumerate()
                .filter(|(_, &c)| c > 0)
                .map(|(i, &c)| {
                    let b = i as i32 - BOOST_RANGE;
                    format!("{b:+}:{:.1}%", 100.0 * c as f64 / total as f64)
                })
                .collect();

            let weighted: i64 = boost
                .iter()
                .enumerate()
                .map(|(i, &c)| (i as i64 - BOOST_RANGE as i64) * c as i64)
                .sum();
            let mean = weighted as f64 / total as f64;

            info!("  boost mean={mean:+.2} dist: {}", occupied.join(" "));
        }

        let step = ULE_MAX / ULE_BUCKETS;
        let ule_all: u64 = ule.iter().sum();

        for c in 0..LAT_CLASSES {
            let slice = &ule[c * ULE_BUCKETS..(c + 1) * ULE_BUCKETS];
            let n: u64 = slice.iter().sum();
            if n == 0 {
                continue;
            }

            // Bucket midpoint, so the mean is not biased low by truncation.
            let weighted: u64 = slice
                .iter()
                .enumerate()
                .map(|(i, &c)| (i * step + step / 2) as u64 * c)
                .sum();

            // Off both extremes, on a band comparable in width to the one
            // used for boost. The flat number was first computed over 25-74,
            // which is half the ULE range against 92% of the boost range --
            // not a comparison, and it made ULE look worse than it is.
            let mid: u64 = slice[2..18].iter().sum();

            let occupied: Vec<String> = slice
                .iter()
                .enumerate()
                .filter(|(_, &c)| c > 0)
                .map(|(i, &c)| format!("{}:{:.1}%", i * step, 100.0 * c as f64 / n as f64))
                .collect();

            info!(
                "  ule[{}] mean={:.1} mid(10-89)={:.1}% share={:.1}% dist: {}",
                LAT_CLASS_NAMES[c],
                weighted as f64 / n as f64,
                100.0 * mid as f64 / n as f64,
                100.0 * n as f64 / ule_all as f64,
                occupied.join(" ")
            );
        }

        for c in 0..LAT_CLASSES {
            let slice = &lat[c * LAT_BUCKETS..(c + 1) * LAT_BUCKETS];
            let Some((p50, p99, p999)) = percentiles(slice) else {
                continue;
            };

            info!(
                "  wake->run {}: p50={} p99={} p99.9={} n={}",
                LAT_CLASS_NAMES[c],
                fmt_ns(p50),
                fmt_ns(p99),
                fmt_ns(p999),
                slice.iter().sum::<u64>()
            );
        }

        // The population every other latency line here is blind to: bounced
        // by ops.cpu_release, re-enqueued without ever passing through
        // ops.runnable, so no wake_at and no wake->run sample.
        if let Some((p50, p99, p999)) = percentiles(&bounce) {
            let n: u64 = bounce.iter().sum();
            let names = ["rt", "dl", "stop", "unknown"];
            let by: Vec<String> = release
                .iter()
                .enumerate()
                .filter(|(_, &c)| c > 0)
                .map(|(i, &c)| format!("{}:{}", names.get(i).unwrap_or(&"?"), c))
                .collect();

            info!(
                "  bounce->run p50={} p99={} p99.9={} n={}  taken by {}",
                fmt_ns(p50),
                fmt_ns(p99),
                fmt_ns(p999),
                n,
                if by.is_empty() { "-".into() } else { by.join(" ") },
            );
        }

        let boosted = &lat[0..LAT_BUCKETS];
        let n: u64 = boosted.iter().sum();
        if n > 0 {
            // Thresholds in ns rather than bucket indices: the bucket layout
            // is now an implementation detail of lat_bucket(), and hardcoded
            // indices silently meant something else the moment it changed.
            let tail: Vec<String> = [1_000_000u64, 4_000_000, 16_000_000, 64_000_000]
                .iter()
                .map(|&ns| {
                    // Label with the bucket's own edge, not the threshold we
                    // asked for. They differ by up to the ~19% bucket width,
                    // and printing ">1.0ms" for a count that really starts at
                    // 1.05ms is the kind of quiet 5% lie this whole change
                    // exists to remove.
                    let from = bucket_at_least(ns);
                    let pct = 100.0 * boosted[from..].iter().sum::<u64>() as f64 / n as f64;
                    format!(">{} {:.3}%", fmt_ns(bucket_ns(from)), pct)
                })
                .collect();

            info!("  wake->run boosted tail: {}", tail.join("  "));
        }
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        let every = self.opts.report_sec.max(1);
        let mut ticks = 0u64;

        // Telemetry is not the scheduler. A broken stats channel used to
        // propagate out of run(), which main() reports as "ejected by the
        // kernel" -- so a dead socket read as a stall in the journal, exited
        // non-zero, and (under the systemd unit) fired the critical desktop
        // notification. Meanwhile the actual policy was still running fine.
        // Now it degrades: log once, stop serving stats, keep scheduling.
        let mut stats_live = true;

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            if !stats_live {
                std::thread::sleep(Duration::from_secs(1));
                ticks += 1;
                if ticks % every == 0 {
                    self.report();
                }
                continue;
            }

            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => {
                    let m = self.metrics();
                    if let Err(e) = res_ch.send(m) {
                        warn!("stats channel closed ({e}); telemetry off, scheduler still running");
                        stats_live = false;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    ticks += 1;
                    if ticks % every == 0 {
                        self.report();
                    }
                }
                Err(e) => {
                    warn!("stats channel closed ({e}); telemetry off, scheduler still running");
                    stats_live = false;
                }
            }
        }

        // Dropping the link is what detaches the scheduler.
        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("{SCHEDULER_NAME} unloaded, tasks returned to default kernel scheduler");
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    let cfg = simplelog::ConfigBuilder::new()
        .set_time_offset_to_local()
        .expect("failed to set local time offset")
        .build();

    // SORYU_LOG=<path> writes the same output to a file as well.
    let mut sinks: Vec<Box<dyn simplelog::SharedLogger>> = vec![simplelog::TermLogger::new(
        simplelog::LevelFilter::Info,
        cfg.clone(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )];

    if let Some(path) = opts.log.clone() {
        let file = std::fs::File::create(&path)
            .with_context(|| format!("cannot open SORYU_LOG file {path:?}"))?;

        sinks.push(simplelog::WriteLogger::new(
            simplelog::LevelFilter::Info,
            cfg,
            file,
        ));
    }

    simplelog::CombinedLogger::init(sinks)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_handler = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_handler.store(true, Ordering::Relaxed);
    })?;

    if let Some(intv) = opts.monitor {
        return stats::monitor(Duration::from_secs_f64(intv), shutdown);
    }

    info!(
        "pid {} — Ctrl-C to unload, or from another terminal: sudo kill -INT {}",
        std::process::id(),
        std::process::id()
    );

    let mut open_object = MaybeUninit::uninit();
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let mut sched = Scheduler::init(opts.clone(), &mut open_object)?;
        let uei = match sched.run(shutdown.clone()) {
            Ok(uei) => uei,
            Err(e) => {
                error!("{SCHEDULER_NAME} was ejected by the kernel: {e:#}");
                error!("all tasks are back on default kernel scheduler; the scheduler is NOT running");
                return Err(e);
            }
        };

        if !uei.should_restart() {
            break;
        }

        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        info!("hotplug detected, reloading");
    }

    info!("{SCHEDULER_NAME} exiting");
    Ok(())
}
