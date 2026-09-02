// SPDX-License-Identifier: GPL-2.0
//
// scx_soryu loader.
//
// runs in the foreground and holds no state of its own: dropping
// the struct_ops link is what unloads the scheduler, so Ctrl-C is the emergency
// exit during development.

mod bpf_skel;
mod stats;
use bpf_skel::*;
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

/// mirrors `enum stat_idx` in main.bpf.c.
const STAT_NAMES: &[&str] = &[
    "enq_shared",
    "enq_local",
    "enq_reenq",
    "enq_pinned",
    "dispatch",
    "insert_fail",
    "cpu_release",
    "boost_sleep",
    "boost_wake",
    "deboost",
    "slice_carry",
    "fork_split",
    "preempt_kick",
    "starve_serve",
    "preempt_none",
    "preempt_idle",
];

/// mirrors BOOST_RANGE in main.bpf.c.
const BOOST_RANGE: i32 = 12;

/// mirrors LAT_CLASSES / LAT_BUCKETS in main.bpf.c.
const LAT_CLASSES: usize = 3;
const LAT_BUCKETS: usize = 32;
const LAT_CLASS_NAMES: [&str; LAT_CLASSES] = ["boosted", "neutral", "deboosted"];

#[derive(Parser, Debug, Clone)]
#[command(about = "BMQ policy port for sched_ext", version)]
struct Opts {
    #[arg(long, default_value_t = 5000, env = "SORYU_TIMEOUT_MS")]
    timeout_ms: u32,
    #[arg(long, default_value_t = true, env = "SORYU_BOOST_ON_WAKE",
          action = clap::ArgAction::Set)]
    boost_on_wake: bool,
    #[arg(long, default_value_t = 1000, env = "SORYU_SLICE_US")]
    slice_us: u64,
    #[arg(long, default_value_t = 128, env = "SORYU_STARVE_MS")]
    starve_ms: u64,
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
        let target = (total as f64 * frac) as u64;
        let mut seen = 0u64;
        for (i, &c) in buckets.iter().enumerate() {
            seen += c;
            if seen >= target {
                return 1u64 << i;
            }
        }
        1u64 << (buckets.len() - 1)
    };

    Some((at(0.50), at(0.99), at(0.999)))
}

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

struct Scheduler<'a> {
    opts: Opts,
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    prev_waits: Vec<u64>,
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
        rodata.nr_cpu_ids = *scx_utils::NR_CPU_IDS as u32;

        // SORYU_BOOST_ON_WAKE=0 reproduces BMQ as shipped (its wake boost is
        // dead code); the default reproduces what BMQ meant to do.
        rodata.boost_on_wake = opts.boost_on_wake;
        rodata.starve_ns = opts.starve_ms * 1_000_000;

        rodata.slice_ns = opts.slice_us * 1_000;

        let mut skel = scx_ops_load!(skel, soryu_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, soryu_ops)?);

        let rd = skel.maps.rodata_data.as_ref().unwrap();
        info!(
            "{} attached: {} CPUs, slice {} us, boost_on_wake={}, \
             starve {} ms, timeout {} ms",
            SCHEDULER_NAME,
            *scx_utils::NR_CPU_IDS,
            rd.slice_ns / 1000,
            rd.boost_on_wake,
            rd.starve_ns / 1_000_000,
            opts.timeout_ms
        );

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            opts,
            skel,
            struct_ops,
            stats_server,
            prev_waits: Vec::new(),
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
    fn metrics(&self) -> Metrics {
        let c = self.read_stats().unwrap_or_default();
        let g = |i: usize| c.get(i).copied().unwrap_or(0);

        let mut m = Metrics {
            enq_shared: g(0),
            enq_local: g(1),
            enq_reenq: g(2),
            enq_pinned: g(3),
            insert_fail: g(5),
            cpu_release: g(6),
            boost_sleep: g(7),
            boost_wake: g(8),
            deboost: g(9),
            slice_carry: g(10),
            fork_split: g(11),
            preempt_kick: g(12),
            starve_serve: g(13),
            preempt_none: g(14),
            preempt_idle: g(15),
            ..Default::default()
        };

        if let Some(bss) = self.skel.maps.bss_data.as_ref() {
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
            let boosted = &bss.lat_hist[0..LAT_BUCKETS];
            m.lat_boosted_n = boosted.iter().sum();
            if let Some((p50, p99, p999)) = percentiles(boosted) {
                m.lat_boosted_p50 = p50;
                m.lat_boosted_p99 = p99;
                m.lat_boosted_p999 = p999;
            }
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

        if let Some(bss) = self.skel.maps.bss_data.as_ref() {
            let hist = &bss.boost_hist;
            let total: u64 = hist.iter().sum();

            if total > 0 {
                let occupied: Vec<String> = hist
                    .iter()
                    .enumerate()
                    .filter(|(_, &c)| c > 0)
                    .map(|(i, &c)| {
                        let boost = i as i32 - BOOST_RANGE;
                        format!("{boost:+}:{:.0}%", 100.0 * c as f64 / total as f64)
                    })
                    .collect();

                let weighted: i64 = hist
                    .iter()
                    .enumerate()
                    .map(|(i, &c)| (i as i64 - BOOST_RANGE as i64) * c as i64)
                    .sum();
                let mean = weighted as f64 / total as f64;

                info!("  boost mean={mean:+.2} dist: {}", occupied.join(" "));
            }

            let lines: Vec<String> = (0..LAT_CLASSES)
                .filter_map(|c| {
                    let slice = &bss.lat_hist[c * LAT_BUCKETS..(c + 1) * LAT_BUCKETS];
                    percentiles(slice).map(|(p50, p99, p999)| {
                        format!(
                            "{}: p50={} p99={} p99.9={} n={}",
                            LAT_CLASS_NAMES[c],
                            fmt_ns(p50),
                            fmt_ns(p99),
                            fmt_ns(p999),
                            slice.iter().sum::<u64>()
                        )
                    })
                })
                .collect();

            for l in lines {
                info!("  wake->run {l}");
            }

            let boosted = &bss.lat_hist[0..LAT_BUCKETS];
            let n: u64 = boosted.iter().sum();
            if n > 0 {
                let above = |bucket: usize| -> f64 {
                    100.0 * boosted[bucket..].iter().sum::<u64>() as f64 / n as f64
                };

                info!(
                    "  wake->run boosted tail: >{} {:.3}%  >{} {:.3}%  >{} {:.4}%  >{} {:.4}%",
                    fmt_ns(1 << 20),
                    above(20),
                    fmt_ns(1 << 22),
                    above(22),
                    fmt_ns(1 << 24),
                    above(24),
                    fmt_ns(1 << 26),
                    above(26),
                );
            }
        }
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        let every = self.opts.report_sec.max(1);
        let mut ticks = 0u64;

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => {
                    let m = self.metrics();
                    res_ch.send(m)?;
                }
                Err(RecvTimeoutError::Timeout) => {
                    ticks += 1;
                    if ticks % every == 0 {
                        self.report();
                    }
                }
                Err(e) => Err(e)?,
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
                error!("all tasks are back on default kernel scheduler; the soryu is NOT running");
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
