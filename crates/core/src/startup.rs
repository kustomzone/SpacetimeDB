use itertools::Itertools;
use once_cell::sync::Lazy;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing_appender::rolling;
use tracing_flame::FlameLayer;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{reload, EnvFilter};

pub struct StartupOptions {
    /// Whether or not to configure the global tracing subscriber.
    pub tracing: bool,
    /// Whether or not to configure the global rayon threadpool.
    pub rayon: bool,
}

impl Default for StartupOptions {
    fn default() -> Self {
        Self {
            tracing: true,
            rayon: true,
        }
    }
}

impl StartupOptions {
    pub fn configure(self) {
        if self.tracing {
            configure_tracing()
        }
        if self.rayon {
            configure_rayon()
        }
    }
}

fn configure_tracing() {
    // Use this to change log levels at runtime.
    // This means you can change the default log level to trace
    // if you are trying to debug an issue and need more logs on then turn it off
    // once you are done.
    let conf_file = std::env::var_os("SPACETIMEDB_LOG_CONFIG")
        .map(PathBuf::from)
        .expect("SPACETIMEDB_LOG_CONFIG must be set to a valid path to a log config file");
    let logs_path: String = std::env::var("SPACETIMEDB_LOGS_PATH")
        .expect("SPACETIMEDB_LOGS_PATH must be set to a valid path to a log directory");

    let timer = tracing_subscriber::fmt::time();
    let format = tracing_subscriber::fmt::format::Format::default()
        .with_timer(timer)
        .with_line_number(true)
        .with_file(true)
        .with_target(false)
        .compact();

    let disable_disk_logging = std::env::var_os("SPACETIMEDB_DISABLE_DISK_LOGGING").is_some();

    let write_to = if disable_disk_logging {
        BoxMakeWriter::new(std::io::stdout)
    } else {
        BoxMakeWriter::new(std::io::stdout.and(rolling::daily(logs_path, "spacetimedb.log")))
    };

    let fmt_layer = tracing_subscriber::fmt::Layer::default()
        .with_writer(write_to)
        .event_format(format);

    let env_filter_layer = parse_from_file(&conf_file);

    let tracy_layer = if std::env::var("SPACETIMEDB_TRACY").is_ok() {
        Some(tracing_tracy::TracyLayer::new())
    } else {
        None
    };

    let (flame_guard, flame_layer) = if std::env::var("SPACETIMEDB_FLAMEGRAPH").is_ok() {
        let flamegraph_path =
            std::env::var("SPACETIMEDB_FLAMEGRAPH_PATH").unwrap_or("/var/log/flamegraph.folded".into());
        let (flame_layer, guard) = FlameLayer::with_file(flamegraph_path).unwrap();
        let flame_layer = flame_layer.with_file_and_line(false).with_empty_samples(false);
        (Some(guard), Some(flame_layer))
    } else {
        (None, None)
    };

    // Is important for `tracy_layer` to be before `fmt_layer` to not print ascii codes...
    let subscriber = tracing_subscriber::Registry::default()
        .with(tracy_layer)
        .with(fmt_layer)
        .with(flame_layer);

    if cfg!(debug_assertions) {
        let (reload_layer, reload_handle) = tracing_subscriber::reload::Layer::new(env_filter_layer);
        std::thread::spawn(move || reload_config(&conf_file, &reload_handle));
        subscriber.with(reload_layer).init();
    } else {
        subscriber.with(env_filter_layer).init();
    };

    if let Some(guard) = flame_guard {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                guard.flush().unwrap();
            }
        });
    }
}

fn parse_from_file(file: &Path) -> EnvFilter {
    let conf = std::fs::read_to_string(file).unwrap_or_default();
    let directives = conf
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .join(",");
    EnvFilter::new(directives)
}

const RELOAD_INTERVAL: Duration = Duration::from_secs(5);
fn reload_config<S>(conf_file: &Path, reload_handle: &reload::Handle<EnvFilter, S>) {
    let mut prev_time = conf_file.metadata().and_then(|m| m.modified()).ok();
    loop {
        std::thread::sleep(RELOAD_INTERVAL);
        if let Ok(modified) = conf_file.metadata().and_then(|m| m.modified()) {
            if prev_time.map_or(true, |prev| modified > prev) {
                log::info!("reloading log config...");
                prev_time = Some(modified);
                if reload_handle.reload(parse_from_file(conf_file)).is_err() {
                    break;
                }
            }
        }
    }
}

fn configure_rayon() {
    let cpus = &CPU_AFFINITY.rayon;
    rayon_core::ThreadPoolBuilder::new()
        .thread_name(|_idx| "rayon-worker".to_string())
        .num_threads(cpus.len())
        .start_handler(|_i| {
            #[cfg(target_os = "linux")]
            sched::set_cpu(cpus.clone().nth(_i).unwrap());
        })
        .build_global()
        .unwrap()
}

/// Contains the cpu affinity ranges for different threadpools in spacetimedb.
#[derive(Clone)]
struct CpuAffinity {
    /// The cpu range for the tokio threadpool; io operations and standard application logic.
    tokio: Range<usize>,
    /// The cpu range for the rayon threadpool; cpu-heavy operations that are parallelized
    /// across multiple cores.
    rayon: Range<usize>,
}

static CPU_AFFINITY: Lazy<CpuAffinity> = Lazy::new(|| {
    let ncpus = std::thread::available_parallelism().unwrap().get();
    assert!(ncpus >= 2);
    let split = ncpus / 2;
    CpuAffinity {
        tokio: 0..split,
        rayon: split..ncpus,
    }
});

#[cfg(target_os = "linux")]
mod sched {

    use nix::sched::{sched_setaffinity, CpuSet};
    use nix::unistd::Pid;

    pub fn set_cpu(cpu: usize) {
        setaffinity(&cpuset([cpu]))
    }

    pub fn cpuset(cpus: impl IntoIterator<Item = usize>) -> CpuSet {
        let mut cpuset = CpuSet::new();
        for cpu in cpus {
            cpuset.set(cpu).unwrap();
        }
        cpuset
    }

    pub fn setaffinity(cpuset: &CpuSet) {
        if let Err(e) = sched_setaffinity(Pid::from_raw(0), cpuset) {
            tracing::warn!("failed to set cpu affinity: {e}")
        }
    }
}

pub fn tokio_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    let cpus = CPU_AFFINITY.tokio.clone();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(cpus.len())
        .on_thread_start({
            #[cfg(target_os = "linux")]
            let cpuset = sched::cpuset(cpus);
            move || {
                #[cfg(target_os = "linux")]
                sched::setaffinity(&cpuset);
            }
        })
        .build()
}
