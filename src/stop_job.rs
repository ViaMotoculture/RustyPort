use std::io;
use std::os::windows::ffi::OsStrExt;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_GEN_FAILURE, HWND};

use crate::elevation;
use crate::ports::{Handle, Port, StopTarget};
use crate::{ports, relaunch};

pub const HELPER_FLAG: &str = "--openport-stop";
pub const BATCH_FLAG: &str = "--openport-stop-batch";
const BATCH_RESULT: u32 = 0x1000000;
const CHANGED: u32 = 0x10000;
const PROTECTED: u32 = 0x10001;
const STOPPING: u32 = 0x10002;

pub struct Job(Handle);

impl Job {
    pub fn start(window: HWND, port: &Port) -> io::Result<Self> {
        let target = StopTarget::from_port(port)?;
        let arguments = format!("{HELPER_FLAG} {}", target.arguments());
        Ok(Self(launch_helper(window, &arguments)?))
    }

    pub fn result(&self) -> Option<io::Result<()>> {
        Some(elevation::exit_code(&self.0)?.and_then(|exit| {
            match exit {
                0 => Ok(()),
                CHANGED => Err(io::Error::other("Le port ou le processus a changé. Actualise la liste.")),
                PROTECTED => Err(io::Error::other("Arrêt refusé pour un processus protégé.")),
                STOPPING => Err(io::Error::other("Le processus est encore en cours d’arrêt.")),
                ERROR_ACCESS_DENIED => Err(io::Error::other("Windows refuse encore l’arrêt après élévation.")),
                code => Err(io::Error::from_raw_os_error(code as i32)),
            }
        }))
    }
}

fn launch_helper(window: HWND, arguments: &str) -> io::Result<Handle> {
    let exe = std::env::current_exe()?;
    let program: Vec<_> = exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    elevation::launch(window, &program, arguments)
}

pub struct BatchJob {
    process: Handle,
    count: usize,
}

impl BatchJob {
    pub fn start(window: HWND, ports: &[Port]) -> io::Result<Self> {
        let mut arguments = BATCH_FLAG.to_string();
        for port in ports {
            arguments.push(' ');
            arguments.push_str(&StopTarget::from_port(port)?.arguments());
        }
        let process = launch_helper(window, &arguments)?;
        Ok(Self { process, count: ports.len() })
    }

    pub fn result(&self) -> Option<io::Result<usize>> {
        Some(elevation::exit_code(&self.process)?.and_then(|code| {
            let count = code.checked_sub(BATCH_RESULT).map(|count| count as usize);
            count.filter(|count| *count <= self.count)
                .ok_or_else(|| io::Error::other("Le résultat de l’arrêt administrateur est indisponible."))
        }))
    }
}

pub fn run_batch_helper(arguments: impl Iterator<Item = String>) -> i32 {
    let arguments: Vec<_> = arguments.collect();
    if arguments.is_empty() || arguments.len() % 6 != 0 {
        return ERROR_GEN_FAILURE as i32;
    }
    let targets = arguments.chunks_exact(6)
        .map(|fields| StopTarget::parse(fields.iter().cloned())).collect::<io::Result<Vec<_>>>();
    match targets {
        Ok(targets) => {
            let stopped = targets.into_iter().filter(|target| target.stop().is_ok()).count();
            (BATCH_RESULT + stopped as u32) as i32
        }
        Err(_) => ERROR_GEN_FAILURE as i32,
    }
}

#[derive(Clone, Copy)]
pub enum Mode {
    Once,
    Watch(Option<u16>),
}

pub struct LocalResult {
    pub stopped: usize,
    pub denied: Vec<Port>,
    pub watches: Vec<relaunch::Watch>,
}

pub fn local_batch(ports: Vec<Port>, mode: Mode, system_directory: String) -> io::Result<Receiver<LocalResult>> {
    let (sender, receiver) = mpsc::channel();
    std::thread::Builder::new().name("openport-stop".into()).spawn(move || {
        let mut stopped = 0;
        let mut denied = Vec::new();
        let mut watches = Vec::new();
        for port in ports {
            if matches!(mode, Mode::Watch(_)) && relaunch::prepare(&port, &system_directory).is_err() {
                continue;
            }
            match ports::stop(&port) {
                Ok(()) => {
                    stopped += 1;
                    if let Mode::Watch(minutes) = mode {
                        let duration = minutes.map(|minutes| Duration::from_secs(u64::from(minutes) * 60));
                        watches.push(relaunch::watch(port, duration));
                    }
                }
                Err(error) if matches!(mode, Mode::Once)
                    && error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => denied.push(port),
                Err(_) => {}
            }
        }
        let _ = sender.send(LocalResult { stopped, denied, watches });
    })?;
    Ok(receiver)
}

pub fn run_helper(arguments: impl Iterator<Item = String>) -> i32 {
    let result = StopTarget::parse(arguments).and_then(StopTarget::stop);
    match result {
        Ok(()) => 0,
        Err(error) => error.raw_os_error().unwrap_or(match error.kind() {
            io::ErrorKind::NotFound => CHANGED as i32,
            io::ErrorKind::PermissionDenied => PROTECTED as i32,
            io::ErrorKind::TimedOut => STOPPING as i32,
            _ => ERROR_GEN_FAILURE as i32,
        }),
    }
}
