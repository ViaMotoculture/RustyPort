use std::io;
use std::mem::size_of;
use std::path::Path;
use std::ptr::null_mut;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::{GetLengthSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE};

use crate::ports::{self, Handle, Port};

#[derive(Clone)]
pub struct Watch {
    pub name: String,
    pub image: String,
    pub until: Option<Instant>,
}

impl Watch {
    pub fn is_active(&self) -> bool {
        self.until.is_none_or(|until| Instant::now() < until)
    }
}

pub fn can_watch(port: &Port, system_directory: &str) -> bool {
    unavailable_reason(port, system_directory).is_none()
}

pub fn unavailable_reason(port: &Port, system_directory: &str) -> Option<&'static str> {
    if let Some(reason) = port.stop_unavailable_reason() {
        return Some(reason);
    }
    let Some((windows, _)) = system_directory.rsplit_once('\\') else {
        return Some("Le dossier système Windows est indisponible.");
    };
    let path = &port.owner.path;
    if !Path::new(path).is_absolute() {
        Some("Le chemin complet de l’application est indisponible.")
    } else if !port.owner.services.is_empty() || !port.owner.known_services.is_empty()
        || path.get(..windows.len()).is_some_and(|prefix| prefix.eq_ignore_ascii_case(windows)
            && path.as_bytes().get(windows.len()) == Some(&b'\\'))
    {
        Some("La surveillance des relances est réservée aux applications utilisateur.")
    } else {
        None
    }
}

pub fn prepare(port: &Port, system_directory: &str) -> io::Result<()> {
    if let Some(reason) = unavailable_reason(port, system_directory) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
    }
    let process = open(port.endpoint.pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    if account_sid(process.0)? != account_sid(unsafe { GetCurrentProcess() })? {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Ce processus appartient à un autre compte Windows"));
    }
    Ok(())
}

pub fn enforce(watches: &mut Vec<Watch>) {
    watches.retain(Watch::is_active);
    if watches.is_empty() {
        return;
    }
    let Ok(account) = account_sid(unsafe { GetCurrentProcess() }) else { return };
    let mut buffer = vec![0; 32768];
    for (pid, name) in ports::process_names(None) {
        if pid <= 4 || pid == std::process::id()
            || !watches.iter().any(|watch| watch.name.eq_ignore_ascii_case(&name))
        {
            continue;
        }
        let Ok(process) = open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE) else { continue };
        let Ok(image) = ports::image_path(&process, &mut buffer) else { continue };
        if !account_sid(process.0).is_ok_and(|sid| sid == account) {
            continue;
        }
        if watches.iter().any(|watch| watch.image.eq_ignore_ascii_case(&image) && watch.is_active()) {
            let _ = ports::terminate(&process);
        }
    }
}

pub fn watch(port: Port, delay: Option<Duration>) -> Watch {
    Watch { name: port.owner.name, image: port.owner.path, until: delay.map(|duration| Instant::now() + duration) }
}

fn open(pid: u32, access: u32) -> io::Result<Handle> {
    let raw = unsafe { OpenProcess(access, 0, pid) };
    if raw.is_null() { Err(io::Error::last_os_error()) } else { Ok(Handle(raw)) }
}

fn account_sid(process: HANDLE) -> io::Result<Vec<u8>> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Handle(token);
    let mut size = 0;
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut size) };
    if (size as usize) < size_of::<TOKEN_USER>() {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
    if unsafe { GetTokenInformation(token.0, TokenUser, buffer.as_mut_ptr().cast(), size, &mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let length = unsafe { GetLengthSid(sid) } as usize;
    Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::{Child, Command, Stdio};
    use std::thread;

    const FIXTURE_ENV: &str = "OPENPORT_RELAUNCH_TEST_FIXTURE";

    #[test]
    fn fixture() {
        if std::env::var_os(FIXTURE_ENV).is_some() {
            let _ = std::io::stdin().read_line(&mut String::new());
        }
    }

    #[test]
    fn stops_only_the_watched_executable_while_rule_is_active() {
        struct Fixture(Child);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let directory = std::env::temp_dir().join(format!("openport-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let executable = directory.join("openport-fixture.exe");
        fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        let mut fixture = Fixture(Command::new(&executable)
            .args(["--exact", "relaunch::tests::fixture"])
            .env(FIXTURE_ENV, "1").stdin(Stdio::piped()).stdout(Stdio::null()).spawn().unwrap());

        let process = open(fixture.0.id(), PROCESS_QUERY_LIMITED_INFORMATION).unwrap();
        let image = ports::image_path(&process, &mut [0; 32768]).unwrap();
        let mut watch = Watch { name: "openport-fixture.exe".into(), image, until: Some(Instant::now()) };
        enforce(&mut vec![watch.clone()]);
        assert!(fixture.0.try_wait().unwrap().is_none());

        watch.until = Some(Instant::now() + Duration::from_secs(5));
        let mut other_image = watch.clone();
        other_image.image.push_str(".other");
        enforce(&mut vec![other_image]);
        assert!(fixture.0.try_wait().unwrap().is_none());
        enforce(&mut vec![watch]);
        let deadline = Instant::now() + Duration::from_secs(3);
        while fixture.0.try_wait().unwrap().is_none() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(25));
        }
        assert!(fixture.0.try_wait().unwrap().is_some());
        drop(process);
        drop(fixture);
        fs::remove_file(executable).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
