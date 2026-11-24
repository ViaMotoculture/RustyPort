use std::io;
use std::mem::size_of;
use std::ptr::null;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::ports::{Handle, Protocol, wide};

pub struct Job {
    process: Handle,
    pub port: u16,
    pub protocol: Protocol,
    pub block: bool,
}

fn script(port: u16, protocol: Protocol, block: bool) -> String {
    let protocol = protocol.name();
    let name = format!("OpenPort-{protocol}-{port}");
    let change = if block {
        format!(
            "if (!$rule) {{ New-NetFirewallRule -PolicyStore PersistentStore -Name '{name}' \
             -DisplayName 'OpenPort - {protocol} {port}' -Direction Inbound -Action Block \
             -Profile Any -Protocol {protocol} -LocalPort {port} | Out-Null }} \
             else {{ Enable-NetFirewallRule -PolicyStore PersistentStore -Name '{name}' | Out-Null }}"
        )
    } else {
        format!("if ($rule) {{ Remove-NetFirewallRule -PolicyStore PersistentStore -Name '{name}' }}")
    };
    format!(
        "try {{ $ErrorActionPreference = 'Stop'; \
         Import-Module (Join-Path $PSHOME 'Modules\\NetSecurity\\NetSecurity.psd1'); \
         $rule = Get-NetFirewallRule -PolicyStore PersistentStore -Name '{name}' -ErrorAction SilentlyContinue; \
         {change}; exit 0 }} catch {{ exit 1 }}"
    )
}

impl Job {
    pub fn start(window: HWND, port: u16, protocol: Protocol, block: bool) -> io::Result<Self> {
        let mut system = [0u16; 260];
        let length = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
        if length == 0 || length >= system.len() {
            return Err(io::Error::last_os_error());
        }
        let directory = String::from_utf16_lossy(&system[..length]);
        let program = wide(&format!("{directory}\\WindowsPowerShell\\v1.0\\powershell.exe"));
        let arguments = wide(&format!(
            "-NoLogo -NoProfile -NonInteractive -Command \"{}\"",
            script(port, protocol, block)
        ));
        let verb = wide("runas");
        let mut execution = SHELLEXECUTEINFOW {
            cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            hwnd: window,
            lpVerb: verb.as_ptr(),
            lpFile: program.as_ptr(),
            lpParameters: arguments.as_ptr(),
            lpDirectory: null(),
            nShow: SW_HIDE,
            ..Default::default()
        };
        if unsafe { ShellExecuteExW(&mut execution) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if execution.hProcess.is_null() {
            return Err(io::Error::other("Windows n’a pas lancé le pare-feu"));
        }
        Ok(Self { process: Handle(execution.hProcess), port, protocol, block })
    }

    pub fn result(&self) -> Option<io::Result<()>> {
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => None,
            WAIT_OBJECT_0 => {
                let mut exit = 0;
                if unsafe { GetExitCodeProcess(self.process.0, &mut exit) } == 0 {
                    return Some(Err(io::Error::last_os_error()));
                }
                Some(if exit == 0 {
                    Ok(())
                } else {
                    Err(io::Error::other("Windows a refusé la modification du pare-feu"))
                })
            }
            _ => Some(Err(io::Error::last_os_error())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn firewall_commands_parse_without_changing_rules() {
        for (protocol, block) in [(Protocol::Tcp, true), (Protocol::Udp, false)] {
            let code = script(45678, protocol, block).replace('\'', "''");
            let check = format!(
                "$tokens = $null; $errors = $null; \
                 [System.Management.Automation.Language.Parser]::ParseInput(\
                 '{code}', [ref]$tokens, [ref]$errors) | Out-Null; \
                 if ($errors.Count) {{ $errors | Write-Error; exit 1 }}"
            );
            let output = Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", &check])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
