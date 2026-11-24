use std::io;
use std::mem::size_of;
use std::ptr::null;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::ports::{Handle, Protocol, system_directory, wide};

pub struct Job {
    process: Handle,
    pub port: u16,
    pub protocol: Protocol,
    pub action: Action,
}

#[derive(Clone, Copy)]
pub enum Action {
    Block,
    Timed(u16),
    Remove,
}

fn script(port: u16, protocol: Protocol, action: Action) -> String {
    let protocol = protocol.name();
    let name = format!("OpenPort-{protocol}-{port}");
    let temporary = format!("OpenPort-Temp-{protocol}-{port}-");
    let new_rule = format!(
        "New-NetFirewallRule -PolicyStore PersistentStore -Name $name \
         -DisplayName ('OpenPort - {protocol} {port} (' + $name + ')') -Direction Inbound -Action Block \
         -Profile Any -Protocol {protocol} -LocalPort {port} | Out-Null"
    );
    let change = match action {
        Action::Block => format!(
            "$name = '{name}'; \
             $rule = Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue; \
             if (!$rule) {{ {new_rule} }} \
             else {{ Enable-NetFirewallRule -PolicyStore PersistentStore -Name $name | Out-Null }}"
        ),
        Action::Timed(minutes) => format!(
            "Import-Module (Join-Path $PSHOME 'Modules\\ScheduledTasks\\ScheduledTasks.psd1'); \
             $name = '{temporary}' + [Guid]::NewGuid().ToString('N'); \
             $expiry = (Get-Date).AddMinutes({minutes}); \
             $cleanup = ('try {{ $ErrorActionPreference = ''Stop''; \
                 Import-Module (Join-Path $PSHOME ''Modules\\NetSecurity\\NetSecurity.psd1''); \
                 Import-Module (Join-Path $PSHOME ''Modules\\ScheduledTasks\\ScheduledTasks.psd1''); \
                 try {{ Remove-NetFirewallRule -PolicyStore PersistentStore -Name ''RULE_ID'' }} \
                 catch {{ if ($_.CategoryInfo.Category -ne ''ObjectNotFound'') {{ throw }} }}; \
                 Unregister-ScheduledTask -TaskPath ''\\'' -TaskName ''RULE_ID'' -Confirm:$false; exit 0 \
             }} catch {{ exit 1 }}').Replace('RULE_ID', $name); \
             $payload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cleanup)); \
             $action = New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'powershell.exe') \
                 -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand ' + $payload); \
             $trigger = New-ScheduledTaskTrigger -Once -At $expiry; \
             $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries \
                 -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1); \
             Register-ScheduledTask -TaskPath '\\' -TaskName $name -User 'S-1-5-18' \
                 -Action $action -Trigger $trigger -Settings $settings | Out-Null; \
             try {{ \
                 {new_rule}; \
                 if ((Get-Date) -ge $expiry) {{ \
                     Remove-NetFirewallRule -PolicyStore PersistentStore -Name $name; \
                     throw 'Le délai est déjà écoulé'; \
                 }} \
             }} catch {{ \
                 try {{ Remove-NetFirewallRule -PolicyStore PersistentStore -Name $name }} \
                 catch {{ if ($_.CategoryInfo.Category -ne 'ObjectNotFound') {{ throw }} }}; \
                 Unregister-ScheduledTask -TaskPath '\\' -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue; throw \
             }}"
        ),
        Action::Remove => format!(
            "foreach ($name in @('{name}', '{temporary}*')) {{ \
                 try {{ Remove-NetFirewallRule -PolicyStore PersistentStore -Name $name }} \
                 catch {{ if ($_.CategoryInfo.Category -ne 'ObjectNotFound') {{ throw }} }} \
             }}"
        ),
    };
    format!(
        "try {{ $ErrorActionPreference = 'Stop'; \
         Import-Module (Join-Path $PSHOME 'Modules\\NetSecurity\\NetSecurity.psd1'); \
         {change}; exit 0 }} catch {{ exit 1 }}"
    )
}

impl Job {
    pub fn start(window: HWND, port: u16, protocol: Protocol, action: Action) -> io::Result<Self> {
        let directory = system_directory()?;
        let program = wide(&format!("{directory}\\WindowsPowerShell\\v1.0\\powershell.exe"));
        let arguments = wide(&format!(
            "-NoLogo -NoProfile -NonInteractive -Command \"{}\"",
            script(port, protocol, action)
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
        Ok(Self { process: Handle(execution.hProcess), port, protocol, action })
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
        for (protocol, action) in [
            (Protocol::Tcp, Action::Block), (Protocol::Udp, Action::Remove), (Protocol::Tcp, Action::Timed(5)),
        ] {
            let code = script(45678, protocol, action).replace('\'', "''");
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
