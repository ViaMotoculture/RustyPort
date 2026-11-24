use std::io;

use windows_sys::Win32::Foundation::HWND;

use crate::elevation;
use crate::ports::{Handle, Protocol, system_directory, wide};

pub struct Job {
    process: Handle,
    pub targets: Vec<(u16, Protocol)>,
    pub action: Action,
}

#[derive(Clone, Copy)]
pub enum Action {
    Block,
    Timed(u16),
    Remove,
}

fn script(targets: &[(u16, Protocol)], action: Action) -> String {
    let targets = targets.iter().map(|(port, protocol)| format!("'{}/{port}'", protocol.name()))
        .collect::<Vec<_>>().join(",");
    let new_rule = "New-NetFirewallRule -PolicyStore PersistentStore -Name $name \
        -DisplayName ('OpenPort - ' + $target + ' (' + $name + ')') -Direction Inbound -Action Block \
        -Profile Any -Protocol $protocol -LocalPort $port | Out-Null";
    let change = match action {
        Action::Block => format!(
            "$name = $base; \
             $rule = Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue; \
             if (!$rule) {{ {new_rule} }} \
             else {{ Enable-NetFirewallRule -PolicyStore PersistentStore -Name $name | Out-Null }}"
        ),
        Action::Timed(minutes) => format!(
            "Import-Module (Join-Path $PSHOME 'Modules\\ScheduledTasks\\ScheduledTasks.psd1'); \
             $name = $temporary + [Guid]::NewGuid().ToString('N'); \
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
            "foreach ($name in @($base, ($temporary + '*'))) {{ \
                 try {{ Remove-NetFirewallRule -PolicyStore PersistentStore -Name $name }} \
                 catch {{ if ($_.CategoryInfo.Category -ne 'ObjectNotFound') {{ throw }} }} \
             }}"
        ),
    };
    format!(
        "try {{ $ErrorActionPreference = 'Stop'; \
         Import-Module (Join-Path $PSHOME 'Modules\\NetSecurity\\NetSecurity.psd1') \
         }} catch {{ exit 65536 }}; \
         $failed = 0; foreach ($target in @({targets})) {{ \
             try {{ \
                 $protocol, $port = $target.Split('/'); \
                 $base = 'OpenPort-' + $protocol + '-' + $port; \
                 $temporary = 'OpenPort-Temp-' + $protocol + '-' + $port + '-'; \
                 {change} \
             }} catch {{ $failed++ }} \
         }}; exit $failed"
    )
}

impl Job {
    pub fn start(window: HWND, targets: Vec<(u16, Protocol)>, action: Action) -> io::Result<Self> {
        let directory = system_directory()?;
        let program = wide(&format!("{directory}\\WindowsPowerShell\\v1.0\\powershell.exe"));
        let arguments = format!(
            "-NoLogo -NoProfile -NonInteractive -Command \"{}\"",
            script(&targets, action)
        );
        let process = elevation::launch(window, &program, &arguments)?;
        Ok(Self { process, targets, action })
    }

    pub fn result(&self) -> Option<io::Result<usize>> {
        Some(elevation::exit_code(&self.process)?.and_then(|exit| {
            if exit as usize <= self.targets.len() {
                Ok(exit as usize)
            } else {
                Err(io::Error::other("Windows a refusé la modification du pare-feu"))
            }
        }))
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
            let code = script(&[(45678, protocol), (45679, Protocol::Udp)], action).replace('\'', "''");
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
