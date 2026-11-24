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
        -DisplayName ('RustyPort - ' + $target + ' (' + $name + ')') -Direction Inbound -Action Block \
        -Profile Any -Protocol $protocol -LocalPort $port | Out-Null";
    let change = match action {
        Action::Block => format!(
            "$name = $base; \
             $rule = Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue; \
             if ($rule) {{ Enable-NetFirewallRule -PolicyStore PersistentStore -Name $name | Out-Null }} \
             elseif (Get-NetFirewallRule -PolicyStore PersistentStore -Name $legacyBase -ErrorAction SilentlyContinue) {{ \
                 Set-NetFirewallRule -PolicyStore PersistentStore -Name $legacyBase \
                     -Enabled True -NewDisplayName ('RustyPort - ' + $target) | Out-Null \
             }} else {{ {new_rule} }}"
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
             "foreach ($name in @($base, ($temporary + '*'), $legacyBase, ($legacyTemporary + '*'))) {{ \
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
                 $base = 'RustyPort-' + $protocol + '-' + $port; \
                 $temporary = 'RustyPort-Temp-' + $protocol + '-' + $port + '-'; \
                 $legacyBase = 'OpenPort-' + $protocol + '-' + $port; \
                 $legacyTemporary = 'OpenPort-Temp-' + $protocol + '-' + $port + '-'; \
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

    #[test]
    fn firewall_commands_reuse_and_remove_legacy_rules() {
        let target = &[(45678, Protocol::Tcp)];
        let mocks = "function Import-Module {};
            function Get-NetFirewallRule {
                param($PolicyStore, $Name, $ErrorAction)
                if ($Name -eq 'OpenPort-TCP-45678') { $true }
            };
            function Set-NetFirewallRule {
                param($PolicyStore, $Name, $Enabled, $NewDisplayName)
                if ($Name -ne 'OpenPort-TCP-45678' -or $Enabled -ne 'True' -or $NewDisplayName -ne 'RustyPort - TCP/45678') {
                    throw 'unexpected legacy rule update'
                }
                [Console]::WriteLine($Name)
            };
            function New-NetFirewallRule { throw 'duplicate legacy rule' };
            function Enable-NetFirewallRule { throw 'unexpected firewall enable' };
            function Remove-NetFirewallRule { param($PolicyStore, $Name) [Console]::WriteLine($Name) };";
        for (action, expected) in [
            (Action::Block, &["OpenPort-TCP-45678"][..]),
            (Action::Remove, &[
                "RustyPort-TCP-45678", "RustyPort-Temp-TCP-45678-*",
                "OpenPort-TCP-45678", "OpenPort-Temp-TCP-45678-*",
            ][..]),
        ] {
            let code = format!("{mocks} {}", script(target, action));
            let output = Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", &code]).output().unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert_eq!(stdout.lines().collect::<Vec<_>>(), expected);
        }
    }
}
