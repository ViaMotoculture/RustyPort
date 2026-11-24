use std::collections::{HashMap, HashSet};
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::System::Threading::*;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn name(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Endpoint {
    pub port: u16,
    pub protocol: Protocol,
    pub address: IpAddr,
    scope: u32,
    pub pid: u32,
}

impl Endpoint {
    fn new(protocol: Protocol, address: IpAddr, scope: u32, port: u32, pid: u32) -> Self {
        Self {
            port: u16::from_be(port as u16),
            protocol,
            address,
            scope: u32::from_be(scope),
            pid,
        }
    }

    pub fn address_label(self) -> String {
        if self.scope == 0 {
            self.address.to_string()
        } else {
            format!("{}%{}", self.address, self.scope)
        }
    }

    pub fn label(self) -> String {
        format!("{}/{}", self.port, self.protocol.name())
    }

    pub fn is_local(self) -> bool {
        match self.address {
            IpAddr::V4(address) => address.is_loopback(),
            IpAddr::V6(address) => {
                address.is_loopback() || address.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct Owner {
    pub name: String,
    pub path: String,
    pub services: Vec<String>,
    pub created: Option<u64>,
}

#[derive(Clone)]
pub struct Port {
    pub endpoint: Endpoint,
    pub owner: Owner,
}

impl Port {
    pub fn can_stop(&self) -> bool {
        let pid = self.endpoint.pid;
        pid > 4 && pid != std::process::id() && self.owner.created.is_some()
    }
}

pub struct Handle(pub HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn decode_wide(value: &[u16]) -> String {
    let length = value.iter().position(|part| *part == 0).unwrap_or(value.len());
    String::from_utf16_lossy(&value[..length])
}

fn table<T: Copy>(mut query: impl FnMut(*mut std::ffi::c_void, &mut u32) -> u32) -> io::Result<Vec<T>> {
    let mut bytes = 0;
    let mut buffer = Vec::<u32>::new();
    for _ in 0..5 {
        let address = if buffer.is_empty() {
            null_mut()
        } else {
            buffer.as_mut_ptr().cast()
        };
        match query(address, &mut bytes) {
            ERROR_INSUFFICIENT_BUFFER => buffer.resize((bytes as usize).div_ceil(4), 0),
            ERROR_NOT_SUPPORTED | ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_SUCCESS if !buffer.is_empty() => {
                // The four OWNER_PID tables start with a DWORD followed by DWORD-aligned rows.
                let count = buffer[0] as usize;
                if count > (buffer.len() * 4 - size_of::<u32>()) / size_of::<T>() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Table réseau invalide"));
                }
                let rows = unsafe { buffer.as_ptr().add(1).cast::<T>() };
                return Ok((0..count)
                    .map(|index| unsafe { rows.add(index).read_unaligned() })
                    .collect());
            }
            ERROR_SUCCESS => return Ok(Vec::new()),
            error => return Err(io::Error::from_raw_os_error(error as i32)),
        }
    }
    Err(io::Error::from_raw_os_error(ERROR_INSUFFICIENT_BUFFER as i32))
}

fn endpoints() -> io::Result<Vec<Endpoint>> {
    let tcp = |family, buffer, size: &mut u32| unsafe {
        GetExtendedTcpTable(buffer, size, 0, u32::from(family), TCP_TABLE_OWNER_PID_LISTENER, 0)
    };
    let udp = |family, buffer, size: &mut u32| unsafe {
        GetExtendedUdpTable(buffer, size, 0, u32::from(family), UDP_TABLE_OWNER_PID, 0)
    };
    let mut endpoints = Vec::new();
    for entry in table::<MIB_TCPROW_OWNER_PID>(|buffer, size| tcp(AF_INET, buffer, size))? {
        endpoints.push(Endpoint::new(
            Protocol::Tcp, Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes()).into(),
            0, entry.dwLocalPort, entry.dwOwningPid,
        ));
    }
    for entry in table::<MIB_TCP6ROW_OWNER_PID>(|buffer, size| tcp(AF_INET6, buffer, size))? {
        endpoints.push(Endpoint::new(
            Protocol::Tcp, Ipv6Addr::from(entry.ucLocalAddr).into(),
            entry.dwLocalScopeId, entry.dwLocalPort, entry.dwOwningPid,
        ));
    }
    for entry in table::<MIB_UDPROW_OWNER_PID>(|buffer, size| udp(AF_INET, buffer, size))? {
        endpoints.push(Endpoint::new(
            Protocol::Udp, Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes()).into(),
            0, entry.dwLocalPort, entry.dwOwningPid,
        ));
    }
    for entry in table::<MIB_UDP6ROW_OWNER_PID>(|buffer, size| udp(AF_INET6, buffer, size))? {
        endpoints.push(Endpoint::new(
            Protocol::Udp, Ipv6Addr::from(entry.ucLocalAddr).into(),
            entry.dwLocalScopeId, entry.dwLocalPort, entry.dwOwningPid,
        ));
    }
    endpoints.sort_unstable();
    endpoints.dedup();
    Ok(endpoints)
}

fn process_names(pids: &HashSet<u32>) -> HashMap<u32, String> {
    let mut names = HashMap::new();
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return names;
    }
    let handle = Handle(raw);
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut ok = unsafe { Process32FirstW(handle.0, &mut entry) };
    while ok != 0 {
        if pids.contains(&entry.th32ProcessID) {
            names.insert(entry.th32ProcessID, decode_wide(&entry.szExeFile));
        }
        ok = unsafe { Process32NextW(handle.0, &mut entry) };
    }
    names
}

fn service_names() -> HashMap<u32, Vec<String>> {
    let mut services = HashMap::<u32, Vec<String>>::new();
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ENUMERATE_SERVICE) };
    if manager.is_null() {
        return services;
    }
    let mut buffer = vec![0usize; 256 * 1024 / size_of::<usize>()];
    let mut resume = 0;
    loop {
        let previous = resume;
        let mut needed = 0;
        let mut count = 0;
        let ok = unsafe {
            EnumServicesStatusExW(
                manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE,
                buffer.as_mut_ptr().cast(), (buffer.len() * size_of::<usize>()) as u32,
                &mut needed, &mut count, &mut resume, null(),
            )
        };
        let error = if ok == 0 { unsafe { GetLastError() } } else { ERROR_SUCCESS };
        if error != ERROR_SUCCESS && error != ERROR_MORE_DATA {
            break;
        }
        let entries = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(), count as usize)
        };
        for entry in entries {
            let pid = entry.ServiceStatusProcess.dwProcessId;
            if pid != 0 && !entry.lpDisplayName.is_null() {
                // The service manager returns NUL-terminated strings inside the buffer.
                let mut length = 0;
                while unsafe { *entry.lpDisplayName.add(length) } != 0 {
                    length += 1;
                }
                let name = String::from_utf16_lossy(unsafe {
                    std::slice::from_raw_parts(entry.lpDisplayName, length)
                });
                services.entry(pid).or_default().push(name);
            }
        }
        if ok != 0 || resume == previous {
            break;
        }
    }
    unsafe { CloseServiceHandle(manager) };
    services
}

fn creation_time(process: &Handle) -> io::Result<u64> {
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetProcessTimes(process.0, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

pub fn list() -> io::Result<Vec<Port>> {
    let endpoints = endpoints()?;
    let pids = endpoints.iter().map(|endpoint| endpoint.pid).collect();
    let mut names = process_names(&pids);
    let mut services = service_names();
    let mut owners = HashMap::new();
    let mut path = vec![0; 32768];
    for pid in pids {
        let mut owner = Owner {
            name: names.remove(&pid).unwrap_or_else(|| match pid {
                4 => "System".into(),
                _ => "Inconnu".into(),
            }),
            services: services.remove(&pid).unwrap_or_default(),
            ..Default::default()
        };
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if !raw.is_null() {
            let process = Handle(raw);
            owner.created = creation_time(&process).ok();
            let mut length = path.len() as u32;
            if unsafe { QueryFullProcessImageNameW(process.0, 0, path.as_mut_ptr(), &mut length) } != 0 {
                owner.path = String::from_utf16_lossy(&path[..length as usize]);
                if let Some((_, name)) = owner.path.rsplit_once('\\') {
                    owner.name = name.into();
                }
            }
        }
        owners.insert(pid, owner);
    }
    Ok(endpoints
        .into_iter()
        .map(|endpoint| Port { endpoint, owner: owners[&endpoint.pid].clone() })
        .collect())
}

pub fn stop(port: &Port) -> io::Result<()> {
    if !port.can_stop() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Processus indisponible"));
    }
    let pid = port.endpoint.pid;
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE, 0, pid) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = Handle(raw);
    if Some(creation_time(&process)?) != port.owner.created || !endpoints()?.contains(&port.endpoint) {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Le port a changé. Actualise la liste."));
    }
    let mut critical = 0;
    if unsafe { IsProcessCritical(process.0, &mut critical) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if critical != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Processus critique de Windows"));
    }
    if unsafe { TerminateProcess(process.0, 1) } == 0 {
        return Err(io::Error::last_os_error());
    }
    match unsafe { WaitForSingleObject(process.0, 800) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(io::Error::new(io::ErrorKind::TimedOut, "Le processus est encore en cours d’arrêt")),
        _ => Err(io::Error::last_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::{TcpListener, UdpSocket};
    use std::process::{Child, Command, Stdio};

    struct ListenerProcess(Child);

    impl Drop for ListenerProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn identifies_tcp_and_udp_for_both_address_families() {
        let tcp4 = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let tcp6 = TcpListener::bind(("::1", 0)).unwrap();
        let udp4 = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let udp6 = UdpSocket::bind(("::1", 0)).unwrap();
        let ports = list().unwrap();
        for (address, protocol) in [
            (tcp4.local_addr().unwrap(), Protocol::Tcp),
            (tcp6.local_addr().unwrap(), Protocol::Tcp),
            (udp4.local_addr().unwrap(), Protocol::Udp),
            (udp6.local_addr().unwrap(), Protocol::Udp),
        ] {
            let found = ports.iter().find(|port| {
                let endpoint = port.endpoint;
                endpoint.port == address.port()
                    && endpoint.address == address.ip()
                    && endpoint.protocol == protocol
                    && endpoint.pid == std::process::id()
            }).unwrap_or_else(|| panic!("{protocol:?} {address} absent"));
            assert!(!found.owner.path.is_empty());
            assert!(found.owner.created.is_some());
        }
    }

    #[test]
    fn releases_a_test_port_and_rejects_stale_process_identity() {
        let mut child = ListenerProcess(
            Command::new("powershell.exe")
                .args([
                    "-NoProfile", "-NonInteractive", "-Command",
                    "$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); \
                     $listener.Start(); [Console]::WriteLine($listener.LocalEndpoint.Port); \
                     [Threading.Thread]::Sleep(15000)",
                ])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut number = String::new();
        BufReader::new(child.0.stdout.take().unwrap()).read_line(&mut number).unwrap();
        let port_number: u16 = number.trim().parse().unwrap();
        let port = list().unwrap().into_iter().find(|port| {
            port.endpoint.port == port_number
                && port.endpoint.protocol == Protocol::Tcp
                && port.endpoint.pid == child.0.id()
        }).unwrap();

        let mut stale = port.clone();
        stale.owner.created = stale.owner.created.map(|time| time ^ 1);
        assert_eq!(stop(&stale).unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(child.0.try_wait().unwrap().is_none());
        stop(&port).unwrap();
        assert!(!endpoints().unwrap().contains(&port.endpoint));
    }
}
