use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::{null, null_mut};
use std::time::Duration;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, GetSystemTimeAsFileTime};
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

    fn wildcard(self) -> Self {
        let address = match self.address {
            IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };
        Self { address, scope: 0, ..self }
    }
}

#[derive(Clone, Default)]
pub struct Owner {
    pub name: String,
    pub path: String,
    pub services: Vec<String>,
    pub known_services: Vec<&'static str>,
    pub created: Option<u64>,
}

impl Owner {
    pub fn age(&self) -> Option<Duration> {
        let created = self.created?;
        let mut now = FILETIME::default();
        unsafe { GetSystemTimeAsFileTime(&mut now) };
        let ticks = filetime_ticks(now).checked_sub(created)?;
        Some(Duration::from_secs(ticks / 10_000_000))
    }
}

#[derive(Clone)]
pub struct Port {
    pub endpoint: Endpoint,
    pub owner: Owner,
    pub established: usize,
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

pub fn system_directory() -> io::Result<String> {
    let mut buffer = [0u16; 260];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    if length >= buffer.len() {
        return Err(io::Error::other("Chemin du dossier système trop long"));
    }
    Ok(String::from_utf16_lossy(&buffer[..length]))
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

fn endpoints() -> io::Result<BTreeMap<Endpoint, usize>> {
    let tcp = |family, buffer, size: &mut u32| unsafe {
        GetExtendedTcpTable(buffer, size, 0, u32::from(family), TCP_TABLE_OWNER_PID_ALL, 0)
    };
    let udp = |family, buffer, size: &mut u32| unsafe {
        GetExtendedUdpTable(buffer, size, 0, u32::from(family), UDP_TABLE_OWNER_PID, 0)
    };
    let ipv4 = table::<MIB_TCPROW_OWNER_PID>(|buffer, size| tcp(AF_INET, buffer, size))?;
    let ipv6 = table::<MIB_TCP6ROW_OWNER_PID>(|buffer, size| tcp(AF_INET6, buffer, size))?;
    let ipv4 = ipv4.into_iter().map(|entry| {
        let endpoint = Endpoint::new(
            Protocol::Tcp, Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes()).into(),
            0, entry.dwLocalPort, entry.dwOwningPid,
        );
        (endpoint, entry.dwState as MIB_TCP_STATE)
    });
    let ipv6 = ipv6.into_iter().map(|entry| {
        let endpoint = Endpoint::new(
            Protocol::Tcp, Ipv6Addr::from(entry.ucLocalAddr).into(),
            entry.dwLocalScopeId, entry.dwLocalPort, entry.dwOwningPid,
        );
        (endpoint, entry.dwState as MIB_TCP_STATE)
    });
    let mut endpoints = BTreeMap::new();
    let mut established = Vec::new();
    for (endpoint, state) in ipv4.chain(ipv6) {
        match state {
            MIB_TCP_STATE_LISTEN => { endpoints.insert(endpoint, 0); }
            MIB_TCP_STATE_ESTAB => established.push(endpoint),
            _ => {}
        }
    }
    for endpoint in established {
        if let Some(count) = endpoints.get_mut(&endpoint) {
            *count += 1;
        } else if let Some(count) = endpoints.get_mut(&endpoint.wildcard()) {
            *count += 1;
        }
    }
    for entry in table::<MIB_UDPROW_OWNER_PID>(|buffer, size| udp(AF_INET, buffer, size))? {
        endpoints.insert(Endpoint::new(
            Protocol::Udp, Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes()).into(),
            0, entry.dwLocalPort, entry.dwOwningPid,
        ), 0);
    }
    for entry in table::<MIB_UDP6ROW_OWNER_PID>(|buffer, size| udp(AF_INET6, buffer, size))? {
        endpoints.insert(Endpoint::new(
            Protocol::Udp, Ipv6Addr::from(entry.ucLocalAddr).into(),
            entry.dwLocalScopeId, entry.dwLocalPort, entry.dwOwningPid,
        ), 0);
    }
    Ok(endpoints)
}

pub(crate) fn process_names(pids: Option<&HashSet<u32>>) -> HashMap<u32, String> {
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
        if pids.is_none_or(|pids| pids.contains(&entry.th32ProcessID)) {
            names.insert(entry.th32ProcessID, decode_wide(&entry.szExeFile));
        }
        ok = unsafe { Process32NextW(handle.0, &mut entry) };
    }
    names
}

pub(crate) fn image_path(process: &Handle, path: &mut [u16]) -> io::Result<String> {
    let mut length = path.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process.0, 0, path.as_mut_ptr(), &mut length) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(String::from_utf16_lossy(&path[..length as usize]))
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

fn known_services(pids: &HashSet<u32>) -> HashMap<u32, Vec<&'static str>> {
    let mut owners: HashMap<u32, Vec<&'static str>> = HashMap::new();
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return owners;
    }
    for name in ["SharedAccess", "Dhcp", "W32Time"] {
        let service = unsafe { OpenServiceW(manager, wide(name).as_ptr(), SERVICE_QUERY_STATUS) };
        if service.is_null() {
            continue;
        }
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut size = 0;
        let ok = unsafe {
            QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32, &mut size)
        };
        unsafe { CloseServiceHandle(service) };
        if ok != 0 && status.dwCurrentState == SERVICE_RUNNING && pids.contains(&status.dwProcessId) {
            owners.entry(status.dwProcessId).or_default().push(name);
        }
    }
    unsafe { CloseServiceHandle(manager) };
    owners
}

fn filetime_ticks(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

fn creation_time(process: &Handle) -> io::Result<u64> {
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetProcessTimes(process.0, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(filetime_ticks(created))
}

pub fn list() -> io::Result<Vec<Port>> {
    let endpoints = endpoints()?;
    let pids = endpoints.keys().map(|endpoint| endpoint.pid).collect();
    let mut names = process_names(Some(&pids));
    let mut services = service_names();
    let mut known = known_services(&pids);
    let mut owners = HashMap::new();
    let mut path = vec![0; 32768];
    for pid in pids {
        let known_services = known.remove(&pid).unwrap_or_default();
        let mut owner = Owner {
            name: names.remove(&pid).unwrap_or_else(|| match pid {
                4 => "System".into(),
                _ => "Inconnu".into(),
            }),
            services: services.remove(&pid).unwrap_or_else(|| known_services.iter().map(|name| (*name).into()).collect()),
            known_services,
            ..Default::default()
        };
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if !raw.is_null() {
            let process = Handle(raw);
            owner.created = creation_time(&process).ok();
            if let Ok(image) = image_path(&process, &mut path) {
                owner.path = image;
                if let Some((_, name)) = owner.path.rsplit_once('\\') {
                    owner.name = name.into();
                }
            }
        }
        owners.insert(pid, owner);
    }
    Ok(endpoints
        .into_iter()
        .map(|(endpoint, established)| Port {
            endpoint, owner: owners[&endpoint.pid].clone(), established,
        })
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
    if Some(creation_time(&process)?) != port.owner.created || !endpoints()?.contains_key(&port.endpoint) {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Le port a changé. Actualise la liste."));
    }
    terminate(&process)?;
    match unsafe { WaitForSingleObject(process.0, 800) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(io::Error::new(io::ErrorKind::TimedOut, "Le processus est encore en cours d’arrêt")),
        _ => Err(io::Error::last_os_error()),
    }
}

pub(crate) fn terminate(process: &Handle) -> io::Result<()> {
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::process::{Child, Command, Stdio};

    struct ListenerProcess(Child);

    impl Drop for ListenerProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn counts_established_tcp_for_exact_and_wildcard_listeners() {
        for (bind, connect) in [("127.0.0.1", "127.0.0.1"), ("0.0.0.0", "127.0.0.1"), ("::", "::1")] {
            let listener = TcpListener::bind((bind, 0)).unwrap();
            let address = listener.local_addr().unwrap();
            let established = || {
                endpoints().unwrap().into_iter().find(|(endpoint, _)| {
                    endpoint.pid == std::process::id()
                        && endpoint.protocol == Protocol::Tcp
                        && endpoint.port == address.port()
                        && endpoint.address == address.ip()
                }).unwrap().1
            };
            assert_eq!(established(), 0);
            let client = TcpStream::connect((connect, address.port())).unwrap();
            let (server, _) = listener.accept().unwrap();
            assert_eq!(established(), 1);
            drop((client, server));
            assert_eq!(established(), 0);
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
        assert!(!endpoints().unwrap().contains_key(&port.endpoint));
    }
}
