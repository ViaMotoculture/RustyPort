use std::collections::BTreeMap;
use std::io;
use std::mem::{offset_of, size_of, take};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::ptr::null;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_INVALID_PARAMETER, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND, FILETIME,
    GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Diagnostics::Etw::*;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateEventW, EVENT_MODIFY_STATE, GetCurrentProcess, GetProcessTimes, INFINITE,
    OpenEventW, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, SetEvent, WaitForSingleObject,
};
use windows_sys::core::GUID;

use crate::ports::{Handle, Protocol, wide};

const PROVIDER: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);
const NETWORK_KEYWORDS: u64 = 0x30;
pub const CLEANUP_FLAG: &str = "--port-traffic-cleanup";
const MIN_WINDOW: Duration = Duration::from_secs(1);
const MAX_SOCKETS_PER_WINDOW: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PortSocket {
    pub pid: u32,
    pub protocol: Protocol,
    pub address: IpAddr,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ByteCount {
    pub received: u64,
    pub sent: u64,
}

pub struct PortWindow {
    pub span: Duration,
    pub entries: Option<BTreeMap<PortSocket, ByteCount>>,
}

#[derive(Default)]
struct Buffer {
    entries: BTreeMap<PortSocket, ByteCount>,
    incomplete: bool,
    consumer_result: Option<u32>,
}

impl Buffer {
    fn record(&mut self, event: NetworkEvent) {
        if self.incomplete {
            return;
        }
        if self.entries.len() >= MAX_SOCKETS_PER_WINDOW && !self.entries.contains_key(&event.socket) {
            self.incomplete = true;
            return;
        }
        let entry = self.entries.entry(event.socket).or_default();
        let count = if event.received { &mut entry.received } else { &mut entry.sent };
        *count = count.saturating_add(u64::from(event.size));
    }

    fn lock(mutex: &Mutex<Self>) -> MutexGuard<'_, Self> {
        mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[repr(C)]
struct SessionProperties {
    values: EVENT_TRACE_PROPERTIES,
    name: [u16; 128],
}

impl SessionProperties {
    fn new() -> Self {
        let mut values = EVENT_TRACE_PROPERTIES::default();
        values.Wnode.BufferSize = size_of::<Self>() as u32;
        values.Wnode.ClientContext = 1;
        values.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        values.BufferSize = 32;
        values.MinimumBuffers = 4;
        values.MaximumBuffers = 64;
        values.FlushTimer = 1;
        values.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        values.LoggerNameOffset = offset_of!(Self, name) as u32;
        Self { values, name: [0; 128] }
    }

    fn lost(&self) -> (u32, u32) {
        (self.values.EventsLost, self.values.RealTimeBuffersLost)
    }
}

#[derive(Clone, Copy)]
struct ProcessIdentity {
    pid: u32,
    created: u64,
}

impl ProcessIdentity {
    fn session(self) -> Vec<u16> {
        wide(&format!("RustyPort Port Traffic {}-{:016x}", self.pid, self.created))
    }

    fn ready_event(self) -> Vec<u16> {
        wide(&format!("Local\\RustyPort.RustyPort.PortTrafficReady.{}-{:016x}", self.pid, self.created))
    }

    fn session_guid(self) -> GUID {
        GUID::from_u128((0x7f18_ac0a_u128 << 96) | (u128::from(self.pid) << 64) | u128::from(self.created))
    }
}

struct CleanupProcess(Child);

impl CleanupProcess {
    fn start(identity: ProcessIdentity) -> io::Result<Self> {
        let event = identity.ready_event();
        let raw = unsafe { CreateEventW(null(), 0, 0, event.as_ptr()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let last = unsafe { GetLastError() };
        let ready = Handle(raw);
        if last == ERROR_ALREADY_EXISTS {
            return Err(io::Error::from_raw_os_error(last as i32));
        }
        let child = Self(Command::new(std::env::current_exe()?)
            .arg(CLEANUP_FLAG).arg(identity.pid.to_string()).arg(identity.created.to_string())
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW).spawn()?);
        wait(ready.0, 3_000)?;
        Ok(child)
    }
}

impl Drop for CleanupProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait(handle: HANDLE, timeout: u32) -> io::Result<()> {
    match unsafe { WaitForSingleObject(handle, timeout) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(io::Error::new(io::ErrorKind::TimedOut, "Le processus de nettoyage ne répond pas.")),
        _ => Err(io::Error::last_os_error()),
    }
}

fn creation_time(handle: HANDLE) -> io::Result<u64> {
    let [mut created, mut exited, mut kernel, mut user] = [FILETIME::default(); 4];
    if unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

pub fn run_cleanup(mut args: impl Iterator<Item = String>) -> i32 {
    let pid = args.next().and_then(|arg| arg.parse().ok()).filter(|pid| *pid > 4);
    let created = args.next().and_then(|arg| arg.parse().ok()).filter(|created| *created > 0);
    let (Some(pid), Some(created), None) = (pid, created, args.next()) else { return ERROR_INVALID_PARAMETER as i32 };
    cleanup_after_exit(ProcessIdentity { pid, created }).map_or_else(|error| error.raw_os_error().unwrap_or(1), |_| 0)
}

fn cleanup_after_exit(identity: ProcessIdentity) -> io::Result<()> {
    let raw = unsafe { OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, identity.pid) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let parent = Handle(raw);
    if creation_time(parent.0)? != identity.created {
        return Err(io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32));
    }
    let event = identity.ready_event();
    let raw = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, event.as_ptr()) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let ready = Handle(raw);
    if unsafe { SetEvent(ready.0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(ready);
    wait(parent.0, INFINITE)?;
    stop_orphan(identity)
}

fn stop_orphan(identity: ProcessIdentity) -> io::Result<()> {
    let name = identity.session();
    let guid = identity.session_guid();
    // A StartTrace request may still complete while the calling process is terminating.
    for _ in 0..20 {
        let mut properties = SessionProperties::new();
        let status = unsafe {
            ControlTraceW(CONTROLTRACE_HANDLE::default(), name.as_ptr(), &mut properties.values, EVENT_TRACE_CONTROL_QUERY)
        };
        if status == ERROR_WMI_INSTANCE_NOT_FOUND {
            thread::sleep(Duration::from_millis(50));
            continue;
        }
        win32(status)?;
        let handle = unsafe { properties.values.Wnode.Anonymous1.HistoricalContext };
        if handle == 0 || !properties.name.starts_with(&name) || !same_guid(&properties.values.Wnode.Guid, &guid) {
            return Err(io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32));
        }
        // Another controller may stop the session after the query, so don't use its recyclable handle.
        let status = unsafe {
            ControlTraceW(CONTROLTRACE_HANDLE::default(), name.as_ptr(), &mut properties.values, EVENT_TRACE_CONTROL_STOP)
        };
        return if status == ERROR_WMI_INSTANCE_NOT_FOUND { Ok(()) } else { win32(status) };
    }
    Ok(())
}

pub struct PortCapture {
    session: CONTROLTRACE_HANDLE,
    session_name: Vec<u16>,
    consumer: Option<PROCESSTRACE_HANDLE>,
    thread: Option<JoinHandle<()>>,
    data: Arc<Mutex<Buffer>>,
    previous: Instant,
    lost: (u32, u32),
    cleanup: Option<CleanupProcess>,
}

impl PortCapture {
    pub fn open() -> io::Result<Self> {
        let identity = ProcessIdentity {
            pid: std::process::id(), created: creation_time(unsafe { GetCurrentProcess() })?,
        };
        let cleanup = CleanupProcess::start(identity)?;
        let mut capture = Self::open_named(identity.session(), identity.session_guid())?;
        capture.cleanup = Some(cleanup);
        Ok(capture)
    }

    fn open_named(name: Vec<u16>, guid: GUID) -> io::Result<Self> {
        let mut properties = SessionProperties::new();
        properties.values.Wnode.Guid = guid;
        let mut session = CONTROLTRACE_HANDLE::default();
        // A session with this name might belong to another user. Never attach to or stop it.
        win32(unsafe { StartTraceW(&mut session, name.as_ptr(), &mut properties.values) })?;
        let mut capture = Self {
            session,
            session_name: name,
            consumer: None,
            thread: None,
            data: Arc::new(Mutex::new(Buffer::default())),
            previous: Instant::now(),
            lost: properties.lost(),
            cleanup: None,
        };

        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: capture.session_name.as_mut_ptr(),
            Anonymous1: EVENT_TRACE_LOGFILEW_0 {
                ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
            },
            Anonymous2: EVENT_TRACE_LOGFILEW_1 { EventRecordCallback: Some(handle_event) },
            Context: Arc::as_ptr(&capture.data).cast_mut().cast(),
            ..Default::default()
        };
        let consumer = unsafe { OpenTraceW(&mut logfile) };
        if consumer.Value == usize::MAX as u64 {
            return Err(io::Error::last_os_error());
        }
        capture.consumer = Some(consumer);

        let data = Arc::clone(&capture.data);
        capture.thread = Some(thread::Builder::new().name("rustyport-port-etw".into()).spawn(move || {
            let result = unsafe { ProcessTrace(&consumer, 1, null(), null()) };
            Buffer::lock(&data).consumer_result = Some(result);
        })?);
        win32(unsafe {
            EnableTraceEx2(session, &PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION as u8,
                NETWORK_KEYWORDS, 0, 1_000, null())
        })?;
        capture.previous = Instant::now();
        Ok(capture)
    }

    pub fn sample(&mut self) -> io::Result<Option<PortWindow>> {
        let now = Instant::now();
        if now.saturating_duration_since(self.previous) < MIN_WINDOW {
            return Ok(None);
        }

        let mut properties = SessionProperties::new();
        win32(unsafe { ControlTraceW(self.session, null(), &mut properties.values, EVENT_TRACE_CONTROL_QUERY) })?;
        let mut buffer = Buffer::lock(&self.data);
        if let Some(result) = buffer.consumer_result {
            win32(result)?;
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Le flux de mesure des ports s’est arrêté."));
        }
        let lost = properties.lost();
        let incomplete = take(&mut buffer.incomplete) || lost != self.lost;
        let entries = take(&mut buffer.entries);
        let end = Instant::now();
        let span = end.saturating_duration_since(self.previous);
        self.previous = end;
        self.lost = lost;
        Ok(Some(PortWindow { span, entries: (!incomplete).then_some(entries) }))
    }
}

impl Drop for PortCapture {
    fn drop(&mut self) {
        let mut properties = SessionProperties::new();
        // Only the controller handle returned by our successful StartTrace is stopped.
        unsafe { ControlTraceW(self.session, null(), &mut properties.values, EVENT_TRACE_CONTROL_STOP) };
        if let Some(consumer) = self.consumer.take() {
            // A real-time OpenTrace handle can be closed while ProcessTrace is draining.
            unsafe { CloseTrace(consumer) };
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        drop(self.cleanup.take());
    }
}

fn win32(status: u32) -> io::Result<()> {
    if status == ERROR_SUCCESS { Ok(()) } else { Err(io::Error::from_raw_os_error(status as i32)) }
}

fn same_guid(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

struct NetworkEvent {
    socket: PortSocket,
    received: bool,
    size: u32,
}

fn decode(id: u16, version: u8, bytes: &[u8]) -> Result<Option<NetworkEvent>, ()> {
    let (protocol, ipv6, received) = match id {
        10 => (Protocol::Tcp, false, false),
        11 => (Protocol::Tcp, false, true),
        26 => (Protocol::Tcp, true, false),
        27 => (Protocol::Tcp, true, true),
        42 => (Protocol::Udp, false, false),
        43 => (Protocol::Udp, false, true),
        58 => (Protocol::Udp, true, false),
        59 => (Protocol::Udp, true, true),
        _ => return Ok(None),
    };
    let addr_len = if ipv6 { 16 } else { 4 };
    let ports_at = 8 + 2 * addr_len;
    if version != 0 || bytes.len() < ports_at + 4 {
        return Err(());
    }
    // The associated PID is in the payload. The event header may identify a kernel thread.
    let pid = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| ())?);
    let size = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| ())?);
    let (address_at, port_at) = if received { (8, ports_at) } else { (8 + addr_len, ports_at + 2) };
    let port = u16::from_be_bytes(bytes[port_at..port_at + 2].try_into().map_err(|_| ())?);
    if pid == 0 || port == 0 || size == 0 {
        return Ok(None);
    }
    let address = if ipv6 {
        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[address_at..address_at + addr_len]).map_err(|_| ())?))
    } else {
        IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[address_at..address_at + addr_len]).map_err(|_| ())?))
    };
    Ok(Some(NetworkEvent { socket: PortSocket { pid, protocol, address, port }, received, size }))
}

unsafe extern "system" fn handle_event(record: *mut EVENT_RECORD) {
    let Some(record) = (unsafe { record.as_ref() }) else { return };
    let hdr = &record.EventHeader;
    if !same_guid(&hdr.ProviderId, &PROVIDER) {
        return;
    }
    let Some(data) = (unsafe { record.UserContext.cast::<Mutex<Buffer>>().as_ref() }) else { return };
    let bytes = if record.UserData.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(record.UserData.cast::<u8>(), usize::from(record.UserDataLength)) }
    };
    match decode(hdr.EventDescriptor.Id, hdr.EventDescriptor.Version, bytes) {
        Ok(Some(event)) => Buffer::lock(data).record(event),
        Ok(None) => (),
        Err(()) => Buffer::lock(data).incomplete = true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

    #[test]
    fn decodes_manifest_network_packets_in_both_directions() {
        for (ids, protocol, dst, src) in [
            ([10, 11], Protocol::Tcp, "127.0.0.1", "127.0.0.2"),
            ([26, 27], Protocol::Tcp, "::1", "2001:db8::2"),
            ([42, 43], Protocol::Udp, "127.0.0.1", "127.0.0.2"),
            ([58, 59], Protocol::Udp, "::1", "2001:db8::2"),
        ] {
            let dst: IpAddr = dst.parse().unwrap();
            let src: IpAddr = src.parse().unwrap();
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&42_u32.to_le_bytes());
            bytes.extend_from_slice(&2048_u32.to_le_bytes());
            for address in [dst, src] {
                match address {
                    IpAddr::V4(addr) => bytes.extend_from_slice(&addr.octets()),
                    IpAddr::V6(addr) => bytes.extend_from_slice(&addr.octets()),
                }
            }
            bytes.extend_from_slice(&443_u16.to_be_bytes());
            bytes.extend_from_slice(&51_002_u16.to_be_bytes());
            let sent = decode(ids[0], 0, &bytes).unwrap().unwrap();
            assert_eq!(sent.socket, PortSocket { pid: 42, protocol, address: src, port: 51_002 });
            assert!(!sent.received);
            assert_eq!(sent.size, 2048);
            let received = decode(ids[1], 0, &bytes).unwrap().unwrap();
            assert_eq!(received.socket, PortSocket { pid: 42, protocol, address: dst, port: 443 });
            assert!(received.received);
            assert_eq!(received.size, 2048);
            assert!(decode(ids[1], 0, &bytes[..bytes.len() - 1]).is_err());
            assert!(decode(ids[1], 1, &bytes).is_err());
        }
        assert!(decode(14, 0, &[]).unwrap().is_none());
    }

    #[test]
    fn collects_both_directions_without_growing_past_the_window_limit() {
        let mut buffer = Buffer::default();
        let socket = |port| PortSocket { pid: 42, protocol: Protocol::Udp, address: Ipv4Addr::LOCALHOST.into(), port };
        for port in 1..=MAX_SOCKETS_PER_WINDOW as u16 {
            buffer.record(NetworkEvent { socket: socket(port), received: true, size: 64 });
        }
        buffer.record(NetworkEvent { socket: socket(1), received: false, size: 128 });
        assert!(!buffer.incomplete);
        assert_eq!(buffer.entries[&socket(1)], ByteCount { received: 64, sent: 128 });
        buffer.record(NetworkEvent { socket: socket(MAX_SOCKETS_PER_WINDOW as u16 + 1), received: false, size: 256 });
        assert!(buffer.incomplete);
        assert_eq!(buffer.entries.len(), MAX_SOCKETS_PER_WINDOW);
    }

    #[test]
    fn starts_native_trace_or_preserves_the_permission_error() {
        match PortCapture::open_named(wide("RustyPort Port Traffic Test"), GUID::default()) {
            Ok(mut capture) => assert!(capture.sample().unwrap().is_none()),
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                assert_eq!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
            }
            Err(error) => panic!("Échec du démarrage ETW natif. {error}"),
        }
    }

    #[test]
    fn rejects_a_reused_pid_before_signalling_or_stopping() {
        let created = creation_time(unsafe { GetCurrentProcess() }).unwrap();
        let args = [std::process::id().to_string(), (created - 1).to_string()];
        assert_eq!(run_cleanup(args.into_iter()), ERROR_INVALID_PARAMETER as i32);
    }

    #[test]
    #[ignore = "requires Windows ETW permissions and generates only loopback traffic"]
    fn measures_native_loopback_tcp_and_udp_in_both_directions() {
        let mut capture = PortCapture::open_named(
            wide("RustyPort Port Traffic Loopback Test"), GUID::default(),
        ).expect("Impossible de démarrer la trace ETW. Vérifier les droits Windows.");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut tcp_client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut tcp_server, _) = listener.accept().unwrap();
        let udp_server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        for stream in [&tcp_client, &tcp_server] {
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        }
        for socket in [&udp_client, &udp_server] {
            socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        }
        let key = |protocol, port| PortSocket {
            pid: std::process::id(), protocol, address: Ipv4Addr::LOCALHOST.into(), port,
        };
        let tcp = key(Protocol::Tcp, listener.local_addr().unwrap().port());
        let udp = key(Protocol::Udp, udp_server.local_addr().unwrap().port());
        let tcp_data = [7; 16_384];
        let udp_data = [8; 512];
        let mut tcp_read = [0; 16_384];
        let mut udp_read = [0; 512];

        tcp_client.write_all(&tcp_data).unwrap();
        tcp_server.read_exact(&mut tcp_read).unwrap();
        udp_client.send_to(&udp_data, udp_server.local_addr().unwrap()).unwrap();
        assert_eq!(udp_server.recv(&mut udp_read).unwrap(), udp_data.len());
        verify_loopback_window(&mut capture, tcp, udp, true, tcp_data.len() as u64, udp_data.len() as u64);

        tcp_server.write_all(&tcp_data).unwrap();
        tcp_client.read_exact(&mut tcp_read).unwrap();
        udp_server.send_to(&udp_data, udp_client.local_addr().unwrap()).unwrap();
        assert_eq!(udp_client.recv(&mut udp_read).unwrap(), udp_data.len());
        verify_loopback_window(&mut capture, tcp, udp, false, tcp_data.len() as u64, udp_data.len() as u64);
    }

    fn verify_loopback_window(
        capture: &mut PortCapture, tcp: PortSocket, udp: PortSocket, received: bool, tcp_size: u64, udp_size: u64,
    ) {
        let deadline = Instant::now() + Duration::from_secs(6);
        let amount = |count: &ByteCount| if received { count.received } else { count.sent };
        let (mut tcp_bytes, mut udp_bytes) = (0_u64, 0_u64);
        while Instant::now() < deadline {
            if let Some(window) = capture.sample().unwrap()
                && let Some(entries) = window.entries
            {
                tcp_bytes = tcp_bytes.saturating_add(entries.get(&tcp).map_or(0, amount));
                udp_bytes = udp_bytes.saturating_add(entries.get(&udp).map_or(0, amount));
                if tcp_bytes >= tcp_size && udp_bytes >= udp_size {
                    return;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("Données ETW incomplètes (réception {received}, TCP {tcp_bytes} octets, UDP {udp_bytes} octets).");
    }
}
