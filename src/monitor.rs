use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::{addr_of, null_mut};
use std::sync::{Arc, Mutex, MutexGuard, atomic::{AtomicBool, AtomicU64, Ordering}, mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError}};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, IF_TYPE_SOFTWARE_LOOPBACK, MIB_IF_ROW2, MIB_IF_TABLE2,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;

use crate::port_traffic::{ByteCount, PortCapture, PortSocket, PortWindow};
use crate::ports::{self, Endpoint, Port, Protocol, TcpConnection};
use crate::relaunch::{self, Watch};

#[cfg(test)]
const POLL_INTERVAL: Duration = Duration::from_secs(2);
pub const DEFAULT_INTERVAL_MS: u64 = 500;
pub const INTERVALS: [(u64, &str); 6] = [(250, "250 ms"), (500, "500 ms"), (1000, "1 s"), (2000, "2 s"), (5000, "5 s"), (10000, "10 s")];
pub const GRAPH_WINDOW: Duration = Duration::from_secs(60);
const TCP_ACTIVITY_WINDOW: Duration = Duration::from_secs(60);

#[derive(Default)]
struct TcpActivity {
    listeners: BTreeMap<(Endpoint, Option<u64>), TcpListenerActivity>,
}

struct TcpListenerActivity {
    established: Arc<BTreeSet<TcpConnection>>,
    arrivals: VecDeque<(Instant, usize)>,
}

impl TcpActivity {
    fn update(&mut self, at: Instant, ports: &mut [Port]) {
        let mut previous = std::mem::take(&mut self.listeners);
        for port in ports.iter_mut().filter(|port| port.endpoint.protocol == Protocol::Tcp) {
            let key = port.key();
            let mut arrivals = VecDeque::new();
            if let Some(last) = previous.remove(&key) {
                arrivals = last.arrivals;
                while arrivals.front().is_some_and(|(seen, _)| {
                    at.saturating_duration_since(*seen) >= TCP_ACTIVITY_WINDOW
                }) {
                    arrivals.pop_front();
                }
                let arrived = port.established.difference(&last.established).count();
                port.tcp_arrivals = Some(arrived as u32);
                if arrived > 0 {
                    arrivals.push_back((at, arrived));
                }
                port.recent_tcp = Some(arrivals.iter().map(|(_, count)| count).sum());
            }
            self.listeners.insert(key, TcpListenerActivity {
                established: Arc::clone(&port.established), arrivals,
            });
        }
    }
}

#[derive(Clone, Copy)]
struct InterfaceBytes {
    received: u64,
    sent: u64,
}

type Counters = HashMap<u64, InterfaceBytes>;

pub struct Reading {
    pub at: Instant,
    pub ports: io::Result<Vec<Port>>,
    interfaces: io::Result<Counters>,
    port_state: PortTrafficState,
    port_window: Option<PortWindow>,
}

impl Reading {
    pub fn apply(self, history: &mut TrafficHistory) -> (Instant, io::Result<Vec<Port>>, TrafficState, PortTrafficState) {
        let ports = self.ports.as_deref().unwrap_or_default();
        if self.ports.is_err() || !matches!(self.port_state, PortTrafficState::Measuring | PortTrafficState::Starting) {
            history.port_keys.clear();
        }
        let port_span = self.port_window.as_ref().map(|window| window.span);
        let rates = self.port_window.map(|window| {
            let rates = window.entries.map_or_else(BTreeMap::new, |entries| {
                attribute_port_rates(ports, &history.port_keys, &entries, window.span)
            });
            history.port_keys = ports.iter().map(Port::key).collect();
            rates
        }).unwrap_or_default();
        let mut sockets = ports.iter()
            .filter(|port| port.endpoint.protocol == Protocol::Tcp || port_span.is_some())
            .map(|port| SocketActivity {
                key: port.graph_key(),
                name: port.owner.name.clone(),
                endpoint: port.endpoint.label(),
                address: port.endpoint.address_label(),
                peer: port.established.iter().next().map_or_else(String::new, |peer| peer.peer_label()),
                protocol: port.endpoint.protocol,
                port_rates: rates.get(&port.key()).copied(),
                established: port.established.len() as u32,
                arrivals: port.tcp_arrivals,
            }).collect::<Vec<_>>();
        sockets.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        let traffic = history.record(self.at, self.interfaces, port_span, sockets);
        (self.at, self.ports, traffic, self.port_state)
    }
}

type PortKey = (Endpoint, Option<u64>);

fn socket_key(endpoint: Endpoint) -> PortSocket {
    PortSocket { pid: endpoint.pid, protocol: endpoint.protocol, address: endpoint.address, port: endpoint.port }
}

fn attribute_port_rates(
    ports: &[Port], previous: &BTreeSet<PortKey>, bytes: &BTreeMap<PortSocket, ByteCount>, span: Duration,
) -> BTreeMap<PortKey, Rates> {
    if span.is_zero() {
        return BTreeMap::new();
    }
    let mut listeners = BTreeMap::new();
    for port in ports.iter().filter(|port| port.endpoint.pid != 0 && port.endpoint.port != 0) {
        listeners.entry(socket_key(port.endpoint)).and_modify(|owner| *owner = None).or_insert(Some(port.key()));
    }
    // A port must be present at both sample boundaries. Multiple interfaces with the
    // same IPv6 address cannot be distinguished when ETW does not report the scope.
    let mut totals = listeners.values().flatten().copied()
        .filter(|key| previous.contains(key) && (key.1.is_some() || key.0.pid == 4))
        .map(|key| (key, ByteCount::default())).collect::<BTreeMap<_, _>>();
    for (socket, count) in bytes {
        let address = match socket.address {
            IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };
        let owner = listeners.get(socket).or_else(|| listeners.get(&PortSocket { address, ..*socket }));
        if let Some(Some(owner)) = owner && let Some(total) = totals.get_mut(owner) {
            total.received = total.received.saturating_add(count.received);
            total.sent = total.sent.saturating_add(count.sent);
        }
    }
    let seconds = span.as_secs_f64();
    totals.into_iter().map(|(key, count)| {
        (key, Rates { received: count.received as f64 / seconds, sent: count.sent as f64 / seconds })
    }).collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PortTrafficState {
    Off,
    Starting,
    Measuring,
    AccessDenied,
    Unavailable,
}

#[derive(Default)]
struct PortSampler {
    capture: Option<PortCapture>,
    failure: Option<PortTrafficState>,
    measuring: bool,
}

impl PortSampler {
    fn read(&mut self, enabled: bool) -> (PortTrafficState, Option<PortWindow>) {
        if !enabled {
            self.capture = None;
            self.failure = None;
            self.measuring = false;
            return (PortTrafficState::Off, None);
        }
        if let Some(failure) = self.failure {
            return (failure, None);
        }
        let result = match self.capture.as_mut() {
            Some(capture) => capture.sample(),
            None => PortCapture::open().map(|capture| {
                self.capture = Some(capture);
                None
            }),
        };
        match result {
            Ok(window @ Some(_)) => {
                self.measuring = true;
                (PortTrafficState::Measuring, window)
            }
            Ok(None) if self.measuring => (PortTrafficState::Measuring, None),
            Ok(None) => (PortTrafficState::Starting, None),
            Err(error) => {
                self.capture = None;
                let code = error.raw_os_error().map(|code| code as u32);
                let failure = if matches!(code, Some(ERROR_ACCESS_DENIED | ERROR_PRIVILEGE_NOT_HELD)) {
                    PortTrafficState::AccessDenied
                } else {
                    PortTrafficState::Unavailable
                };
                self.failure = Some(failure);
                (failure, None)
            }
        }
    }
}

pub struct Monitor {
    refresh: SyncSender<()>,
    readings: Option<Receiver<Reading>>,
    interval_ms: Arc<AtomicU64>,
    watches: Arc<Mutex<Vec<Watch>>>,
    port_capture: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Monitor {
    pub fn start() -> io::Result<Self> {
        let (refresh, requests) = mpsc::sync_channel(1);
        let (publish, readings) = mpsc::sync_channel(1);
        let interval_ms = Arc::new(AtomicU64::new(DEFAULT_INTERVAL_MS));
        let interval = Arc::clone(&interval_ms);
        let watches = Arc::new(Mutex::new(Vec::new()));
        let monitored = Arc::clone(&watches);
        let port_capture = Arc::new(AtomicBool::new(false));
        let requested = Arc::clone(&port_capture);
        let shutdown = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&shutdown);
        let worker = thread::Builder::new().name("rustyport-monitor".into()).spawn(move || {
            let mut tcp_activity = TcpActivity::default();
            let mut port_sampler = PortSampler::default();
            while !stopped.load(Ordering::Relaxed) {
                relaunch::enforce(&mut lock_watches(&monitored));
                let mut ports = ports::list();
                let interfaces = read_interfaces();
                let (port_state, port_window) = port_sampler.read(requested.load(Ordering::Relaxed));
                let at = Instant::now();
                match &mut ports {
                    Ok(ports) => tcp_activity.update(at, ports),
                    Err(_) => tcp_activity.listeners.clear(),
                }
                let reading = Reading { at, ports, interfaces, port_state, port_window };
                if publish.send(reading).is_err()
                    || requests.recv_timeout(Duration::from_millis(interval.load(Ordering::Relaxed))) == Err(RecvTimeoutError::Disconnected)
                {
                    break;
                }
            }
        })?;
        Ok(Self { refresh, readings: Some(readings), interval_ms, watches, port_capture, shutdown, worker: Some(worker) })
    }

    pub fn set_interval(&self, milliseconds: u64) {
        self.interval_ms.store(milliseconds, Ordering::Relaxed);
        self.refresh();
    }

    pub fn refresh(&self) -> bool {
        !matches!(self.refresh.try_send(()), Err(TrySendError::Disconnected(_)))
    }

    pub fn set_port_capture(&self, enabled: bool) {
        if self.port_capture.swap(enabled, Ordering::Relaxed) != enabled {
            self.refresh();
        }
    }

    pub fn watch(&self, watch: Watch) {
        let mut watches = lock_watches(&self.watches);
        watches.retain(|existing| !existing.image.eq_ignore_ascii_case(&watch.image));
        watches.push(watch);
        drop(watches);
        self.refresh();
    }

    pub fn active_watches(&self) -> Vec<Watch> {
        lock_watches(&self.watches).iter().filter(|watch| watch.is_active()).cloned().collect()
    }

    pub fn stop_watching(&self, image: &str) {
        lock_watches(&self.watches).retain(|watch| !watch.image.eq_ignore_ascii_case(image));
    }

    pub fn clear_watches(&self) {
        lock_watches(&self.watches).clear();
    }

    pub fn poll(&self) -> Result<Option<Reading>, TryRecvError> {
        match self.readings.as_ref().ok_or(TryRecvError::Disconnected)?.try_recv() {
            Ok(reading) => Ok(Some(reading)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.readings.take();
        self.refresh();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn lock_watches(watches: &Mutex<Vec<Watch>>) -> MutexGuard<'_, Vec<Watch>> {
    watches.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn read_interfaces() -> io::Result<Counters> {
    let mut table: *mut MIB_IF_TABLE2 = null_mut();
    let code = unsafe { GetIfTable2(&mut table) };
    if code != NO_ERROR {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    if table.is_null() {
        return Err(io::Error::other("Windows n’a pas renvoyé la table des interfaces"));
    }
    // IP Helper allocates a variable-length table with padding before the first row.
    let rows = unsafe {
        std::slice::from_raw_parts(addr_of!((*table).Table).cast::<MIB_IF_ROW2>(), (*table).NumEntries as usize)
    };
    // The second status bit marks a filter module, which can repeat adapter counters.
    const FILTER_INTERFACE: u8 = 1 << 1;
    let counters = rows.iter().filter_map(|row| {
        let relevant = row.OperStatus == IfOperStatusUp
            && row.Type != IF_TYPE_SOFTWARE_LOOPBACK
            && row.InterfaceAndOperStatusFlags._bitfield & FILTER_INTERFACE == 0;
        relevant.then(|| {
            (unsafe { row.InterfaceLuid.Value }, InterfaceBytes { received: row.InOctets, sent: row.OutOctets })
        })
    }).collect();
    unsafe { FreeMibTable(table.cast()) };
    Ok(counters)
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rates {
    pub received: f64,
    pub sent: f64,
}

fn rates_between(previous: &Counters, current: &Counters, elapsed: Duration) -> Option<Rates> {
    if elapsed.is_zero() || elapsed > Duration::from_secs(20) || previous.len() != current.len() {
        return None;
    }
    let mut received = 0.0;
    let mut sent = 0.0;
    for (id, totals) in current {
        let before = previous.get(id)?;
        received += totals.received.checked_sub(before.received)? as f64;
        sent += totals.sent.checked_sub(before.sent)? as f64;
    }
    let seconds = elapsed.as_secs_f64();
    Some(Rates { received: received / seconds, sent: sent / seconds })
}

pub enum TrafficState {
    WarmingUp,
    NoInterfaces,
    Unavailable,
    Measured { rates: Rates, interfaces: usize },
}

#[derive(Clone)]
pub struct SocketActivity {
    pub key: String,
    pub name: String,
    pub endpoint: String,
    pub address: String,
    pub peer: String,
    pub protocol: Protocol,
    pub port_rates: Option<Rates>,
    pub established: u32,
    pub arrivals: Option<u32>,
}

#[derive(Clone)]
pub struct Point {
    pub at: Instant,
    pub rates: Option<Rates>,
    pub span: Duration,
    pub port_span: Option<Duration>,
    pub sockets: Vec<SocketActivity>,
}

impl Point {
    pub fn socket(&self, key: &str) -> Option<&SocketActivity> {
        let index = self.sockets.binary_search_by(|socket| socket.key.as_str().cmp(key)).ok()?;
        self.sockets.get(index)
    }
}

#[derive(Default)]
pub struct TrafficHistory {
    previous: Option<(Instant, Counters)>,
    port_keys: BTreeSet<PortKey>,
    pub points: VecDeque<Point>,
}

impl TrafficHistory {
    fn record(&mut self, now: Instant, counters: io::Result<Counters>, port_span: Option<Duration>, sockets: Vec<SocketActivity>) -> TrafficState {
        let span = self.previous.as_ref().map_or(Duration::ZERO, |(then, _)| now.saturating_duration_since(*then));
        let state = match counters {
            Ok(counters) if !counters.is_empty() => {
                let rate = self.previous.as_ref().and_then(|(_, previous)| {
                    rates_between(previous, &counters, span)
                });
                let interfaces = counters.len();
                self.previous = Some((now, counters));
                match rate {
                    Some(rates) => TrafficState::Measured { rates, interfaces },
                    None => TrafficState::WarmingUp,
                }
            }
            Ok(_) => {
                self.previous = None;
                TrafficState::NoInterfaces
            }
            Err(_) => {
                self.previous = None;
                TrafficState::Unavailable
            }
        };
        let rates = match state {
            TrafficState::Measured { rates, .. } => Some(rates),
            _ => None,
        };
        self.points.push_back(Point { at: now, rates, span, port_span, sockets });
        while self.points.front().is_some_and(|point| now.duration_since(point.at) > GRAPH_WINDOW) {
            self.points.pop_front();
        }
        state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    #[test]
    fn byte_windows_keep_two_ports_distinct_and_preserve_zero_and_gaps() {
        let tcp_local = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let tcp_wildcard = TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let udp = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let endpoints = [
            (Protocol::Tcp, tcp_local.local_addr().unwrap().port()),
            (Protocol::Tcp, tcp_wildcard.local_addr().unwrap().port()),
            (Protocol::Udp, udp.local_addr().unwrap().port()),
        ];
        let ports: Vec<_> = ports::list().unwrap().into_iter().filter(|port| {
            port.endpoint.pid == std::process::id()
                && endpoints.contains(&(port.endpoint.protocol, port.endpoint.port))
        }).collect();
        assert_eq!(ports.len(), 3);
        let port = |index| ports.iter()
            .find(|port| (port.endpoint.protocol, port.endpoint.port) == endpoints[index]).unwrap();
        let local = socket_key(port(0).endpoint);
        let wildcard = PortSocket { address: Ipv4Addr::LOCALHOST.into(), ..socket_key(port(1).endpoint) };
        let bytes = BTreeMap::from([
            (local, ByteCount { received: 2048, sent: 4096 }),
            (wildcard, ByteCount { received: 8192, sent: 512 }),
        ]);
        let mut history = TrafficHistory::default();
        let start = Instant::now();
        let span = Duration::from_secs(2);
        let mut record = |step, entries| {
            let (_, reading_ports, _, _) = Reading {
                at: start + span * step, ports: Ok(ports.clone()), interfaces: Ok(HashMap::new()),
                port_state: PortTrafficState::Measuring,
                port_window: Some(PortWindow { span, entries }),
            }.apply(&mut history);
            assert!(reading_ports.is_ok());
            let sample = history.points.back().unwrap();
            assert_eq!(sample.port_span, Some(span));
            [0, 1, 2].map(|index| sample.socket(&port(index).graph_key()).unwrap().port_rates)
        };
        assert_eq!(record(1, Some(bytes.clone())), [None, None, None]);
        assert_eq!(record(2, Some(bytes)), [
            Some(Rates { received: 1024.0, sent: 2048.0 }),
            Some(Rates { received: 4096.0, sent: 256.0 }),
            Some(Rates { received: 0.0, sent: 0.0 }),
        ]);
        assert_eq!(record(3, None), [None, None, None]);
    }

    #[test]
    fn tcp_activity_counts_changed_connections_at_the_same_total_and_expires() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let mut samples = TrafficHistory::default();
        let mut observe = |history: &mut TcpActivity, now| {
            let mut ports = ports::list().unwrap();
            history.update(now, &mut ports);
            let (_, ports, _, _) = Reading {
                at: now, ports: Ok(ports), interfaces: Ok(HashMap::new()),
                port_state: PortTrafficState::Off, port_window: None,
            }.apply(&mut samples);
            let listener = ports.unwrap().into_iter().find(|port| {
                port.endpoint.port == address.port() && port.endpoint.address == address.ip()
                    && port.endpoint.pid == std::process::id() && port.endpoint.protocol == Protocol::Tcp
            }).unwrap();
            let sample = samples.points.back().unwrap().socket(&listener.graph_key()).unwrap();
            assert_eq!(sample.arrivals, listener.tcp_arrivals);
            (sample.established, listener.recent_tcp, sample.arrivals)
        };
        let mut history = TcpActivity::default();
        let start = Instant::now();
        let first = TcpStream::connect(address).unwrap();
        let (first_peer, _) = listener.accept().unwrap();
        assert_eq!(observe(&mut history, start), (1, None, None));
        let second = TcpStream::connect(address).unwrap();
        let (second_peer, _) = listener.accept().unwrap();
        drop((first, first_peer));
        assert_eq!(observe(&mut history, start + POLL_INTERVAL), (1, Some(1), Some(1)));
        assert_eq!(observe(&mut history, start + POLL_INTERVAL * 2), (1, Some(1), Some(0)));
        let expired = start + TCP_ACTIVITY_WINDOW + POLL_INTERVAL;
        assert_eq!(observe(&mut history, expired), (1, Some(0), Some(0)));
        history.update(expired + POLL_INTERVAL, &mut []);
        assert_eq!(observe(&mut history, expired + POLL_INTERVAL * 2), (1, None, None));
        assert_eq!(observe(&mut history, expired + POLL_INTERVAL * 3), (1, Some(0), Some(0)));
        drop((second, second_peer));
    }

    #[test]
    fn windows_interface_counters_are_readable() {
        read_interfaces().unwrap();
    }

    #[test]
    fn measures_real_deltas_without_turning_gaps_into_zero_traffic() {
        let counters = |id, received, sent| HashMap::from([(id, InterfaceBytes { received, sent })]);
        let first = counters(1, 100, 200);
        let second = counters(1, 500, 260);
        assert_eq!(rates_between(&first, &second, POLL_INTERVAL), Some(Rates { received: 200.0, sent: 30.0 }));
        assert_eq!(rates_between(&second, &second, POLL_INTERVAL), Some(Rates { received: 0.0, sent: 0.0 }));
        assert_eq!(rates_between(&second, &first, POLL_INTERVAL), None);
        assert_eq!(rates_between(&second, &counters(2, 700, 300), POLL_INTERVAL), None);
        assert_eq!(rates_between(&first, &second, Duration::from_secs(30)), None);
    }
}
