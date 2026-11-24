use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io;
use std::ptr::{addr_of, null_mut};
use std::sync::{Arc, Mutex, MutexGuard, atomic::{AtomicU64, Ordering}, mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError}};
use std::thread;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, IF_TYPE_SOFTWARE_LOOPBACK, MIB_IF_ROW2, MIB_IF_TABLE2,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;

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
}

impl Reading {
    pub fn apply(self, history: &mut TrafficHistory) -> (Instant, io::Result<Vec<Port>>, TrafficState) {
        let mut sockets = self.ports.as_deref().unwrap_or_default().iter()
            .filter(|port| port.endpoint.protocol == Protocol::Tcp)
            .map(|port| SocketActivity {
                key: port.graph_key(),
                name: port.owner.name.clone(),
                endpoint: port.endpoint.label(),
                address: port.endpoint.address_label(),
                peer: port.established.iter().next().map_or_else(String::new, |peer| peer.peer_label()),
                established: port.established.len() as u32,
            }).collect::<Vec<_>>();
        sockets.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        (self.at, self.ports, history.record(self.at, self.interfaces, sockets))
    }
}

pub struct Monitor {
    refresh: SyncSender<()>,
    readings: Receiver<Reading>,
    interval_ms: Arc<AtomicU64>,
    watches: Arc<Mutex<Vec<Watch>>>,
}

impl Monitor {
    pub fn start() -> io::Result<Self> {
        let (refresh, requests) = mpsc::sync_channel(1);
        let (publish, readings) = mpsc::sync_channel(1);
        let interval_ms = Arc::new(AtomicU64::new(DEFAULT_INTERVAL_MS));
        let interval = Arc::clone(&interval_ms);
        let watches = Arc::new(Mutex::new(Vec::new()));
        let monitored = Arc::clone(&watches);
        thread::Builder::new().name("rustyport-monitor".into()).spawn(move || {
            let mut tcp_activity = TcpActivity::default();
            loop {
                relaunch::enforce(&mut lock_watches(&monitored));
                let mut ports = ports::list();
                let interfaces = read_interfaces();
                let at = Instant::now();
                match &mut ports {
                    Ok(ports) => tcp_activity.update(at, ports),
                    Err(_) => tcp_activity.listeners.clear(),
                }
                let reading = Reading { at, ports, interfaces };
                if publish.send(reading).is_err()
                    || requests.recv_timeout(Duration::from_millis(interval.load(Ordering::Relaxed))) == Err(RecvTimeoutError::Disconnected)
                {
                    break;
                }
            }
        })?;
        Ok(Self { refresh, readings, interval_ms, watches })
    }

    pub fn set_interval(&self, milliseconds: u64) {
        self.interval_ms.store(milliseconds, Ordering::Relaxed);
        self.refresh();
    }

    pub fn refresh(&self) -> bool {
        !matches!(self.refresh.try_send(()), Err(TrySendError::Disconnected(_)))
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
        match self.readings.try_recv() {
            Ok(reading) => Ok(Some(reading)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(error) => Err(error),
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
    pub established: u32,
}

#[derive(Clone)]
pub struct Point {
    pub at: Instant,
    pub rates: Option<Rates>,
    pub span: Duration,
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
    pub points: VecDeque<Point>,
}

impl TrafficHistory {
    fn record(&mut self, now: Instant, counters: io::Result<Counters>, sockets: Vec<SocketActivity>) -> TrafficState {
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
        self.points.push_back(Point { at: now, rates, span, sockets });
        while self.points.front().is_some_and(|point| now.duration_since(point.at) > GRAPH_WINDOW) {
            self.points.pop_front();
        }
        state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn tcp_activity_counts_changed_connections_at_the_same_total_and_expires() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let observe = |history: &mut TcpActivity, now| {
            let mut ports = ports::list().unwrap();
            history.update(now, &mut ports);
            let listener = ports.into_iter().find(|port| {
                port.endpoint.port == address.port() && port.endpoint.address == address.ip()
                    && port.endpoint.pid == std::process::id() && port.endpoint.protocol == Protocol::Tcp
            }).unwrap();
            (listener.established.len(), listener.recent_tcp)
        };
        let mut history = TcpActivity::default();
        let start = Instant::now();
        let first = TcpStream::connect(address).unwrap();
        let (first_peer, _) = listener.accept().unwrap();
        assert_eq!(observe(&mut history, start), (1, None));
        let second = TcpStream::connect(address).unwrap();
        let (second_peer, _) = listener.accept().unwrap();
        drop((first, first_peer));
        assert_eq!(observe(&mut history, start + POLL_INTERVAL), (1, Some(1)));
        assert_eq!(observe(&mut history, start + POLL_INTERVAL * 2), (1, Some(1)));
        assert_eq!(observe(&mut history, start + TCP_ACTIVITY_WINDOW + POLL_INTERVAL), (1, Some(0)));
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
