use std::cmp::Ordering;
use std::time::{Duration, Instant};

use crate::ports::{Endpoint, Port, Protocol};
use crate::risk::{Assessment, Risk, usual_use};

pub type PortKey = (Endpoint, Option<u64>);

#[derive(Clone)]
pub struct Entry {
    pub port: Port,
    pub first_seen: Instant,
    pub assessment: Assessment,
    name: String,
    lookup: String,
}

impl Entry {
    pub fn new(port: Port, first_seen: Instant, assessment: Assessment) -> Self {
        let endpoint = port.endpoint;
        let name = port.owner.name.to_lowercase();
        let lookup = format!(
            "{} {} {} {} {} {} {} {}",
            endpoint.label(), endpoint.address_label(), endpoint.pid, name, port.owner.path,
            port.owner.services.join(" "), assessment.level.label(), usual_use(endpoint).unwrap_or_default()
        ).to_lowercase();
        Self { port, first_seen, assessment, name, lookup }
    }

    pub fn key(&self) -> PortKey {
        self.port.key()
    }

    fn tcp_connections(&self) -> Option<usize> {
        (self.port.endpoint.protocol == Protocol::Tcp).then_some(self.port.established.len())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Column {
    Risk,
    Port,
    Protocol,
    Address,
    Process,
    Pid,
    Seen,
    Connections,
    RecentTcp,
}

pub const COLUMNS: [(Column, &str, i32); 9] = [
    (Column::Risk, "Niveau", 90),
    (Column::Port, "Port", 64),
    (Column::Protocol, "Protocole", 77),
    (Column::Address, "Adresse locale", 183),
    (Column::Process, "Processus", 170),
    (Column::Pid, "PID", 66),
    (Column::Seen, "Vu depuis", 94),
    (Column::Connections, "TCP établies", 107),
    (Column::RecentTcp, "Nouv. TCP / 60 s", 119),
];

#[derive(Clone, Copy)]
pub struct Sort {
    pub column: Column,
    pub descending: bool,
}

impl Default for Sort {
    fn default() -> Self {
        Self { column: Column::Risk, descending: true }
    }
}

impl Sort {
    pub fn select(self, column: Column) -> Self {
        let descending = if self.column == column {
            !self.descending
        } else {
            matches!(column, Column::Risk | Column::Seen | Column::Connections | Column::RecentTcp)
        };
        Self { column, descending }
    }

    fn compare(self, a: &Entry, b: &Entry) -> Ordering {
        let a_socket = a.port.endpoint;
        let b_socket = b.port.endpoint;
        let order = match self.column {
            Column::Risk => a.assessment.level.cmp(&b.assessment.level),
            Column::Port => a_socket.port.cmp(&b_socket.port),
            Column::Protocol => a_socket.protocol.cmp(&b_socket.protocol),
            Column::Address => a_socket.address.cmp(&b_socket.address),
            Column::Process => a.name.cmp(&b.name),
            Column::Pid => a_socket.pid.cmp(&b_socket.pid),
            Column::Seen => b.first_seen.cmp(&a.first_seen),
            Column::Connections | Column::RecentTcp => match if self.column == Column::Connections {
                (a.tcp_connections(), b.tcp_connections())
            } else {
                (a.port.recent_tcp, b.port.recent_tcp)
            } {
                (Some(a), Some(b)) => a.cmp(&b),
                (Some(_), None) => return Ordering::Less,
                (None, Some(_)) => return Ordering::Greater,
                (None, None) => Ordering::Equal,
            },
        };
        let order = if self.descending { order.reverse() } else { order };
        order.then_with(|| a.key().cmp(&b.key()))
    }
}

pub struct Row {
    pub key: PortKey,
    pub index: usize,
    pub level: Risk,
    pub fields: [String; COLUMNS.len()],
}

pub fn visible_rows(ports: &[Entry], query: &str, filter: Option<Risk>, sort: Sort, at: Instant) -> Vec<Row> {
    let mut visible: Vec<_> = ports.iter().enumerate().filter(|(_, port)| {
        filter.is_none_or(|level| level == port.assessment.level)
            && query.split_whitespace().all(|part| port.lookup.contains(part))
    }).collect();
    visible.sort_unstable_by(|(_, a), (_, b)| sort.compare(a, b));
    visible.into_iter().map(|(index, entry)| {
        let port = &entry.port;
        let endpoint = port.endpoint;
        let level = entry.assessment.level;
        Row {
            key: entry.key(), index, level,
            fields: [
                level.label().into(),
                endpoint.port.to_string(),
                endpoint.protocol.name().into(),
                endpoint.address_label(),
                port.owner.name.clone(),
                endpoint.pid.to_string(),
                duration_label(at.saturating_duration_since(entry.first_seen)),
                entry.tcp_connections().map_or_else(|| "—".into(), |count| count.to_string()),
                port.recent_tcp.map_or_else(|| "—".into(), |count| count.to_string()),
            ],
        }
    }).collect()
}

pub fn duration_label(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let days = seconds / 86400;
    let (hours, minutes, seconds) = (seconds / 3600 % 24, seconds / 60 % 60, seconds % 60);
    let clock = format!("{hours:02}:{minutes:02}:{seconds:02}");
    if days == 0 { clock } else { format!("{days} j {clock}") }
}
