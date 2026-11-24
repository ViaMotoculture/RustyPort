use crate::ports::{Endpoint, Port, Protocol};

pub const GUIDE: &str = "À risque · Un port habituel d’un service sensible est lié au réseau. Exemples · partage Windows, administration à distance et bases de données.\r\n\r\n\
    Inconnu · Le chemin est indisponible ou l’usage réseau du programme reste à confirmer.\r\n\r\n\
    Normal · Bouclage avec exécutable identifié, processus système reconnu ou service Windows confirmé sur un port attendu.\r\n\r\n\
    Le niveau indique l’exposition locale et l’identification du processus. L’accès réel dépend du pare-feu et du réseau.\r\n\r\n\
    Un astérisque signale un niveau choisi dans le menu « Niveau ». Le détail affiche aussi le classement automatique.";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Risk {
    Normal,
    Unknown,
    Elevated,
}

impl Risk {
    pub const LEVELS: [Self; 3] = [Self::Normal, Self::Unknown, Self::Elevated];

    pub fn label(self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::Unknown => "Inconnu",
            Self::Elevated => "À risque",
        }
    }
}

#[derive(Clone, Copy)]
pub struct Assessment {
    pub level: Risk,
    pub reason: &'static str,
}

pub fn assess(port: &Port, system_directory: &str) -> Assessment {
    let endpoint = port.endpoint;
    let path = &port.owner.path;
    let (level, reason) = if !endpoint.is_local() && sensitive_use(endpoint).is_some() {
        (
            Risk::Elevated,
            "Port habituel d’un service sensible, lié à une interface réseau. L’accès dépend du pare-feu et du réseau.",
        )
    } else if endpoint.pid == 4 {
        (Risk::Normal, "Port associé au processus système de Windows (PID 4).")
    } else if path.is_empty() && let Some(reason) = known_service_use(port) {
        (Risk::Normal, reason)
    } else if path.is_empty() {
        (Risk::Unknown, "Windows ne communique pas le chemin de l’exécutable.")
    } else if endpoint.is_local() {
        (Risk::Normal, "Adresse de bouclage et chemin du processus identifié.")
    } else if !system_directory.is_empty()
        && path.rsplit_once('\\').is_some_and(|(directory, name)| {
            directory.eq_ignore_ascii_case(system_directory)
                && ["svchost.exe", "lsass.exe", "services.exe", "spoolsv.exe"]
                    .iter()
                    .any(|known| name.eq_ignore_ascii_case(known))
        })
    {
        (Risk::Normal, "Exécutable système reconnu dans le dossier système de Windows.")
    } else {
        (Risk::Unknown, "Application réseau identifiée par son chemin. Son usage reste à confirmer.")
    };
    Assessment { level, reason }
}

fn known_service_use(port: &Port) -> Option<&'static str> {
    if !port.owner.name.eq_ignore_ascii_case("svchost.exe") {
        return None;
    }
    let runs = |name| port.owner.known_services.contains(&name);
    match (port.endpoint.protocol, port.endpoint.port) {
        (_, 53) | (Protocol::Udp, 67) if runs("SharedAccess") => {
            Some("Port attendu pour le partage de connexion Windows. Le service SharedAccess est actif dans ce processus.")
        }
        (Protocol::Udp, 68 | 546) if runs("Dhcp") => {
            Some("Port attendu pour le client DHCP de Windows. Le service Dhcp est actif dans ce processus.")
        }
        (Protocol::Udp, 123) if runs("W32Time") => {
            Some("Port attendu pour la synchronisation de l’heure. Le service W32Time est actif dans ce processus.")
        }
        _ => None,
    }
}

fn sensitive_use(endpoint: Endpoint) -> Option<&'static str> {
    match (endpoint.protocol, endpoint.port) {
        (Protocol::Tcp, 21) => Some("FTP"),
        (Protocol::Tcp, 22) => Some("SSH"),
        (Protocol::Tcp, 23) => Some("Telnet"),
        (Protocol::Tcp, 135) => Some("RPC Windows"),
        (Protocol::Udp, 137 | 138) => Some("NetBIOS"),
        (Protocol::Tcp, 139 | 445) => Some("Partage de fichiers Windows"),
        (Protocol::Tcp, 1433) | (Protocol::Udp, 1434) => Some("SQL Server"),
        (Protocol::Tcp, 3306) => Some("MySQL"),
        (_, 3389) => Some("Bureau à distance"),
        (Protocol::Tcp, 5432) => Some("PostgreSQL"),
        (Protocol::Tcp, 5900) => Some("VNC"),
        (Protocol::Tcp, 5985 | 5986) => Some("WinRM"),
        (Protocol::Tcp, 6379) => Some("Redis"),
        (Protocol::Tcp, 27017) => Some("MongoDB"),
        _ => None,
    }
}

pub fn usual_use(endpoint: Endpoint) -> Option<&'static str> {
    sensitive_use(endpoint).or(match (endpoint.protocol, endpoint.port) {
        (_, 53) => Some("DNS"),
        (Protocol::Udp, 67 | 68) => Some("DHCP"),
        (Protocol::Udp, 123) => Some("NTP / synchronisation de l’heure"),
        (Protocol::Udp, 546) => Some("Client DHCPv6"),
        (Protocol::Tcp, 80) => Some("HTTP"),
        (Protocol::Tcp, 443) => Some("HTTPS"),
        (Protocol::Udp, 443) => Some("QUIC / HTTP/3"),
        (Protocol::Udp, 1900) => Some("SSDP / découverte UPnP"),
        (Protocol::Udp, 5353) => Some("mDNS"),
        (Protocol::Udp, 5355) => Some("LLMNR"),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn distinguishes_exposure_and_only_recognizes_system_paths() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut port = crate::ports::list().unwrap().into_iter().find(|port| {
            port.endpoint.port == listener.local_addr().unwrap().port()
                && port.endpoint.pid == std::process::id()
                && port.endpoint.protocol == Protocol::Tcp
        }).unwrap();
        let directory = crate::ports::system_directory().unwrap();
        assert_eq!(assess(&port, &directory).level, Risk::Normal);
        port.owner.path.clear();
        assert_eq!(assess(&port, &directory).level, Risk::Unknown);

        port.endpoint.address = "0.0.0.0".parse().unwrap();
        port.endpoint.port = 53;
        port.owner.name = "svchost.exe".into();
        port.owner.known_services.push("SharedAccess");
        assert_eq!(assess(&port, &directory).level, Risk::Normal);

        port.endpoint.port = 445;
        assert_eq!(assess(&port, &directory).level, Risk::Elevated);
        port.endpoint.port = 50000;
        port.owner.path = format!("{directory}-copie\\svchost.exe");
        assert_eq!(assess(&port, &directory).level, Risk::Unknown);
        port.owner.path = format!("{directory}\\svchost.exe");
        assert_eq!(assess(&port, &directory).level, Risk::Normal);
    }
}
