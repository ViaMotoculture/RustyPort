use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ports::Port;
use crate::risk::Risk;

const FILE_NAME: &str = "manual-port-levels.bin";
const FORMAT: &[u8] = b"RPL\x01";
const MAX_BYTES: usize = 4 * 1024 * 1024;
static TEMP_SERIAL: AtomicU64 = AtomicU64::new(0);

type Levels = BTreeMap<String, Risk>;

pub struct LevelPreferences {
    levels: Levels,
    path: Option<PathBuf>,
}

impl LevelPreferences {
    pub fn load() -> io::Result<Self> {
        let local = std::env::var_os("LOCALAPPDATA").filter(|path| !path.is_empty()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Le dossier LOCALAPPDATA est indisponible.")
        })?;
        let path = PathBuf::from(local).join("RustyPort").join(FILE_NAME);
        Self::load_from(path)
    }

    fn load_from(path: PathBuf) -> io::Result<Self> {
        Ok(Self { levels: read_settings(&path)?, path: Some(path) })
    }

    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self { levels: Levels::new(), path: None }
    }

    pub fn can_set(port: &Port) -> bool {
        port.endpoint.port != 0 && owner_identity(port).is_some()
    }

    pub fn get(&self, port: &Port) -> Option<Risk> {
        if self.levels.is_empty() {
            return None;
        }
        self.levels.get(&port_identity(port)?).copied()
    }

    pub fn set(&mut self, ports: &[&Port], level: Option<Risk>) -> io::Result<()> {
        if ports.is_empty() {
            return Ok(());
        }
        let identities = ports.iter().map(|port| port_identity(port).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "L’identité d’un port ne permet pas de mémoriser son niveau.")
        })).collect::<io::Result<Vec<_>>>()?;
        let previous = match &self.path {
            Some(path) => read_settings(path)?,
            None => self.levels.clone(),
        };
        let mut next = previous.clone();
        for identity in identities {
            if let Some(level) = level {
                next.insert(identity, level);
            } else {
                next.remove(&identity);
            }
        }
        if next != previous && let Some(path) = &self.path {
            write_settings(path, &next)?;
        }
        self.levels = next;
        Ok(())
    }
}

fn owner_identity(port: &Port) -> Option<(&'static str, &str)> {
    if port.endpoint.pid == 4 {
        return Some(("system", ""));
    }
    if !port.owner.path.is_empty() {
        return Some(("path", &port.owner.path));
    }
    let name = port.owner.name.trim();
    (!name.is_empty() && !name.eq_ignore_ascii_case("Inconnu")).then_some(("name", name))
}

fn port_identity(port: &Port) -> Option<String> {
    if port.endpoint.port == 0 {
        return None;
    }
    let (kind, owner) = owner_identity(port)?;
    // Keep executable paths verbatim, including case-sensitive Windows directories.
    let owner = if kind == "name" { owner.to_ascii_lowercase().into() } else { std::borrow::Cow::Borrowed(owner) };
    Some(format!("{}\0{}\0{kind}\0{owner}", port.endpoint.label(), port.endpoint.address_label()))
}

fn invalid_settings() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Les niveaux manuels enregistrés sont illisibles.")
}

fn read_settings(path: &Path) -> io::Result<Levels> {
    let input = match File::open(path) {
        Ok(input) => input,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Levels::new()),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    input.take((MAX_BYTES + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid_settings());
    }
    decode(&bytes)
}

fn write_settings(path: &Path, levels: &Levels) -> io::Result<()> {
    let bytes = encode(levels)?;
    let directory = path.parent().ok_or_else(|| io::Error::other("Dossier des niveaux manuels introuvable."))?;
    fs::create_dir_all(directory)?;
    let serial = TEMP_SERIAL.fetch_add(1, Ordering::Relaxed);
    let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let temporary = directory.join(format!(".manual-port-levels-{}-{time}-{serial}.tmp", std::process::id()));
    let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
    let written = file.write_all(&bytes).and_then(|()| file.sync_all());
    drop(file);
    // Both paths are on the same volume. A reader sees either complete snapshot.
    let result = written.and_then(|()| fs::rename(&temporary, path));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn encode(levels: &Levels) -> io::Result<Vec<u8>> {
    let mut data = FORMAT.to_vec();
    for (identity, risk) in levels {
        if data.len().saturating_add(5).saturating_add(identity.len()) > MAX_BYTES {
            return Err(io::Error::other("Trop de niveaux manuels pour les enregistrer."));
        }
        data.extend_from_slice(&(identity.len() as u32).to_le_bytes());
        data.extend_from_slice(identity.as_bytes());
        data.push(match risk { Risk::Normal => 0, Risk::Unknown => 1, Risk::Elevated => 2 });
    }
    Ok(data)
}

fn decode(data: &[u8]) -> io::Result<Levels> {
    let mut rest = data.strip_prefix(FORMAT).ok_or_else(invalid_settings)?;
    let mut levels = Levels::new();
    while !rest.is_empty() {
        let (length, data) = rest.split_at_checked(4).ok_or_else(invalid_settings)?;
        let length = u32::from_le_bytes(length.try_into().unwrap()) as usize;
        if length == 0 {
            return Err(invalid_settings());
        }
        let (identity, data) = data.split_at_checked(length).ok_or_else(invalid_settings)?;
        let identity = std::str::from_utf8(identity).map_err(|_| invalid_settings())?;
        let (level, remaining) = data.split_first().ok_or_else(invalid_settings)?;
        let level = match level {
            0 => Risk::Normal,
            1 => Risk::Unknown,
            2 => Risk::Elevated,
            _ => return Err(invalid_settings()),
        };
        if levels.insert(identity.to_owned(), level).is_some() {
            return Err(invalid_settings());
        }
        rest = remaining;
    }
    Ok(levels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
    use crate::ports::Protocol;

    fn fixture_port() -> Port {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let local = listener.local_addr().unwrap();
        let mut port = crate::ports::list().unwrap().into_iter().find(|port| {
            port.endpoint.port == local.port() && port.endpoint.address == local.ip()
                && port.endpoint.pid == std::process::id() && port.endpoint.protocol == Protocol::Tcp
        }).unwrap();
        port.owner.path = r"C:\Example\server.exe".into();
        port.owner.name = "server.exe".into();
        port
    }

    #[test]
    fn manual_level_follows_identity_and_can_be_cleared() {
        let original = fixture_port();
        let mut levels = LevelPreferences::in_memory();
        let mut restarted = original.clone();
        restarted.endpoint.pid += 1;
        restarted.owner.created = None;
        assert_eq!(levels.get(&original), None);
        levels.set(&[&original], Some(Risk::Normal)).unwrap();
        assert_eq!(levels.get(&restarted), Some(Risk::Normal));
        let mut other = restarted.clone();
        other.owner.path = r"C:\Different\server.exe".into();
        assert_eq!(levels.get(&other), None);
        other = restarted.clone();
        other.endpoint.address = "0.0.0.0".parse().unwrap();
        assert_eq!(levels.get(&other), None);
        other = restarted.clone();
        other.endpoint.protocol = Protocol::Udp;
        assert_eq!(levels.get(&other), None);

        levels.set(&[&restarted], None).unwrap();
        assert_eq!(levels.get(&original), None);
    }

    #[test]
    fn batch_levels_do_not_mix_system_and_unverified_paths() {
        let known = fixture_port();
        let mut named = known.clone();
        named.owner.path.clear();
        let mut system = named.clone();
        system.endpoint.pid = 4;
        let mut unidentified = named.clone();
        unidentified.owner.name = "Inconnu".into();

        let mut preferences = LevelPreferences::in_memory();
        assert!(!LevelPreferences::can_set(&unidentified));
        assert!(preferences.set(&[&named, &unidentified], Some(Risk::Normal)).is_err());
        assert_eq!(preferences.get(&named), None);
        preferences.set(&[&named, &system], Some(Risk::Unknown)).unwrap();
        assert_eq!(preferences.get(&system), Some(Risk::Unknown));
        assert_eq!(preferences.get(&named), Some(Risk::Unknown));
        assert_eq!(preferences.get(&known), None);
        assert_eq!(preferences.get(&unidentified), None);

        let encoded = encode(&preferences.levels).unwrap();
        assert_eq!(decode(&encoded).unwrap(), preferences.levels);
        assert!(decode(&encoded[..encoded.len() - 1]).is_err());
        preferences.set(&[&named, &system], None).unwrap();
        assert!(preferences.levels.is_empty());
    }

    #[test]
    fn levels_persist_and_a_failed_replace_preserves_the_previous_choice() {
        let port = fixture_port();
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join(format!(
            "manual-levels-test-{}-{}", std::process::id(), TEMP_SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        let path = directory.join(FILE_NAME);
        let mut preferences = LevelPreferences::load_from(path.clone()).unwrap();
        preferences.set(&[&port], None).unwrap();
        assert!(!directory.exists());

        preferences.set(&[&port], Some(Risk::Normal)).unwrap();
        let mut reopened = LevelPreferences::load_from(path.clone()).unwrap();
        assert_eq!(reopened.get(&port), Some(Risk::Normal));

        let in_use = OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(&path).unwrap();
        assert!(reopened.set(&[&port], Some(Risk::Elevated)).is_err());
        assert_eq!(reopened.get(&port), Some(Risk::Normal));
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        drop(in_use);
        assert_eq!(LevelPreferences::load_from(path.clone()).unwrap().get(&port), Some(Risk::Normal));

        reopened.set(&[&port], Some(Risk::Elevated)).unwrap();
        assert_eq!(LevelPreferences::load_from(path.clone()).unwrap().get(&port), Some(Risk::Elevated));
        reopened.set(&[&port], None).unwrap();
        assert_eq!(LevelPreferences::load_from(path.clone()).unwrap().get(&port), None);
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
