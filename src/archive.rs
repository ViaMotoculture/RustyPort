use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_DELETE_ON_CLOSE;

use crate::monitor::{GRAPH_WINDOW, Point, Rates, SocketActivity};

const INDEX_BYTES: u64 = 24;

pub struct Archive {
    index: File,
    data: File,
    start: Instant,
    len: usize,
    index_path: PathBuf,
    data_path: PathBuf,
}

impl Archive {
    pub fn open(start: Instant) -> io::Result<Self> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let prefix = format!("rustyport-{}-{unique}", std::process::id());
        let open = |extension| {
            let path = std::env::temp_dir().join(format!("{prefix}.{extension}"));
            let file = OpenOptions::new().read(true).write(true).create_new(true)
                .custom_flags(FILE_FLAG_DELETE_ON_CLOSE).open(&path)?;
            Ok::<_, io::Error>((file, path))
        };
        let (index, index_path) = open("index")?;
        let (data, data_path) = open("releves")?;
        Ok(Self { index, data, start, len: 0, index_path, data_path })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn size(&self) -> io::Result<u64> {
        Ok(self.index.metadata()?.len() + self.data.metadata()?.len())
    }

    pub fn reader(&self) -> io::Result<Self> {
        // Opening independent handles keeps the export cursor separate from collection.
        Ok(Self {
            index: File::open(&self.index_path)?, data: File::open(&self.data_path)?,
            start: self.start, len: self.len,
            index_path: self.index_path.clone(), data_path: self.data_path.clone(),
        })
    }

    pub fn bounds(&mut self) -> io::Result<(u64, u64)> {
        if self.len == 0 {
            return Err(invalid());
        }
        let first = self.item(0)?.0;
        let last = self.item(self.len - 1)?.0;
        Ok((first, last))
    }

    pub fn append(&mut self, point: &Point) -> io::Result<()> {
        let at = point.at.saturating_duration_since(self.start).as_millis() as u64;
        let mut data = Vec::new();
        data.write_all(&(point.span.as_micros() as u64).to_le_bytes())?;
        data.write_all(&[u8::from(point.rates.is_some())])?;
        if let Some(rates) = point.rates {
            data.write_all(&rates.received.to_le_bytes())?;
            data.write_all(&rates.sent.to_le_bytes())?;
        }
        let count = u32::try_from(point.sockets.len()).map_err(|_| invalid())?;
        data.write_all(&count.to_le_bytes())?;
        for socket in &point.sockets {
            data.write_all(&socket.established.to_le_bytes())?;
            data.write_all(&[u8::from(socket.arrivals.is_some())])?;
            if let Some(arrivals) = socket.arrivals {
                data.write_all(&arrivals.to_le_bytes())?;
            }
            for text in [&socket.key, &socket.name, &socket.endpoint, &socket.address, &socket.peer] {
                let size = u32::try_from(text.len()).map_err(|_| invalid())?;
                data.write_all(&size.to_le_bytes())?;
                data.write_all(text.as_bytes())?;
            }
        }
        let offset = self.data.seek(SeekFrom::End(0))?;
        self.data.write_all(&data)?;
        self.index.seek(SeekFrom::Start(self.len as u64 * INDEX_BYTES))?;
        self.index.write_all(&at.to_le_bytes())?;
        self.index.write_all(&offset.to_le_bytes())?;
        self.index.write_all(&(data.len() as u64).to_le_bytes())?;
        self.len += 1;
        Ok(())
    }

    pub fn page(&mut self, end: usize) -> io::Result<VecDeque<Point>> {
        if end >= self.len {
            return Err(invalid());
        }
        let mut points = VecDeque::new();
        let mut latest = None;
        let total = self.data.metadata()?.len();
        for item in (0..=end).rev() {
            let (at, offset, size) = self.item(item)?;
            let limit = *latest.get_or_insert(at);
            if limit.saturating_sub(at) > GRAPH_WINDOW.as_millis() as u64 {
                break;
            }
            points.push_front(self.read_point(at, offset, size, total)?);
        }
        Ok(points)
    }

    fn item(&mut self, index: usize) -> io::Result<(u64, u64, u64)> {
        self.index.seek(SeekFrom::Start(index as u64 * INDEX_BYTES))?;
        Ok((u64::from_le_bytes(read(&mut self.index)?),
            u64::from_le_bytes(read(&mut self.index)?), u64::from_le_bytes(read(&mut self.index)?)))
    }

    fn read_point(&mut self, at: u64, offset: u64, size: u64, total: u64) -> io::Result<Point> {
        if offset > total || size > total - offset {
            return Err(invalid());
        }
        self.data.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; usize::try_from(size).map_err(|_| invalid())?];
        self.data.read_exact(&mut bytes)?;
        decode(self.start + Duration::from_millis(at), &bytes)
    }

    pub fn export(&mut self, destination: &Path, range: Option<(u64, u64)>) -> io::Result<usize> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let temporary = destination.with_file_name(format!(".rustyport-export-{}-{unique}.part", std::process::id()));
        let output = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        let result = self.write_csv(BufWriter::new(output), range);
        let result = result.and_then(|count| {
            fs::rename(&temporary, destination)?;
            Ok(count)
        });
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn write_csv(&mut self, mut output: BufWriter<File>, range: Option<(u64, u64)>) -> io::Result<usize> {
        output.write_all(&[0xef, 0xbb, 0xbf])?;
        writeln!(output, "session_ms;mesure_ms;type;recu_octets_s;envoye_octets_s;processus;port_protocole;adresse_locale;correspondant_tcp;tcp_etablies;tcp_nouvelles_releve\r")?;
        let (first, last) = range.unwrap_or((0, u64::MAX));
        let total = self.data.metadata()?.len();
        let mut count = 0;
        for index in 0..self.len {
            let (at, offset, size) = self.item(index)?;
            if at < first {
                continue;
            }
            if at > last {
                break;
            }
            let point = self.read_point(at, offset, size, total)?;
            let span = point.span.as_millis();
            if let Some(rates) = point.rates {
                let received = format!("{:.3}", rates.received).replace('.', ",");
                let sent = format!("{:.3}", rates.sent).replace('.', ",");
                writeln!(output, "{at};{span};Interfaces;{received};{sent};;;;;;\r")?;
            } else {
                writeln!(output, "{at};{span};Interfaces;;;;;;;;\r")?;
            }
            for socket in point.sockets {
                let arrivals = socket.arrivals.map_or_else(String::new, |count| count.to_string());
                writeln!(output, "{at};{span};TCP;;;{};{};{};{};{};{arrivals}\r", csv_field(&socket.name),
                    csv_field(&socket.endpoint), csv_field(&socket.address), csv_field(&socket.peer), socket.established)?;
            }
            count += 1;
        }
        if count == 0 {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Aucun relevé dans cette période."));
        }
        output.flush()?;
        output.get_ref().sync_all()?;
        Ok(count)
    }
}

fn csv_field(text: &str) -> String {
    let prefix = if text.trim_start().starts_with(['=', '+', '-', '@']) { "'" } else { "" };
    format!("\"{prefix}{}\"", text.replace('"', "\"\""))
}

fn decode(at: Instant, bytes: &[u8]) -> io::Result<Point> {
    let mut input = Cursor::new(bytes);
    let span = Duration::from_micros(u64::from_le_bytes(read(&mut input)?));
    let rates = if read::<1>(&mut input)?[0] != 0 {
        Some(Rates {
            received: f64::from_le_bytes(read(&mut input)?),
            sent: f64::from_le_bytes(read(&mut input)?),
        })
    } else { None };
    let count = u32::from_le_bytes(read(&mut input)?);
    let mut sockets = Vec::new();
    for _ in 0..count {
        let established = u32::from_le_bytes(read(&mut input)?);
        let arrivals = match read::<1>(&mut input)?[0] {
            0 => None,
            1 => Some(u32::from_le_bytes(read(&mut input)?)),
            _ => return Err(invalid()),
        };
        sockets.push(SocketActivity {
            established, arrivals, key: read_string(&mut input)?, name: read_string(&mut input)?,
            endpoint: read_string(&mut input)?, address: read_string(&mut input)?, peer: read_string(&mut input)?,
        });
    }
    Ok(Point { at, rates, span, sockets })
}

fn read<const N: usize>(input: &mut impl Read) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_string(input: &mut Cursor<&[u8]>) -> io::Result<String> {
    let size = u32::from_le_bytes(read(input)?) as usize;
    let at = input.position() as usize;
    let end = at.checked_add(size).ok_or_else(invalid)?;
    let bytes = input.get_ref().get(at..end).ok_or_else(invalid)?;
    let value = std::str::from_utf8(bytes).map_err(|_| invalid())?.into();
    input.set_position(end as u64);
    Ok(value)
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Archive RustyPort illisible")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_old_samples_while_new_samples_continue() {
        let start = Instant::now();
        let mut archive = Archive::open(start).unwrap();
        for second in 0..=80 {
            archive.append(&Point {
                at: start + Duration::from_secs(second),
                span: Duration::from_millis(500),
                rates: (second > 0).then_some(Rates { sent: 20.0, received: second as f64 }),
                sockets: vec![SocketActivity {
                    key: "test".into(), name: "Serveur démo".into(), endpoint: "8514/TCP".into(),
                    address: "127.0.0.1".into(), peer: "127.0.0.1:12345".into(), established: second as u32,
                    arrivals: match second {
                        0 => None,
                        1 => Some(0),
                        _ => Some(3),
                    },
                }],
            }).unwrap();
        }
        let old = archive.page(2).unwrap();
        assert_eq!(old.len(), 3);
        assert_eq!(old[0].socket("test").unwrap().arrivals, None);
        assert_eq!(old[1].socket("test").unwrap().arrivals, Some(0));
        let point = old.back().unwrap();
        assert_eq!(point.socket("test").unwrap().established, 2);
        assert_eq!(point.socket("test").unwrap().arrivals, Some(3));
        assert_eq!(point.rates.unwrap().received, 2.0);
        let latest = archive.page(80).unwrap();
        assert_eq!(latest.len(), 61);
        assert_eq!(latest.front().unwrap().socket("test").unwrap().established, 20);
        let mut reader = archive.reader().unwrap();
        let destination = archive.index_path.with_extension("test.csv");
        assert_eq!(reader.export(&destination, Some((0, 3000))).unwrap(), 4);
        let csv = fs::read_to_string(&destination).unwrap();
        assert!(csv.lines().all(|line| line.split(';').count() == 11));
        assert!(csv.lines().next().unwrap().ends_with(";tcp_etablies;tcp_nouvelles_releve"));
        assert!(csv.lines().any(|line| line.starts_with("0;500;TCP;") && line.ends_with(";0;")));
        assert!(csv.lines().any(|line| line.starts_with("1000;500;TCP;") && line.ends_with(";1;0")));
        assert!(csv.lines().any(|line| line.starts_with("2000;500;TCP;;;\"Serveur démo\"") && line.ends_with(";2;3")));
        assert!(csv.contains("3000;500;Interfaces;"));
        assert!(!csv.contains("4000;500;Interfaces;"));
        fs::remove_file(destination).unwrap();
        let temporary_index = archive.index_path.clone();
        let temporary_data = archive.data_path.clone();
        drop(reader);
        drop(archive);
        assert!(!temporary_index.exists());
        assert!(!temporary_data.exists());
    }
}
