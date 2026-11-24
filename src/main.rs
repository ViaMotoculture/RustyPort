#![windows_subsystem = "windows"]

mod chart;
mod firewall;
mod icon;
mod monitor;
mod ports;
mod risk;
mod relaunch;
mod table_view;
mod tray;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io;
use std::mem::size_of;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus, TME_LEAVE, TRACKMOUSEEVENT, TrackMouseEvent};
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::{PCWSTR, w};

use firewall::Action as FirewallAction;
use monitor::{INTERVALS, Monitor, Reading, TrafficHistory, TrafficState};
use ports::{Port, Protocol, wide};
use risk::{Risk, usual_use};
use table_view::{COLUMNS, Entry, PortKey, Row, Sort, duration_label, visible_rows};

const ID_FILTER: u16 = 100;
const ID_REFRESH: u16 = 101;
const ID_STOP: u16 = 102;
const ID_BLOCK: u16 = 103;
const ID_UNBLOCK: u16 = 104;
const ID_RISK: u16 = 105;
const ID_INTERVAL: u16 = 106;
const ID_WATCHES: u16 = 107;
const ID_DURATION: u16 = 108;
const EXIT_MENU: usize = 450;
const FIREWALL_TIMER: usize = 1;
const MONITOR_TIMER: usize = 2;

struct App {
    window: HWND,
    traffic_label: HWND,
    traffic_status: HWND,
    session: HWND,
    interval_label: HWND,
    interval: HWND,
    overview: HWND,
    filter_label: HWND,
    filter: HWND,
    risk_filter: HWND,
    refresh: HWND,
    list: HWND,
    details: HWND,
    stop: HWND,
    block: HWND,
    unblock: HWND,
    status: HWND,
    duration_label: HWND,
    duration: HWND,
    watches: HWND,
    started: Instant,
    shown_uptime: Cell<u64>,
    system_directory: String,
    monitor: Monitor,
    monitor_lost: Cell<bool>,
    traffic: RefCell<TrafficHistory>,
    live_traffic: RefCell<String>,
    graph_pointer: Cell<Option<i32>>,
    tray: tray::Tray,
    _small_icon: icon::Icon,
    _large_icon: icon::Icon,
    list_error: RefCell<Option<String>>,
    last_port_read: Cell<Option<Instant>>,
    ports: RefCell<Vec<Entry>>,
    rows: RefCell<Vec<Row>>,
    sort: Cell<Sort>,
    high_contrast: Cell<bool>,
    drawing_list: Cell<bool>,
    firewall: RefCell<Option<(firewall::Job, Option<Port>)>>,
}

impl App {
    fn new(window: HWND) -> io::Result<Self> {
        let traffic_label = control(window, w!("STATIC"), "Trafic des interfaces · 60 dernières secondes", 0, 0, false)?;
        let traffic_status = control(window, w!("STATIC"), "Mesure du débit en cours…", 0, 0, false)?;
        let session = control(window, w!("STATIC"), "", 0, 0, false)?;
        let interval_label = control(window, w!("STATIC"), "Relevé", 0, 0, false)?;
        let interval = control(window, w!("COMBOBOX"), "", CBS_DROPDOWNLIST as u32 | WS_VSCROLL, ID_INTERVAL, false)?;
        for (_, label) in INTERVALS {
            unsafe { SendMessageW(interval, CB_ADDSTRING, 0, wide(label).as_ptr() as isize) };
        }
        unsafe { SendMessageW(interval, CB_SETCURSEL, 3, 0) };
        let overview = control(window, w!("STATIC"), "", 0, 0, false)?;
        let filter_label = control(window, w!("STATIC"), "Filtrer", 0, 0, false)?;
        let filter = control(window, w!("EDIT"), "", ES_AUTOHSCROLL as u32, ID_FILTER, true)?;
        unsafe {
            SendMessageW(filter, EM_SETCUEBANNER, 1, w!("Port, processus, adresse ou service") as isize);
        }
        let risk_filter = control(window, w!("COMBOBOX"), "", CBS_DROPDOWNLIST as u32 | WS_VSCROLL, ID_RISK, false)?;
        for label in std::iter::once("Tous les niveaux").chain(Risk::LEVELS.map(Risk::label)) {
            unsafe { SendMessageW(risk_filter, CB_ADDSTRING, 0, wide(label).as_ptr() as isize) };
        }
        unsafe { SendMessageW(risk_filter, CB_SETCURSEL, 0, 0) };
        let refresh = control(window, w!("BUTTON"), "Actualiser", 0, ID_REFRESH, false)?;
        let list = control(window, WC_LISTVIEWW, "", LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 0, true)?;
        unsafe {
            SendMessageW(list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
                (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP) as isize);
        }
        for (index, (_, label, width)) in COLUMNS.into_iter().enumerate() {
            let mut label = wide(label);
            let column = LVCOLUMNW { mask: LVCF_TEXT | LVCF_WIDTH, cx: width, pszText: label.as_mut_ptr(), ..Default::default() };
            unsafe { SendMessageW(list, LVM_INSERTCOLUMNW, index, &column as *const _ as isize) };
        }
        let details = control(
            window, w!("EDIT"), "", (ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL) as u32 | WS_VSCROLL, 0, true,
        )?;
        let stop = control(window, w!("BUTTON"), "Terminer le processus…", 0, ID_STOP, false)?;
        let block = control(window, w!("BUTTON"), "Actions du port…", 0, ID_BLOCK, false)?;
        let unblock = control(window, w!("BUTTON"), "Retirer le blocage", 0, ID_UNBLOCK, false)?;
        let status = control(window, w!("STATIC"), "", 0, 0, false)?;
        let duration_label = control(window, w!("STATIC"), "Durée (min)", 0, 0, false)?;
        let duration = control(window, w!("EDIT"), "15", ES_NUMBER as u32 | ES_AUTOHSCROLL as u32, ID_DURATION, true)?;
        unsafe { SendMessageW(duration, EM_SETLIMITTEXT, 5, 0) };
        let watches = control(window, w!("BUTTON"), "Relances (0)…", 0, ID_WATCHES, false)?;
        unsafe { EnableWindow(watches, 0) };
        let started = Instant::now();
        let monitor = Monitor::start()?;
        let small_icon = icon::Icon::load(16);
        let large_icon = icon::Icon::load(32);
        unsafe {
            SendMessageW(window, WM_SETICON, ICON_SMALL as usize, small_icon.handle as isize);
            SendMessageW(window, WM_SETICON, ICON_BIG as usize, large_icon.handle as isize);
        }
        Ok(Self {
            window, traffic_label, traffic_status, session, interval_label, interval, overview, filter_label, filter, risk_filter,
            refresh, list, details, stop, block, unblock, status, duration_label, duration, watches, started, shown_uptime: Cell::new(u64::MAX),
            system_directory: ports::system_directory().unwrap_or_default(),
            monitor, monitor_lost: Cell::new(false),
            traffic: RefCell::new(TrafficHistory::default()),
            live_traffic: RefCell::new("Mesure du débit en cours…".into()),
            graph_pointer: Cell::new(None),
            tray: tray::Tray::new(window, small_icon.handle),
            _small_icon: small_icon,
            _large_icon: large_icon,
            list_error: RefCell::new(Some("Relevé des ports en cours…".into())),
            last_port_read: Cell::new(None),
            ports: RefCell::new(Vec::new()), rows: RefCell::new(Vec::new()),
            sort: Cell::new(Sort::default()), high_contrast: Cell::new(chart::high_contrast()),
            drawing_list: Cell::new(false),
            firewall: RefCell::new(None),
        })
    }

    fn layout(&self) {
        let mut client = RECT::default();
        unsafe { GetClientRect(self.window, &mut client) };
        let width = client.right;
        let height = client.bottom;
        let content = width - 32;
        let controls = [
            (self.traffic_label, 16, 14, 382, 22),
            (self.session, width - 230, 14, 214, 22),
            (self.interval_label, width - 378, 14, 51, 22),
            (self.interval, width - 325, 10, 83, 170),
            (self.traffic_status, 16, 36, content, 20),
            (self.overview, 16, 159, content, 20),
            (self.filter_label, 16, 190, 46, 20),
            (self.filter, 64, 183, width - 356, 28),
            (self.risk_filter, width - 276, 183, 143, 150),
            (self.refresh, width - 117, 182, 101, 30),
            (self.list, 16, 223, content, height - 409),
            (self.details, 16, height - 175, content, 101),
            (self.stop, 16, height - 65, 154, 31),
            (self.block, 180, height - 65, 152, 31),
            (self.unblock, 343, height - 65, 145, 31),
            (self.duration_label, 505, height - 57, 77, 22),
            (self.duration, 583, height - 63, 60, 26),
            (self.watches, 659, height - 65, 160, 31),
            (self.status, 16, height - 26, content, 21),
        ];
        for (control, x, y, w, h) in controls {
            unsafe { MoveWindow(control, x, y, w.max(1), h.max(1), 1) };
        }
        let fixed_width: i32 = COLUMNS.iter().filter(|(column, _, _)| *column != table_view::Column::Process)
            .map(|(_, _, width)| *width).sum();
        let process_width = (content - fixed_width - 24).max(140);
        unsafe { SendMessageW(self.list, LVM_SETCOLUMNWIDTH, 4, process_width as isize) };
        self.invalidate_chart();
    }

    fn chart_bounds(&self) -> RECT {
        let mut client = RECT::default();
        unsafe { GetClientRect(self.window, &mut client) };
        RECT { left: 16, top: 58, right: client.right - 16, bottom: 149 }
    }

    fn invalidate_chart(&self) {
        unsafe { InvalidateRect(self.window, &self.chart_bounds(), 0) };
    }

    fn selected(&self) -> Option<Entry> {
        let row = unsafe { SendMessageW(self.list, LVM_GETNEXTITEM, usize::MAX, LVNI_SELECTED as isize) };
        let index = self.rows.borrow().get(usize::try_from(row).ok()?)?.index;
        self.ports.borrow().get(index).cloned()
    }

    fn refresh(&self) {
        if !self.monitor.refresh() {
            set_text(self.status, "Le relevé automatique est indisponible.");
        }
    }

    fn set_interval(&self) {
        let index = unsafe { SendMessageW(self.interval, CB_GETCURSEL, 0, 0) };
        if let Some(&(milliseconds, _)) = INTERVALS.get(index as usize) {
            self.monitor.set_interval(milliseconds);
        }
    }

    fn set_live_traffic(&self, message: String) {
        self.live_traffic.replace(message);
        self.update_traffic_label();
    }

    fn update_traffic_label(&self) {
        let hovered = self.graph_pointer.get().map(|x| {
            let traffic = self.traffic.borrow();
            let Some(point) = chart::sample_at(&traffic, self.chart_bounds(), x) else {
                return "Aucun relevé à cet endroit.".into();
            };
            let age = format!("{:.1}", point.at.elapsed().as_secs_f64()).replace('.', ",");
            if let Some(rates) = point.rates {
                let span = format!("{:.2}", point.span.as_secs_f64()).replace('.', ",");
                format!("Il y a {age} s · Reçu {} · Envoyé {} · Mesure sur {span} s",
                    chart::rate_label(rates.received), chart::rate_label(rates.sent))
            } else {
                format!("Il y a {age} s · Échantillon indisponible")
            }
        });
        let live = self.live_traffic.borrow();
        set_text(self.traffic_status, hovered.as_deref().unwrap_or(&live));
    }

    fn pointer_moved(&self, coordinates: LPARAM) {
        let point = POINT { x: coordinates as i16 as i32, y: (coordinates >> 16) as i16 as i32 };
        let bounds = self.chart_bounds();
        let inside = point.x >= bounds.left && point.x < bounds.right
            && point.y >= bounds.top && point.y < bounds.bottom;
        let previous = self.graph_pointer.replace(inside.then_some(point.x));
        if inside && previous.is_none() {
            let mut request = TRACKMOUSEEVENT {
                cbSize: size_of::<TRACKMOUSEEVENT>() as u32,
                dwFlags: TME_LEAVE, hwndTrack: self.window, dwHoverTime: 0,
            };
            unsafe { TrackMouseEvent(&mut request) };
        }
        if previous != self.graph_pointer.get() {
            self.update_traffic_label();
            self.invalidate_chart();
        }
    }

    fn hide_to_tray(&self) {
        if self.tray.install() {
            unsafe { ShowWindow(self.window, SW_HIDE) };
        } else {
            unsafe { ShowWindow(self.window, SW_MINIMIZE) };
        }
    }

    fn restore_window(&self) {
        unsafe {
            ShowWindow(self.window, SW_RESTORE);
            SetForegroundWindow(self.window);
        }
    }

    fn tray_action(&self, action: u32) {
        match action {
            WM_LBUTTONUP => self.restore_window(),
            WM_RBUTTONUP => {
                let mut position = POINT::default();
                unsafe {
                    GetCursorPos(&mut position);
                    SetForegroundWindow(self.window);
                }
                let choice = popup_menu(self.window, position, &[(1, "Ouvrir OpenPort", true), (2, "Quitter OpenPort", true)]);
                unsafe { PostMessageW(self.window, WM_NULL, 0, 0) };
                match choice {
                    1 => self.restore_window(),
                    2 => { unsafe { DestroyWindow(self.window) }; }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn poll_monitor(&self) {
        let elapsed = self.started.elapsed();
        if elapsed.as_secs() != self.shown_uptime.replace(elapsed.as_secs()) {
            set_text(self.session, &format!("Surveillance depuis {}", duration_label(elapsed)));
        }
        self.update_watch_button();
        if self.monitor_lost.get() {
            return;
        }
        match self.monitor.poll() {
            Ok(Some(reading)) => self.apply_reading(reading),
            Ok(None) => {}
            Err(_) => {
                self.monitor_lost.set(true);
                self.list_error.replace(Some("Relevé automatique interrompu. Dernières lignes conservées.".into()));
                self.set_live_traffic("Mesure du débit interrompue.".into());
                self.populate(self.selected().map(|entry| entry.key()));
            }
        }
    }

    fn apply_reading(&self, reading: Reading) {
        let previous = self.selected().map(|entry| entry.key());
        let (at, ports, traffic) = reading.apply(&mut self.traffic.borrow_mut());
        let message = match traffic {
            TrafficState::WarmingUp => "Mesure du débit en cours…".into(),
            TrafficState::NoInterfaces => "Aucune interface réseau active à mesurer.".into(),
            TrafficState::Unavailable => "Compteurs des interfaces indisponibles.".into(),
            TrafficState::Measured { rates, interfaces } => format!(
                "Reçu {}    ·    Envoyé {}    ·    {} interface(s) active(s) hors bouclage",
                chart::rate_label(rates.received), chart::rate_label(rates.sent), interfaces
            ),
        };
        self.set_live_traffic(message);
        self.invalidate_chart();
        match ports {
            Ok(ports) => {
                let mut first_seen = BTreeMap::new();
                if self.list_error.borrow_mut().take().is_none() {
                    first_seen.extend(self.ports.borrow().iter().map(|entry| (entry.key(), entry.first_seen)));
                }
                let entries = ports.into_iter().map(|port| {
                    let key = (port.endpoint, port.owner.created);
                    let first_seen = first_seen.get(&key).copied().unwrap_or(at);
                    let assessment = risk::assess(&port, &self.system_directory);
                    Entry::new(port, first_seen, assessment)
                }).collect();
                self.ports.replace(entries);
                self.last_port_read.set(Some(at));
            }
            Err(error) => {
                self.list_error.replace(Some(format!("Relevé des ports indisponible. {error}")));
            }
        }
        self.populate(previous);
    }

    fn set_sort_header(&self) {
        for (index, (column, label, _)) in COLUMNS.into_iter().enumerate() {
            let sort = self.sort.get();
            let label = if sort.column == column {
                format!("{label} {}", if sort.descending { "↓" } else { "↑" })
            } else {
                label.into()
            };
            let mut label = wide(&label);
            let item = LVCOLUMNW { mask: LVCF_TEXT, pszText: label.as_mut_ptr(), ..Default::default() };
            unsafe { SendMessageW(self.list, LVM_SETCOLUMNW, index, &item as *const _ as isize) };
        }
    }

    fn sort_by(&self, index: usize) {
        if let Some(&(column, _, _)) = COLUMNS.get(index) {
            self.sort.set(self.sort.get().select(column));
            self.set_sort_header();
            self.populate(self.selected().map(|entry| entry.key()));
        }
    }

    fn populate(&self, previous: Option<PortKey>) {
        let query = window_text(self.filter).to_lowercase();
        let selected_level = unsafe { SendMessageW(self.risk_filter, CB_GETCURSEL, 0, 0) };
        let risk_filter = Risk::LEVELS.get(selected_level.saturating_sub(1) as usize).copied();
        let ports = self.ports.borrow();
        let at = self.last_port_read.get().unwrap_or_else(Instant::now);
        let rows = visible_rows(&ports, &query, risk_filter, self.sort.get(), at);
        let total = ports.len();
        let mut counts = [0; 3];
        for entry in ports.iter() {
            counts[entry.assessment.level as usize] += 1;
        }
        drop(ports);

        let old = self.rows.borrow();
        let rebuild = old.len() != rows.len() || old.iter().zip(&rows).any(|(a, b)| a.key != b.key);
        self.drawing_list.set(true);
        unsafe { SendMessageW(self.list, WM_SETREDRAW, 0, 0) };
        let top = if rebuild {
            let top = unsafe { SendMessageW(self.list, LVM_GETTOPINDEX, 0, 0) } as usize;
            let key = old.get(top).map(|row| row.key);
            unsafe { SendMessageW(self.list, LVM_DELETEALLITEMS, 0, 0) };
            key.and_then(|key| rows.iter().position(|row| row.key == key))
        } else {
            None
        };
        for (index, row) in rows.iter().enumerate() {
            for (column, value) in row.fields.iter().enumerate() {
                if !rebuild && *value == old[index].fields[column] {
                    continue;
                }
                let mut value = wide(value);
                let item = LVITEMW {
                    mask: LVIF_TEXT, iItem: index as i32, iSubItem: column as i32,
                    pszText: value.as_mut_ptr(), ..Default::default()
                };
                let message = if rebuild && column == 0 { LVM_INSERTITEMW } else { LVM_SETITEMTEXTW };
                unsafe { SendMessageW(self.list, message, index, &item as *const _ as isize) };
            }
        }
        if rebuild && let Some(index) = rows.iter().position(|row| Some(row.key) == previous) {
            let item = LVITEMW {
                state: LVIS_SELECTED | LVIS_FOCUSED, stateMask: LVIS_SELECTED | LVIS_FOCUSED, ..Default::default()
            };
            unsafe { SendMessageW(self.list, LVM_SETITEMSTATE, index, &item as *const _ as isize) };
        }
        if let Some(top) = top.filter(|top| *top != 0) {
            let mut rect = RECT { left: LVIR_BOUNDS as i32, ..Default::default() };
            unsafe {
                if SendMessageW(self.list, LVM_GETITEMRECT, 0, &mut rect as *mut _ as isize) != 0 {
                    let pixels = (rect.bottom - rect.top).saturating_mul(top as i32);
                    SendMessageW(self.list, LVM_SCROLL, 0, pixels as isize);
                }
            }
        }
        let shown = rows.len();
        drop(old);
        self.rows.replace(rows);
        self.drawing_list.set(false);
        unsafe {
            SendMessageW(self.list, WM_SETREDRAW, 1, 0);
            InvalidateRect(self.list, null(), 1);
        }

        let overview = self.list_error.borrow().clone().unwrap_or_else(|| format!(
            "{} à risque    ·    {} inconnus    ·    {} normaux    ·    {shown} / {total} affichés",
            counts[Risk::Elevated as usize], counts[Risk::Unknown as usize], counts[Risk::Normal as usize]
        ));
        set_text(self.overview, &overview);
        self.update_selection();
    }

    fn paint_row(&self, drawing: &mut NMLVCUSTOMDRAW) -> LRESULT {
        match drawing.nmcd.dwDrawStage {
            CDDS_PREPAINT => CDRF_NOTIFYITEMDRAW as isize,
            CDDS_ITEMPREPAINT => CDRF_NOTIFYSUBITEMDRAW as isize,
            stage if stage == CDDS_ITEMPREPAINT | CDDS_SUBITEM && drawing.iSubItem == 0
                && drawing.nmcd.uItemState & CDIS_SELECTED == 0 && !self.high_contrast.get() =>
            {
                if let Some(row) = self.rows.borrow().get(drawing.nmcd.dwItemSpec) {
                    drawing.clrText = match row.level {
                        Risk::Normal => chart::rgb(16, 99, 73),
                        Risk::Unknown => chart::rgb(103, 77, 18),
                        Risk::Elevated => chart::rgb(165, 40, 43),
                    };
                }
                CDRF_NEWFONT as isize
            }
            _ => CDRF_DODEFAULT as isize,
        }
    }

    fn typed_port(&self) -> Option<u16> {
        window_text(self.filter).trim().parse::<u16>().ok().filter(|port| *port != 0)
    }

    fn update_selection(&self) {
        let selected = self.selected();
        let current = self.list_error.borrow().is_none();
        let available = self.firewall.borrow().is_none();
        let has_selection = current && selected.is_some();
        unsafe {
            EnableWindow(self.stop, i32::from(current && selected.as_ref().is_some_and(|entry| entry.port.can_stop())));
            EnableWindow(self.block, i32::from(has_selection));
            EnableWindow(self.unblock, i32::from(available && (has_selection || (selected.is_none() && self.typed_port().is_some()))));
        }
        let Some(entry) = selected else {
            let prompt = if self.typed_port().is_some() {
                "Sélectionne une ligne ou clique sur « Retirer le blocage » pour le numéro saisi."
            } else {
                "Sélectionne un port pour voir son niveau, son processus et son activité."
            };
            set_text(self.details, prompt);
            return;
        };
        let port = entry.port;
        let endpoint = port.endpoint;
        let address = if endpoint.is_local() {
            "Ce PC uniquement"
        } else if endpoint.address.is_unspecified() {
            "Toutes les interfaces de cette famille IP"
        } else {
            "Adresse d’une interface réseau"
        };
        let age = port.owner.age().map_or_else(
            || "Démarrage du processus inconnu".into(),
            |age| format!("Processus actif depuis {}", duration_label(age)),
        );
        let observation = if current {
            format!("Vu depuis {}", duration_label(entry.first_seen.elapsed()))
        } else {
            "Dernier relevé conservé".into()
        };
        let activity = match endpoint.protocol {
            Protocol::Tcp if current => format!("{} connexion(s) TCP établie(s) au relevé", port.established),
            Protocol::Tcp => "Connexions TCP indisponibles".into(),
            Protocol::Udp => "UDP · activité par port indisponible".into(),
        };
        let mut detail = format!(
            "{} · {} · {address}\r\n{}\r\n{observation} · {age} · {activity}",
            entry.assessment.level.label(), endpoint.label(), entry.assessment.reason
        );
        if let Some(usage) = usual_use(endpoint) {
            detail.push_str(&format!("\r\nUsage courant du numéro · {usage}"));
        }
        if !port.owner.path.is_empty() {
            detail.push_str(&format!("\r\n{}", port.owner.path));
        }
        if !port.owner.services.is_empty() {
            detail.push_str(&format!("\r\nServices de ce processus · {}", port.owner.services.join(", ")));
        }
        if window_text(self.details) != detail {
            set_text(self.details, &detail);
        }
    }

    fn ask_stop(&self, port: &Port, consequence: &str) -> bool {
        let message = format!("Terminer {} (PID {}) ?\n{consequence}", port.owner.name, port.endpoint.pid);
        let answer = unsafe {
            MessageBoxW(
                self.window, wide(&message).as_ptr(), w!("OpenPort"),
                MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION,
            )
        };
        answer == IDYES
    }

    fn stop_port(&self, port: &Port) -> bool {
        let result = ports::stop(port);
        self.refresh();
        match result {
            Ok(()) => {
                set_text(self.status, &format!("Processus terminé. {}", port.owner.name));
                true
            }
            Err(error) => {
                set_text(self.status, &format!("Arrêt non confirmé. {error}"));
                false
            }
        }
    }

    fn stop_selected(&self) {
        let Some(port) = self.available_port().filter(Port::can_stop) else { return };
        if self.ask_stop(&port, "Ses tâches et ses connexions seront interrompues.") {
            self.stop_port(&port);
        }
    }

    fn available_port(&self) -> Option<Port> {
        if self.list_error.borrow().is_some() {
            return None;
        }
        self.selected().map(|entry| entry.port)
    }

    fn minutes(&self) -> Option<u16> {
        window_text(self.duration).trim().parse::<u16>().ok().filter(|minutes| *minutes != 0)
    }

    fn watch_relaunch(&self, minutes: Option<u16>) {
        let Some(port) = self.available_port() else { return };
        if let Err(error) = relaunch::prepare(&port, &self.system_directory) {
            set_text(self.status, &error.to_string());
            return;
        }
        let period = minutes.map_or_else(|| "jusqu’à la fermeture complète d’OpenPort".into(), |minutes| format!("pendant {minutes} min"));
        let message = format!("Les nouvelles instances du même fichier seront arrêtées {period}.");
        if self.ask_stop(&port, &message) && self.stop_port(&port) {
            let delay = minutes.map(|minutes| Duration::from_secs(u64::from(minutes) * 60));
            let label = format!("Relances surveillées {period} · {}", port.owner.name);
            self.monitor.watch(relaunch::watch(port, delay));
            self.update_watch_button();
            set_text(self.status, &label);
        }
    }

    fn action_menu(&self, position: POINT) {
        let selected = self.available_port();
        let can_stop = selected.as_ref().is_some_and(Port::can_stop);
        let can_watch = !self.monitor_lost.get() && selected.as_ref()
            .is_some_and(|port| relaunch::can_watch(port, &self.system_directory));
        let can_block = selected.is_some() && self.firewall.borrow().is_none();
        let minutes = self.minutes();
        let block_label = minutes.map_or_else(|| "Bloquer temporairement".into(), |minutes| format!("Bloquer le port pendant {minutes} min"));
        let both_label = minutes.map_or_else(|| "Terminer et bloquer temporairement".into(), |minutes| format!("Terminer et bloquer le port pendant {minutes} min"));
        let watch_label = minutes.map_or_else(|| "Terminer et surveiller temporairement les relances".into(), |minutes| format!("Terminer et surveiller les relances pendant {minutes} min"));

        let choice = popup_menu(self.window, position, &[
            (1, "Terminer le processus…", can_stop),
            (2, "Bloquer le port", can_block),
            (3, &block_label, can_block && minutes.is_some()),
            (4, "Terminer et bloquer le port…", can_stop && can_block),
            (5, &both_label, can_stop && can_block && minutes.is_some()),
            (6, "Terminer et surveiller les relances jusqu’à Quitter…", can_watch),
            (7, &watch_label, can_watch && minutes.is_some()),
        ]);
        match choice {
            1 => self.stop_selected(),
            2 => self.change_firewall(FirewallAction::Block, false),
            3 | 5 => {
                if let Some(minutes) = minutes {
                    self.change_firewall(FirewallAction::Timed(minutes), choice == 5);
                }
            }
            4 => self.change_firewall(FirewallAction::Block, true),
            6 => self.watch_relaunch(None),
            7 => {
                if minutes.is_some() { self.watch_relaunch(minutes); }
            }
            _ => {}
        }
    }

    fn watches_menu(&self) {
        let watches = self.monitor.active_watches();
        let labels: Vec<_> = watches.iter().map(|watch| {
            let duration = watch.until.map_or_else(|| "jusqu’à Quitter".into(), |end| duration_label(end.saturating_duration_since(Instant::now())));
            format!("Autoriser {} · {duration}", watch.image)
        }).collect();
        let items: Vec<_> = labels.iter().enumerate().map(|(index, label)| (index + 1, label.as_str(), true)).collect();
        let index = popup_menu(self.window, under(self.watches), &items);
        if let Some(watch) = index.checked_sub(1).and_then(|index| watches.get(index as usize)) {
            self.monitor.stop_watching(&watch.image);
            self.update_watch_button();
            set_text(self.status, &format!("Relances autorisées · {}", watch.name));
        }
    }

    fn update_watch_button(&self) {
        let count = self.monitor.active_watches().len();
        let text = format!("Relances ({count})…");
        if window_text(self.watches) != text {
            set_text(self.watches, &text);
            unsafe { EnableWindow(self.watches, i32::from(count != 0)) };
        }
    }

    fn change_firewall(&self, action: FirewallAction, stop_after: bool) {
        if self.firewall.borrow().is_some() {
            return;
        }
        let selected = self.available_port();
        let (port, protocol) = if let Some(selected) = selected.as_ref() {
            (selected.endpoint.port, selected.endpoint.protocol)
        } else if matches!(action, FirewallAction::Remove) && self.selected().is_none() {
            let Some(port) = self.typed_port() else { return };
            let Some(protocol) = self.choose_protocol(port) else { return };
            (port, protocol)
        } else {
            return;
        };
        let stop_after = if stop_after {
            let Some(process) = selected.filter(Port::can_stop) else { return };
            let label = match action {
                FirewallAction::Timed(minutes) => format!("Windows bloquera d’abord le trafic entrant sur {port}/{} pendant {minutes} min.", protocol.name()),
                _ => format!("Windows bloquera d’abord le trafic entrant sur {port}/{}.", protocol.name()),
            };
            if !self.ask_stop(&process, &label) {
                return;
            }
            Some(process)
        } else {
            None
        };
        match firewall::Job::start(self.window, port, protocol, action) {
            Ok(job) => {
                self.firewall.replace(Some((job, stop_after)));
                self.update_selection();
                set_text(self.status, &format!("Pare-feu Windows · {port}/{}", protocol.name()));
                unsafe { SetTimer(self.window, FIREWALL_TIMER, 250, None) };
            }
            Err(error) if error.raw_os_error() == Some(ERROR_CANCELLED as i32) => {
                set_text(self.status, "Modification du pare-feu annulée.");
            }
            Err(error) => set_text(self.status, &format!("Pare-feu inaccessible. {error}")),
        }
    }

    fn choose_protocol(&self, port: u16) -> Option<Protocol> {
        let tcp = format!("{port}/TCP");
        let udp = format!("{port}/UDP");
        match popup_menu(self.window, under(self.unblock), &[(1, &tcp, true), (2, &udp, true)]) {
            1 => Some(Protocol::Tcp),
            2 => Some(Protocol::Udp),
            _ => None,
        }
    }

    fn poll_firewall(&self) {
        let mut pending = self.firewall.borrow_mut();
        let Some(result) = pending.as_ref().and_then(|(job, _)| job.result()) else { return };
        let (job, process) = pending.take().unwrap();
        drop(pending);
        unsafe { KillTimer(self.window, FIREWALL_TIMER) };
        let endpoint = format!("{}/{}", job.port, job.protocol.name());
        let message = match result {
            Ok(()) => {
                let firewall = match job.action {
                    FirewallAction::Block => format!("Trafic entrant bloqué · {endpoint}."),
                    FirewallAction::Timed(minutes) => format!("Trafic entrant bloqué pendant {minutes} min · {endpoint}."),
                    FirewallAction::Remove => format!("Blocages OpenPort retirés · {endpoint}."),
                };
                if let Some(process) = process {
                    let stop = match ports::stop(&process) {
                        Ok(()) => format!("Processus terminé · {}.", process.owner.name),
                        Err(error) => format!("Arrêt non confirmé. {error}"),
                    };
                    self.refresh();
                    format!("{firewall} {stop}")
                } else {
                    firewall
                }
            }
            Err(error) => error.to_string(),
        };
        set_text(self.status, &message);
        self.update_selection();
    }

}

fn control(window: HWND, class: PCWSTR, text: &str, style: u32, id: u16, edge: bool) -> io::Result<HWND> {
    let handle = unsafe {
        CreateWindowExW(
            if edge { WS_EX_CLIENTEDGE } else { 0 },
            class,
            wide(text).as_ptr(),
            WS_VISIBLE | WS_CHILD | style | if id != 0 || edge { WS_TABSTOP } else { 0 },
            0, 0, 0, 0, window, usize::from(id) as HMENU, GetModuleHandleW(null()), null(),
        )
    };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    unsafe { SendMessageW(handle, WM_SETFONT, GetStockObject(DEFAULT_GUI_FONT) as usize, 1) };
    Ok(handle)
}

fn set_text(control: HWND, text: &str) {
    unsafe { SetWindowTextW(control, wide(text).as_ptr()) };
}

fn window_text(control: HWND) -> String {
    let length = unsafe { GetWindowTextLengthW(control) } as usize;
    let mut text = vec![0; length + 1];
    let length = unsafe { GetWindowTextW(control, text.as_mut_ptr(), text.len() as i32) } as usize;
    String::from_utf16_lossy(&text[..length])
}

fn under(control: HWND) -> POINT {
    let mut bounds = RECT::default();
    unsafe { GetWindowRect(control, &mut bounds) };
    POINT { x: bounds.left, y: bounds.bottom }
}

fn popup_menu(window: HWND, at: POINT, items: &[(usize, &str, bool)]) -> u32 {
    let menu = unsafe { CreatePopupMenu() };
    if menu.is_null() {
        return 0;
    }
    unsafe {
        for &(id, label, enabled) in items {
            let flags = if enabled { MF_STRING } else { MF_STRING | MF_GRAYED };
            AppendMenuW(menu, flags, id, wide(label).as_ptr());
        }
        let result = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, at.x, at.y, 0, window, null());
        DestroyMenu(menu);
        result as u32
    }
}

unsafe extern "system" fn handle_message(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // The box in run() outlives the message loop and owns this window's state.
    let app = unsafe { (GetWindowLongPtrW(window, GWLP_USERDATA) as *const App).as_ref() };
    if message == WM_DESTROY {
        if let Some(app) = app {
            app.tray.remove();
            app.monitor.clear_watches();
        }
        unsafe { PostQuitMessage(0) };
        return 0;
    }
    if message == WM_GETMINMAXINFO {
        let limits = unsafe { &mut *(lparam as *mut MINMAXINFO) };
        limits.ptMinTrackSize.x = 900;
        limits.ptMinTrackSize.y = 590;
        return 0;
    }
    if let Some(app) = app {
        match message {
            WM_CLOSE => { app.hide_to_tray(); return 0; }
            WM_SYSCOMMAND if wparam == EXIT_MENU => {
                unsafe { DestroyWindow(window) };
                return 0;
            }
            tray::TRAY_MESSAGE => { app.tray_action(lparam as u32); return 0; }
            id if id == app.tray.taskbar_created && id != 0 => {
                if !app.tray.reinstall() && unsafe { IsWindowVisible(window) } == 0 {
                    app.restore_window();
                }
                return 0;
            }
            WM_SIZE if wparam != SIZE_MINIMIZED as usize => app.layout(),
            WM_SETTINGCHANGE => {
                app.high_contrast.set(chart::high_contrast());
                app.invalidate_chart();
                unsafe { InvalidateRect(app.list, null(), 1) };
            }
            WM_COMMAND => {
                let id = wparam as u16;
                let notification = (wparam >> 16) as u16;
                match id {
                    ID_FILTER if notification == EN_CHANGE as u16 => {
                        app.populate(app.selected().map(|entry| entry.key()));
                    }
                    ID_RISK if notification == CBN_SELCHANGE as u16 => {
                        app.populate(app.selected().map(|entry| entry.key()));
                    }
                    ID_INTERVAL if notification == CBN_SELCHANGE as u16 => app.set_interval(),
                    ID_REFRESH => app.refresh(),
                    ID_STOP => app.stop_selected(),
                    ID_BLOCK => app.action_menu(under(app.block)),
                    ID_UNBLOCK => app.change_firewall(FirewallAction::Remove, false),
                    ID_WATCHES => app.watches_menu(),
                    _ => {}
                }
            }
            WM_NOTIFY if lparam != 0 && !app.drawing_list.get() => {
                let note = unsafe { &*(lparam as *const NMHDR) };
                if note.hwndFrom == app.list {
                    match note.code {
                        LVN_ITEMCHANGED => app.update_selection(),
                        LVN_COLUMNCLICK => {
                            let click = unsafe { &*(lparam as *const NMLISTVIEW) };
                            app.sort_by(click.iSubItem as usize);
                        }
                        NM_RCLICK => {
                            let click = unsafe { &*(lparam as *const NMITEMACTIVATE) };
                            if let Ok(index) = usize::try_from(click.iItem) {
                                let selection = LVITEMW {
                                    state: LVIS_SELECTED | LVIS_FOCUSED, stateMask: LVIS_SELECTED | LVIS_FOCUSED,
                                    ..Default::default()
                                };
                                let mut position = POINT::default();
                                unsafe {
                                    SendMessageW(app.list, LVM_SETITEMSTATE, index, &selection as *const _ as isize);
                                    GetCursorPos(&mut position);
                                }
                                app.action_menu(position);
                            }
                        }
                        NM_CUSTOMDRAW => return app.paint_row(unsafe { &mut *(lparam as *mut NMLVCUSTOMDRAW) }),
                        _ => {}
                    }
                }
            }
            WM_TIMER if wparam == FIREWALL_TIMER => app.poll_firewall(),
            WM_TIMER if wparam == MONITOR_TIMER => app.poll_monitor(),
            WM_MOUSEMOVE => app.pointer_moved(lparam),
            WM_MOUSELEAVE => {
                app.graph_pointer.set(None);
                app.update_traffic_label();
                app.invalidate_chart();
            }
            WM_PAINT => {
                let mut paint = PAINTSTRUCT::default();
                let dc = unsafe { BeginPaint(window, &mut paint) };
                chart::paint(dc, app.chart_bounds(), &app.traffic.borrow(), app.graph_pointer.get());
                unsafe { EndPaint(window, &paint) };
                return 0;
            }
            _ => {}
        }
    }
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

fn create_window() -> io::Result<HWND> {
    unsafe {
        let setup = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES,
        };
        if InitCommonControlsEx(&setup) == 0 {
            return Err(io::Error::other("La liste Windows n’a pas pu être initialisée."));
        }
        let instance = GetModuleHandleW(null());
        let class = w!("OpenPortWindow");
        let definition = WNDCLASSW {
            lpfnWndProc: Some(handle_message),
            hInstance: instance,
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hIcon: LoadIconW(null_mut(), IDI_APPLICATION),
            hbrBackground: (COLOR_BTNFACE + 1) as HBRUSH,
            lpszClassName: class,
            ..Default::default()
        };
        if RegisterClassW(&definition) == 0 {
            return Err(io::Error::last_os_error());
        }
        let window = CreateWindowExW(
            0, class, w!("OpenPort — Surveillance réseau"), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT, CW_USEDEFAULT, 1100, 720, null_mut(), null_mut(), instance, null(),
        );
        if window.is_null() { Err(io::Error::last_os_error()) } else { Ok(window) }
    }
}

fn run() -> io::Result<()> {
    let window = create_window()?;
    unsafe {
        let app = Box::new(App::new(window).map_err(|error| {
            io::Error::other(format!("Création des contrôles impossible. {error}"))
        })?);
        SetWindowLongPtrW(window, GWLP_USERDATA, &*app as *const App as isize);
        app.layout();
        app.set_sort_header();
        app.populate(None);
        app.poll_monitor();
        if SetTimer(window, MONITOR_TIMER, 100, None) == 0 {
            return Err(io::Error::last_os_error());
        }
        ShowWindow(window, SW_SHOW);
        app.tray.install();
        let system_menu = GetSystemMenu(window, 0);
        if !system_menu.is_null() {
            AppendMenuW(system_menu, MF_SEPARATOR, 0, null());
            AppendMenuW(system_menu, MF_STRING, EXIT_MENU, w!("Quitter OpenPort"));
        }
        SetFocus(app.filter);
        let mut message = MSG::default();
        loop {
            match GetMessageW(&mut message, null_mut(), 0, 0) {
                0 => return Ok(()),
                -1 => return Err(io::Error::last_os_error()),
                _ if IsDialogMessageW(window, &message) == 0 => {
                    TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
                _ => {}
            }
        }
    }
}

fn main() {
    if let Err(error) = run() {
        let error = wide(&error.to_string());
        unsafe { MessageBoxW(null_mut(), error.as_ptr(), w!("OpenPort"), MB_ICONERROR) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn native_list_tracks_a_connection_and_keeps_selection_when_sorted() {
        let listener_a = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let listener_b = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let a = listener_a.local_addr().unwrap();
        let b = listener_b.local_addr().unwrap();
        let client = TcpStream::connect(a).unwrap();
        let (server, _) = listener_a.accept().unwrap();

        let window = create_window().unwrap();
        let app = Box::new(App::new(window).unwrap());
        assert!(app._small_icon.custom && app._large_icon.custom);
        unsafe { SetWindowLongPtrW(window, GWLP_USERDATA, &*app as *const App as isize) };
        app.layout();
        app.set_sort_header();
        set_text(app.filter, &format!("tcp {}", std::process::id()));

        let deadline = Instant::now() + Duration::from_secs(5);
        while app.list_error.borrow().is_some() && Instant::now() < deadline {
            unsafe { SendMessageW(window, WM_TIMER, MONITOR_TIMER, 0) };
            thread::sleep(Duration::from_millis(25));
        }
        assert!(app.list_error.borrow().is_none());
        assert!(!app.traffic.borrow().points.is_empty());
        let chart = app.chart_bounds();
        let pointer = ((chart.top + 20) as isize) << 16 | (chart.right - 88) as isize;
        unsafe { SendMessageW(window, WM_MOUSEMOVE, 0, pointer) };
        assert!(window_text(app.traffic_status).starts_with("Il y a "));
        unsafe { SendMessageW(window, WM_MOUSELEAVE, 0, 0) };
        assert_eq!(window_text(app.traffic_status), *app.live_traffic.borrow());
        let index_of = |port| app.rows.borrow().iter().position(|row| row.key.0.port == port).unwrap();
        let row_a = index_of(a.port());
        assert_eq!(app.rows.borrow()[row_a].fields[7], "1");
        assert_eq!(app.rows.borrow()[index_of(b.port())].fields[7], "0");
        let selection = LVITEMW { state: LVIS_SELECTED, stateMask: LVIS_SELECTED, ..Default::default() };
        unsafe { SendMessageW(app.list, LVM_SETITEMSTATE, row_a, &selection as *const _ as isize) };

        let click = NMLISTVIEW {
            hdr: NMHDR { hwndFrom: app.list, code: LVN_COLUMNCLICK, ..Default::default() },
            iSubItem: 1, ..Default::default()
        };
        unsafe { SendMessageW(window, WM_NOTIFY, 0, &click as *const _ as isize) };
        assert_eq!(index_of(a.port()) < index_of(b.port()), a.port() < b.port());
        assert_eq!(app.selected().unwrap().port.endpoint.port, a.port());
        unsafe { SendMessageW(window, WM_NOTIFY, 0, &click as *const _ as isize) };
        assert_eq!(index_of(a.port()) < index_of(b.port()), a.port() > b.port());
        assert!(window_text(app.details).contains("1 connexion(s) TCP établie(s)"));
        assert!(window_text(app.details).contains("Processus actif depuis"));

        drop((client, server));
        unsafe {
            SendMessageW(app.interval, CB_SETCURSEL, 0, 0);
            SendMessageW(window, WM_COMMAND, usize::from(ID_INTERVAL) | ((CBN_SELCHANGE as usize) << 16), app.interval as isize);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while app.selected().unwrap().port.established != 0 && Instant::now() < deadline {
            unsafe { SendMessageW(window, WM_TIMER, MONITOR_TIMER, 0) };
            thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(app.selected().unwrap().port.established, 0);
        assert_eq!(app.selected().unwrap().port.endpoint.port, a.port());
        assert!(window_text(app.details).contains("0 connexion(s) TCP établie(s)"));

        unsafe {
            SendMessageW(app.risk_filter, CB_SETCURSEL, 3, 0);
            SendMessageW(window, WM_COMMAND, usize::from(ID_RISK) | ((CBN_SELCHANGE as usize) << 16), app.risk_filter as isize);
        }
        assert!(app.rows.borrow().iter().all(|row| row.level == Risk::Elevated));
        assert!(app.selected().is_none());
        unsafe { DestroyWindow(window) };
    }
}
