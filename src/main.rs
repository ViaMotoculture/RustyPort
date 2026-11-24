#![windows_subsystem = "windows"]

mod archive;
mod chart;
mod duration_dialog;
mod elevation;
mod firewall;
mod icon;
mod level_preferences;
mod monitor;
mod port_traffic;
mod ports;
mod risk;
mod relaunch;
mod stop_job;
mod table_view;
mod tray;
mod ui;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::io;
use std::mem::size_of;
use std::ptr::{null, null_mut};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Controls::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, GetCapture, GetKeyState, IsWindowEnabled, ReleaseCapture, SetCapture, SetFocus,
    TME_LEAVE, TRACKMOUSEEVENT, TrackMouseEvent, VK_A, VK_CONTROL,
};
use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass, ShellExecuteW};
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::{PCWSTR, w};

use firewall::Action as FirewallAction;
use level_preferences::LevelPreferences;
use monitor::{DEFAULT_INTERVAL_MS, INTERVALS, Monitor, Point, PortTrafficState, Reading, TrafficHistory, TrafficState};
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
const ID_LEVELS: u16 = 108;
const ID_PAUSE_GRAPH: u16 = 109;
const ID_PORT_GRAPH: u16 = 110;
const ID_SAVE_ARCHIVE: u16 = 112;
const ID_SAVE_RANGE: u16 = 113;
const ID_CLEAR_ARCHIVE: u16 = 114;
const ID_ARCHIVE_ENABLED: u16 = 115;
const ID_ARCHIVE_PANEL: u16 = 116;
const ID_GRAPH_METRIC: u16 = 117;
const MENU_LEVEL_AUTO: u32 = 12;
const MENU_LEVEL_NORMAL: u32 = 13;
const MENU_LEVEL_ELEVATED: u32 = 15;
const TBM_GETPOS: u32 = WM_USER;
const SS_ICON: u32 = 0x0003;
const SS_CENTERIMAGE: u32 = 0x0200;
const SS_ENDELLIPSIS: u32 = 0x4000;
const EXIT_MENU: usize = 450;
const FIREWALL_TIMER: usize = 1;
const MONITOR_TIMER: usize = 2;
// Keep the singleton identifiers shared with existing OpenPort executables.
const SINGLETON_CLASS: PCWSTR = w!("OpenPortWindow");
const SINGLETON_MUTEX: PCWSTR = w!("Local\\RustyPort.OpenPort");
const SINGLETON_PROPERTY: PCWSTR = w!("RustyPort.OpenPort");

struct PendingStop {
    job: stop_job::Job,
    name: String,
    prefix: String,
}

enum BulkPhase {
    Local(Receiver<stop_job::LocalResult>),
    Elevated(stop_job::BatchJob, usize),
}

struct PendingBulk {
    phase: BulkPhase,
    total: usize,
    prefix: String,
}

struct App {
    window: HWND,
    theme: RefCell<ui::Theme>,
    brand_icon: HWND,
    brand: HWND,
    traffic_label: HWND,
    traffic_status: HWND,
    graph_detail: HWND,
    pause_graph: HWND,
    port_graph: HWND,
    graph_metric: HWND,
    timeline: HWND,
    timeline_label: HWND,
    archive_panel: HWND,
    save_archive: HWND,
    save_range: HWND,
    clear_archive: HWND,
    archive_toggle: HWND,
    session: HWND,
    interval_label: HWND,
    interval: HWND,
    overview: HWND,
    levels: HWND,
    filter_label: HWND,
    filter: HWND,
    risk_filter: HWND,
    refresh: HWND,
    list: HWND,
    details_label: HWND,
    details: HWND,
    stop: HWND,
    block: HWND,
    unblock: HWND,
    status: HWND,
    watches: HWND,
    started: Instant,
    shown_uptime: Cell<u64>,
    system_directory: String,
    monitor: Monitor,
    monitor_lost: Cell<bool>,
    port_traffic: Cell<PortTrafficState>,
    traffic: RefCell<TrafficHistory>,
    archive: RefCell<Option<archive::Archive>>,
    archive_error: Cell<bool>,
    archive_enabled: Cell<bool>,
    archive_open: Cell<bool>,
    layout_width: Cell<i32>,
    pending_export: RefCell<Option<Receiver<io::Result<usize>>>>,
    paused: RefCell<Option<VecDeque<Point>>>,
    graph_series: RefCell<Option<Vec<chart::Series>>>,
    live_traffic: RefCell<String>,
    graph_pointer: Cell<Option<(i32, i32)>>,
    tray: tray::Tray,
    _small_icon: icon::Icon,
    _large_icon: icon::Icon,
    risk_markers: Option<icon::RiskMarkers>,
    list_error: RefCell<Option<String>>,
    last_port_read: Cell<Option<Instant>>,
    level_preferences: RefCell<io::Result<LevelPreferences>>,
    ports: RefCell<Vec<Entry>>,
    rows: RefCell<Vec<Row>>,
    sort: Cell<Sort>,
    drag: Cell<Option<(PortKey, PortKey)>>,
    drawing_list: Cell<bool>,
    firewall: RefCell<Option<(firewall::Job, Vec<Port>)>>,
    pending_stop: RefCell<Option<PendingStop>>,
    pending_bulk: RefCell<Option<PendingBulk>>,
}

impl App {
    fn new(window: HWND) -> io::Result<Self> {
        let label = |text| control(window, w!("STATIC"), text, SS_CENTERIMAGE | SS_ENDELLIPSIS, 0, false);
        let brand_icon = control(window, w!("STATIC"), "", SS_ICON | SS_CENTERIMAGE, 0, false)?;
        let brand = label("RustyPort")?;
        let session = label("")?;
        let interval_label = label("Cadence")?;
        let interval = control(window, w!("COMBOBOX"), "", CBS_DROPDOWNLIST as u32 | WS_VSCROLL, ID_INTERVAL, false)?;
        for (_, label) in INTERVALS {
            unsafe { SendMessageW(interval, CB_ADDSTRING, 0, wide(label).as_ptr() as isize) };
        }
        let default_interval = INTERVALS.iter().position(|(milliseconds, _)| *milliseconds == DEFAULT_INTERVAL_MS).unwrap();
        unsafe { SendMessageW(interval, CB_SETCURSEL, default_interval, 0) };
        let refresh = control(window, w!("BUTTON"), "Actualiser", 0, ID_REFRESH, false)?;
        let traffic_label = label("Débit des interfaces · 60 s")?;
        let traffic_status = label("Mesure du débit en cours…")?;
        let graph_detail = label("")?;
        let port_graph = control(window, w!("BUTTON"), "Ports sélectionnés", BS_AUTOCHECKBOX as u32, ID_PORT_GRAPH, false)?;
        let graph_metric = control(window, w!("COMBOBOX"), "", CBS_DROPDOWNLIST as u32, ID_GRAPH_METRIC, false)?;
        unsafe {
            SendMessageW(graph_metric, CB_ADDSTRING, 0, w!("Débit par port") as isize);
            SendMessageW(graph_metric, CB_ADDSTRING, 0, w!("Nouvelles connexions") as isize);
            SendMessageW(graph_metric, CB_ADDSTRING, 0, w!("Connexions établies") as isize);
            SendMessageW(graph_metric, CB_SETCURSEL, 0, 0);
            ShowWindow(graph_metric, SW_HIDE);
        }
        let pause_graph = control(window, w!("BUTTON"), "Pause", 0, ID_PAUSE_GRAPH, false)?;
        let archive_panel = control(window, w!("BUTTON"), "Historique + · 0 o", 0, ID_ARCHIVE_PANEL, false)?;
        let timeline_label = label("Parcourir les relevés")?;
        let timeline = control(window, TRACKBAR_CLASSW, "", TBS_NOTICKS, 111, false)?;
        let archive_toggle = control(window, w!("BUTTON"), "Archivage sur disque", BS_AUTOCHECKBOX as u32,
            ID_ARCHIVE_ENABLED, false)?;
        let save_archive = control(window, w!("BUTTON"), "Sauvegarder tout…", 0, ID_SAVE_ARCHIVE, false)?;
        let save_range = control(window, w!("BUTTON"), "Sauvegarder une période…", 0, ID_SAVE_RANGE, false)?;
        let clear_archive = control(window, w!("BUTTON"), "Nettoyer…", 0, ID_CLEAR_ARCHIVE, false)?;
        unsafe {
            SendMessageW(timeline, TBM_SETRANGE, 1, 0);
            EnableWindow(timeline, 0);
        }
        let overview = label("")?;
        let filter_label = label("&Filtrer")?;
        let filter = control(window, w!("EDIT"), "", ES_AUTOHSCROLL as u32, ID_FILTER, true)?;
        unsafe {
            SendMessageW(filter, EM_SETCUEBANNER, 1, w!("Port, processus, adresse…") as isize);
        }
        let risk_filter = control(window, w!("COMBOBOX"), "", CBS_DROPDOWNLIST as u32 | WS_VSCROLL, ID_RISK, false)?;
        for label in std::iter::once("Tous les niveaux").chain(Risk::LEVELS.map(Risk::label)) {
            unsafe { SendMessageW(risk_filter, CB_ADDSTRING, 0, wide(label).as_ptr() as isize) };
        }
        unsafe { SendMessageW(risk_filter, CB_SETCURSEL, 0, 0) };
        let levels = control(window, w!("BUTTON"), "Critères de niveau…", 0, ID_LEVELS, false)?;
        let list = control(window, WC_LISTVIEWW, "",
            LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SHAREIMAGELISTS, 0, true)?;
        unsafe {
            SendMessageW(list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
                (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP) as isize);
        }
        for (index, (column, label, width)) in COLUMNS.into_iter().enumerate() {
            use table_view::Column;
            let mut label = wide(label);
            let width = match column {
                Column::Address => 141,
                Column::Process => width,
                Column::Protocol => 67,
                Column::Seen => 80,
                Column::RecentTcp => 124,
                _ => width - 6,
            };
            let column = LVCOLUMNW { mask: LVCF_TEXT | LVCF_WIDTH, cx: width, pszText: label.as_mut_ptr(), ..Default::default() };
            unsafe { SendMessageW(list, LVM_INSERTCOLUMNW, index, &column as *const _ as isize) };
        }
        let details_label = label("Détail de la sélection")?;
        let details = control(
            window, w!("EDIT"), "", (ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL) as u32 | WS_VSCROLL, 0, true,
        )?;
        let block = control(window, w!("BUTTON"), "Actions du port…", 0, ID_BLOCK, false)?;
        let stop = control(window, w!("BUTTON"), "Terminer le processus…", 0, ID_STOP, false)?;
        let unblock = control(window, w!("BUTTON"), "Retirer le blocage", 0, ID_UNBLOCK, false)?;
        let watches = control(window, w!("BUTTON"), "Relances (0)…", 0, ID_WATCHES, false)?;
        let status = label("La croix masque RustyPort · Quitter depuis la zone de notification")?;
        let level_preferences = LevelPreferences::load();
        if let Err(error) = &level_preferences {
            set_text(status, &format!("Préférences de niveau indisponibles · {error}"));
        }
        unsafe { EnableWindow(watches, 0) };
        let started = Instant::now();
        let monitor = Monitor::start()?;
        let small_icon = icon::Icon::load(16);
        let large_icon = icon::Icon::load(32);
        unsafe {
            SendMessageW(window, WM_SETICON, ICON_SMALL as usize, small_icon.handle as isize);
            SendMessageW(window, WM_SETICON, ICON_BIG as usize, large_icon.handle as isize);
            SendMessageW(brand_icon, STM_SETICON, small_icon.handle as usize, 0);
        }
        let app = Self {
            window, theme: RefCell::new(ui::Theme::new()), brand_icon, brand,
            traffic_label, traffic_status, graph_detail, pause_graph, port_graph, graph_metric, timeline,
            timeline_label, archive_panel, save_archive, save_range, clear_archive, archive_toggle,
            session, interval_label, interval, overview, levels, filter_label, filter, risk_filter,
            refresh, list, details_label, details, stop, block, unblock, status, watches, started,
            shown_uptime: Cell::new(u64::MAX),
            system_directory: ports::system_directory().unwrap_or_default(),
            monitor, monitor_lost: Cell::new(false),
            port_traffic: Cell::new(PortTrafficState::Off),
            traffic: RefCell::new(TrafficHistory::default()),
            archive: RefCell::new(None),
            archive_error: Cell::new(false),
            archive_enabled: Cell::new(false),
            archive_open: Cell::new(false),
            layout_width: Cell::new(0),
            pending_export: RefCell::new(None),
            paused: RefCell::new(None),
            graph_series: RefCell::new(None),
            live_traffic: RefCell::new("Mesure du débit en cours…".into()),
            graph_pointer: Cell::new(None),
            tray: tray::Tray::new(window, small_icon.handle),
            _small_icon: small_icon,
            _large_icon: large_icon,
            risk_markers: icon::RiskMarkers::new(),
            list_error: RefCell::new(Some("Relevé des ports en cours…".into())),
            last_port_read: Cell::new(None),
            level_preferences: RefCell::new(level_preferences),
            ports: RefCell::new(Vec::new()), rows: RefCell::new(Vec::new()),
            sort: Cell::new(Sort::default()), drag: Cell::new(None),
            drawing_list: Cell::new(false),
            firewall: RefCell::new(None),
            pending_stop: RefCell::new(None),
            pending_bulk: RefCell::new(None),
        };
        app.apply_fonts();
        app.update_level_markers();
        app.update_timeline();
        Ok(app)
    }

    fn layout(&self) {
        let layout = self.geometry();
        let left = layout.plot.left;
        let right = layout.plot.right;
        let content = right - left;
        let toolbar = layout.ports.top + 8;
        let filter_width = (content / 5).clamp(170, 276);
        let filter_left = right - 275 - filter_width;
        let list_top = toolbar + 33;
        let action_top = layout.details.top + 8;
        let detail_top = action_top + 33;
        let layout_flags = SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOREDRAW | SWP_NOCOPYBITS;
        let controls = [
            (self.brand_icon, left, layout.header.top + 14, 16, 16),
            (self.brand, left + 26, layout.header.top + 8, 182, 28),
            (self.session, right - 420, layout.header.top + 9, 178, 26),
            (self.interval_label, right - 237, layout.header.top + 9, 54, 26),
            (self.interval, right - 181, layout.header.top + 11, 78, 170),
            (self.refresh, right - 90, layout.header.top + 9, 90, 26),
            (self.traffic_label, left, layout.graph.top + 4, content - 620, 28),
            (self.graph_metric, right - 610, layout.graph.top + 6, 160, 110),
            (self.port_graph, right - 442, layout.graph.top + 5, 177, 26),
            (self.pause_graph, right - 260, layout.graph.top + 5, 82, 26),
            (self.archive_panel, right - 170, layout.graph.top + 5, 170, 26),
            (self.traffic_status, left, layout.plot.bottom + 4, content, 20),
            (self.graph_detail, left, layout.plot.bottom + 23, content, 19),
            (self.overview, left, toolbar, filter_left - left - 57, 25),
            (self.filter_label, filter_left - 46, toolbar, 42, 25),
            (self.filter, filter_left, toolbar, filter_width, 24),
            (self.risk_filter, right - 266, toolbar, 130, 150),
            (self.levels, right - 127, toolbar, 127, 25),
            (self.list, left, list_top, content, layout.ports.bottom - list_top - ui::INSET),
            (self.details_label, left, action_top, content - 553, 26),
            (self.block, right - 538, action_top, 129, 26),
            (self.stop, right - 401, action_top, 145, 26),
            (self.unblock, right - 248, action_top, 125, 26),
            (self.watches, right - 115, action_top, 115, 26),
            (self.details, left, detail_top, content, layout.details.bottom - detail_top - ui::INSET),
            (self.status, left, layout.status.top + 1, content, layout.status.bottom - layout.status.top - 2),
        ];
        for (control, x, y, w, h) in controls {
            unsafe { SetWindowPos(control, null_mut(), x, y, w.max(1), h.max(1), layout_flags) };
        }
        let archive = layout.archive.unwrap_or_default();
        for (control, x, y, w, h) in [
            (self.timeline_label, left, archive.top + 3, 140, 23),
            (self.timeline, left + 147, archive.top + 2, content - 147, 25),
            (self.archive_toggle, left, archive.top + 32, 176, 26),
            (self.save_archive, left + 185, archive.top + 32, 134, 26),
            (self.save_range, left + 327, archive.top + 32, 165, 26),
            (self.clear_archive, left + 500, archive.top + 32, 99, 26),
        ] {
            unsafe {
                if layout.archive.is_some() {
                    SetWindowPos(control, null_mut(), x, y, w.max(1), h, layout_flags);
                    ShowWindow(control, SW_SHOWNA);
                } else {
                    ShowWindow(control, SW_HIDE);
                }
            }
        }
        if self.layout_width.replace(content) != content {
            let fixed_width: i32 = (0..COLUMNS.len()).filter(|index| *index != 4)
                .map(|index| unsafe { SendMessageW(self.list, LVM_GETCOLUMNWIDTH, index, 0) as i32 }).sum();
            let scrollbar = unsafe { GetSystemMetrics(SM_CXVSCROLL) };
            let process_width = (content - fixed_width - scrollbar - 6).max(90);
            unsafe { SendMessageW(self.list, LVM_SETCOLUMNWIDTH, 4, process_width as isize) };
        }
        unsafe { RedrawWindow(self.window, null(), null_mut(), ui::REDRAW_SURFACE) };
    }

    fn geometry(&self) -> ui::Layout {
        ui::Layout::new(self.window, self.archive_open.get())
    }

    fn apply_fonts(&self) {
        let theme = self.theme.borrow();
        for control in [
            self.session, self.interval_label, self.interval, self.refresh, self.pause_graph, self.port_graph, self.graph_metric,
            self.archive_panel, self.traffic_status, self.graph_detail, self.timeline_label, self.archive_toggle,
            self.save_archive, self.save_range, self.clear_archive, self.overview, self.filter_label, self.filter,
            self.risk_filter, self.levels, self.list, self.details, self.block, self.stop, self.unblock,
            self.watches, self.status,
        ] {
            unsafe { SendMessageW(control, WM_SETFONT, theme.body_font() as usize, 0) };
        }
        for control in [self.traffic_label, self.details_label] {
            unsafe { SendMessageW(control, WM_SETFONT, theme.heading_font() as usize, 0) };
        }
        unsafe { SendMessageW(self.brand, WM_SETFONT, theme.display_font() as usize, 0) };
    }

    fn color_control(&self, dc: HDC, control: HWND) -> LRESULT {
        let theme = self.theme.borrow();
        let (ink, brush) = if [self.brand, self.brand_icon, self.session, self.interval_label].contains(&control) {
            (theme.header_ink, theme.header_brush())
        } else if control == self.status {
            (theme.status_ink, theme.status_brush())
        } else {
            (theme.body_ink, theme.panel_brush())
        };
        unsafe {
            SetTextColor(dc, ink);
            if control == self.details {
                SetBkColor(dc, theme.panel_color);
                SetBkMode(dc, OPAQUE as i32);
            } else {
                SetBkMode(dc, TRANSPARENT as i32);
            }
        }
        brush as LRESULT
    }

    fn draw_list_row(&self, draw: &mut NMLVCUSTOMDRAW) -> LRESULT {
        match draw.nmcd.dwDrawStage {
            CDDS_PREPAINT => CDRF_NOTIFYITEMDRAW as LRESULT,
            CDDS_ITEMPREPAINT => {
                let index = draw.nmcd.dwItemSpec;
                let selected = unsafe { SendMessageW(self.list, LVM_GETITEMSTATE, index, LVIS_SELECTED as isize) } != 0;
                if !selected && let Some(row) = self.rows.borrow().get(index)
                    && let Some(tint) = self.theme.borrow().row_tint(row.level)
                {
                    draw.clrTextBk = tint;
                }
                CDRF_DODEFAULT as LRESULT
            }
            _ => CDRF_DODEFAULT as LRESULT,
        }
    }

    fn chart_bounds(&self) -> RECT {
        self.geometry().plot
    }

    fn invalidate_chart(&self) {
        unsafe { InvalidateRect(self.window, &self.chart_bounds(), 0) };
    }

    fn paint_surface(&self, dc: HDC) {
        let layout = self.geometry();
        let theme = self.theme.borrow();
        theme.paint(dc, &layout);
        let archive = self.paused.borrow();
        let live = self.traffic.borrow();
        let series = self.graph_series.borrow();
        let selection = series.as_deref().map(|series| chart::PortSelection { series, metric: self.port_metric() });
        chart::paint(dc, theme.body_font(), layout.plot, archive.as_ref().unwrap_or(&live.points),
            self.graph_pointer.get().map(|(x, _)| x), selection, archive.is_some());
    }

    fn selected(&self) -> Option<Entry> {
        if self.selected_count() != 1 {
            return None;
        }
        self.entry_at(self.find_row(usize::MAX, LVNI_SELECTED)?)
    }

    fn focused_selection(&self) -> Option<Entry> {
        self.find_row(usize::MAX, LVNI_FOCUSED | LVNI_SELECTED)
            .or_else(|| self.find_row(usize::MAX, LVNI_SELECTED))
            .and_then(|row| self.entry_at(row))
    }

    fn selected_entries(&self) -> Vec<Entry> {
        let mut entries = Vec::new();
        let mut after = usize::MAX;
        while let Some(row) = self.find_row(after, LVNI_SELECTED) {
            if let Some(entry) = self.entry_at(row) {
                entries.push(entry);
            }
            after = row;
        }
        entries
    }

    fn entry_at(&self, row: usize) -> Option<Entry> {
        let index = self.rows.borrow().get(row)?.index;
        self.ports.borrow().get(index).cloned()
    }

    fn selected_count(&self) -> usize {
        unsafe { SendMessageW(self.list, LVM_GETSELECTEDCOUNT, 0, 0) as usize }
    }

    fn find_row(&self, after: usize, flags: u32) -> Option<usize> {
        usize::try_from(unsafe { SendMessageW(self.list, LVM_GETNEXTITEM, after, flags as isize) }).ok()
    }

    fn set_row_state(&self, row: usize, state: u32, state_mask: u32) {
        let item = LVITEMW { state, stateMask: state_mask, ..Default::default() };
        unsafe { SendMessageW(self.list, LVM_SETITEMSTATE, row, &item as *const _ as isize) };
    }

    fn select_all(&self) {
        self.drawing_list.set(true);
        self.set_row_state(usize::MAX, LVIS_SELECTED, LVIS_SELECTED);
        if self.find_row(usize::MAX, LVNI_FOCUSED).is_none() && !self.rows.borrow().is_empty() {
            self.set_row_state(0, LVIS_FOCUSED, LVIS_FOCUSED);
            unsafe { SendMessageW(self.list, LVM_SETSELECTIONMARK, 0, 0) };
        }
        self.drawing_list.set(false);
        self.update_selection();
    }

    fn select_range(&self, first: usize, last: usize) {
        self.drawing_list.set(true);
        self.set_row_state(usize::MAX, 0, LVIS_SELECTED | LVIS_FOCUSED);
        for row in first.min(last)..=first.max(last) {
            self.set_row_state(row, LVIS_SELECTED, LVIS_SELECTED);
        }
        self.set_row_state(last, LVIS_FOCUSED, LVIS_FOCUSED);
        unsafe { SendMessageW(self.list, LVM_SETSELECTIONMARK, 0, first as isize) };
        self.drawing_list.set(false);
        self.update_selection();
    }

    fn row_at_point(&self, position: LPARAM) -> Option<usize> {
        let mut hit = LVHITTESTINFO {
            pt: POINT { x: position as i16 as i32, y: (position >> 16) as i16 as i32 },
            ..Default::default()
        };
        usize::try_from(unsafe { SendMessageW(self.list, LVM_HITTEST, 0, &mut hit as *mut _ as isize) }).ok()
    }

    fn drag_to(&self, position: LPARAM) {
        let Some((anchor, last)) = self.drag.get() else { return };
        let Some(target) = self.row_at_point(position) else { return };
        let rows = self.rows.borrow();
        let Some(end) = rows.get(target).map(|row| row.key) else { return };
        if end == last {
            return;
        }
        let start = rows.iter().position(|row| row.key == anchor);
        drop(rows);
        if let Some(start) = start {
            self.select_range(start, target);
            self.drag.set(Some((anchor, end)));
        }
    }

    fn context_actions(&self, row: usize) {
        let Some(entry) = self.entry_at(row) else { return };
        let state = unsafe { SendMessageW(self.list, LVM_GETITEMSTATE, row, LVIS_SELECTED as isize) };
        if state == 0 {
            self.select_range(row, row);
        } else {
            self.set_row_state(row, LVIS_FOCUSED, LVIS_FOCUSED);
        }
        let mut position = POINT::default();
        unsafe { GetCursorPos(&mut position) };
        self.action_menu(position, entry);
    }

    fn bind_table_input(&self) -> io::Result<()> {
        let bound = unsafe { SetWindowSubclass(self.list, Some(table_input), 1, self as *const App as usize) };
        if bound == 0 {
            return Err(io::Error::other("Les raccourcis de la liste sont indisponibles."));
        }
        Ok(())
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

    fn port_metric(&self) -> chart::PortMetric {
        match unsafe { SendMessageW(self.graph_metric, CB_GETCURSEL, 0, 0) } {
            1 => chart::PortMetric::Arrivals,
            2 => chart::PortMetric::Established,
            _ => chart::PortMetric::Rates,
        }
    }

    fn refresh_graph_mode(&self) {
        let metric = self.port_metric();
        let graph_series = self.graph_series.borrow();
        self.monitor.set_port_capture(metric == chart::PortMetric::Rates
            && graph_series.as_ref().is_some_and(|series| !series.is_empty()));
        let title = match graph_series.as_ref().map(|_| metric) {
            None => "Débit des interfaces · 60 s",
            Some(chart::PortMetric::Rates) => "Débit par port · 60 s",
            Some(chart::PortMetric::Arrivals) => "Nouvelles TCP par relevé · 60 s",
            Some(chart::PortMetric::Established) => "Connexions TCP établies · 60 s",
        };
        drop(graph_series);
        set_text(self.traffic_label, title);
        self.update_traffic_label();
        self.invalidate_chart();
    }

    fn update_traffic_label(&self) {
        let paused = self.paused.borrow();
        let history = self.traffic.borrow();
        let series = self.graph_series.borrow();
        let selection = series.as_deref().map(|series| chart::PortSelection { series, metric: self.port_metric() });
        let metric = selection.map(|view| view.metric);
        let arrivals = metric == Some(chart::PortMetric::Arrivals);
        let port_rates = metric == Some(chart::PortMetric::Rates);
        let port_state = self.port_traffic.get();
        let points = paused.as_ref().unwrap_or(&history.points);
        let bounds = self.chart_bounds();
        let mut detail = String::new();
        let hovered = self.graph_pointer.get().and_then(|(x, y)| {
            let point = chart::sample_at(points, bounds, metric, x)?;
            let age = format!("{:.1}", point.at.elapsed().as_secs_f64()).replace('.', ",");
            let sockets = chart::hovered_sockets(point, points, bounds, selection, y);
            if let Some(socket) = sockets.first() {
                detail = format!("{} · {}", socket.name, socket.endpoint);
                if port_rates {
                    if let Some(rates) = socket.port_rates {
                        let _ = write!(detail, " · Reçu {} · Envoyé {} · {}", chart::rate_label(rates.received),
                            chart::rate_label(rates.sent), socket.address);
                    }
                } else {
                    if arrivals && let Some(count) = socket.arrivals {
                        let _ = write!(detail, " · {count} nouvelle(s)");
                    }
                    let _ = write!(detail, " · {} établie(s) · {}", socket.established, socket.address);
                    if !socket.peer.is_empty() {
                        detail.push_str(&format!(" ↔ {}", socket.peer));
                        if socket.established > 1 {
                            detail.push_str(" (un correspondant)");
                        }
                    }
                }
                if series.is_none() {
                    detail.insert_str(0, "TCP au même relevé · ");
                    let active = point.sockets.iter().filter(|socket| socket.established > 0).count();
                    if active > 1 {
                        detail.push_str(&format!(" · {} autre(s) port(s) TCP actif(s)", active - 1));
                    }
                }
            } else {
                detail = if port_rates {
                    "Aucun débit attribuable à ces ports à ce relevé."
                } else if arrivals {
                    "Nouvelles connexions indisponibles pour ces ports à ce relevé."
                } else {
                    "Aucune connexion TCP correspondante au relevé."
                }.into();
            }
            let label = if series.is_some() {
                let measurement = if port_rates { "Débit en octets/s · reçu + envoyé" }
                    else if arrivals { "Nouvelles TCP depuis le relevé précédent" } else { "Connexions TCP établies" };
                let mut label = format!("Il y a {age} s · {measurement}");
                if sockets.len() > 1 {
                    let others = sockets.iter().skip(1).take(2).map(|socket| socket.endpoint.as_str())
                        .collect::<Vec<_>>().join(", ");
                    let _ = write!(label, " · Courbes superposées avec {others}");
                    if sockets.len() > 3 {
                        let _ = write!(label, " (+ {})", sockets.len() - 3);
                    }
                }
                label
            } else if let Some(rates) = point.rates {
                let span = format!("{:.2}", point.span.as_secs_f64()).replace('.', ",");
                format!("Il y a {age} s · Reçu {} · Envoyé {} · Mesure sur {span} s",
                    chart::rate_label(rates.received), chart::rate_label(rates.sent))
            } else {
                format!("Il y a {age} s · Échantillon indisponible")
            };
            Some(label)
        });
        let label = hovered.unwrap_or_else(|| {
            if let Some(selection) = selection {
                if port_rates && !selection.series.is_empty() && paused.is_none() {
                    match port_state {
                        PortTrafficState::AccessDenied => return "Débit par port indisponible · accès Windows refusé.".into(),
                        PortTrafficState::Unavailable => return "La capture réseau Windows est indisponible.".into(),
                        PortTrafficState::Off | PortTrafficState::Starting => return "Débit par port · initialisation de la mesure Windows…".into(),
                        PortTrafficState::Measuring => {}
                    }
                }
                let stats = chart::selection_stats(points, selection);
                let ports = if port_rates { "port(s)" } else { "port(s) TCP" };
                let observed = if port_rates { "avec trafic" } else if arrivals { "avec des arrivées" } else { "avec des connexions" };
                let mut label = format!("{} {ports} · {} {observed} · {} à zéro", selection.series.len(), stats.active, stats.zero);
                if stats.no_data > 0 {
                    let _ = write!(label, " · {} sans relevé", stats.no_data);
                }
                if paused.is_some() {
                    label.push_str(" · Vue figée");
                }
                label
            } else if paused.is_some() {
                "Vue figée · Débits des interfaces · Collecte en cours".into()
            } else {
                self.live_traffic.borrow().clone()
            }
        });
        if detail.is_empty() {
            detail = if self.archive_error.get() {
                "Archivage sur disque indisponible pour les nouveaux relevés."
            } else if port_rates && port_state == PortTrafficState::AccessDenied {
                "Ouvre RustyPort en tant qu’administrateur pour accéder à la capture réseau de Windows."
            } else if port_rates {
                "Une courbe par port TCP ou UDP. Le débit total additionne les octets reçus et envoyés."
            } else if arrivals {
                "Chaque pic compte les nouvelles connexions observées entre deux relevés."
            } else if selection.is_some() {
                "Une ligne plate indique que le nombre de connexions ouvertes reste stable."
            } else {
                "Débit total en octets par seconde sur les interfaces actives hors bouclage."
            }.into();
        }
        set_text(self.traffic_status, &label);
        set_text(self.graph_detail, &detail);
    }

    fn toggle_graph_pause(&self) {
        if self.paused.borrow().is_some() {
            self.paused.replace(None);
            set_text(self.pause_graph, "Pause");
            self.update_timeline();
        } else {
            self.paused.replace(Some(self.traffic.borrow().points.clone()));
            set_text(self.pause_graph, "Reprendre");
        }
        self.update_traffic_label();
        self.invalidate_chart();
    }

    fn update_graph_series(&self) {
        let selected = unsafe { SendMessageW(self.port_graph, BM_GETCHECK, 0, 0) } == BST_CHECKED as isize;
        if !selected && self.graph_series.borrow().is_none() {
            return;
        }
        if selected != self.graph_series.borrow().is_some() {
            unsafe { ShowWindow(self.graph_metric, if selected { SW_SHOWNA } else { SW_HIDE }) };
        }
        let port_rates = self.port_metric() == chart::PortMetric::Rates;
        let series = selected.then(|| {
            let mut series: Vec<_> = self.selected_entries().into_iter().filter_map(|entry| {
                let port = entry.port;
                (port_rates || port.endpoint.protocol == Protocol::Tcp).then(|| chart::Series {
                    key: port.graph_key(),
                    label: format!("{} · {}", port.endpoint.label(), port.owner.name),
                })
            }).collect();
            series.sort_unstable_by(|a, b| a.key.cmp(&b.key));
            series
        });
        if *self.graph_series.borrow() != series {
            self.graph_series.replace(series);
            self.refresh_graph_mode();
        }
    }

    fn update_timeline(&self) {
        let archive = self.archive.borrow();
        let length = archive.as_ref().map_or(0, archive::Archive::len);
        let size = archive.as_ref().and_then(|archive| archive.size().ok()).unwrap_or(0);
        let exporting = self.pending_export.borrow().is_some();
        let label = if size >= 1_048_576 {
            format!("{:.2} Mio", size as f64 / 1_048_576.0)
        } else if size >= 1024 {
            format!("{:.1} Kio", size as f64 / 1024.0)
        } else {
            format!("{size} o")
        };
        let indicator = if self.archive_open.get() { "−" } else { "+" };
        let caption = format!("Historique {indicator} · {}", label.replace('.', ","));
        if window_text(self.archive_panel) != caption {
            set_text(self.archive_panel, &caption);
        }
        let last = length.saturating_sub(1).min(i32::MAX as usize) as isize;
        unsafe {
            EnableWindow(self.timeline, i32::from(length > 1));
            EnableWindow(self.save_archive, i32::from(!exporting && length != 0));
            EnableWindow(self.save_range, i32::from(!exporting && length != 0));
            EnableWindow(self.clear_archive, i32::from(!exporting && (size != 0 || !self.traffic.borrow().points.is_empty())));
            SendMessageW(self.timeline, TBM_SETRANGEMAX, 1, last);
            if self.paused.borrow().is_none() {
                SendMessageW(self.timeline, TBM_SETPOS, 1, last);
            }
        }
    }

    fn toggle_archive_panel(&self) {
        self.archive_open.set(!self.archive_open.get());
        self.layout();
        self.update_timeline();
    }

    fn toggle_archive(&self) {
        let enabled = unsafe { SendMessageW(self.archive_toggle, BM_GETCHECK, 0, 0) } == BST_CHECKED as isize;
        self.archive_enabled.set(enabled);
        if enabled && self.archive.borrow().is_none() {
            self.archive.replace(archive::Archive::open(self.started).ok());
        }
        self.archive_error.set(enabled && self.archive.borrow().is_none());
        self.update_timeline();
        self.update_traffic_label();
    }

    fn clean_archive(&self) {
        if self.pending_export.borrow().is_some() {
            return;
        }
        let choice = unsafe { MessageBoxW(self.window,
            w!("Effacer les relevés temporaires de la session et repartir avec un graphe vide ?"),
            w!("Nettoyer l’historique"), MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION) };
        if choice != IDYES {
            return;
        }
        self.archive.replace(None);
        self.traffic.borrow_mut().points.clear();
        self.paused.replace(None);
        self.graph_pointer.set(None);
        set_text(self.pause_graph, "Pause");
        if self.archive_enabled.get() {
            self.archive.replace(archive::Archive::open(self.started).ok());
        }
        self.archive_error.set(self.archive_enabled.get() && self.archive.borrow().is_none());
        set_text(self.status, "Historique de session nettoyé.");
        self.update_timeline();
        self.update_traffic_label();
        self.invalidate_chart();
    }

    fn save_history(&self, period: bool) {
        if self.pending_export.borrow().is_some() {
            return;
        }
        let range = if period {
            let bounds = self.archive.borrow_mut().as_mut().and_then(|archive| archive.bounds().ok());
            let Some((first, last)) = bounds else { return };
            let Some(range) = duration_dialog::choose_range(self.window, first, last) else { return };
            Some(range)
        } else {
            None
        };
        let destination = match duration_dialog::save_csv(self.window) {
            Ok(Some(path)) => path,
            Ok(None) => return,
            Err(error) => {
                set_text(self.status, &error.to_string());
                return;
            }
        };
        let reader = self.archive.borrow().as_ref().map(archive::Archive::reader);
        let mut reader = match reader {
            Some(Ok(reader)) => reader,
            Some(Err(error)) => {
                set_text(self.status, &format!("Archives indisponibles. {error}"));
                return;
            }
            None => return,
        };
        let (sender, receiver) = std::sync::mpsc::channel();
        match std::thread::Builder::new().name("rustyport-export".into()).spawn(move || {
            let _ = sender.send(reader.export(&destination, range));
        }) {
            Ok(_) => {
                self.pending_export.replace(Some(receiver));
                set_text(self.status, "Sauvegarde CSV en cours…");
                self.update_timeline();
            }
            Err(error) => set_text(self.status, &format!("Sauvegarde indisponible. {error}")),
        }
    }

    fn poll_export(&self) {
        let result = self.pending_export.borrow().as_ref().map(Receiver::try_recv);
        let message = match result {
            Some(Ok(Ok(count))) => format!("{count} relevé(s) sauvegardé(s) en CSV."),
            Some(Ok(Err(error))) => format!("Sauvegarde impossible. {error}"),
            Some(Err(TryRecvError::Disconnected)) => "Sauvegarde interrompue.".into(),
            _ => return,
        };
        self.pending_export.replace(None);
        self.update_timeline();
        set_text(self.status, &message);
    }

    fn quit(&self) {
        if self.pending_export.borrow().is_some() {
            unsafe { MessageBoxW(self.window, w!("La sauvegarde CSV est en cours. Réessaie après la fin de l’export."),
                w!("RustyPort"), MB_OK | MB_ICONINFORMATION) };
            return;
        }
        unsafe { DestroyWindow(self.window) };
    }

    fn seek_graph(&self) {
        let index = unsafe { SendMessageW(self.timeline, TBM_GETPOS, 0, 0) } as usize;
        let page = self.archive.borrow_mut().as_mut().map(|archive| archive.page(index));
        match page {
            Some(Ok(page)) => {
                self.paused.replace(Some(page));
                set_text(self.pause_graph, "Reprendre");
                self.update_traffic_label();
                self.invalidate_chart();
            }
            Some(Err(error)) => set_text(self.status, &format!("Historique indisponible. {error}")),
            None => {}
        }
    }

    fn pointer_moved(&self, coordinates: LPARAM) {
        let point = POINT { x: coordinates as i16 as i32, y: (coordinates >> 16) as i16 as i32 };
        let bounds = self.chart_bounds();
        let inside = point.x >= bounds.left && point.x < bounds.right
            && point.y >= bounds.top && point.y < bounds.bottom;
        let previous = self.graph_pointer.replace(inside.then_some((point.x, point.y)));
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
                let choice = popup_menu(self.window, position, &[(1, "Ouvrir RustyPort", true), (2, "Quitter RustyPort", true)]);
                unsafe { PostMessageW(self.window, WM_NULL, 0, 0) };
                match choice {
                    1 => self.restore_window(),
                    2 => self.quit(),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn poll_monitor(&self) {
        self.poll_export();
        self.poll_stop();
        self.poll_bulk_stop();
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
                self.populate();
            }
        }
    }

    fn apply_reading(&self, reading: Reading) {
        let (at, ports, traffic, port_traffic) = reading.apply(&mut self.traffic.borrow_mut());
        self.port_traffic.set(port_traffic);
        if self.archive_enabled.get() && !self.archive_error.get()
            && let Some(point) = self.traffic.borrow().points.back()
            && let Some(archive) = self.archive.borrow_mut().as_mut()
            && archive.append(point).is_err()
        {
            self.archive_error.set(true);
        }
        self.update_timeline();
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
        if self.paused.borrow().is_none() {
            self.invalidate_chart();
        }
        match ports {
            Ok(ports) => {
                let mut first_seen = BTreeMap::new();
                if self.list_error.borrow_mut().take().is_none() {
                    first_seen.extend(self.ports.borrow().iter().map(|entry| (entry.key(), entry.first_seen)));
                }
                let preferences = self.level_preferences.borrow();
                let entries = ports.into_iter().map(|port| {
                    let key = port.key();
                    let first_seen = first_seen.get(&key).copied().unwrap_or(at);
                    let assessment = risk::assess(&port, &self.system_directory);
                    let mut entry = Entry::new(port, first_seen, assessment);
                    entry.manual_level = preferences.as_ref().ok().and_then(|settings| settings.get(&entry.port));
                    entry
                }).collect();
                self.ports.replace(entries);
                self.last_port_read.set(Some(at));
            }
            Err(error) => {
                self.list_error.replace(Some(format!("Relevé des ports indisponible. {error}")));
            }
        }
        self.populate();
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
            self.populate_rows(false);
        }
    }

    fn populate(&self) {
        self.populate_rows(true);
    }

    fn populate_rows(&self, preserve_viewport: bool) {
        let query = window_text(self.filter).to_lowercase();
        let selected_level = unsafe { SendMessageW(self.risk_filter, CB_GETCURSEL, 0, 0) };
        let risk_filter = Risk::LEVELS.get(selected_level.saturating_sub(1) as usize).copied();
        let ports = self.ports.borrow();
        let at = self.last_port_read.get().unwrap_or_else(Instant::now);
        let rows = visible_rows(&ports, &query, risk_filter, self.sort.get(), at);
        let total = ports.len();
        let mut counts = [0; 3];
        for entry in ports.iter() {
            counts[entry.level() as usize] += 1;
        }
        drop(ports);

        let old = self.rows.borrow();
        let rebuild = old.len() != rows.len() || old.iter().zip(&rows).any(|(a, b)| a.key != b.key);
        let mut selected = BTreeSet::new();
        let mut focused = None;
        let mut anchor = None;
        if rebuild {
            let mut after = usize::MAX;
            while let Some(index) = self.find_row(after, LVNI_SELECTED) {
                if let Some(row) = old.get(index) {
                    selected.insert(row.key);
                }
                after = index;
            }
            focused = self.find_row(usize::MAX, LVNI_FOCUSED)
                .and_then(|row| old.get(row)).map(|row| row.key);
            let selection_mark = unsafe { SendMessageW(self.list, LVM_GETSELECTIONMARK, 0, 0) };
            anchor = old.get(selection_mark as usize).map(|row| row.key);
        }
        self.drawing_list.set(true);
        let top = if !preserve_viewport {
            Some(0)
        } else if rebuild {
            let current = unsafe { SendMessageW(self.list, LVM_GETTOPINDEX, 0, 0) } as usize;
            let kept_row = (current > 0).then_some(current).and_then(|index| old.get(index));
            Some(kept_row.and_then(|previous| rows.iter().position(|row| row.key == previous.key)).unwrap_or(0))
        } else {
            None
        };
        if rebuild {
            unsafe {
                SendMessageW(self.list, WM_SETREDRAW, 0, 0);
                SendMessageW(self.list, LVM_DELETEALLITEMS, 0, 0);
            }
        }
        for (index, row) in rows.iter().enumerate() {
            for (column, value) in row.fields.iter().enumerate() {
                if !rebuild && *value == old[index].fields[column] {
                    continue;
                }
                let mut value = wide(value);
                let item = LVITEMW {
                    mask: if column == 0 { LVIF_TEXT | LVIF_IMAGE } else { LVIF_TEXT },
                    iItem: index as i32, iSubItem: column as i32, iImage: row.level as i32,
                    pszText: value.as_mut_ptr(), ..Default::default()
                };
                let message = match (column, rebuild) {
                    (0, true) => LVM_INSERTITEMW,
                    (0, false) => LVM_SETITEMW,
                    _ => LVM_SETITEMTEXTW,
                };
                unsafe { SendMessageW(self.list, message, index, &item as *const _ as isize) };
            }
        }
        if rebuild {
            for (index, row) in rows.iter().enumerate() {
                let selected = if selected.contains(&row.key) { LVIS_SELECTED } else { 0 };
                let focused = if focused == Some(row.key) { LVIS_FOCUSED } else { 0 };
                if selected | focused != 0 {
                    self.set_row_state(index, selected | focused, LVIS_SELECTED | LVIS_FOCUSED);
                }
                if anchor == Some(row.key) {
                    unsafe { SendMessageW(self.list, LVM_SETSELECTIONMARK, 0, index as isize) };
                }
            }
        }
        let shown = rows.len();
        drop(old);
        self.rows.replace(rows);
        self.drawing_list.set(false);
        if rebuild {
            unsafe { SendMessageW(self.list, WM_SETREDRAW, 1, 0) };
        }
        if let Some(top) = top {
            let current = unsafe { SendMessageW(self.list, LVM_GETTOPINDEX, 0, 0) } as i32;
            let delta = top as i32 - current;
            let mut rect = RECT { left: LVIR_BOUNDS as i32, ..Default::default() };
            unsafe {
                if delta != 0 && SendMessageW(self.list, LVM_GETITEMRECT, 0, &mut rect as *mut _ as isize) != 0 {
                    let pixels = (rect.bottom - rect.top).saturating_mul(delta);
                    SendMessageW(self.list, LVM_SCROLL, 0, pixels as isize);
                }
            }
        }
        if rebuild {
            unsafe { RedrawWindow(self.list, null(), null_mut(), ui::REDRAW_SURFACE) };
        }

        let overview = self.list_error.borrow().clone().unwrap_or_else(|| format!(
            "Ports {shown}/{total}  ·  {} à risque  ·  {} inconnus  ·  {} normaux",
            counts[Risk::Elevated as usize], counts[Risk::Unknown as usize], counts[Risk::Normal as usize]
        ));
        set_text(self.overview, &overview);
        self.update_selection();
    }

    fn update_level_markers(&self) {
        let markers = if chart::high_contrast() {
            0
        } else {
            self.risk_markers.as_ref().map_or(0, |markers| markers.0 as isize)
        };
        unsafe { SendMessageW(self.list, LVM_SETIMAGELIST, LVSIL_SMALL as usize, markers) };
    }

    fn typed_port(&self) -> Option<u16> {
        window_text(self.filter).trim().parse::<u16>().ok().filter(|port| *port != 0)
    }

    fn update_selection(&self) {
        self.update_graph_series();
        let count = self.selected_count();
        let selected = self.selected();
        let current = self.list_error.borrow().is_none();
        let available = self.firewall.borrow().is_none();
        let can_request_stop = !self.stop_in_progress();
        let has_selection = current && count != 0;
        let has_stoppable = if count > 1 {
            self.selected_entries().iter().any(|entry| entry.port.can_stop())
        } else {
            selected.as_ref().is_some_and(|entry| entry.port.can_stop())
        };
        for (button, enabled) in [
            (self.stop, has_selection && can_request_stop && has_stoppable),
            (self.block, count > 0),
            (self.unblock, available && (has_selection || (count == 0 && self.typed_port().is_some()))),
        ] {
            let enabled = i32::from(enabled);
            unsafe {
                if IsWindowEnabled(button) != enabled {
                    EnableWindow(button, enabled);
                }
            }
        }
        if count > 1 {
            self.set_details(&format!(
                "{count} lignes sélectionnées. Le clic droit donne accès aux actions du groupe."
            ));
            return;
        }
        let Some(entry) = selected else {
            let prompt = if self.typed_port().is_some() {
                "Sélectionne une ligne ou clique sur « Retirer le blocage » pour le numéro saisi."
            } else {
                "Sélectionne un port pour voir son niveau, son processus et son activité."
            };
            self.set_details(prompt);
            return;
        };
        self.set_details(&self.detail_text(&entry, false));
    }

    fn set_details(&self, text: &str) {
        if write_changed_text(self.details, text) {
            unsafe { RedrawWindow(self.details, null(), null_mut(), RDW_INVALIDATE | RDW_ERASE) };
        }
    }

    fn detail_text(&self, entry: &Entry, expanded: bool) -> String {
        let port = &entry.port;
        let endpoint = port.endpoint;
        let current = self.list_error.borrow().is_none();
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
            Protocol::Tcp if current => {
                let current = format!("{} connexion(s) TCP établie(s) au relevé", port.established.len());
                if let Some(recent) = port.recent_tcp {
                    format!("{current} · {recent} nouvelle(s) TCP observée(s) sur 60 s")
                } else {
                    current
                }
            }
            Protocol::Tcp => "Connexions TCP indisponibles".into(),
            Protocol::Udp => "UDP · activité par port indisponible".into(),
        };
        let (level, reason) = if let Some(manual) = entry.manual_level {
            (format!("{} (manuel)", manual.label()), format!("Classement automatique · {} · {}",
                entry.assessment.level.label(), entry.assessment.reason))
        } else {
            (entry.level().label().into(), entry.assessment.reason.into())
        };
        let mut detail = format!(
            "{} · {} · {address}\r\n{}\r\n{activity}\r\n{observation} · {age}",
            level, endpoint.label(), reason
        );
        if !LevelPreferences::can_set(port) {
            detail.push_str("\r\nNiveau manuel indisponible · processus non identifié.");
        }
        if expanded {
            detail.push_str(&format!("\r\nAdresse locale · {}\r\nProcessus · {} · PID {}",
                endpoint.address_label(), port.owner.name, endpoint.pid));
        }
        if let Some(reason) = self.action_limitation(port) {
            detail.push_str(&format!("\r\n{reason}"));
        }
        if let Some(usage) = usual_use(endpoint) {
            detail.push_str(&format!("\r\nUsage courant du numéro · {usage}"));
        }
        if !port.owner.path.is_empty() {
            detail.push_str(&format!("\r\n{}", port.owner.path));
        }
        if !port.owner.services.is_empty() {
            detail.push_str(&format!("\r\nServices de ce processus · {}", port.owner.services.join(", ")));
        }
        detail
    }

    fn action_limitation(&self, port: &Port) -> Option<String> {
        if self.list_error.borrow().is_some() {
            return Some("Les actions d’arrêt attendent un relevé valide.".into());
        }
        if let Some(reason) = port.stop_unavailable_reason() {
            return Some(format!("Arrêt indisponible · {reason}"));
        }
        if self.stop_in_progress() {
            return Some("Une demande d’arrêt est en cours.".into());
        }
        relaunch::unavailable_reason(port, &self.system_directory)
            .map(|reason| format!("Relances indisponibles · {reason}"))
    }

    fn stop_in_progress(&self) -> bool {
        self.pending_stop.borrow().is_some() || self.pending_bulk.borrow().is_some()
            || self.firewall.borrow().as_ref().is_some_and(|(_, stop_after)| !stop_after.is_empty())
    }

    fn ask_stop(&self, port: &Port, consequence: &str) -> bool {
        let message = format!("Terminer {} (PID {}) ?\n{consequence}", port.owner.name, port.endpoint.pid);
        let answer = unsafe {
            MessageBoxW(
                self.window, wide(&message).as_ptr(), w!("RustyPort"),
                MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION,
            )
        };
        answer == IDYES
    }

    fn report_stop(&self, name: &str, result: io::Result<()>, prefix: &str) -> bool {
        self.refresh();
        match result {
            Ok(()) => {
                set_text(self.status, &format!("{prefix}Processus terminé · {name}."));
                true
            }
            Err(error) => {
                set_text(self.status, &format!("{prefix}Arrêt non confirmé. {error}"));
                false
            }
        }
    }

    fn request_stop(&self, port: &Port, prefix: String) {
        let result = ports::stop(port);
        if result.as_ref().err().and_then(io::Error::raw_os_error) != Some(ERROR_ACCESS_DENIED as i32) {
            self.report_stop(&port.owner.name, result, &prefix);
            return;
        }
        set_text(self.status, &format!("{prefix}Autorisation Windows requise pour {}.", port.owner.name));
        match stop_job::Job::start(self.window, port) {
            Ok(job) => {
                self.pending_stop.replace(Some(PendingStop { job, name: port.owner.name.clone(), prefix }));
                self.update_selection();
            }
            Err(error) if error.raw_os_error() == Some(ERROR_CANCELLED as i32) => {
                set_text(self.status, &format!("{prefix}Autorisation annulée."));
            }
            Err(error) => {
                let error = io::Error::other(format!("Élévation indisponible. {error}"));
                self.report_stop(&port.owner.name, Err(error), &prefix);
            }
        }
    }

    fn poll_stop(&self) {
        let mut pending = self.pending_stop.borrow_mut();
        let Some(result) = pending.as_ref().and_then(|stop| stop.job.result()) else { return };
        let stop = pending.take().unwrap();
        drop(pending);
        self.report_stop(&stop.name, result, &stop.prefix);
        self.update_selection();
    }

    fn stop_selected(&self) {
        if self.selected_count() > 1 {
            self.run_bulk(self.selected_entries(), 1);
            return;
        }
        let Some(port) = self.available_port().filter(Port::can_stop) else { return };
        self.confirm_and_stop(&port);
    }

    fn confirm_and_stop(&self, port: &Port) {
        if self.stop_in_progress() {
            return;
        }
        if self.ask_stop(port, "Ses tâches et ses connexions seront interrompues.") {
            self.request_stop(port, String::new());
        }
    }

    fn available_port(&self) -> Option<Port> {
        if self.list_error.borrow().is_some() {
            return None;
        }
        self.selected().map(|entry| entry.port)
    }

    fn ask_duration(&self, context: &str) -> Option<u16> {
        match duration_dialog::ask(self.window, "Durée de l’action", context) {
            Ok(minutes) => minutes,
            Err(error) => {
                set_text(self.status, &format!("Saisie de la durée indisponible. {error}"));
                None
            }
        }
    }

    fn watch_relaunch(&self, port: Port, minutes: Option<u16>) {
        if self.stop_in_progress() || self.monitor_lost.get() {
            return;
        }
        if let Err(error) = relaunch::prepare(&port, &self.system_directory) {
            set_text(self.status, &error.to_string());
            return;
        }
        let period = minutes.map_or_else(|| "jusqu’à la fermeture complète de RustyPort".into(), |minutes| format!("pendant {minutes} min"));
        let message = format!("Les nouvelles instances du même fichier seront arrêtées {period}.");
        if self.ask_stop(&port, &message) {
            let result = ports::stop(&port).map_err(|error| {
                if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
                    io::Error::other("La surveillance des relances nécessite le droit d’arrêter cette application.")
                } else {
                    error
                }
            });
            if !self.report_stop(&port.owner.name, result, "") {
                return;
            }
            let delay = minutes.map(|minutes| Duration::from_secs(u64::from(minutes) * 60));
            let label = format!("Relances surveillées {period} · {}", port.owner.name);
            self.monitor.watch(relaunch::watch(port, delay));
            self.update_watch_button();
            set_text(self.status, &label);
        }
    }

    fn action_menu(&self, position: POINT, entry: Entry) {
        if self.selected_count() > 1 {
            self.bulk_menu(position);
            return;
        }
        let port = &entry.port;
        let count = self.selected_count();
        let one = count == 1 && self.list_error.borrow().is_none();
        let can_stop = one && port.can_stop() && !self.stop_in_progress();
        let can_watch = can_stop && !self.monitor_lost.get() && relaunch::can_watch(port, &self.system_directory);
        let can_block = one && self.firewall.borrow().is_none();

        let choices = self.level_menu(std::slice::from_ref(&entry));
        let choice = popup_menu_with_levels(self.window, position, &[
            (10, "Plus d’infos sur ce port…", true),
            (11, "Rechercher ce port sur le web…", true),
            (0, "", true),
            (1, "Terminer le processus…", can_stop),
            (2, "Bloquer le port", can_block),
            (3, "Bloquer le port pendant X minutes…", can_block),
            (4, "Terminer et bloquer le port…", can_stop && can_block),
            (5, "Terminer et bloquer le port pendant X minutes…", can_stop && can_block),
            (6, "Terminer et surveiller les relances jusqu’à Quitter…", can_watch),
            (7, "Terminer et surveiller les relances pendant X minutes…", can_watch),
            (8, "Retirer le blocage", can_block),
            (9, "Pourquoi une action est grisée ?", !can_stop || !can_watch || !can_block),
        ], Some(choices));
        match choice {
            MENU_LEVEL_AUTO..=MENU_LEVEL_ELEVATED => {
                self.change_level(std::slice::from_ref(&entry), level_for_choice(choice));
            }
            1 => self.confirm_and_stop(port),
            2 | 4 => self.change_firewall(FirewallAction::Block, Some(port.clone()), choice == 4),
            3 | 5 => {
                let context = format!("Combien de temps bloquer le trafic entrant sur {} ?", port.endpoint.label());
                if let Some(minutes) = self.ask_duration(&context) {
                    self.change_firewall(FirewallAction::Timed(minutes), Some(port.clone()), choice == 5);
                }
            }
            6 => self.watch_relaunch(port.clone(), None),
            7 => {
                let context = format!("Combien de temps surveiller les relances de {} ?", port.owner.name);
                if let Some(minutes) = self.ask_duration(&context) {
                    self.watch_relaunch(port.clone(), Some(minutes));
                }
            }
            8 => self.change_firewall(FirewallAction::Remove, Some(port.clone()), false),
            9 => {
                let reason = self.action_limitation(port).unwrap_or_else(|| {
                    if !can_block {
                        "Une modification du pare-feu est en cours.".into()
                    } else {
                        "La surveillance des relances est indisponible.".into()
                    }
                });
                unsafe {
                    MessageBoxW(self.window, wide(&reason).as_ptr(), w!("Actions du port"), MB_OK | MB_ICONINFORMATION);
                }
            }
            10 => {
                let detail = wide(&self.detail_text(&entry, true));
                let title = wide(&format!("Détails · {}", port.endpoint.label()));
                unsafe { MessageBoxW(self.window, detail.as_ptr(), title.as_ptr(), MB_OK | MB_ICONINFORMATION) };
            }
            11 => {
                if !self.open_search(&web_search_url(port)) {
                    set_text(self.status, "Ouverture du navigateur impossible.");
                }
            }
            _ => {}
        }
    }

    fn open_search(&self, url: &str) -> bool {
        let url = wide(url);
        let result = unsafe { ShellExecuteW(self.window, w!("open"), url.as_ptr(), null(), null(), SW_SHOWNORMAL) };
        result as isize > 32
    }

    fn level_menu(&self, entries: &[Entry]) -> LevelMenu {
        let mut candidates = entries.iter().filter(|entry| LevelPreferences::can_set(&entry.port))
            .map(|entry| entry.manual_level);
        let first = candidates.next();
        let checked = first.filter(|level| candidates.all(|candidate| candidate == *level))
            .map(|level| level.map_or(MENU_LEVEL_AUTO, |level| MENU_LEVEL_NORMAL + level as u32));
        LevelMenu {
            checked,
            enabled: first.is_some() && self.list_error.borrow().is_none() && self.level_preferences.borrow().is_ok(),
        }
    }

    fn change_level(&self, entries: &[Entry], level: Option<Risk>) {
        if self.list_error.borrow().is_some() {
            return;
        }
        let targets = entries.iter().map(|entry| &entry.port).filter(|port| LevelPreferences::can_set(port))
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return;
        }
        if entries.len() > 1 {
            let action = level.map_or_else(|| "Rétablir le classement automatique".into(),
                |level| format!("Choisir le niveau {}", level.label()));
            let mut details = targets.iter().map(|port| format!("{} · {} · {}",
                port.owner.name, port.endpoint.label(), port.endpoint.address_label())).collect::<Vec<_>>();
            let skipped = entries.len() - targets.len();
            if skipped > 0 {
                details.push(format!("{skipped} ligne(s) écartée(s) · processus non identifié."));
            }
            if !duration_dialog::review(self.window, "Niveaux de la sélection", &action, &details.join("\r\n"), true) {
                return;
            }
        }
        let mut preferences = self.level_preferences.borrow_mut();
        let settings = match preferences.as_mut() {
            Ok(settings) => settings,
            Err(error) => {
                set_text(self.status, &format!("Préférences de niveau indisponibles · {error}"));
                return;
            }
        };
        if let Err(error) = settings.set(&targets, level) {
            set_text(self.status, &format!("Enregistrement du niveau impossible · {error}"));
            return;
        }
        for entry in self.ports.borrow_mut().iter_mut() {
            entry.manual_level = settings.get(&entry.port);
        }
        drop(preferences);
        self.populate();
        unsafe { RedrawWindow(self.window, null(), null_mut(), ui::REDRAW_SURFACE) };
        let message = level.map_or_else(|| "Classement automatique rétabli.".into(),
            |level| format!("Niveau manuel enregistré · {}.", level.label()));
        set_text(self.status, &message);
    }

    fn bulk_menu(&self, position: POINT) {
        let entries = self.selected_entries();
        let ready = self.list_error.borrow().is_none();
        let can_stop = ready && !self.stop_in_progress() && entries.iter().any(|entry| entry.port.can_stop());
        let can_watch = can_stop && !self.monitor_lost.get()
            && entries.iter().any(|entry| relaunch::can_watch(&entry.port, &self.system_directory));
        let can_block = ready && self.firewall.borrow().is_none();
        let choice = popup_menu_with_levels(self.window, position, &[
            (10, "Plus d’infos sur la sélection…", true),
            (11, "Rechercher la sélection sur le web…", true),
            (0, "", true),
            (1, "Terminer les processus…", can_stop),
            (2, "Bloquer les ports…", can_block),
            (3, "Bloquer les ports pendant X minutes…", can_block),
            (4, "Terminer et bloquer les ports…", can_stop && can_block),
            (5, "Terminer et bloquer les ports pendant X minutes…", can_stop && can_block),
            (6, "Terminer et surveiller les relances jusqu’à Quitter…", can_watch),
            (7, "Terminer et surveiller les relances pendant X minutes…", can_watch),
            (8, "Retirer les blocages…", can_block),
        ], Some(self.level_menu(&entries)));
        self.run_bulk(entries, choice);
    }

    fn run_bulk(&self, entries: Vec<Entry>, choice: u32) {
        if choice == 0 || entries.is_empty() {
            return;
        }
        if (MENU_LEVEL_AUTO..=MENU_LEVEL_ELEVATED).contains(&choice) {
            self.change_level(&entries, level_for_choice(choice));
            return;
        }
        if choice == 10 {
            let details = entries.iter().map(|entry| self.detail_text(entry, true)).collect::<Vec<_>>().join("\r\n\r\n");
            duration_dialog::review(self.window, "Détails de la sélection", &format!("{} lignes", entries.len()), &details, false);
            return;
        }
        if choice == 11 {
            let queries: BTreeMap<_, _> = entries.iter().map(|entry| {
                let port = &entry.port;
                (web_search_url(port), format!("{} · {}", port.owner.name, port.endpoint.label()))
            }).collect();
            let context = format!("Ouvrir {} recherches dans le navigateur par défaut ?", queries.len());
            let details = queries.values().cloned().collect::<Vec<_>>().join("\r\n");
            if duration_dialog::review(self.window, "Recherches web", &context, &details, true) {
                let opened = queries.keys().filter(|url| self.open_search(url)).count();
                set_text(self.status, &format!("{opened}/{} recherches ouvertes.", queries.len()));
            }
            return;
        }
        if self.list_error.borrow().is_some() {
            return;
        }
        let stops = matches!(choice, 1 | 4 | 5 | 6 | 7);
        let watches = matches!(choice, 6 | 7);
        let firewall = matches!(choice, 2 | 3 | 4 | 5 | 8);
        if (stops && self.stop_in_progress()) || (firewall && self.firewall.borrow().is_some()) {
            return;
        }
        let minutes = if matches!(choice, 3 | 5 | 7) {
            let Some(minutes) = self.ask_duration("Combien de minutes pour l’ensemble de la sélection ?") else { return };
            Some(minutes)
        } else {
            None
        };
        let mut rules = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut processes = Vec::new();
        let mut excluded = Vec::new();
        for entry in entries {
            let port = entry.port;
            if firewall {
                rules.insert((port.endpoint.port, port.endpoint.protocol));
            }
            if stops && seen.insert((port.endpoint.pid, port.owner.created)) {
                let reason = if watches {
                    relaunch::unavailable_reason(&port, &self.system_directory)
                } else {
                    port.stop_unavailable_reason()
                };
                if let Some(reason) = reason {
                    excluded.push(format!("{} · PID {} · {reason}", port.owner.name, port.endpoint.pid));
                } else {
                    processes.push(port);
                }
            }
        }
        let rules: Vec<_> = rules.into_iter().collect();
        let label = match choice {
            1 => "Terminer les processus",
            2 | 3 => "Bloquer le trafic entrant",
            4 | 5 => "Bloquer puis terminer les processus",
            6 | 7 => "Terminer et surveiller les relances",
            8 => "Retirer les blocages RustyPort",
            _ => return,
        };
        let period = minutes.map_or_else(String::new, |minutes| format!(" · {minutes} min"));
        let context = format!("{label}{period}\r\n{} port(s) · {} processus à arrêter · {} processus écarté(s)",
            rules.len(), processes.len(), excluded.len());
        let mut details = rules.iter().map(|(port, protocol)| format!("Port · {port}/{}", protocol.name())).collect::<Vec<_>>();
        details.extend(processes.iter().map(|port| format!("Arrêt · {} · PID {}", port.owner.name, port.endpoint.pid)));
        details.extend(excluded.into_iter().map(|reason| format!("Écarté · {reason}")));
        if !duration_dialog::review(self.window, "Confirmer le lot", &context, &details.join("\r\n"), true) {
            return;
        }
        if firewall {
            let action = if choice == 8 {
                FirewallAction::Remove
            } else if let Some(minutes) = minutes {
                FirewallAction::Timed(minutes)
            } else {
                FirewallAction::Block
            };
            self.launch_firewall(rules, action, processes);
        } else {
            let mode = if watches { stop_job::Mode::Watch(minutes) } else { stop_job::Mode::Once };
            self.request_bulk_stop(processes, mode, String::new());
        }
    }

    fn request_bulk_stop(&self, ports: Vec<Port>, mode: stop_job::Mode, prefix: String) {
        let total = ports.len();
        if total == 0 {
            return;
        }
        match stop_job::local_batch(ports, mode, self.system_directory.clone()) {
            Ok(receiver) => {
                self.pending_bulk.replace(Some(PendingBulk { phase: BulkPhase::Local(receiver), total, prefix }));
                self.update_selection();
                set_text(self.status, &format!("Arrêt de {total} processus en cours…"));
            }
            Err(error) => set_text(self.status, &format!("{prefix}Arrêt indisponible. {error}")),
        }
    }

    fn poll_bulk_stop(&self) {
        let Some(mut pending) = self.pending_bulk.borrow_mut().take() else { return };
        let stopped = match pending.phase {
            BulkPhase::Local(ref receiver) => match receiver.try_recv() {
                Ok(result) => {
                    for watch in result.watches {
                        self.monitor.watch(watch);
                    }
                    if !result.denied.is_empty() {
                        match stop_job::BatchJob::start(self.window, &result.denied) {
                            Ok(job) => {
                                pending.phase = BulkPhase::Elevated(job, result.stopped);
                                self.pending_bulk.replace(Some(pending));
                                return;
                            }
                            Err(error) if error.raw_os_error() == Some(ERROR_CANCELLED as i32) => {
                                pending.prefix.push_str("Autorisation Windows annulée. ");
                            }
                            Err(error) => pending.prefix.push_str(&format!("Élévation indisponible. {error}. ")),
                        }
                    }
                    result.stopped
                }
                Err(TryRecvError::Empty) => {
                    self.pending_bulk.replace(Some(pending));
                    return;
                }
                Err(TryRecvError::Disconnected) => {
                    pending.prefix.push_str("Traitement interrompu. ");
                    0
                }
            },
            BulkPhase::Elevated(ref job, first) => match job.result() {
                Some(Ok(stopped)) => first + stopped,
                Some(Err(error)) => {
                    pending.prefix.push_str(&format!("{error}. "));
                    first
                }
                None => {
                    self.pending_bulk.replace(Some(pending));
                    return;
                }
            },
        };
        set_text(self.status, &format!("{}{stopped}/{} processus arrêtés.", pending.prefix, pending.total));
        self.refresh();
        self.update_selection();
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

    fn change_firewall(&self, action: FirewallAction, selected: Option<Port>, stop_after: bool) {
        if self.firewall.borrow().is_some() || (stop_after && self.stop_in_progress()) {
            return;
        }
        let (port, protocol) = if let Some(selected) = selected.as_ref() {
            (selected.endpoint.port, selected.endpoint.protocol)
        } else if matches!(action, FirewallAction::Remove) && self.selected_count() == 0 {
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
        self.launch_firewall(vec![(port, protocol)], action, stop_after.into_iter().collect());
    }

    fn launch_firewall(&self, targets: Vec<(u16, Protocol)>, action: FirewallAction, stop_after: Vec<Port>) {
        if targets.is_empty() || self.firewall.borrow().is_some() {
            return;
        }
        let label = rule_label(&targets);
        match firewall::Job::start(self.window, targets, action) {
            Ok(job) => {
                self.firewall.replace(Some((job, stop_after)));
                self.update_selection();
                set_text(self.status, &format!("Pare-feu Windows · {label}"));
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
        let (job, mut processes) = pending.take().unwrap();
        drop(pending);
        unsafe { KillTimer(self.window, FIREWALL_TIMER) };
        let endpoint = rule_label(&job.targets);
        let message = match result {
            Ok(0) => {
                let firewall = match job.action {
                    FirewallAction::Block => format!("Trafic entrant bloqué · {endpoint}."),
                    FirewallAction::Timed(minutes) => format!("Trafic entrant bloqué pendant {minutes} min · {endpoint}."),
                    FirewallAction::Remove => format!("Blocages RustyPort retirés · {endpoint}."),
                };
                if processes.len() > 1 {
                    self.request_bulk_stop(processes, stop_job::Mode::Once, format!("{firewall} "));
                    return;
                }
                if let Some(process) = processes.pop() {
                    self.request_stop(&process, format!("{firewall} "));
                    self.update_selection();
                    return;
                }
                firewall
            }
            Ok(failed) => format!("Pare-feu · {}/{} opérations réussies · {failed} échec(s).",
                job.targets.len() - failed, job.targets.len()),
            Err(error) => error.to_string(),
        };
        set_text(self.status, &message);
        self.update_selection();
    }

}

fn rule_label(targets: &[(u16, Protocol)]) -> String {
    match targets {
        [(port, protocol)] => format!("{port}/{}", protocol.name()),
        _ => format!("{} ports", targets.len()),
    }
}

fn control(window: HWND, class: PCWSTR, text: &str, style: u32, id: u16, edge: bool) -> io::Result<HWND> {
    let handle = unsafe {
        CreateWindowExW(
            if edge { WS_EX_CLIENTEDGE } else { 0 },
            class,
            wide(text).as_ptr(),
            WS_VISIBLE | WS_CHILD | WS_CLIPSIBLINGS | style | if id != 0 || edge { WS_TABSTOP } else { 0 },
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
    write_changed_text(control, text);
}

fn write_changed_text(control: HWND, text: &str) -> bool {
    window_text(control) != text && unsafe { SetWindowTextW(control, wide(text).as_ptr()) } != 0
}

fn window_text(control: HWND) -> String {
    let length = unsafe { GetWindowTextLengthW(control) } as usize;
    let mut text = vec![0; length + 1];
    let length = unsafe { GetWindowTextW(control, text.as_mut_ptr(), text.len() as i32) } as usize;
    String::from_utf16_lossy(&text[..length])
}

fn web_search_url(port: &Port) -> String {
    let mut query = format!("port {} {} c’est quoi ?", port.endpoint.port, port.endpoint.protocol.name());
    if !port.owner.name.is_empty() && port.owner.name != "Inconnu" {
        query = format!("\"{}\" {query}", port.owner.name);
    }
    let mut url = String::from("https://www.google.com/search?q=");
    for byte in query.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            url.push(char::from(byte));
        } else {
            let _ = write!(url, "%{byte:02X}");
        }
    }
    url
}

fn under(control: HWND) -> POINT {
    let mut bounds = RECT::default();
    unsafe { GetWindowRect(control, &mut bounds) };
    POINT { x: bounds.left, y: bounds.bottom }
}

fn popup_menu(window: HWND, at: POINT, items: &[(usize, &str, bool)]) -> u32 {
    popup_menu_with_levels(window, at, items, None)
}

struct LevelMenu {
    checked: Option<u32>,
    enabled: bool,
}

fn level_for_choice(choice: u32) -> Option<Risk> {
    let index = choice.checked_sub(MENU_LEVEL_NORMAL)?;
    Risk::LEVELS.get(index as usize).copied()
}

fn popup_menu_with_levels(window: HWND, at: POINT, items: &[(usize, &str, bool)], levels: Option<LevelMenu>) -> u32 {
    let menu = unsafe { CreatePopupMenu() };
    if menu.is_null() {
        return 0;
    }
    unsafe {
        if let Some(levels) = levels {
            let submenu = CreatePopupMenu();
            if !submenu.is_null() {
                for (index, level) in Risk::LEVELS.into_iter().enumerate() {
                    let id = MENU_LEVEL_NORMAL + index as u32;
                    let flags = MF_STRING | if levels.checked == Some(id) { MF_CHECKED } else { MF_UNCHECKED };
                    AppendMenuW(submenu, flags, id as usize, wide(level.label()).as_ptr());
                }
                AppendMenuW(submenu, MF_SEPARATOR, 0, null());
                let flags = MF_STRING | if levels.checked == Some(MENU_LEVEL_AUTO) { MF_CHECKED } else { MF_UNCHECKED };
                AppendMenuW(submenu, flags, MENU_LEVEL_AUTO as usize, w!("Rétablir le classement automatique"));
                let flags = MF_POPUP | if levels.enabled { MF_ENABLED } else { MF_GRAYED };
                if AppendMenuW(menu, flags, submenu as usize, w!("Niveau")) == 0 {
                    DestroyMenu(submenu);
                }
            }
        }
        for &(id, label, enabled) in items {
            if id == 0 {
                AppendMenuW(menu, MF_SEPARATOR, 0, null());
                continue;
            }
            let flags = if enabled { MF_STRING } else { MF_STRING | MF_GRAYED };
            AppendMenuW(menu, flags, id, wide(label).as_ptr());
        }
        let result = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, at.x, at.y, 0, window, null());
        DestroyMenu(menu);
        result as u32
    }
}

unsafe extern "system" fn table_input(
    window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM, id: usize, data: usize,
) -> LRESULT {
    if message == WM_NCDESTROY {
        unsafe { RemoveWindowSubclass(window, Some(table_input), id) };
        return unsafe { DefSubclassProc(window, message, wparam, lparam) };
    }
    // The window owns the subclass only while the boxed App is alive.
    let app = unsafe { &*(data as *const App) };
    const SHIFT: usize = 0x0004;
    const CONTROL: usize = 0x0008;
    match message {
        WM_KEYDOWN if wparam == usize::from(VK_A) && unsafe { GetKeyState(i32::from(VK_CONTROL)) } < 0 => {
            app.select_all();
            return 0;
        }
        // Mouse modifier flags arrive in wParam. Preserve the native Shift range behavior.
        WM_LBUTTONDOWN if wparam & SHIFT == 0 => {
            if let Some(row) = app.row_at_point(lparam) {
                let key = app.rows.borrow().get(row).map(|item| item.key);
                if let Some(key) = key {
                    unsafe { SetFocus(window) };
                    if wparam & CONTROL != 0 {
                        let state = unsafe { SendMessageW(window, LVM_GETITEMSTATE, row, LVIS_SELECTED as isize) };
                        let selected = if state == 0 { LVIS_SELECTED } else { 0 };
                        app.set_row_state(row, selected | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                        unsafe { SendMessageW(window, LVM_SETSELECTIONMARK, 0, row as isize) };
                    } else {
                        app.select_range(row, row);
                        app.drag.set(Some((key, key)));
                        unsafe { SetCapture(window) };
                    }
                    return 0;
                }
            }
        }
        WM_MOUSEMOVE if app.drag.get().is_some() => {
            app.drag_to(lparam);
            return 0;
        }
        WM_LBUTTONUP if app.drag.get().is_some() => {
            app.drag_to(lparam);
            app.drag.set(None);
            if unsafe { GetCapture() } == window {
                unsafe { ReleaseCapture() };
            }
            return 0;
        }
        WM_CAPTURECHANGED | WM_CANCELMODE => app.drag.set(None),
        WM_RBUTTONDOWN if app.row_at_point(lparam).is_some() => return 0,
        WM_RBUTTONUP => {
            if let Some(row) = app.row_at_point(lparam) {
                app.context_actions(row);
                return 0;
            }
        }
        WM_CONTEXTMENU if lparam == -1 => {
            if let Some(entry) = app.focused_selection() {
                app.action_menu(under(app.block), entry);
                return 0;
            }
        }
        _ => {}
    }
    unsafe { DefSubclassProc(window, message, wparam, lparam) }
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
        limits.ptMinTrackSize.y = 630;
        return 0;
    }
    if let Some(app) = app {
        match message {
            WM_CLOSE => { app.hide_to_tray(); return 0; }
            WM_SYSCOMMAND if wparam == EXIT_MENU => {
                app.quit();
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
            WM_SETTINGCHANGE | WM_SYSCOLORCHANGE => {
                let previous = app.theme.replace(ui::Theme::new());
                app.apply_fonts();
                drop(previous);
                app.update_level_markers();
                unsafe { RedrawWindow(window, null(), null_mut(), RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN) };
            }
            WM_CTLCOLORSTATIC => return app.color_control(wparam as HDC, lparam as HWND),
            WM_COMMAND => {
                let id = wparam as u16;
                let notification = (wparam >> 16) as u16;
                match id {
                    ID_FILTER if notification == EN_CHANGE as u16 => {
                        app.populate();
                    }
                    ID_RISK if notification == CBN_SELCHANGE as u16 => {
                        app.populate();
                    }
                    ID_INTERVAL if notification == CBN_SELCHANGE as u16 => app.set_interval(),
                    ID_REFRESH => app.refresh(),
                    ID_STOP => app.stop_selected(),
                    ID_BLOCK => {
                        if let Some(entry) = app.focused_selection() {
                            app.action_menu(under(app.block), entry);
                        }
                    }
                    ID_UNBLOCK => {
                        if app.selected_count() > 1 {
                            app.run_bulk(app.selected_entries(), 8);
                        } else {
                            app.change_firewall(FirewallAction::Remove, app.available_port(), false);
                        }
                    }
                    ID_WATCHES => app.watches_menu(),
                    ID_PAUSE_GRAPH => app.toggle_graph_pause(),
                    ID_PORT_GRAPH => app.update_graph_series(),
                    ID_GRAPH_METRIC if notification == CBN_SELCHANGE as u16 => {
                        app.update_graph_series();
                        app.refresh_graph_mode();
                    }
                    ID_ARCHIVE_PANEL => app.toggle_archive_panel(),
                    ID_ARCHIVE_ENABLED => app.toggle_archive(),
                    ID_SAVE_ARCHIVE => app.save_history(false),
                    ID_SAVE_RANGE => app.save_history(true),
                    ID_CLEAR_ARCHIVE => app.clean_archive(),
                    ID_LEVELS => unsafe {
                        MessageBoxW(window, wide(risk::GUIDE).as_ptr(), w!("Critères des niveaux"), MB_OK | MB_ICONINFORMATION);
                    },
                    _ => {}
                }
            }
            WM_NOTIFY if lparam != 0 && !app.drawing_list.get() => {
                let note = unsafe { &*(lparam as *const NMHDR) };
                if note.hwndFrom == app.list {
                    match note.code {
                        NM_CUSTOMDRAW => return app.draw_list_row(unsafe { &mut *(lparam as *mut NMLVCUSTOMDRAW) }),
                        LVN_ITEMCHANGED => app.update_selection(),
                        LVN_COLUMNCLICK => {
                            let click = unsafe { &*(lparam as *const NMLISTVIEW) };
                            app.sort_by(click.iSubItem as usize);
                        }
                        _ => {}
                    }
                }
            }
            WM_TIMER if wparam == FIREWALL_TIMER => app.poll_firewall(),
            WM_TIMER if wparam == MONITOR_TIMER => app.poll_monitor(),
            WM_HSCROLL if lparam == app.timeline as isize => app.seek_graph(),
            WM_MOUSEMOVE => app.pointer_moved(lparam),
            WM_MOUSELEAVE => {
                app.graph_pointer.set(None);
                app.update_traffic_label();
                app.invalidate_chart();
            }
            WM_ERASEBKGND => return 1,
            WM_PAINT => {
                let mut paint = PAINTSTRUCT::default();
                let dc = unsafe { BeginPaint(window, &mut paint) };
                ui::paint_buffered(dc, paint.rcPaint, |buffer| app.paint_surface(buffer));
                unsafe { EndPaint(window, &paint) };
                return 0;
            }
            WM_PRINTCLIENT => {
                app.paint_surface(wparam as HDC);
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
            dwICC: ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES,
        };
        if InitCommonControlsEx(&setup) == 0 {
            return Err(io::Error::other("La liste Windows n’a pas pu être initialisée."));
        }
        let instance = GetModuleHandleW(null());
        let definition = WNDCLASSW {
            lpfnWndProc: Some(handle_message),
            hInstance: instance,
            hCursor: LoadCursorW(null_mut(), IDC_ARROW),
            hIcon: LoadIconW(null_mut(), IDI_APPLICATION),
            hbrBackground: (COLOR_BTNFACE + 1) as HBRUSH,
            lpszClassName: SINGLETON_CLASS,
            ..Default::default()
        };
        if RegisterClassW(&definition) == 0 {
            return Err(io::Error::last_os_error());
        }
        let window = CreateWindowExW(
            0, SINGLETON_CLASS, w!("RustyPort — Surveillance réseau"), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT, CW_USEDEFAULT, 1100, 760, null_mut(), null_mut(), instance, null(),
        );
        if window.is_null() { Err(io::Error::last_os_error()) } else { Ok(window) }
    }
}

fn run() -> io::Result<()> {
    let instance = unsafe { CreateMutexW(null(), 0, SINGLETON_MUTEX) };
    if instance.is_null() {
        return Err(io::Error::last_os_error());
    }
    let already_running = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    let _instance = ports::Handle(instance);
    if already_running {
        for _ in 0..30 {
            let mut previous = null_mut();
            loop {
                let window = unsafe { FindWindowExW(null_mut(), previous, SINGLETON_CLASS, null()) };
                if window.is_null() {
                    break;
                }
                if !unsafe { GetPropW(window, SINGLETON_PROPERTY) }.is_null() {
                    unsafe {
                        ShowWindowAsync(window, SW_RESTORE);
                        SetForegroundWindow(window);
                    }
                    return Ok(());
                }
                previous = window;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        return Ok(());
    }
    let window = create_window()?;
    unsafe {
        let app = Box::new(App::new(window).map_err(|error| {
            io::Error::other(format!("Création des contrôles impossible. {error}"))
        })?);
        SetWindowLongPtrW(window, GWLP_USERDATA, &*app as *const App as isize);
        if let Err(error) = app.bind_table_input() {
            DestroyWindow(window);
            return Err(error);
        }
        app.layout();
        app.set_sort_header();
        app.populate();
        app.poll_monitor();
        if SetTimer(window, MONITOR_TIMER, 100, None) == 0 {
            let error = io::Error::last_os_error();
            DestroyWindow(window);
            return Err(error);
        }
        ShowWindow(window, SW_SHOW);
        SetPropW(window, SINGLETON_PROPERTY, 1usize as HANDLE);
        app.tray.install();
        let system_menu = GetSystemMenu(window, 0);
        if !system_menu.is_null() {
            AppendMenuW(system_menu, MF_SEPARATOR, 0, null());
            AppendMenuW(system_menu, MF_STRING, EXIT_MENU, w!("Quitter RustyPort"));
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
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        Some(port_traffic::CLEANUP_FLAG) => std::process::exit(port_traffic::run_cleanup(arguments)),
        Some(stop_job::HELPER_FLAG) => std::process::exit(stop_job::run_helper(arguments)),
        Some(stop_job::BATCH_FLAG) => std::process::exit(stop_job::run_batch_helper(arguments)),
        Some("--embed-icon") => {
            let result = arguments.next().filter(|path| path.to_ascii_lowercase().ends_with(".exe"))
                .ok_or_else(|| io::Error::other("Fichier exécutable attendu."))
                .and_then(|path| icon::embed(std::path::Path::new(&path)));
            std::process::exit(i32::from(result.is_err()));
        }
        _ => {}
    }
    if let Err(error) = run() {
        let error = wide(&error.to_string());
        unsafe { MessageBoxW(null_mut(), error.as_ptr(), w!("RustyPort"), MB_ICONERROR) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetKeyboardState, SetKeyboardState};

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
        *app.level_preferences.borrow_mut() = Ok(LevelPreferences::in_memory());
        assert!(app._small_icon.custom && app._large_icon.custom);
        unsafe { SetWindowLongPtrW(window, GWLP_USERDATA, &*app as *const App as isize) };
        app.bind_table_input().unwrap();
        app.layout();
        assert_eq!(unsafe { SendMessageW(app.interval, CB_GETCURSEL, 0, 0) }, 1);
        assert!(app.archive.borrow().is_none());
        assert!(!app.archive_enabled.get());
        let archive_visible = || unsafe { GetWindowLongPtrW(app.archive_toggle, GWL_STYLE) as u32 & WS_VISIBLE != 0 };
        assert!(!archive_visible());
        unsafe {
            SetWindowPos(window, null_mut(), 0, 0, 900, 630, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOZORDER);
            SendMessageW(window, WM_COMMAND, usize::from(ID_ARCHIVE_PANEL), 0);
        }
        assert!(archive_visible());
        assert!(app.archive.borrow().is_none());
        let mut list_body = RECT::default();
        unsafe { GetClientRect(app.list, &mut list_body) };
        assert!(list_body.bottom >= 73);
        unsafe {
            SendMessageW(window, WM_COMMAND, usize::from(ID_ARCHIVE_PANEL), 0);
            SetWindowPos(window, null_mut(), 0, 0, 1100, 760, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOZORDER);
        }
        assert!(!archive_visible());
        unsafe {
            SendMessageW(app.archive_toggle, BM_SETCHECK, BST_CHECKED as usize, 0);
            SendMessageW(window, WM_COMMAND, usize::from(ID_ARCHIVE_ENABLED), 0);
        }
        assert!(app.archive.borrow().is_some());
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
        let pointer = ((chart.top + 20) as isize) << 16 | chart::plot(chart, false).right as isize;
        unsafe { SendMessageW(window, WM_MOUSEMOVE, 0, pointer) };
        assert!(window_text(app.traffic_status).starts_with("Il y a "));
        unsafe { SendMessageW(window, WM_MOUSELEAVE, 0, 0) };
        assert_eq!(window_text(app.traffic_status), *app.live_traffic.borrow());
        let index_of = |port| app.rows.borrow().iter().position(|row| row.key.0.port == port).unwrap();
        let row_a = index_of(a.port());
        assert_eq!(app.rows.borrow()[row_a].fields[7], "1");
        assert_eq!(app.rows.borrow()[index_of(b.port())].fields[7], "0");
        assert!(app.risk_markers.is_some());
        let mut item = LVITEMW { mask: LVIF_IMAGE, iItem: row_a as i32, ..Default::default() };
        assert_ne!(unsafe { SendMessageW(app.list, LVM_GETITEMW, 0, &mut item as *mut _ as isize) }, 0);
        assert_eq!(item.iImage, Risk::Normal as i32);
        let selection = LVITEMW { state: LVIS_SELECTED, stateMask: LVIS_SELECTED, ..Default::default() };
        unsafe { SendMessageW(app.list, LVM_SETITEMSTATE, row_a, &selection as *const _ as isize) };

        let target = [app.selected().unwrap()];
        assert_eq!(app.level_menu(&target).checked, Some(MENU_LEVEL_AUTO));
        app.change_level(&target, Some(Risk::Elevated));
        let selected = app.selected().unwrap();
        assert_eq!(selected.assessment.level, Risk::Normal);
        assert_eq!(selected.level(), Risk::Elevated);
        assert_eq!(app.rows.borrow()[index_of(a.port())].fields[0], "À risque *");
        assert!(window_text(app.details).contains("Classement automatique · Normal"));
        assert_eq!(app.level_menu(&[selected]).checked, Some(MENU_LEVEL_ELEVATED));
        app.change_level(&target, None);
        assert_eq!(app.rows.borrow()[index_of(a.port())].fields[0], "Normal");
        assert!(app.selected().unwrap().manual_level.is_none());

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
        while !app.selected().unwrap().port.established.is_empty() && Instant::now() < deadline {
            unsafe { SendMessageW(window, WM_TIMER, MONITOR_TIMER, 0) };
            thread::sleep(Duration::from_millis(25));
        }
        assert!(app.selected().unwrap().port.established.is_empty());
        assert_eq!(app.selected().unwrap().port.endpoint.port, a.port());
        assert!(window_text(app.details).contains("0 connexion(s) TCP établie(s)"));
        assert!(window_text(app.details).contains("Arrêt indisponible"));

        let busy = TcpStream::connect(b).unwrap();
        let (accepted, _) = listener_b.accept().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while app.rows.borrow()[index_of(b.port())].fields[8] != "1" && Instant::now() < deadline {
            unsafe { SendMessageW(window, WM_TIMER, MONITOR_TIMER, 0) };
            thread::sleep(Duration::from_millis(25));
        }
        assert_eq!(app.rows.borrow()[index_of(b.port())].fields[8], "1");
        app.sort_by(8);
        assert!(index_of(b.port()) < index_of(a.port()));
        assert_eq!(app.selected().unwrap().port.endpoint.port, a.port());

        let mut search = app.selected().unwrap().port;
        search.owner.name = "Démo & Co.exe".into();
        let url = web_search_url(&search);
        assert!(url.starts_with("https://www.google.com/search?q=%22D%C3%A9mo%20%26%20Co.exe%22%20port%20"));
        assert!(url.ends_with("%20TCP%20c%E2%80%99est%20quoi%20%3F"));
        assert!(!url.contains("127.0.0.1"));
        let detail = app.detail_text(&app.selected().unwrap(), true);
        assert!(detail.contains("Adresse locale · 127.0.0.1"));
        assert!(detail.contains(&format!("PID {}", std::process::id())));

        let point = |row: usize| {
            let mut rect = RECT { left: LVIR_BOUNDS as i32, ..Default::default() };
            let located = unsafe { SendMessageW(app.list, LVM_GETITEMRECT, row, &mut rect as *mut _ as isize) };
            assert_ne!(located, 0);
            (((rect.top + rect.bottom) / 2) as isize) << 16 | (rect.left + 49) as isize
        };
        let from = index_of(b.port());
        let to = index_of(a.port());
        unsafe {
            SendMessageW(app.list, WM_LBUTTONDOWN, 1, point(from));
            SendMessageW(app.list, WM_MOUSEMOVE, 1, point(to));
            SendMessageW(app.list, WM_LBUTTONUP, 0, point(to));
        }
        assert_eq!(app.selected_count(), to - from + 1);
        assert!(app.selected().is_none());
        assert!(window_text(app.details).contains("lignes sélectionnées"));
        let selection_before_sort: BTreeSet<_> = [a.port(), b.port()].into_iter().map(|port| {
            app.rows.borrow()[index_of(port)].key
        }).collect();
        app.sort_by(1);
        for row in app.rows.borrow().iter().enumerate().filter(|(_, row)| selection_before_sort.contains(&row.key)) {
            assert_ne!(unsafe { SendMessageW(app.list, LVM_GETITEMSTATE, row.0, LVIS_SELECTED as isize) }, 0);
        }
        let selected_before = app.selected_count();
        unsafe { SendMessageW(app.list, WM_LBUTTONDOWN, 0x0009, point(index_of(a.port()))) };
        assert_eq!(app.selected_count(), selected_before - 1);
        unsafe { SendMessageW(app.list, WM_LBUTTONDOWN, 0x0009, point(index_of(a.port()))) };
        assert_eq!(app.selected_count(), selected_before);
        let mut keyboard = [0u8; 256];
        unsafe {
            GetKeyboardState(keyboard.as_mut_ptr());
            let mut control_held = keyboard;
            control_held[usize::from(VK_CONTROL)] = 0x80;
            SetKeyboardState(control_held.as_ptr());
            SendMessageW(app.list, WM_KEYDOWN, usize::from(VK_A), 0);
            SetKeyboardState(keyboard.as_ptr());
        }
        assert_eq!(app.selected_count(), app.rows.borrow().len());
        assert!(app.port_metric() == chart::PortMetric::Rates);
        unsafe {
            SendMessageW(app.graph_metric, CB_SETCURSEL, 1, 0);
            SendMessageW(app.port_graph, BM_SETCHECK, BST_CHECKED as usize, 0);
            SendMessageW(window, WM_COMMAND, usize::from(ID_PORT_GRAPH), 0);
        }
        assert!(app.graph_series.borrow().as_ref().unwrap().len() >= 2);
        assert!(app.port_metric() == chart::PortMetric::Arrivals);
        assert_eq!(window_text(app.traffic_label), "Nouvelles TCP par relevé · 60 s");
        let choose_metric = |index| unsafe {
            SendMessageW(app.graph_metric, CB_SETCURSEL, index, 0);
            SendMessageW(window, WM_COMMAND, usize::from(ID_GRAPH_METRIC) | ((CBN_SELCHANGE as usize) << 16),
                app.graph_metric as isize);
        };
        choose_metric(2);
        assert!(app.port_metric() == chart::PortMetric::Established);
        assert_eq!(window_text(app.traffic_label), "Connexions TCP établies · 60 s");
        choose_metric(1);
        app.toggle_graph_pause();
        let frozen = app.paused.borrow().as_ref().unwrap().back().unwrap().at;
        let deadline = Instant::now() + Duration::from_secs(5);
        while app.traffic.borrow().points.back().unwrap().at <= frozen && Instant::now() < deadline {
            unsafe { SendMessageW(window, WM_TIMER, MONITOR_TIMER, 0) };
            thread::sleep(Duration::from_millis(25));
        }
        assert!(app.traffic.borrow().points.back().unwrap().at > frozen);
        assert_eq!(app.paused.borrow().as_ref().unwrap().back().unwrap().at, frozen);
        unsafe { SendMessageW(app.timeline, TBM_SETPOS, 1, 0) };
        app.seek_graph();
        assert!(app.paused.borrow().as_ref().unwrap().back().unwrap().at < frozen);
        app.toggle_graph_pause();
        assert!(app.paused.borrow().is_none());
        drop((busy, accepted));

        unsafe {
            SendMessageW(app.risk_filter, CB_SETCURSEL, 3, 0);
            SendMessageW(window, WM_COMMAND, usize::from(ID_RISK) | ((CBN_SELCHANGE as usize) << 16), app.risk_filter as isize);
        }
        assert!(app.rows.borrow().iter().all(|row| row.level == Risk::Elevated));
        assert!(app.selected().is_none());

        let template = app.ports.borrow().iter().find(|entry| entry.port.endpoint.port == a.port()).unwrap().clone();
        let fixtures = |first| (first..50_050).map(|number| {
            let mut port = template.port.clone();
            port.endpoint.port = number;
            Entry::new(port, template.first_seen, template.assessment.clone())
        }).collect();
        let top_index = || unsafe { SendMessageW(app.list, LVM_GETTOPINDEX, 0, 0) as usize };
        let top_port = || app.rows.borrow()[top_index()].key.0.port;
        app.sort.set(Sort { column: table_view::Column::Port, descending: false });
        unsafe { SendMessageW(app.risk_filter, CB_SETCURSEL, 0, 0) };
        app.ports.replace(fixtures(50_002));
        app.populate();
        assert_eq!(top_port(), 50_002);

        app.ports.replace(fixtures(50_000));
        app.populate();
        assert_eq!(top_port(), 50_000);
        unsafe { SendMessageW(app.list, LVM_ENSUREVISIBLE, 27, 0) };
        assert!(top_index() > 0);
        let scrolled_port = top_port();
        app.ports.replace(fixtures(49_998));
        app.populate();
        assert_eq!(top_port(), scrolled_port);

        app.set_row_state(top_index(), LVIS_SELECTED, LVIS_SELECTED);
        app.sort_by(1);
        assert_eq!(top_port(), 50_049);
        assert_eq!(app.selected().unwrap().port.endpoint.port, scrolled_port);
        unsafe { DestroyWindow(window) };
    }
}
