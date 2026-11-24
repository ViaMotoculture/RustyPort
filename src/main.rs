#![windows_subsystem = "windows"]

mod firewall;
mod ports;

use std::cell::{Cell, RefCell};
use std::io;
use std::mem::size_of;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::{PCWSTR, w};

use ports::{Endpoint, Port, Protocol, wide};

const ID_FILTER: u16 = 100;
const ID_REFRESH: u16 = 101;
const ID_STOP: u16 = 102;
const ID_BLOCK: u16 = 103;
const ID_UNBLOCK: u16 = 104;
const FIREWALL_TIMER: usize = 1;

struct App {
    window: HWND,
    filter_label: HWND,
    filter: HWND,
    refresh: HWND,
    list: HWND,
    details: HWND,
    stop: HWND,
    block: HWND,
    unblock: HWND,
    status: HWND,
    ports: RefCell<Vec<Port>>,
    visible: RefCell<Vec<usize>>,
    drawing_list: Cell<bool>,
    firewall: RefCell<Option<firewall::Job>>,
}

impl App {
    fn new(window: HWND) -> io::Result<Self> {
        let filter_label = control(window, w!("STATIC"), "Filtrer", 0, 0, false)?;
        let filter = control(window, w!("EDIT"), "", ES_AUTOHSCROLL as u32, ID_FILTER, true)?;
        unsafe {
            SendMessageW(filter, EM_SETCUEBANNER, 1, w!("Filtrer par port, processus ou adresse") as isize);
        }
        let refresh = control(window, w!("BUTTON"), "Actualiser", 0, ID_REFRESH, false)?;
        let list = control(
            window,
            WC_LISTVIEWW,
            "",
            LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            0,
            true,
        )?;
        unsafe {
            SendMessageW(
                list,
                LVM_SETEXTENDEDLISTVIEWSTYLE,
                0,
                (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP) as isize,
            );
        }
        for (index, (label, width)) in [
            ("Port", 75),
            ("Protocole", 88),
            ("Adresse locale", 215),
            ("Processus", 260),
            ("PID", 74),
        ].into_iter().enumerate() {
            let mut label = wide(label);
            let column = LVCOLUMNW {
                mask: LVCF_TEXT | LVCF_WIDTH,
                cx: width,
                pszText: label.as_mut_ptr(),
                ..Default::default()
            };
            unsafe { SendMessageW(list, LVM_INSERTCOLUMNW, index, &column as *const _ as isize) };
        }
        let details = control(
            window, w!("EDIT"), "", (ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL) as u32 | WS_VSCROLL, 0, true,
        )?;
        let stop = control(window, w!("BUTTON"), "Terminer le processus…", 0, ID_STOP, false)?;
        let block = control(window, w!("BUTTON"), "Bloquer le trafic entrant", 0, ID_BLOCK, false)?;
        let unblock = control(window, w!("BUTTON"), "Retirer le blocage", 0, ID_UNBLOCK, false)?;
        let status = control(window, w!("STATIC"), "", 0, 0, false)?;
        Ok(Self {
            window, filter_label, filter, refresh, list, details, stop, block, unblock, status,
            ports: RefCell::new(Vec::new()),
            visible: RefCell::new(Vec::new()),
            drawing_list: Cell::new(false),
            firewall: RefCell::new(None),
        })
    }

    fn layout(&self) {
        let mut client = RECT::default();
        unsafe { GetClientRect(self.window, &mut client) };
        let width = client.right;
        let height = client.bottom;
        let content = width - 28;
        let controls = [
            (self.filter_label, 14, 19, 49, 22),
            (self.filter, 66, 14, content - 170, 27),
            (self.refresh, width - 120, 13, 106, 29),
            (self.list, 14, 52, content, height - 220),
            (self.details, 14, height - 158, content, 76),
            (self.stop, 14, height - 72, 172, 31),
            (self.block, 195, height - 72, 184, 31),
            (self.unblock, 388, height - 72, 146, 31),
            (self.status, 14, height - 29, content, 22),
        ];
        for (control, x, y, w, h) in controls {
            unsafe { MoveWindow(control, x, y, w.max(1), h.max(1), 1) };
        }
        let process_width = (content - 75 - 88 - 215 - 74 - 21).max(130);
        unsafe { SendMessageW(self.list, LVM_SETCOLUMNWIDTH, 3, process_width as isize) };
    }

    fn selected(&self) -> Option<Port> {
        let row = unsafe { SendMessageW(self.list, LVM_GETNEXTITEM, usize::MAX, LVNI_SELECTED as isize) };
        let index = *self.visible.borrow().get(usize::try_from(row).ok()?)?;
        self.ports.borrow().get(index).cloned()
    }

    fn refresh(&self) {
        let previous = self.selected().map(|port| port.endpoint);
        match ports::list() {
            Ok(ports) => {
                self.ports.replace(ports);
                self.populate(previous);
            }
            Err(error) => set_text(self.status, &format!("Lecture des ports impossible. {error}")),
        }
    }

    fn populate(&self, previous: Option<Endpoint>) {
        let query = window_text(self.filter).to_lowercase();
        let ports = self.ports.borrow();
        let mut visible = Vec::new();
        let mut restore = None;
        self.drawing_list.set(true);
        unsafe {
            SendMessageW(self.list, WM_SETREDRAW, 0, 0);
            SendMessageW(self.list, LVM_DELETEALLITEMS, 0, 0);
        }
        for (index, port) in ports.iter().enumerate() {
            let endpoint = port.endpoint;
            let address = endpoint.address_label();
            let pid = endpoint.pid.to_string();
            let lookup = format!(
                "{} {} {} {} {} {}", endpoint.label(), address, pid,
                port.owner.name, port.owner.path, port.owner.services.join(" ")
            ).to_lowercase();
            if !query.split_whitespace().all(|part| lookup.contains(part)) {
                continue;
            }
            let row = visible.len();
            let fields = [
                endpoint.port.to_string(),
                endpoint.protocol.name().into(),
                address,
                port.owner.name.clone(),
                pid,
            ];
            for (column, value) in fields.iter().enumerate() {
                let mut value = wide(value);
                let item = LVITEMW {
                    mask: LVIF_TEXT,
                    iItem: row as i32,
                    iSubItem: column as i32,
                    pszText: value.as_mut_ptr(),
                    ..Default::default()
                };
                let message = if column == 0 { LVM_INSERTITEMW } else { LVM_SETITEMTEXTW };
                unsafe { SendMessageW(self.list, message, row, &item as *const _ as isize) };
            }
            if previous == Some(endpoint) {
                restore = Some(row);
            }
            visible.push(index);
        }
        let shown = visible.len();
        let total = ports.len();
        drop(ports);
        self.visible.replace(visible);
        unsafe {
            if let Some(row) = restore {
                let item = LVITEMW {
                    state: LVIS_SELECTED | LVIS_FOCUSED,
                    stateMask: LVIS_SELECTED | LVIS_FOCUSED,
                    ..Default::default()
                };
                SendMessageW(self.list, LVM_SETITEMSTATE, row, &item as *const _ as isize);
                SendMessageW(self.list, LVM_ENSUREVISIBLE, row, 0);
            }
            SendMessageW(self.list, WM_SETREDRAW, 1, 0);
            InvalidateRect(self.list, null(), 1);
        }
        self.drawing_list.set(false);
        let status = if shown == total {
            format!("{total} entrées · ports TCP en écoute et sockets UDP")
        } else {
            format!("{shown} entrées sur {total}")
        };
        set_text(self.status, &status);
        self.update_selection();
    }

    fn typed_port(&self) -> Option<u16> {
        window_text(self.filter).trim().parse::<u16>().ok().filter(|port| *port != 0)
    }

    fn update_selection(&self) {
        let selected = self.selected();
        let available = self.firewall.borrow().is_none();
        unsafe {
            EnableWindow(self.stop, i32::from(selected.as_ref().is_some_and(Port::can_stop)));
            EnableWindow(self.block, i32::from(available && selected.is_some()));
            EnableWindow(self.unblock, i32::from(available && (selected.is_some() || self.typed_port().is_some())));
        }
        let Some(port) = selected else {
            let prompt = if self.typed_port().is_some() {
                "Sélectionne une ligne ou clique sur « Retirer le blocage » pour le numéro saisi."
            } else {
                "Sélectionne un port pour voir son programme et son adresse d’écoute."
            };
            set_text(self.details, prompt);
            return;
        };
        let endpoint = port.endpoint;
        let address = if endpoint.is_local() {
            "Ce PC uniquement"
        } else if endpoint.address.is_unspecified() {
            "Toutes les interfaces de cette famille IP"
        } else {
            "Adresse d’une interface réseau"
        };
        let kind = if endpoint.protocol == Protocol::Tcp { "TCP en écoute" } else { "Socket UDP" };
        let mut detail = format!("{}  ·  {kind}  ·  {address}", endpoint.label());
        if let Some(usage) = usual_use(endpoint) {
            detail.push_str(&format!("  ·  Usage courant — {usage}"));
        }
        if !port.owner.path.is_empty() {
            detail.push_str(&format!("\r\n{}", port.owner.path));
        }
        if !port.owner.services.is_empty() {
            detail.push_str(&format!("\r\nServices de ce processus — {}", port.owner.services.join(", ")));
        }
        set_text(self.details, &detail);
    }

    fn stop_selected(&self) {
        let Some(port) = self.selected().filter(Port::can_stop) else { return };
        let message = format!(
            "Terminer {} (PID {}) ?\nToutes ses tâches et connexions seront interrompues.",
            port.owner.name, port.endpoint.pid
        );
        let answer = unsafe {
            MessageBoxW(
                self.window, wide(&message).as_ptr(), w!("OpenPort"),
                MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION,
            )
        };
        if answer == IDYES {
            match ports::stop(&port) {
                Ok(()) => {
                    self.refresh();
                    set_text(self.status, &format!("Processus terminé. {}", port.owner.name));
                }
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    self.refresh();
                    set_text(self.status, &error.to_string());
                }
                Err(error) => {
                    self.refresh();
                    set_text(self.status, &format!("Arrêt impossible. {error}"));
                }
            }
        }
    }

    fn change_firewall(&self, block: bool) {
        if self.firewall.borrow().is_some() {
            return;
        }
        let (port, protocol) = if let Some(selected) = self.selected() {
            (selected.endpoint.port, selected.endpoint.protocol)
        } else if !block {
            let Some(port) = self.typed_port() else { return };
            let Some(protocol) = self.choose_protocol(port) else { return };
            (port, protocol)
        } else {
            return;
        };
        match firewall::Job::start(self.window, port, protocol, block) {
            Ok(job) => {
                self.firewall.replace(Some(job));
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
        let menu = unsafe { CreatePopupMenu() };
        if menu.is_null() {
            return None;
        }
        let mut placement = RECT::default();
        let selection = unsafe {
            AppendMenuW(menu, MF_STRING, 1, wide(&format!("{port}/TCP")).as_ptr());
            AppendMenuW(menu, MF_STRING, 2, wide(&format!("{port}/UDP")).as_ptr());
            GetWindowRect(self.unblock, &mut placement);
            let selection = TrackPopupMenu(
                menu, TPM_RETURNCMD | TPM_NONOTIFY, placement.left, placement.top,
                0, self.window, null(),
            );
            DestroyMenu(menu);
            selection
        };
        match selection {
            1 => Some(Protocol::Tcp),
            2 => Some(Protocol::Udp),
            _ => None,
        }
    }

    fn poll_firewall(&self) {
        let mut pending = self.firewall.borrow_mut();
        let Some(result) = pending.as_ref().and_then(firewall::Job::result) else { return };
        let job = pending.take().unwrap();
        drop(pending);
        unsafe { KillTimer(self.window, FIREWALL_TIMER) };
        let protocol = job.protocol.name();
        let port = job.port;
        let message = match result {
            Ok(()) if job.block => format!("Règle de blocage entrant activée pour {port}/{protocol}."),
            Ok(()) => format!("Blocage OpenPort retiré pour {port}/{protocol}."),
            Err(error) => error.to_string(),
        };
        set_text(self.status, &message);
        self.update_selection();
    }
}

fn usual_use(endpoint: Endpoint) -> Option<&'static str> {
    match (endpoint.protocol, endpoint.port) {
        (Protocol::Tcp, 22) => Some("SSH"),
        (_, 53) => Some("DNS"),
        (Protocol::Udp, 67 | 68) => Some("DHCP"),
        (Protocol::Tcp, 80) => Some("HTTP"),
        (Protocol::Tcp, 443) => Some("HTTPS"),
        (Protocol::Udp, 443) => Some("QUIC / HTTP/3"),
        (Protocol::Tcp, 135) => Some("RPC Windows"),
        (Protocol::Tcp, 139 | 445) => Some("Partage de fichiers Windows"),
        (Protocol::Udp, 1900) => Some("SSDP / découverte UPnP"),
        (Protocol::Tcp, 3306) => Some("MySQL"),
        (_, 3389) => Some("Bureau à distance"),
        (Protocol::Udp, 5353) => Some("mDNS"),
        (Protocol::Udp, 5355) => Some("LLMNR"),
        (Protocol::Tcp, 5432) => Some("PostgreSQL"),
        (Protocol::Tcp, 6379) => Some("Redis"),
        _ => None,
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

unsafe extern "system" fn handle_message(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if message == WM_DESTROY {
        unsafe { PostQuitMessage(0) };
        return 0;
    }
    if message == WM_GETMINMAXINFO {
        let limits = unsafe { &mut *(lparam as *mut MINMAXINFO) };
        limits.ptMinTrackSize.x = 650;
        limits.ptMinTrackSize.y = 370;
        return 0;
    }
    // The box in run() outlives the message loop and owns this window's state.
    let app = unsafe { (GetWindowLongPtrW(window, GWLP_USERDATA) as *const App).as_ref() };
    if let Some(app) = app {
        match message {
            WM_SIZE if wparam != SIZE_MINIMIZED as usize => app.layout(),
            WM_COMMAND => {
                let id = wparam as u16;
                let notification = (wparam >> 16) as u16;
                match id {
                    ID_FILTER if notification == EN_CHANGE as u16 => {
                        app.populate(app.selected().map(|port| port.endpoint));
                    }
                    ID_REFRESH => app.refresh(),
                    ID_STOP => app.stop_selected(),
                    ID_BLOCK => app.change_firewall(true),
                    ID_UNBLOCK => app.change_firewall(false),
                    _ => {}
                }
            }
            WM_NOTIFY if lparam != 0 && !app.drawing_list.get() => {
                let note = unsafe { &*(lparam as *const NMHDR) };
                if note.hwndFrom == app.list && note.code == LVN_ITEMCHANGED {
                    app.update_selection();
                }
            }
            WM_TIMER if wparam == FIREWALL_TIMER => app.poll_firewall(),
            _ => {}
        }
    }
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

fn run() -> io::Result<()> {
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
            0, class, w!("OpenPort — Ports locaux"), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT, CW_USEDEFAULT, 900, 570, null_mut(), null_mut(), instance, null(),
        );
        if window.is_null() {
            return Err(io::Error::last_os_error());
        }
        let app = Box::new(App::new(window).map_err(|error| {
            io::Error::other(format!("Création des contrôles impossible. {error}"))
        })?);
        SetWindowLongPtrW(window, GWLP_USERDATA, &*app as *const App as isize);
        app.layout();
        app.refresh();
        ShowWindow(window, SW_SHOW);
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
