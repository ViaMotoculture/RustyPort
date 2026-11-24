use std::cell::Cell;
use std::mem::size_of;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::UI::WindowsAndMessaging::{HICON, RegisterWindowMessageW, WM_APP};
use windows_sys::core::w;

pub const TRAY_MESSAGE: u32 = WM_APP + 1;

pub struct Tray {
    window: HWND,
    icon: HICON,
    installed: Cell<bool>,
    pub taskbar_created: u32,
}

impl Tray {
    pub fn new(window: HWND, icon: HICON) -> Self {
        Self {
            window,
            icon,
            installed: Cell::new(false),
            taskbar_created: unsafe { RegisterWindowMessageW(w!("TaskbarCreated")) },
        }
    }

    fn data(&self) -> NOTIFYICONDATAW {
        NOTIFYICONDATAW {
            cbSize: size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: self.window,
            uID: 1,
            ..Default::default()
        }
    }

    pub fn install(&self) -> bool {
        if self.installed.get() {
            return true;
        }
        let mut icon = self.data();
        icon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        icon.uCallbackMessage = TRAY_MESSAGE;
        icon.hIcon = self.icon;
        for (slot, value) in icon.szTip.iter_mut().zip("OpenPort - Surveillance réseau".encode_utf16()) {
            *slot = value;
        }
        let installed = unsafe { Shell_NotifyIconW(NIM_ADD, &icon) } != 0;
        self.installed.set(installed);
        installed
    }

    pub fn reinstall(&self) -> bool {
        self.installed.set(false);
        self.install()
    }

    pub fn remove(&self) {
        if self.installed.replace(false) {
            unsafe { Shell_NotifyIconW(NIM_DELETE, &self.data()) };
        }
    }
}
