use std::io;
use std::mem::size_of;

use windows_sys::Win32::Foundation::{HWND, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
use windows_sys::core::w;

use crate::ports::{Handle, wide};

pub fn launch(window: HWND, program: &[u16], arguments: &str) -> io::Result<Handle> {
    let arguments = wide(arguments);
    let mut execution = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        hwnd: window,
        lpVerb: w!("runas"),
        lpFile: program.as_ptr(),
        lpParameters: arguments.as_ptr(),
        nShow: SW_HIDE,
        ..Default::default()
    };
    if unsafe { ShellExecuteExW(&mut execution) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if execution.hProcess.is_null() {
        return Err(io::Error::other("Windows n’a pas lancé la commande."));
    }
    Ok(Handle(execution.hProcess))
}

pub fn exit_code(process: &Handle) -> Option<io::Result<u32>> {
    match unsafe { WaitForSingleObject(process.0, 0) } {
        WAIT_TIMEOUT => None,
        WAIT_OBJECT_0 => {
            let mut exit = 0;
            Some(if unsafe { GetExitCodeProcess(process.0, &mut exit) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(exit)
            })
        }
        _ => Some(Err(io::Error::last_os_error())),
    }
}
