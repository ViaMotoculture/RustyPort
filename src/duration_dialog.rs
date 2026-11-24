use std::io;
use std::ffi::OsString;
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr::null;

use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{EM_SETCUEBANNER, EM_SETLIMITTEXT};
use windows_sys::Win32::UI::Controls::Dialogs::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::w;

use crate::{ports::wide, window_text};

const MINUTES: u16 = 300;
const ERROR_TEXT: u16 = 301;
const RANGE_FROM: u16 = 304;
const RANGE_TO: u16 = 305;
const STATIC: u16 = 0x0082;
const EDIT: u16 = 0x0081;
const BUTTON: u16 = 0x0080;
type Item<'a> = (u16, u16, u32, [u16; 4], &'a str);

pub fn ask(owner: HWND, title: &str, context: &str) -> io::Result<Option<u16>> {
    let template = template(title, context);
    let result = unsafe {
        DialogBoxIndirectParamW(GetModuleHandleW(null()), template.as_ptr().cast(),
            owner, Some(dialog_message), 0)
    };
    match result {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(None),
        minutes => Ok(u16::try_from(minutes).ok()),
    }
}

pub fn review(owner: HWND, title: &str, context: &str, details: &str, confirm: bool) -> bool {
    let mut items = vec![
        (STATIC, 0xffff, 0, [12, 10, 332, 36], context),
        (EDIT, 302, WS_TABSTOP | WS_BORDER | WS_VSCROLL | (ES_MULTILINE | ES_READONLY) as u32, [12, 51, 332, 147], details),
        (BUTTON, IDCANCEL as u16, WS_TABSTOP | BS_DEFPUSHBUTTON as u32, [285, 208, 59, 17],
            if confirm { "Annuler" } else { "Fermer" }),
    ];
    if confirm {
        items.push((BUTTON, IDOK as u16, WS_TABSTOP | BS_PUSHBUTTON as u32, [215, 208, 64, 17], "Confirmer"));
    }
    let data = build_template(title, 356, 237, &items);
    unsafe { DialogBoxIndirectParamW(GetModuleHandleW(null()), data.as_ptr().cast(),
        owner, Some(review_message), 0) == 1 }
}

pub fn choose_range(owner: HWND, first: u64, last: u64) -> Option<(u64, u64)> {
    let start = export_clock(first / 1000);
    let end = export_clock(last.div_ceil(1000));
    let context = format!("Historique de {start} à {end}. Temps écoulé depuis l’ouverture.");
    let items = [
        (STATIC, 0xffff, 0, [12, 11, 268, 28], context.as_str()),
        (STATIC, 0xffff, 0, [12, 42, 146, 15], "&Début (hh:mm:ss)"),
        (EDIT, RANGE_FROM, WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL as u32, [159, 39, 107, 17], start.as_str()),
        (STATIC, 0xffff, 0, [12, 66, 146, 15], "&Fin (hh:mm:ss)"),
        (EDIT, RANGE_TO, WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL as u32, [159, 63, 107, 17], end.as_str()),
        (STATIC, ERROR_TEXT, 0, [12, 87, 266, 22], ""),
        (BUTTON, IDOK as u16, WS_TABSTOP | BS_DEFPUSHBUTTON as u32, [138, 115, 62, 18], "Continuer"),
        (BUTTON, IDCANCEL as u16, WS_TABSTOP | BS_PUSHBUTTON as u32, [205, 115, 62, 18], "Annuler"),
    ];
    let data = build_template("Période à sauvegarder", 285, 145, &items);
    let mut range = None;
    unsafe { DialogBoxIndirectParamW(GetModuleHandleW(null()), data.as_ptr().cast(), owner,
        Some(range_message), &mut range as *mut Option<(u64, u64)> as isize) };
    range
}

fn export_clock(seconds: u64) -> String {
    format!("{:02}:{:02}:{:02}", seconds / 3600, seconds / 60 % 60, seconds % 60)
}

fn parse_export_clock(text: &str) -> Option<u64> {
    let (hours, tail) = text.trim().split_once(':')?;
    let (minutes, seconds) = tail.split_once(':')?;
    let hours = hours.parse::<u64>().ok()?;
    let minutes = minutes.parse::<u64>().ok()?;
    let seconds = seconds.parse::<u64>().ok()?;
    if minutes >= 60 || seconds >= 60 {
        return None;
    }
    hours.checked_mul(3600)?.checked_add(minutes * 60 + seconds)?.checked_mul(1000)
}

unsafe extern "system" fn range_message(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> isize {
    if message == WM_INITDIALOG {
        unsafe { SetWindowLongPtrW(window, GWLP_USERDATA, lparam) };
        return 1;
    }
    if message == WM_COMMAND && wparam as u16 == IDOK as u16 {
        let start = parse_export_clock(&window_text(unsafe { GetDlgItem(window, i32::from(RANGE_FROM)) }));
        let end = parse_export_clock(&window_text(unsafe { GetDlgItem(window, i32::from(RANGE_TO)) }));
        if let (Some(start), Some(end)) = (start, end)
            && start <= end
        {
            let data = unsafe { (GetWindowLongPtrW(window, GWLP_USERDATA) as *mut Option<(u64, u64)>).as_mut() };
            if let Some(data) = data {
                *data = Some((start, end.saturating_add(999)));
                unsafe { EndDialog(window, 1) };
                return 1;
            }
        }
        unsafe { SetDlgItemTextW(window, i32::from(ERROR_TEXT), w!("Vérifie le format et l’ordre des deux horaires.")) };
        return 1;
    }
    unsafe { review_message(window, message, wparam, lparam) }
}

pub fn save_csv(owner: HWND) -> io::Result<Option<PathBuf>> {
    let mut file = vec![0u16; 32768];
    let proposed = wide("OpenPort-releves.csv");
    file[..proposed.len()].copy_from_slice(&proposed);
    let filter = wide("Fichiers CSV (*.csv)\0*.csv\0");
    let mut request = OPENFILENAMEW {
        lStructSize: size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: owner, lpstrFilter: filter.as_ptr(), nFilterIndex: 1,
        lpstrFile: file.as_mut_ptr(), nMaxFile: file.len() as u32,
        lpstrDefExt: w!("csv"), lpstrTitle: w!("Sauvegarder les relevés OpenPort"),
        Flags: OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR | OFN_PATHMUSTEXIST,
        ..Default::default()
    };
    if unsafe { GetSaveFileNameW(&mut request) } == 0 {
        let code = unsafe { CommDlgExtendedError() };
        return if code == 0 { Ok(None) } else { Err(io::Error::other(format!("Dialogue de sauvegarde indisponible ({code})."))) };
    }
    let end = file.iter().position(|&unit| unit == 0).unwrap_or(file.len());
    Ok(Some(PathBuf::from(OsString::from_wide(&file[..end]))))
}

unsafe extern "system" fn review_message(window: HWND, message: u32, wparam: WPARAM, _: LPARAM) -> isize {
    match message {
        WM_INITDIALOG => {
            unsafe { SetFocus(GetDlgItem(window, IDCANCEL)) };
            0
        }
        WM_CLOSE => unsafe { EndDialog(window, 0) as isize },
        WM_COMMAND => match wparam as i32 & 0xffff {
            IDOK => unsafe { EndDialog(window, 1) as isize },
            IDCANCEL => unsafe { EndDialog(window, 0) as isize },
            _ => 0,
        },
        _ => 0,
    }
}

unsafe extern "system" fn dialog_message(window: HWND, message: u32, wparam: WPARAM, _: LPARAM) -> isize {
    match message {
        WM_INITDIALOG => unsafe {
            let edit = GetDlgItem(window, i32::from(MINUTES));
            SendMessageW(edit, EM_SETLIMITTEXT, 16, 0);
            SendMessageW(edit, EM_SETCUEBANNER, 1, w!("Ex. 10") as isize);
            SetFocus(edit);
            0
        },
        WM_CLOSE => unsafe { EndDialog(window, 0) as isize },
        WM_COMMAND if wparam as u16 == IDCANCEL as u16 => unsafe { EndDialog(window, 0) as isize },
        WM_COMMAND if wparam as u16 == IDOK as u16 => {
            let value = window_text(unsafe { GetDlgItem(window, i32::from(MINUTES)) });
            let minutes = value.trim().parse::<u16>().ok().filter(|minutes| *minutes > 0);
            unsafe {
                if let Some(minutes) = minutes {
                    EndDialog(window, minutes as isize);
                } else {
                    SetDlgItemTextW(window, i32::from(ERROR_TEXT), w!("Saisis un nombre entier entre 1 et 65 535."));
                    SetFocus(GetDlgItem(window, i32::from(MINUTES)));
                }
            }
            1
        }
        WM_COMMAND if wparam as u16 == MINUTES && (wparam >> 16) as u16 == EN_CHANGE as u16 => {
            unsafe { SetDlgItemTextW(window, i32::from(ERROR_TEXT), w!("")) };
            1
        }
        _ => 0,
    }
}

fn template(title: &str, context: &str) -> Vec<u32> {
    let items = [
        (STATIC, 0xffff, 0, [12, 10, 242, 26], context),
        (STATIC, 0xffff, 0, [12, 43, 100, 14], "&Minutes"),
        (EDIT, MINUTES, WS_TABSTOP | WS_BORDER | (ES_NUMBER | ES_AUTOHSCROLL) as u32, [112, 40, 68, 16], ""),
        (STATIC, ERROR_TEXT, 0, [12, 63, 242, 13], ""),
        (BUTTON, IDOK as u16, WS_TABSTOP | BS_DEFPUSHBUTTON as u32, [128, 83, 59, 17], "Valider"),
        (BUTTON, IDCANCEL as u16, WS_TABSTOP | BS_PUSHBUTTON as u32, [194, 83, 59, 17], "Annuler"),
    ];
    build_template(title, 265, 111, &items)
}

fn build_template(title: &str, width: u16, height: u16, items: &[Item<'_>]) -> Vec<u32> {
    let mut words = Vec::new();
    push_dword(&mut words, WS_POPUP | WS_CAPTION | WS_SYSMENU | (DS_MODALFRAME | DS_SETFONT | DS_CENTER) as u32);
    push_dword(&mut words, 0);
    words.extend([items.len() as u16, 0, 0, width, height, 0, 0]);
    words.extend(wide(title));
    words.push(9);
    words.extend(wide("Segoe UI"));
    for &(class, id, style, bounds, text) in items {
        if words.len() % 2 != 0 {
            words.push(0);
        }
        push_dword(&mut words, WS_CHILD | WS_VISIBLE | style);
        push_dword(&mut words, 0);
        words.extend(bounds);
        words.extend([id, 0xffff, class]);
        words.extend(wide(text));
        words.push(0);
    }
    // Use DWORD storage to align the standard header and item templates.
    words.chunks(2).map(|pair| {
        u32::from(pair[0]) | (u32::from(pair.get(1).copied().unwrap_or_default()) << 16)
    }).collect()
}

fn push_dword(words: &mut Vec<u16>, value: u32) {
    words.extend([value as u16, (value >> 16) as u16]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::null_mut;
    use std::thread;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;

    #[test]
    fn native_duration_dialog_validates_input_and_cancels() {
        for cancel in [false, true] {
            let thread_id = unsafe { GetCurrentThreadId() };
            let title = format!("OpenPort test durée {thread_id}");
            let lookup = wide(&title);
            let driver = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let dialog = unsafe { FindWindowW(null(), lookup.as_ptr()) };
                    let mut owner = 0;
                    if !dialog.is_null() && unsafe { GetWindowThreadProcessId(dialog, &mut owner) } == thread_id
                        && owner == std::process::id()
                    {
                        unsafe {
                            SetDlgItemTextW(dialog, i32::from(MINUTES), w!("0"));
                            SendMessageW(dialog, WM_COMMAND, IDOK as usize, 0);
                            let validation = GetWindowTextLengthW(GetDlgItem(dialog, i32::from(ERROR_TEXT))) > 0;
                            SetDlgItemTextW(dialog, i32::from(MINUTES), w!("27"));
                            if !cancel {
                                SendMessageW(dialog, WM_COMMAND, IDOK as usize, 0);
                            }
                            PostMessageW(dialog, WM_COMMAND, IDCANCEL as usize, 0);
                            return validation;
                        }
                    }
                    if Instant::now() >= deadline {
                        unsafe { PostThreadMessageW(thread_id, WM_QUIT, 0, 0) };
                        return false;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            });
            let result = ask(null_mut(), &title, "Durée de blocage d’un port de test.");
            assert!(driver.join().unwrap());
            assert_eq!(result.unwrap(), if cancel { None } else { Some(27) });
        }
    }
}
