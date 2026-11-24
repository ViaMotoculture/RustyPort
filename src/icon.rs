use std::ptr::{copy_nonoverlapping, null_mut};

use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateIconFromResourceEx, DestroyIcon, HICON, IDI_APPLICATION, LoadIconW,
};

const DATA: &[u8] = include_bytes!("../assets/OpenPort.ico");

pub struct Icon {
    pub handle: HICON,
    pub custom: bool,
}

impl Icon {
    pub fn load(size: u8) -> Self {
        let handle = resource(size).map_or(null_mut(), |data| {
            let mut aligned = vec![0u32; data.len().div_ceil(4)];
            unsafe {
                copy_nonoverlapping(data.as_ptr(), aligned.as_mut_ptr().cast(), data.len());
                CreateIconFromResourceEx(aligned.as_ptr().cast(), data.len() as u32, 1,
                    0x00030000, i32::from(size), i32::from(size), 0)
            }
        });
        if handle.is_null() {
            Self { handle: unsafe { LoadIconW(null_mut(), IDI_APPLICATION) }, custom: false }
        } else {
            Self { handle, custom: true }
        }
    }
}

impl Drop for Icon {
    fn drop(&mut self) {
        if self.custom {
            unsafe { DestroyIcon(self.handle) };
        }
    }
}

fn resource(size: u8) -> Option<&'static [u8]> {
    let count = u16::from_le_bytes(DATA.get(4..6)?.try_into().ok()?) as usize;
    let entries = DATA.get(6..6 + count * 16)?;
    let entry = entries.chunks_exact(16).find(|entry| entry[0] == size && entry[1] == size)?;
    let length = u32::from_le_bytes(entry[8..12].try_into().ok()?) as usize;
    let offset = u32::from_le_bytes(entry[12..16].try_into().ok()?) as usize;
    DATA.get(offset..offset.checked_add(length)?)
}
