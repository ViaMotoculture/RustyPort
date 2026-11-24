use std::mem::size_of;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{copy_nonoverlapping, null_mut};

use windows_sys::Win32::Graphics::Gdi::{BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateDIBSection, DIB_RGB_COLORS, DeleteObject};
use windows_sys::Win32::System::LibraryLoader::{BeginUpdateResourceW, EndUpdateResourceW, UpdateResourceW};
use windows_sys::Win32::UI::Controls::{HIMAGELIST, ILC_COLOR24, ILC_MASK, ImageList_AddMasked, ImageList_Create, ImageList_Destroy};

use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateIconFromResourceEx, DestroyIcon, HICON, IDI_APPLICATION, LoadIconW,
};

const DATA: &[u8] = include_bytes!("../assets/RustyPort.ico");

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

pub struct RiskMarkers(pub HIMAGELIST);

impl RiskMarkers {
    pub fn new() -> Option<Self> {
        const SIZE: i32 = 12;
        const TRANSPARENT: u32 = 0x00ff00ff;
        let list = unsafe { ImageList_Create(SIZE, SIZE, ILC_COLOR24 | ILC_MASK, 3, 1) };
        if list == 0 {
            return None;
        }
        let markers = Self(list);
        let info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: SIZE, biHeight: -SIZE, biPlanes: 1, biBitCount: 32, biCompression: BI_RGB,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits = null_mut();
        let bitmap = unsafe { CreateDIBSection(null_mut(), &info, DIB_RGB_COLORS, &mut bits, null_mut(), 0) };
        if bitmap.is_null() {
            return None;
        }
        // Keep the image order identical to Risk::LEVELS.
        let colors = [(0x00c7ead4, 0x00518667), (0x00fae7b4, 0x00a77831), (0x00f6d7d6, 0x00a85b54)];
        let pixels = unsafe { std::slice::from_raw_parts_mut(bits.cast::<u32>(), (SIZE * SIZE) as usize) };
        let mut added = true;
        for (index, (fill, stroke)) in colors.into_iter().enumerate() {
            for (index, pixel) in pixels.iter_mut().enumerate() {
                let index = index as i32;
                let x = 2 * (index % SIZE) - (SIZE - 1);
                let y = 2 * (index / SIZE) - (SIZE - 1);
                *pixel = match x * x + y * y {
                    0..=49 => fill,
                    50..=85 => stroke,
                    _ => TRANSPARENT,
                };
            }
            if unsafe { ImageList_AddMasked(markers.0, bitmap, TRANSPARENT) } != index as i32 {
                added = false;
                break;
            }
        }
        unsafe { DeleteObject(bitmap) };
        added.then_some(markers)
    }
}

impl Drop for RiskMarkers {
    fn drop(&mut self) {
        unsafe { ImageList_Destroy(self.0) };
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

pub fn embed(path: &Path) -> io::Result<()> {
    let path: Vec<_> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let update = unsafe { BeginUpdateResourceW(path.as_ptr(), 0) };
    if update.is_null() {
        return Err(io::Error::last_os_error());
    }
    let write = |kind: usize, id: usize, bytes: &[u8]| -> io::Result<()> {
        let ok = unsafe { UpdateResourceW(update, kind as *const u16, id as *const u16, 0,
            bytes.as_ptr().cast(), bytes.len() as u32) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    };
    let result = (|| {
        let count = u16::from_le_bytes([DATA[4], DATA[5]]) as usize;
        let mut group = DATA[..6].to_vec();
        for (index, entry) in DATA[6..6 + count * 16].chunks_exact(16).enumerate() {
            let image = resource(entry[0]).ok_or_else(|| io::Error::other("Image d’icône illisible."))?;
            let id = index + 1;
            write(3, id, image)?;
            group.extend_from_slice(&entry[..12]);
            group.extend_from_slice(&(id as u16).to_le_bytes());
        }
        write(14, 1, &group)
    })();
    let done = unsafe { EndUpdateResourceW(update, i32::from(result.is_err())) };
    result?;
    if done == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}
