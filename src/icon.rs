use std::mem::size_of;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{copy_nonoverlapping, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_RESOURCE_DATA_NOT_FOUND, ERROR_RESOURCE_LANG_NOT_FOUND, ERROR_RESOURCE_NAME_NOT_FOUND,
    ERROR_RESOURCE_TYPE_NOT_FOUND, FreeLibrary, GetLastError, HMODULE,
};
use windows_sys::Win32::Graphics::Gdi::{BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateDIBSection, DIB_RGB_COLORS, DeleteObject};
use windows_sys::Win32::System::LibraryLoader::{
    BeginUpdateResourceW, EndUpdateResourceW, EnumResourceLanguagesExW, LoadLibraryExW, UpdateResourceW,
    LOAD_LIBRARY_AS_DATAFILE, LOAD_LIBRARY_AS_IMAGE_RESOURCE, RESOURCE_ENUM_LN,
};
use windows_sys::Win32::UI::Controls::{HIMAGELIST, ILC_COLOR24, ILC_MASK, ImageList_AddMasked, ImageList_Create, ImageList_Destroy};

use windows_sys::Win32::UI::WindowsAndMessaging::{
    CREATEPROCESS_MANIFEST_RESOURCE_ID, CreateIconFromResourceEx, DestroyIcon, HICON, IDI_APPLICATION,
    LoadIconW, RT_GROUP_ICON, RT_ICON, RT_MANIFEST,
};
use windows_sys::core::PCWSTR;

const DATA: &[u8] = include_bytes!("../assets/RustyPort.ico");
const MANIFEST: &[u8] = include_bytes!("../assets/RustyPort.manifest");
const MANIFEST_ID: PCWSTR = CREATEPROCESS_MANIFEST_RESOURCE_ID as usize as PCWSTR;

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

struct ResourceModule(HMODULE);

impl ResourceModule {
    fn open(path: &[u16]) -> io::Result<Self> {
        let module = unsafe {
            LoadLibraryExW(path.as_ptr(), null_mut(), LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE)
        };
        if module.is_null() { Err(io::Error::last_os_error()) } else { Ok(Self(module)) }
    }

    fn manifest_languages(&self) -> io::Result<Vec<u16>> {
        let mut languages = Vec::<u16>::new();
        let found = unsafe {
            EnumResourceLanguagesExW(self.0, RT_MANIFEST, MANIFEST_ID, Some(collect_language),
                &mut languages as *mut Vec<u16> as isize, RESOURCE_ENUM_LN, 0)
        };
        if found == 0 {
            match unsafe { GetLastError() } {
                ERROR_RESOURCE_DATA_NOT_FOUND | ERROR_RESOURCE_TYPE_NOT_FOUND |
                ERROR_RESOURCE_NAME_NOT_FOUND | ERROR_RESOURCE_LANG_NOT_FOUND => {}
                code => return Err(io::Error::from_raw_os_error(code as i32)),
            }
        }
        Ok(languages)
    }
}

impl Drop for ResourceModule {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.0) };
    }
}

unsafe extern "system" fn collect_language(_: HMODULE, _: PCWSTR, _: PCWSTR, language: u16, data: isize) -> i32 {
    // Enumeration is synchronous and the caller keeps the vector alive for all callbacks.
    unsafe { (&mut *(data as *mut Vec<u16>)).push(language) };
    1
}

pub fn embed(path: &Path) -> io::Result<()> {
    let path: Vec<_> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut languages = ResourceModule::open(&path)?.manifest_languages()?;
    languages.push(0);
    languages.sort_unstable();
    languages.dedup();
    let update = unsafe { BeginUpdateResourceW(path.as_ptr(), 0) };
    if update.is_null() {
        return Err(io::Error::last_os_error());
    }
    let write = |kind: PCWSTR, id: PCWSTR, language: u16, bytes: &[u8]| -> io::Result<()> {
        let ok = unsafe { UpdateResourceW(update, kind, id, language,
            bytes.as_ptr().cast(), bytes.len() as u32) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    };
    let result = (|| -> io::Result<()> {
        let count = u16::from_le_bytes([DATA[4], DATA[5]]) as usize;
        let mut group = DATA[..6].to_vec();
        for (index, entry) in DATA[6..6 + count * 16].chunks_exact(16).enumerate() {
            let image = resource(entry[0]).ok_or_else(|| io::Error::other("Image d’icône illisible."))?;
            let id = index + 1;
            write(RT_ICON, id as PCWSTR, 0, image)?;
            group.extend_from_slice(&entry[..12]);
            group.extend_from_slice(&(id as u16).to_le_bytes());
        }
        write(RT_GROUP_ICON, 1usize as PCWSTR, 0, &group)?;
        for language in languages {
            write(RT_MANIFEST, MANIFEST_ID, language, MANIFEST)?;
        }
        Ok(())
    })();
    let done = unsafe { EndUpdateResourceW(update, i32::from(result.is_err())) };
    result?;
    if done == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use windows_sys::Win32::System::LibraryLoader::{FindResourceExW, LoadResource, LockResource, SizeofResource};

    #[test]
    fn packaged_manifest_replaces_existing_language_variants_without_running_the_executable() {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("target")
            .join(format!("manifest-test-{}-{unique}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("resource-test.exe");
        fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        let wide: Vec<_> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let update = unsafe { BeginUpdateResourceW(wide.as_ptr(), 0) };
        assert!(!update.is_null());
        let old = b"existing manifest variant";
        for language in [1033, 1036] {
            assert_ne!(unsafe { UpdateResourceW(update, RT_MANIFEST, MANIFEST_ID, language,
                old.as_ptr().cast(), old.len() as u32) }, 0);
        }
        assert_ne!(unsafe { EndUpdateResourceW(update, 0) }, 0);
        embed(&path).unwrap();

        let module = ResourceModule::open(&wide).unwrap();
        let languages = module.manifest_languages().unwrap();
        assert!([0, 1033, 1036].iter().all(|language| languages.contains(language)));
        for language in languages {
            let resource = unsafe { FindResourceExW(module.0, RT_MANIFEST, MANIFEST_ID, language) };
            assert!(!resource.is_null());
            let data = unsafe { LockResource(LoadResource(module.0, resource)) };
            let size = unsafe { SizeofResource(module.0, resource) } as usize;
            assert!(!data.is_null());
            assert_eq!(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), size) }, MANIFEST);
        }
        assert!(!unsafe { FindResourceExW(module.0, RT_GROUP_ICON, 1usize as PCWSTR, 0) }.is_null());
        drop(module);
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
