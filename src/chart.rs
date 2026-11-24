use std::mem::size_of;

use windows_sys::Win32::Foundation::{COLORREF, RECT};
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::UI::Accessibility::{HIGHCONTRASTW, HCF_HIGHCONTRASTON};
use windows_sys::Win32::UI::WindowsAndMessaging::{SPI_GETHIGHCONTRAST, SystemParametersInfoW};

use crate::monitor::{GRAPH_WINDOW, Point, TrafficHistory};
use crate::ports::wide;

pub const RECEIVED_COLOR: COLORREF = rgb(87, 219, 191);
pub const SENT_COLOR: COLORREF = rgb(129, 175, 253);

pub const fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    r as u32 | ((g as u32) << 8) | ((b as u32) << 16)
}

pub fn high_contrast() -> bool {
    let mut settings = HIGHCONTRASTW { cbSize: size_of::<HIGHCONTRASTW>() as u32, ..Default::default() };
    let ok = unsafe { SystemParametersInfoW(SPI_GETHIGHCONTRAST, settings.cbSize, (&mut settings as *mut HIGHCONTRASTW).cast(), 0) };
    ok != 0 && settings.dwFlags & HCF_HIGHCONTRASTON != 0
}

pub fn rate_label(rate: f64) -> String {
    if rate > 0.0 && rate < 1.0 {
        return "< 1 o/s".into();
    }
    let (factor, unit) = if rate >= 1_073_741_824.0 {
        (1_073_741_824.0, "Gio/s")
    } else if rate >= 1_048_576.0 {
        (1_048_576.0, "Mio/s")
    } else if rate >= 1024.0 {
        (1024.0, "Kio/s")
    } else {
        return format!("{rate:.0} o/s");
    };
    format!("{:.1} {unit}", rate / factor).replace('.', ",")
}

fn plot(bounds: RECT) -> RECT {
    RECT { left: bounds.left + 88, right: bounds.right - 88, top: bounds.top + 13, bottom: bounds.bottom - 25 }
}

fn sample_x(plot: RECT, latest: &Point, point: &Point) -> i32 {
    let age = latest.at.duration_since(point.at).as_secs_f64() / GRAPH_WINDOW.as_secs_f64();
    plot.right - (age * f64::from(plot.right - plot.left)).round() as i32
}

pub fn sample_at(history: &TrafficHistory, bounds: RECT, x: i32) -> Option<&Point> {
    let plot = plot(bounds);
    let latest = history.points.back()?;
    let leftmost = sample_x(plot, latest, history.points.front()?);
    if !(leftmost..=plot.right).contains(&x) {
        return None;
    }
    history.points.iter().rev().min_by_key(|point| sample_x(plot, latest, point).abs_diff(x))
}

pub fn paint(dc: HDC, bounds: RECT, history: &TrafficHistory, pointer: Option<i32>) {
    let high_contrast = high_contrast();
    let (background, grid, text, received, sent) = if high_contrast {
        unsafe { (
            GetSysColor(COLOR_WINDOW), GetSysColor(COLOR_GRAYTEXT), GetSysColor(COLOR_WINDOWTEXT),
            GetSysColor(COLOR_WINDOWTEXT), GetSysColor(COLOR_HIGHLIGHT),
        ) }
    } else {
        (rgb(16, 27, 42), rgb(48, 65, 83), rgb(203, 215, 229), RECEIVED_COLOR, SENT_COLOR)
    };
    let scale = history.points.iter().filter_map(|point| point.rates)
        .map(|rate| rate.received.max(rate.sent)).fold(1.0, f64::max);
    let plot = plot(bounds);
    unsafe {
        if SaveDC(dc) == 0 {
            return;
        }
        SelectObject(dc, GetStockObject(DC_BRUSH));
        SetDCBrushColor(dc, background);
        FillRect(dc, &bounds, GetStockObject(DC_BRUSH));
        SelectObject(dc, GetStockObject(DC_PEN));
        SetDCPenColor(dc, grid);
        for step in 0..=2 {
            let y = plot.top + (plot.bottom - plot.top) * step / 2;
            MoveToEx(dc, plot.left, y, std::ptr::null_mut());
            LineTo(dc, plot.right + 1, y);
        }
        for step in 0..=4 {
            let x = plot.left + (plot.right - plot.left) * step / 4;
            MoveToEx(dc, x, plot.top, std::ptr::null_mut());
            LineTo(dc, x, plot.bottom + 1);
        }
        SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
        SetBkMode(dc, TRANSPARENT as i32);
        SetTextColor(dc, text);
        paint_text(dc, bounds.left + 9, plot.top - 5, &rate_label(scale));
        paint_text(dc, bounds.left + 9, plot.bottom - 9, "0 o/s");
        paint_text(dc, plot.left, plot.bottom + 5, "−60 s");
        paint_text(dc, plot.right - 48, plot.bottom + 5, "Maintenant");
        SetTextColor(dc, received);
        paint_text(dc, plot.right + 15, plot.top - 4, "Reçu");
        SetTextColor(dc, sent);
        paint_text(dc, plot.right + 15, plot.top + 16, "Envoyé");

        if let Some(latest) = history.points.back() {
            if let Some(point) = pointer.and_then(|x| sample_at(history, bounds, x)) {
                let x = sample_x(plot, latest, point);
                SetDCPenColor(dc, text);
                MoveToEx(dc, x, plot.top, std::ptr::null_mut());
                LineTo(dc, x, plot.bottom + 1);
            }
            for (is_received, color) in [(true, received), (false, sent)] {
                SetDCPenColor(dc, color);
                let mut previous = None;
                for point in &history.points {
                    let Some(rates) = point.rates else {
                        previous = None;
                        continue;
                    };
                    let rate = if is_received { rates.received } else { rates.sent };
                    let x = sample_x(plot, latest, point);
                    let y = plot.bottom - (rate / scale * f64::from(plot.bottom - plot.top)).round() as i32;
                    if let Some((last_x, last_y)) = previous {
                        MoveToEx(dc, last_x, last_y, std::ptr::null_mut());
                        LineTo(dc, x, y);
                    }
                    SetPixel(dc, x, y, color);
                    previous = Some((x, y));
                }
            }
        }
        RestoreDC(dc, -1);
    }
}

unsafe fn paint_text(dc: HDC, x: i32, y: i32, label: &str) {
    let label = wide(label);
    unsafe { TextOutW(dc, x, y, label.as_ptr(), (label.len() - 1) as i32) };
}
