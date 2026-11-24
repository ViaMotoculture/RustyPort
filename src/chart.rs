use std::collections::VecDeque;
use std::mem::size_of;

use windows_sys::Win32::Foundation::{COLORREF, RECT};
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::UI::Accessibility::{HIGHCONTRASTW, HCF_HIGHCONTRASTON};
use windows_sys::Win32::UI::WindowsAndMessaging::{SPI_GETHIGHCONTRAST, SystemParametersInfoW};

use crate::monitor::{GRAPH_WINDOW, Point, SocketActivity};
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

pub struct Series {
    pub key: String,
    pub label: String,
}

fn plot(bounds: RECT, selection: bool) -> RECT {
    RECT { left: bounds.left + 88, right: bounds.right - if selection { 171 } else { 88 },
        top: bounds.top + 13, bottom: bounds.bottom - 25 }
}

fn sample_x(plot: RECT, latest: &Point, point: &Point) -> i32 {
    let age = latest.at.duration_since(point.at).as_secs_f64() / GRAPH_WINDOW.as_secs_f64();
    plot.right - (age * f64::from(plot.right - plot.left)).round() as i32
}

fn y_position(plot: RECT, scale: f64, value: f64) -> i32 {
    plot.bottom - (value / scale * f64::from(plot.bottom - plot.top)).round() as i32
}

pub fn sample_at(points: &VecDeque<Point>, bounds: RECT, selection: bool, x: i32) -> Option<&Point> {
    let plot = plot(bounds, selection);
    let latest = points.back()?;
    let leftmost = sample_x(plot, latest, points.front()?);
    if !(leftmost..=plot.right).contains(&x) {
        return None;
    }
    points.iter().rev().min_by_key(|point| sample_x(plot, latest, point).abs_diff(x))
}

fn series_value(point: &Point, series: &Series) -> Option<f64> {
    point.socket(&series.key).map(|socket| f64::from(socket.established))
}

fn selection_scale(points: &VecDeque<Point>, selection: &[Series]) -> f64 {
    selection.iter().flat_map(|series| points.iter().filter_map(move |point| series_value(point, series)))
        .fold(1.0, f64::max)
}

pub fn hovered_socket<'a>(
    point: &'a Point, points: &VecDeque<Point>, bounds: RECT, selection: Option<&[Series]>, y: i32,
) -> Option<&'a SocketActivity> {
    if let Some(selection) = selection {
        let plot = plot(bounds, true);
        let scale = selection_scale(points, selection);
        selection.iter().filter_map(|series| point.socket(&series.key))
            .min_by_key(|socket| y_position(plot, scale, f64::from(socket.established)).abs_diff(y))
    } else {
        point.sockets.iter().filter(|socket| socket.established > 0).max_by_key(|socket| socket.established)
    }
}

fn series_color(index: usize) -> COLORREF {
    const PALETTE: [COLORREF; 8] = [
        RECEIVED_COLOR, SENT_COLOR, rgb(251, 191, 111), rgb(238, 148, 195),
        rgb(196, 164, 255), rgb(178, 227, 119), rgb(253, 135, 126), rgb(111, 221, 245),
    ];
    PALETTE[index % PALETTE.len()]
}

pub fn paint(
    dc: HDC, bounds: RECT, points: &VecDeque<Point>, pointer: Option<i32>,
    selection: Option<&[Series]>, paused: bool,
) {
    let high_contrast = high_contrast();
    let (background, grid, text, received, sent) = if high_contrast {
        unsafe { (
            GetSysColor(COLOR_WINDOW), GetSysColor(COLOR_GRAYTEXT), GetSysColor(COLOR_WINDOWTEXT),
            GetSysColor(COLOR_WINDOWTEXT), GetSysColor(COLOR_HIGHLIGHT),
        ) }
    } else {
        (rgb(16, 27, 42), rgb(48, 65, 83), rgb(203, 215, 229), RECEIVED_COLOR, SENT_COLOR)
    };
    let scale = if let Some(selection) = selection {
        selection_scale(points, selection)
    } else {
        points.iter().filter_map(|point| point.rates)
            .map(|rate| rate.received.max(rate.sent)).fold(1.0, f64::max)
    };
    let plot = plot(bounds, selection.is_some());
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
        let top = if selection.is_some() { format!("{scale:.0} TCP") } else { rate_label(scale) };
        let zero = if selection.is_some() { "0 TCP" } else { "0 o/s" };
        paint_text(dc, bounds.left + 9, plot.top - 5, &top);
        paint_text(dc, bounds.left + 9, plot.bottom - 9, zero);
        paint_text(dc, plot.left, plot.bottom + 5, "−60 s");
        paint_text(dc, plot.right - 48, plot.bottom + 5, if paused { "Vue figée" } else { "Maintenant" });

        if let Some(latest) = points.back() {
            if let Some(point) = pointer.and_then(|x| sample_at(points, bounds, selection.is_some(), x)) {
                let x = sample_x(plot, latest, point);
                SetDCPenColor(dc, text);
                MoveToEx(dc, x, plot.top, std::ptr::null_mut());
                LineTo(dc, x, plot.bottom + 1);
            }
        }
        if let Some(selection) = selection {
            if selection.is_empty() {
                SetTextColor(dc, text);
                paint_text(dc, plot.left + 12, plot.top + 16, "Sélectionne un ou plusieurs ports TCP.");
            }
            for (index, series) in selection.iter().enumerate() {
                let color = if high_contrast { text } else { series_color(index) };
                draw_series(dc, plot, points, scale, color, |point| series_value(point, series));
                if index < 3 {
                    let label: String = series.label.chars().take(25).collect();
                    SetTextColor(dc, color);
                    paint_text(dc, plot.right + 11, plot.top - 4 + index as i32 * 16, &label);
                }
            }
            if selection.len() > 3 {
                SetTextColor(dc, text);
                paint_text(dc, plot.right + 11, plot.top + 44, &format!("+ {} autres", selection.len() - 3));
            }
        } else {
            for (is_received, label, color, offset) in [(true, "Reçu", received, -4), (false, "Envoyé", sent, 16)] {
                SetTextColor(dc, color);
                paint_text(dc, plot.right + 15, plot.top + offset, label);
                draw_series(dc, plot, points, scale, color, |point| {
                    point.rates.map(|rates| if is_received { rates.received } else { rates.sent })
                });
            }
        }
        RestoreDC(dc, -1);
    }
}

unsafe fn draw_series(
    dc: HDC, plot: RECT, points: &VecDeque<Point>, scale: f64, color: COLORREF,
    value_at: impl Fn(&Point) -> Option<f64>,
) {
    let Some(latest) = points.back() else { return };
    let mut previous = None;
    unsafe {
        SetDCPenColor(dc, color);
        for point in points {
            let Some(value) = value_at(point) else {
                previous = None;
                continue;
            };
            let x = sample_x(plot, latest, point);
            let y = y_position(plot, scale, value);
            if let Some((last_x, last_y)) = previous {
                MoveToEx(dc, last_x, last_y, std::ptr::null_mut());
                LineTo(dc, x, y);
            }
            SetPixel(dc, x, y, color);
            previous = Some((x, y));
        }
    }
}

unsafe fn paint_text(dc: HDC, x: i32, y: i32, label: &str) {
    let label = wide(label);
    unsafe { TextOutW(dc, x, y, label.as_ptr(), (label.len() - 1) as i32) };
}
