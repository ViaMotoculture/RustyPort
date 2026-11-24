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

pub fn plot(bounds: RECT, selection: bool) -> RECT {
    RECT { left: bounds.left + 80, right: bounds.right - if selection { 201 } else { 104 },
        top: bounds.top + 16, bottom: bounds.bottom - 24 }
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

pub fn hovered_sockets<'a>(
    point: &'a Point, points: &VecDeque<Point>, bounds: RECT, selection: Option<&[Series]>, y: i32,
) -> Vec<&'a SocketActivity> {
    if let Some(selection) = selection {
        let plot = plot(bounds, true);
        let scale = selection_scale(points, selection);
        let selected_sockets = || selection.iter().rev().filter_map(|series| point.socket(&series.key));
        let height = |socket: &SocketActivity| y_position(plot, scale, f64::from(socket.established));
        let Some(nearest) = selected_sockets().map(height).min_by_key(|position| position.abs_diff(y)) else {
            return Vec::new();
        };
        selected_sockets().filter(|socket| height(socket) == nearest).collect()
    } else {
        point.sockets.iter().filter(|socket| socket.established > 0).max_by_key(|socket| socket.established)
            .into_iter().collect()
    }
}

fn series_color(index: usize) -> COLORREF {
    const PALETTE: [COLORREF; 12] = [
        RECEIVED_COLOR, SENT_COLOR, rgb(251, 191, 111), rgb(238, 148, 195),
        rgb(196, 164, 255), rgb(178, 227, 119), rgb(253, 135, 126), rgb(111, 221, 245),
        rgb(244, 234, 133), rgb(220, 183, 150), rgb(137, 202, 254), rgb(250, 166, 244),
    ];
    PALETTE[index % PALETTE.len()]
}

pub fn paint(
    dc: HDC, font: HFONT, bounds: RECT, points: &VecDeque<Point>, pointer: Option<i32>,
    selection: Option<&[Series]>, paused: bool,
) {
    let high_contrast = high_contrast();
    let (background, grid, text, received, sent) = if high_contrast {
        unsafe { (
            GetSysColor(COLOR_WINDOW), GetSysColor(COLOR_GRAYTEXT), GetSysColor(COLOR_WINDOWTEXT),
            GetSysColor(COLOR_WINDOWTEXT), GetSysColor(COLOR_HIGHLIGHT),
        ) }
    } else {
        (rgb(19, 38, 44), rgb(47, 75, 82), rgb(203, 225, 229), RECEIVED_COLOR, SENT_COLOR)
    };
    let scale = if let Some(selection) = selection {
        selection_scale(points, selection)
    } else {
        points.iter().filter_map(|point| point.rates)
            .map(|rate| rate.received.max(rate.sent)).fold(1.0, f64::max)
    };
    let hovered_point = pointer.and_then(|x| sample_at(points, bounds, selection.is_some(), x));
    let plot = plot(bounds, selection.is_some());
    let hovered = hovered_point.zip(points.back()).map(|(point, latest)| (point, sample_x(plot, latest, point)));
    unsafe {
        if SaveDC(dc) == 0 {
            return;
        }
        SelectObject(dc, GetStockObject(DC_BRUSH));
        SetDCBrushColor(dc, background);
        FillRect(dc, &bounds, GetStockObject(DC_BRUSH));
        SelectObject(dc, GetStockObject(DC_PEN));
        SetDCPenColor(dc, grid);
        MoveToEx(dc, plot.right + 10, bounds.top + 8, std::ptr::null_mut());
        LineTo(dc, plot.right + 10, bounds.bottom - 10);
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
        SelectObject(dc, font);
        SetBkMode(dc, TRANSPARENT as i32);
        SetTextColor(dc, text);
        let top = if selection.is_some() { format!("{scale:.0} TCP") } else { rate_label(scale) };
        let zero = if selection.is_some() { "0 TCP" } else { "0 o/s" };
        paint_text(dc, bounds.left + 9, plot.top - 5, &top);
        if selection.is_none() && scale >= 2.0 {
            paint_text(dc, bounds.left + 9, (plot.top + plot.bottom) / 2 - 7, &rate_label(scale / 2.0));
        }
        paint_text(dc, bounds.left + 9, plot.bottom - 9, zero);
        for (step, label) in ["−60 s", "−45 s", "−30 s", "−15 s"].into_iter().enumerate() {
            let x = plot.left + (plot.right - plot.left) * step as i32 / 4;
            paint_text(dc, x - 13, plot.bottom + 5, label);
        }
        let right_label = if paused { "Vue figée" } else { "Maintenant" };
        let right_axis = RECT { left: plot.right - 83, right: plot.right + 1, top: plot.bottom + 3, bottom: bounds.bottom - 3 };
        paint_label(dc, right_axis, DT_RIGHT, right_label);

        if let Some((_, x)) = hovered {
            SetDCPenColor(dc, text);
            MoveToEx(dc, x, plot.top, std::ptr::null_mut());
            LineTo(dc, x, plot.bottom + 1);
        }
        if let Some(selection) = selection {
            if selection.is_empty() {
                SetTextColor(dc, text);
                paint_text(dc, plot.left + 12, plot.top + 16, "Sélectionnez un ou plusieurs ports TCP dans la liste.");
            }
            let available = ((bounds.bottom - bounds.top - 20) / 18).max(1) as usize;
            let listed = if selection.len() > available { available.saturating_sub(1) } else { available };
            for (index, series) in selection.iter().enumerate() {
                let color = if high_contrast { text } else { series_color(index) };
                draw_series(dc, plot, points, scale, color, |point| series_value(point, series));
                draw_marker(dc, plot, hovered, scale, color, |point| series_value(point, series));
                if index < listed {
                    paint_legend(dc, bounds, plot.right, plot.top - 6 + index as i32 * 18, color, &series.label);
                }
            }
            if selection.len() > listed {
                SetTextColor(dc, text);
                paint_text(dc, plot.right + 19, plot.top - 6 + listed as i32 * 18,
                    &format!("+ {} courbes", selection.len() - listed));
            }
        } else {
            for (is_received, label, color, offset) in [(true, "Reçu", received, -6), (false, "Envoyé", sent, 15)] {
                let value = |point: &Point| {
                    point.rates.map(|rates| if is_received { rates.received } else { rates.sent })
                };
                paint_legend(dc, bounds, plot.right, plot.top + offset, color, label);
                draw_series(dc, plot, points, scale, color, value);
                draw_marker(dc, plot, hovered, scale, color, value);
            }
        }
        RestoreDC(dc, -1);
    }
}

unsafe fn draw_marker(
    dc: HDC, plot: RECT, hovered: Option<(&Point, i32)>, scale: f64, color: COLORREF,
    value_at: impl Fn(&Point) -> Option<f64>,
) {
    let Some((point, x)) = hovered else { return };
    let Some(value) = value_at(point) else { return };
    let y = y_position(plot, scale, value);
    unsafe {
        SetDCPenColor(dc, color);
        SetDCBrushColor(dc, color);
        Ellipse(dc, x - 3, y - 3, x + 4, y + 4);
    }
}

unsafe fn paint_legend(dc: HDC, bounds: RECT, plot_right: i32, top: i32, color: COLORREF, label: &str) {
    let line = RECT { left: plot_right + 19, top: top + 8, right: plot_right + 32, bottom: top + 10 };
    let text = RECT { left: line.right + 6, top, right: bounds.right - 6, bottom: top + 17 };
    unsafe {
        SetDCBrushColor(dc, color);
        FillRect(dc, &line, GetStockObject(DC_BRUSH));
        SetTextColor(dc, color);
        paint_label(dc, text, DT_LEFT, label);
    }
}

unsafe fn paint_label(dc: HDC, mut rect: RECT, alignment: DRAW_TEXT_FORMAT, label: &str) {
    let label = wide(label);
    unsafe { DrawTextW(dc, label.as_ptr(), (label.len() - 1) as i32, &mut rect,
        alignment | DT_END_ELLIPSIS | DT_NOPREFIX | DT_SINGLELINE | DT_VCENTER) };
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn hover_identifies_overlapping_curves_for_selected_ports() {
        let sockets = [("443/TCP", 0), ("8514/TCP", 0), ("9000/TCP", 1)].map(|(endpoint, established)| {
            SocketActivity {
                key: endpoint.into(), endpoint: endpoint.into(), established,
                name: String::new(), address: String::new(), peer: String::new(),
            }
        });
        let selection = sockets.iter().map(|socket| Series {
            key: socket.key.clone(), label: socket.endpoint.clone(),
        }).collect::<Vec<_>>();
        let points = VecDeque::from([Point {
            at: Instant::now(), rates: None, span: Duration::ZERO, sockets: sockets.into(),
        }]);
        let point = points.back().unwrap();
        let bounds = RECT { left: 0, top: 0, right: 800, bottom: 150 };
        let plot = plot(bounds, true);
        let ports = |y| hovered_sockets(point, &points, bounds, Some(&selection), y)
            .into_iter().map(|socket| socket.endpoint.as_str()).collect::<Vec<_>>();
        assert_eq!(ports(plot.bottom), ["8514/TCP", "443/TCP"]);
        assert_eq!(ports(plot.top), ["9000/TCP"]);
    }
}
