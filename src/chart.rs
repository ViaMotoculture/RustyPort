use std::collections::VecDeque;
use std::mem::size_of;

use windows_sys::Win32::Foundation::{COLORREF, RECT};
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::UI::Accessibility::{HIGHCONTRASTW, HCF_HIGHCONTRASTON};
use windows_sys::Win32::UI::WindowsAndMessaging::{SPI_GETHIGHCONTRAST, SystemParametersInfoW};

use crate::monitor::{GRAPH_WINDOW, Point, SocketActivity};
use crate::ports::{Protocol, wide};

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

#[derive(PartialEq, Eq)]
pub struct Series {
    pub key: String,
    pub label: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PortMetric {
    Rates,
    Arrivals,
    Established,
}

impl PortMetric {
    fn value(self, socket: &SocketActivity) -> Option<f64> {
        match self {
            Self::Rates => socket.port_rates.map(|rates| rates.received + rates.sent),
            Self::Arrivals if socket.protocol == Protocol::Tcp => socket.arrivals.map(f64::from),
            Self::Established if socket.protocol == Protocol::Tcp => Some(f64::from(socket.established)),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub struct PortSelection<'a> {
    pub series: &'a [Series],
    pub metric: PortMetric,
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct SelectionStats {
    pub active: usize,
    pub zero: usize,
    pub no_data: usize,
}

pub fn selection_stats(points: &VecDeque<Point>, selection: PortSelection) -> SelectionStats {
    let mut stats = SelectionStats::default();
    for (_, peak) in selected_peaks(points, selection) {
        stats.observe(peak);
    }
    stats
}

impl SelectionStats {
    fn observe(&mut self, peak: Option<f64>) {
        match peak {
            Some(0.0) => self.zero += 1,
            Some(_) => self.active += 1,
            None => self.no_data += 1,
        }
    }
}

pub fn plot(bounds: RECT, selection: bool) -> RECT {
    RECT { left: bounds.left + 80, right: bounds.right - if selection { 201 } else { 104 },
        top: bounds.top + 16, bottom: bounds.bottom - 24 }
}

fn series_plot(plot: RECT) -> RECT {
    RECT { top: plot.top + 5, bottom: plot.bottom - 4, ..plot }
}

fn sample_x(plot: RECT, latest: &Point, point: &Point) -> i32 {
    let age = latest.at.duration_since(point.at).as_secs_f64() / GRAPH_WINDOW.as_secs_f64();
    plot.right - (age * f64::from(plot.right - plot.left)).round() as i32
}

fn y_position(plot: RECT, scale: f64, value: f64) -> i32 {
    plot.bottom - (value / scale * f64::from(plot.bottom - plot.top)).round() as i32
}

fn samples_for(points: &VecDeque<Point>, selection: Option<PortMetric>) -> impl DoubleEndedIterator<Item = &Point> {
    points.iter().filter(move |point| selection != Some(PortMetric::Rates) || point.port_span.is_some())
}

pub fn sample_at(points: &VecDeque<Point>, bounds: RECT, selection: Option<PortMetric>, x: i32) -> Option<&Point> {
    let plot = plot(bounds, selection.is_some());
    let latest = points.back()?;
    let samples = || samples_for(points, selection);
    let leftmost = sample_x(plot, latest, samples().next()?);
    if !(leftmost..=plot.right).contains(&x) {
        return None;
    }
    samples().rev().min_by_key(|point| sample_x(plot, latest, point).abs_diff(x))
}

fn series_value(point: &Point, series: &Series, metric: PortMetric) -> Option<f64> {
    point.socket(&series.key).and_then(|socket| metric.value(socket))
}

fn selected_peaks<'a>(points: &'a VecDeque<Point>, selection: PortSelection<'a>)
    -> impl Iterator<Item = (&'a Series, Option<f64>)> + 'a
{
    selection.series.iter().map(move |series| {
        let peak = samples_for(points, Some(selection.metric)).filter_map(|point| series_value(point, series, selection.metric))
            .reduce(f64::max);
        (series, peak)
    })
}

fn series_scale(metric: PortMetric, peak: Option<f64>) -> f64 {
    let ceiling = peak.unwrap_or(0.0) * 1.1;
    match metric {
        PortMetric::Rates => ceiling.max(1.0),
        _ => ceiling.ceil().max(2.0),
    }
}

pub fn hovered_sockets<'a>(
    point: &'a Point, points: &VecDeque<Point>, bounds: RECT, selection: Option<PortSelection<'_>>, y: i32,
) -> Vec<&'a SocketActivity> {
    if let Some(selection) = selection {
        if selection.metric == PortMetric::Rates && point.port_span.is_none() {
            return Vec::new();
        }
        let plot = series_plot(plot(bounds, true));
        let peak = selected_peaks(points, selection).filter_map(|(_, peak)| peak).reduce(f64::max);
        let scale = series_scale(selection.metric, peak);
        let positioned = || selection.series.iter().rev().filter_map(|series| {
            let socket = point.socket(&series.key)?;
            let value = selection.metric.value(socket)?;
            Some((socket, y_position(plot, scale, value)))
        });
        let Some(nearest) = positioned().map(|(_, height)| height).min_by_key(|position| position.abs_diff(y)) else {
            return Vec::new();
        };
        positioned().filter_map(|(socket, height)| (height == nearest).then_some(socket)).collect()
    } else {
        point.sockets.iter().filter(|socket| socket.protocol == Protocol::Tcp && socket.established > 0)
            .max_by_key(|socket| socket.established)
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
    selection: Option<PortSelection<'_>>, paused: bool,
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
    let selected = selection.map(|selection| selected_peaks(points, selection).collect::<Vec<_>>());
    let metric = selection.map(|selection| selection.metric);
    let scale = if let Some((metric, selected)) = metric.zip(selected.as_ref()) {
        series_scale(metric, selected.iter().filter_map(|(_, peak)| *peak).reduce(f64::max))
    } else {
        points.iter().filter_map(|point| point.rates)
            .map(|rate| rate.received.max(rate.sent)).fold(1.0, f64::max)
    };
    let hovered_point = pointer.and_then(|x| sample_at(points, bounds, metric, x));
    let plot = plot(bounds, selection.is_some());
    let data_plot = if selection.is_some() { series_plot(plot) } else { plot };
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
            let y = data_plot.top + (data_plot.bottom - data_plot.top) * step / 2;
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
        let unit = match metric {
            Some(PortMetric::Arrivals) => Some("nouv."),
            Some(PortMetric::Established) => Some("TCP"),
            _ => None,
        };
        let top = unit.map_or_else(|| rate_label(scale), |unit| format!("{scale:.0} {unit}"));
        let zero = unit.map_or_else(|| "0 o/s".into(), |unit| format!("0 {unit}"));
        paint_text(dc, bounds.left + 9, data_plot.top - 5, &top);
        if unit.is_none() && scale >= 2.0 {
            paint_text(dc, bounds.left + 9, (data_plot.top + data_plot.bottom) / 2 - 7, &rate_label(scale / 2.0));
        }
        paint_text(dc, bounds.left + 9, data_plot.bottom - 9, &zero);
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
        if let Some((metric, selected)) = metric.zip(selected.as_deref()) {
            let mut stats = SelectionStats::default();
            for &(_, peak) in selected {
                stats.observe(peak);
            }
            let note = if selected.is_empty() {
                Some(match metric {
                    PortMetric::Rates => "Sélectionnez un ou plusieurs ports TCP ou UDP dans la liste.",
                    _ => "Sélectionnez un ou plusieurs ports TCP dans la liste.",
                })
            } else if stats.zero == 0 && stats.active == 0 {
                Some("Aucun relevé disponible pour ces ports sur cette période.")
            } else if stats.active == 0 {
                Some(match metric {
                    PortMetric::Rates => "Aucun octet observé pour ces ports sur cette période.",
                    PortMetric::Arrivals => "Aucune nouvelle connexion TCP observée sur cette période.",
                    PortMetric::Established => "Aucune connexion TCP établie observée sur cette période.",
                })
            } else {
                None
            };
            if let Some(note) = note {
                SetTextColor(dc, text);
                paint_text(dc, plot.left + 12, plot.top + 16, note);
            }

            // The shared baseline breaks wherever no zero-only port was measured.
            let zero_color = if high_contrast { text } else { rgb(139, 166, 170) };
            if stats.zero > 0 {
                let zero_series = selected.iter().filter(|(_, peak)| *peak == Some(0.0))
                    .map(|(series, _)| *series).collect::<Vec<_>>();
                let zero_value = |point: &Point| {
                    zero_series.iter().any(|series| series_value(point, series, metric) == Some(0.0)).then_some(0.0)
                };
                draw_series(dc, data_plot, points, Some(metric), scale, zero_color, 1, zero_value);
                draw_marker(dc, data_plot, hovered, scale, zero_color, zero_value);
            }

            let available = ((bounds.bottom - bounds.top - 20) / 18).max(1) as usize;
            let has_summary = stats.zero + stats.no_data > 0;
            let active_slots = available.saturating_sub(usize::from(has_summary));
            let overflow = stats.active > active_slots && active_slots > 1;
            let listed = stats.active.min(active_slots - usize::from(overflow));
            let legend_start = plot.top - 6;
            let active = selected.iter().filter(|(_, peak)| peak.is_some_and(|peak| peak > 0.0));
            for (index, (series, _)) in active.enumerate() {
                let color = if high_contrast { text } else { series_color(index) };
                let value = |point: &Point| series_value(point, series, metric);
                match metric {
                    PortMetric::Arrivals => draw_stems(dc, data_plot, points, scale, color, value),
                    PortMetric::Rates | PortMetric::Established => {
                        draw_series(dc, data_plot, points, Some(metric), scale, color, 2, value);
                        let last = samples_for(points, Some(metric)).next_back().zip(points.back())
                            .map(|(point, latest)| (point, sample_x(data_plot, latest, point)));
                        draw_marker(dc, data_plot, last, scale, color, value);
                    }
                }
                draw_marker(dc, data_plot, hovered, scale, color, value);
                if index < listed {
                    paint_legend(dc, bounds, plot.right, legend_start + index as i32 * 18, color, &series.label);
                }
            }
            if overflow {
                SetTextColor(dc, text);
                paint_text(dc, plot.right + 19, legend_start + listed as i32 * 18,
                    &format!("+ {} courbe(s) active(s)", stats.active - listed));
            }
            if has_summary {
                let y = legend_start + (listed + usize::from(overflow)) as i32 * 18;
                match (stats.zero, stats.no_data) {
                    (0, missing) => {
                        SetTextColor(dc, text);
                        paint_text(dc, plot.right + 19, y, &format!("{missing} sans relevé"));
                    }
                    (zero, missing) => {
                        let label = if missing == 0 { format!("{zero} à zéro") }
                            else { format!("{zero} à zéro · {missing} sans relevé") };
                        paint_legend(dc, bounds, plot.right, y, zero_color, &label);
                    }
                }
            }
        } else {
            for (is_received, label, color, offset) in [(true, "Reçu", received, -6), (false, "Envoyé", sent, 15)] {
                let value = |point: &Point| {
                    point.rates.map(|rates| if is_received { rates.received } else { rates.sent })
                };
                paint_legend(dc, bounds, plot.right, plot.top + offset, color, label);
                draw_series(dc, plot, points, None, scale, color, 1, value);
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
    dc: HDC, plot: RECT, points: &VecDeque<Point>, metric: Option<PortMetric>, scale: f64, color: COLORREF, width: i32,
    value_at: impl Fn(&Point) -> Option<f64>,
) {
    let Some(latest) = points.back() else { return };
    let mut previous = None;
    unsafe {
        SetDCPenColor(dc, color);
        SetDCBrushColor(dc, color);
        let pen = if width > 1 { CreatePen(PS_SOLID, width, color) } else { std::ptr::null_mut() };
        let old_pen = if pen.is_null() { std::ptr::null_mut() } else { SelectObject(dc, pen) };
        // UI refreshes between capture intervals are skipped, while a sampled loss breaks the line.
        for point in samples_for(points, metric) {
            let Some(value) = value_at(point) else {
                previous = None;
                continue;
            };
            let x = sample_x(plot, latest, point);
            let y = y_position(plot, scale, value);
            if let Some((last_x, last_y)) = previous {
                MoveToEx(dc, last_x, last_y, std::ptr::null_mut());
                LineTo(dc, x, y);
            } else if width > 1 {
                Ellipse(dc, x - 2, y - 2, x + 3, y + 3);
            }
            SetPixel(dc, x, y, color);
            previous = Some((x, y));
        }
        if !old_pen.is_null() {
            SelectObject(dc, old_pen);
        }
        if !pen.is_null() {
            DeleteObject(pen);
        }
    }
}

unsafe fn draw_stems(
    dc: HDC, plot: RECT, points: &VecDeque<Point>, scale: f64, color: COLORREF,
    value_at: impl Fn(&Point) -> Option<f64>,
) {
    let Some(latest) = points.back() else { return };
    unsafe {
        SetDCPenColor(dc, color);
        SetDCBrushColor(dc, color);
        for point in points {
            let Some(value) = value_at(point).filter(|value| *value > 0.0) else { continue };
            let x = sample_x(plot, latest, point);
            let y = y_position(plot, scale, value);
            MoveToEx(dc, x, plot.bottom, std::ptr::null_mut());
            LineTo(dc, x, y);
            Ellipse(dc, x - 2, y - 2, x + 3, y + 3);
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
    use crate::monitor::Rates;

    #[test]
    fn hover_identifies_overlapping_curves_for_selected_ports() {
        let sockets = [("443/TCP", 0, Some(3)), ("8514/TCP", 0, Some(0)), ("9000/TCP", 1, None)]
            .map(|(endpoint, established, arrivals)| {
            SocketActivity {
                key: endpoint.into(), endpoint: endpoint.into(), established, arrivals,
                name: String::new(), address: String::new(), peer: String::new(),
                protocol: Protocol::Tcp, port_rates: None,
            }
        });
        let selection = sockets.iter().map(|socket| Series {
            key: socket.key.clone(), label: socket.endpoint.clone(),
        }).collect::<Vec<_>>();
        let points = VecDeque::from([Point {
            at: Instant::now(), rates: None, span: Duration::ZERO, sockets: sockets.into(), port_span: None,
        }]);
        let point = points.back().unwrap();
        let bounds = RECT { left: 0, top: 0, right: 800, bottom: 150 };
        let plot = series_plot(plot(bounds, true));
        let ports = |metric, y| hovered_sockets(point, &points, bounds, Some(PortSelection { series: &selection, metric }), y)
            .into_iter().map(|socket| socket.endpoint.as_str()).collect::<Vec<_>>();
        let established_scale = series_scale(PortMetric::Established, Some(1.0));
        let arrivals_scale = series_scale(PortMetric::Arrivals, Some(3.0));
        assert_eq!(ports(PortMetric::Established, plot.bottom), ["8514/TCP", "443/TCP"]);
        assert_eq!(ports(PortMetric::Established, y_position(plot, established_scale, 1.0)), ["9000/TCP"]);
        assert_eq!(ports(PortMetric::Arrivals, plot.bottom), ["8514/TCP"]);
        assert_eq!(ports(PortMetric::Arrivals, y_position(plot, arrivals_scale, 3.0)), ["443/TCP"]);
        assert!(y_position(plot, established_scale, 1.0) > plot.top);

        let mut selection = selection;
        selection.push(Series { key: "missing".into(), label: "Sans relevé".into() });
        let established = PortSelection { series: &selection, metric: PortMetric::Established };
        let arrivals = PortSelection { series: &selection, metric: PortMetric::Arrivals };
        assert_eq!(selection_stats(&points, established), SelectionStats { active: 1, zero: 2, no_data: 1 });
        assert_eq!(selection_stats(&points, arrivals), SelectionStats { active: 1, zero: 1, no_data: 2 });
        assert_eq!(selection_stats(&VecDeque::new(), established), SelectionStats { active: 0, zero: 0, no_data: 4 });
        assert_eq!(series_value(point, selection.last().unwrap(), PortMetric::Established), None);
    }

    #[test]
    fn rate_curves_keep_measured_windows_and_break_at_sampled_losses() {
        let start = Instant::now();
        let reading = |seconds, sampled: bool, tcp, udp| Point {
            at: start + Duration::from_secs(seconds),
            span: Duration::from_secs(1),
            rates: None,
            port_span: sampled.then_some(Duration::from_secs(1)),
            sockets: [("443/TCP", Protocol::Tcp, tcp), ("5353/UDP", Protocol::Udp, udp)].map(|(endpoint, protocol, port_rates)| SocketActivity {
                key: endpoint.into(), endpoint: endpoint.into(), name: String::new(), address: String::new(), peer: String::new(),
                protocol, established: 0, arrivals: None, port_rates,
            }).into(),
        };
        let quiet = Some(Rates { received: 0.0, sent: 0.0 });
        let points = VecDeque::from([
            reading(0, true, Some(Rates { received: 10.0, sent: 5.0 }), Some(Rates { received: 2.0, sent: 3.0 })),
            reading(1, false, None, None),
            reading(2, true, None, None),
            reading(3, true, quiet, quiet),
            reading(4, false, None, None),
        ]);
        let selection = points[0].sockets.iter().map(|socket| Series { key: socket.key.clone(), label: socket.endpoint.clone() })
            .collect::<Vec<_>>();
        let metric = PortMetric::Rates;
        let selected = PortSelection { series: &selection, metric };
        assert_eq!(selection_stats(&points, selected), SelectionStats { active: 2, zero: 0, no_data: 0 });
        assert_eq!(selection_stats(&VecDeque::from([points[2].clone()]), selected), SelectionStats { active: 0, zero: 0, no_data: 2 });
        assert_eq!(selection_stats(&VecDeque::from([points[3].clone()]), selected), SelectionStats { active: 0, zero: 2, no_data: 0 });
        let samples = samples_for(&points, Some(metric)).map(|point| series_value(point, &selection[0], metric))
            .collect::<Vec<_>>();
        assert_eq!(samples, [Some(15.0), None, Some(0.0)]);

        let bounds = RECT { left: 0, top: 0, right: 800, bottom: 150 };
        let plot = series_plot(plot(bounds, true));
        let scale = series_scale(metric, Some(15.0));
        for (value, expected) in [(15.0, "443/TCP"), (5.0, "5353/UDP")] {
            let sockets = hovered_sockets(&points[0], &points, bounds, Some(selected), y_position(plot, scale, value));
            assert_eq!(sockets.len(), 1);
            assert_eq!(sockets[0].endpoint, expected);
        }
        let lost_x = sample_x(plot, points.back().unwrap(), &points[2]);
        assert_eq!(sample_at(&points, bounds, Some(metric), lost_x).unwrap().at, points[2].at);
        assert_eq!(sample_at(&points, bounds, Some(metric), plot.right).unwrap().at, points[3].at);
    }
}
