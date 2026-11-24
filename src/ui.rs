use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{COLORREF, HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::UI::WindowsAndMessaging::GetClientRect;
use windows_sys::core::w;

use crate::chart::{high_contrast, rgb};
use crate::risk::Risk;

const MARGIN: i32 = 12;
pub const INSET: i32 = 10;
pub const REDRAW_SURFACE: REDRAW_WINDOW_FLAGS = RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN;

pub struct Layout {
    pub client: RECT,
    pub header: RECT,
    pub graph: RECT,
    pub plot: RECT,
    pub archive: Option<RECT>,
    pub ports: RECT,
    pub details: RECT,
    pub status: RECT,
}

impl Layout {
    pub fn new(window: HWND, archive_open: bool) -> Self {
        let mut client = RECT::default();
        unsafe { GetClientRect(window, &mut client) };
        let width = client.right;
        let height = client.bottom;
        let compact = if archive_open { (700 - height).clamp(0, 110) } else { 0 };
        let panel = |top, bottom| RECT { left: MARGIN, top, right: width - MARGIN, bottom };
        let header = panel(10, 55);
        let plot = RECT {
            left: MARGIN + INSET,
            top: 98,
            right: width - MARGIN - INSET,
            bottom: 98 + (height / 5).clamp(110, 185) - compact / 3,
        };
        let graph = panel(header.bottom + 8, plot.bottom + 47);
        let archive = archive_open.then(|| panel(graph.bottom + 8, graph.bottom + 74));
        let status = panel(height - 31, height - 8);
        let detail_height = (height / 6).clamp(108, 134) - compact / 5;
        let details = panel(status.top - detail_height - 8, status.top - 8);
        let ports = panel(archive.unwrap_or(graph).bottom + 8, details.top - 8);
        Self { client, header, graph, plot, archive, ports, details, status }
    }
}

pub struct Theme {
    pub contrast: bool,
    face: HBRUSH,
    panel: HBRUSH,
    header: HBRUSH,
    status: HBRUSH,
    body: HFONT,
    heading: HFONT,
    display: HFONT,
    pub body_ink: COLORREF,
    pub header_ink: COLORREF,
    pub status_ink: COLORREF,
    pub panel_color: COLORREF,
}

impl Theme {
    pub fn new() -> Self {
        let contrast = high_contrast();
        let (face, panel, header, status, body_ink, header_ink, status_ink) = if contrast {
            unsafe { (
                GetSysColor(COLOR_BTNFACE), GetSysColor(COLOR_BTNFACE), GetSysColor(COLOR_BTNFACE),
                GetSysColor(COLOR_BTNFACE), GetSysColor(COLOR_BTNTEXT), GetSysColor(COLOR_BTNTEXT),
                GetSysColor(COLOR_BTNTEXT),
            ) }
        } else {
            (rgb(211, 223, 226), rgb(239, 245, 245), rgb(40, 77, 86), rgb(224, 234, 235),
                rgb(28, 52, 58), rgb(248, 252, 252), rgb(50, 74, 80))
        };
        unsafe {
            Self {
                contrast,
                face: CreateSolidBrush(face),
                panel: CreateSolidBrush(panel),
                header: CreateSolidBrush(header),
                status: CreateSolidBrush(status),
                body: font(13, FW_NORMAL),
                heading: font(14, FW_BOLD),
                display: font(19, FW_BOLD),
                body_ink, header_ink, status_ink, panel_color: panel,
            }
        }
    }

    pub fn body_font(&self) -> HFONT {
        font_or_default(self.body)
    }

    pub fn heading_font(&self) -> HFONT {
        font_or_default(self.heading)
    }

    pub fn display_font(&self) -> HFONT {
        font_or_default(self.display)
    }

    pub fn panel_brush(&self) -> HBRUSH {
        brush_or_default(self.panel, COLOR_BTNFACE)
    }

    pub fn header_brush(&self) -> HBRUSH {
        brush_or_default(self.header, COLOR_BTNFACE)
    }

    pub fn status_brush(&self) -> HBRUSH {
        brush_or_default(self.status, COLOR_BTNFACE)
    }

    pub fn row_tint(&self, risk: Risk) -> Option<COLORREF> {
        if self.contrast {
            return None;
        }
        Some(match risk {
            Risk::Normal => rgb(243, 249, 246),
            Risk::Unknown => rgb(255, 249, 232),
            Risk::Elevated => rgb(252, 238, 236),
        })
    }

    pub fn paint(&self, dc: HDC, layout: &Layout) {
        fill(dc, layout.client, brush_or_default(self.face, COLOR_BTNFACE));
        fill(dc, layout.header, self.header_brush());
        for panel in [Some(layout.graph), layout.archive, Some(layout.ports), Some(layout.details)].into_iter().flatten() {
            self.paint_panel(dc, panel, self.panel_brush());
        }
        self.paint_panel(dc, layout.status, self.status_brush());
    }

    fn paint_panel(&self, dc: HDC, mut rect: RECT, brush: HBRUSH) {
        fill(dc, rect, brush);
        if self.contrast {
            unsafe { DrawEdge(dc, &mut rect, BDR_RAISEDINNER | BDR_RAISEDOUTER, BF_RECT) };
            return;
        }
        let border = rgb(152, 174, 178);
        let highlight = rgb(254, 255, 255);
        unsafe {
            if SaveDC(dc) == 0 {
                return;
            }
            SelectObject(dc, GetStockObject(DC_PEN));
            SetDCPenColor(dc, border);
            MoveToEx(dc, rect.left, rect.bottom - 1, null_mut());
            LineTo(dc, rect.right - 1, rect.bottom - 1);
            LineTo(dc, rect.right - 1, rect.top - 1);
            SetDCPenColor(dc, highlight);
            MoveToEx(dc, rect.left, rect.bottom - 1, null_mut());
            LineTo(dc, rect.left, rect.top);
            LineTo(dc, rect.right - 1, rect.top);
            RestoreDC(dc, -1);
        }
    }
}

impl Drop for Theme {
    fn drop(&mut self) {
        for resource in [self.face, self.panel, self.header, self.status, self.body, self.heading, self.display] {
            if !resource.is_null() {
                unsafe { DeleteObject(resource) };
            }
        }
    }
}

pub fn paint_buffered(dc: HDC, area: RECT, paint: impl Fn(HDC)) {
    let width = area.right - area.left;
    let height = area.bottom - area.top;
    if width <= 0 || height <= 0 {
        return;
    }
    let copied = unsafe {
        let buffer = CreateCompatibleDC(dc);
        if buffer.is_null() {
            paint(dc);
            return;
        }
        let bitmap = CreateCompatibleBitmap(dc, width, height);
        let previous = if bitmap.is_null() { null_mut() } else { SelectObject(buffer, bitmap) };
        let mut copied = false;
        if !previous.is_null() {
            if SetViewportOrgEx(buffer, -area.left, -area.top, null_mut()) != 0 {
                paint(buffer);
                copied = BitBlt(dc, area.left, area.top, width, height, buffer, area.left, area.top, SRCCOPY) != 0;
            }
            SelectObject(buffer, previous);
        }
        if !bitmap.is_null() {
            DeleteObject(bitmap);
        }
        DeleteDC(buffer);
        copied
    };
    if !copied {
        paint(dc);
    }
}

fn fill(dc: HDC, rect: RECT, brush: HBRUSH) {
    unsafe { FillRect(dc, &rect, brush) };
}

fn brush_or_default(brush: HBRUSH, system_color: SYS_COLOR_INDEX) -> HBRUSH {
    if brush.is_null() { unsafe { GetSysColorBrush(system_color) } } else { brush }
}

fn font_or_default(font: HFONT) -> HFONT {
    if font.is_null() { unsafe { GetStockObject(DEFAULT_GUI_FONT) } } else { font }
}

unsafe fn font(height: i32, weight: u32) -> HFONT {
    unsafe { CreateFontW(
        -height, 0, 0, 0, weight as i32, 0, 0, 0, u32::from(DEFAULT_CHARSET),
        u32::from(OUT_DEFAULT_PRECIS), u32::from(CLIP_DEFAULT_PRECIS), u32::from(CLEARTYPE_QUALITY),
        u32::from(DEFAULT_PITCH), w!("Tahoma"),
    ) }
}
