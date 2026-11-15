//! Widget de terminal para egui basado en el emulador `vt100`.

use std::num::NonZeroU16;

use eframe::egui::{
    self, Color32, CursorIcon, Event, EventFilter, FontId, Key, Modifiers, MouseWheelUnit, Pos2,
    Rect, Sense, Stroke, StrokeKind, TextFormat, Vec2, text::LayoutJob,
};

const SCROLLBACK: usize = 5000;
const BG: Color32 = Color32::from_rgb(0x1e, 0x1f, 0x29);
const FG: Color32 = Color32::from_rgb(0xe6, 0xe6, 0xe6);
const SEL_BG: Color32 = Color32::from_rgb(0x44, 0x5a, 0x90);
/// Ancho de la barra de desplazamiento vertical.
const SCROLLBAR_W: f32 = 12.0;

pub struct Terminal {
    parser: vt100::Parser,
    cols: u16,
    rows: u16,
    font_size: f32,
    /// Selección en coordenadas de pantalla visibles (fila, col), inicio/fin.
    selection: Option<((u16, u16), (u16, u16))>,
    scroll_accum: f32,
}

/// Resultado de dibujar el terminal en un frame.
#[derive(Default)]
pub struct TermOutput {
    /// Bytes que hay que enviar a la sesión.
    pub input: Vec<u8>,
    /// Nuevo tamaño (cols, rows) si cambió.
    pub resized: Option<(u16, u16)>,
}

fn nz(v: u16) -> NonZeroU16 {
    NonZeroU16::new(v.max(1)).unwrap()
}

impl Terminal {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            parser: vt100::Parser::new(nz(rows), nz(cols), SCROLLBACK),
            cols,
            rows,
            font_size: 14.0,
            selection: None,
            scroll_accum: 0.0,
        }
    }

    pub fn size(&self) -> (u16, u16) {
        (self.cols, self.rows)
    }

    pub fn process(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    /// Escribe texto local (mensajes de estado) en la pantalla.
    pub fn print_local(&mut self, msg: &str) {
        let s = format!("\r\n\x1b[1;33m{}\x1b[0m\r\n", msg.replace('\n', "\r\n"));
        self.parser.process(s.as_bytes());
    }

    pub fn bracketed_paste(&self) -> bool {
        self.parser.screen().bracketed_paste()
    }

    /// Prepara un texto para pegarlo/enviarlo a la terminal.
    pub fn paste_bytes(&self, text: &str) -> Vec<u8> {
        let text = text.replace("\r\n", "\r").replace('\n', "\r");
        if self.bracketed_paste() {
            format!("\x1b[200~{text}\x1b[201~").into_bytes()
        } else {
            text.into_bytes()
        }
    }

    fn selected_text(&self) -> Option<String> {
        let ((r0, c0), (r1, c1)) = self.ordered_selection()?;
        Some(self.parser.screen().contents_between(r0, c0, r1, c1 + 1))
    }

    fn ordered_selection(&self) -> Option<((u16, u16), (u16, u16))> {
        let (a, b) = self.selection?;
        if a == b {
            return None;
        }
        Some(if a <= b { (a, b) } else { (b, a) })
    }

    fn in_selection(&self, row: u16, col: u16) -> bool {
        match self.ordered_selection() {
            Some((s, e)) => (row, col) >= s && (row, col) <= e,
            None => false,
        }
    }

    /// Dibuja el terminal ocupando todo el espacio disponible y procesa la entrada.
    pub fn ui(&mut self, ui: &mut egui::Ui, id: egui::Id, request_focus: bool) -> TermOutput {
        let mut out = TermOutput::default();
        let font = FontId::monospace(self.font_size);
        let (cw, rh) = ui.fonts_mut(|f| (f.glyph_width(&font, 'M'), f.row_height(&font)));

        let rect = ui.available_rect_before_wrap();
        // A la derecha queda la barra de desplazamiento del historial.
        let mut term_rect = rect;
        term_rect.max.x -= SCROLLBAR_W;
        let sb_rect = Rect::from_min_max(Pos2::new(term_rect.max.x, rect.min.y), rect.max);
        let response = ui.interact(term_rect, id, Sense::click_and_drag());
        let sb_resp = ui.interact(sb_rect, id.with("scrollbar"), Sense::click_and_drag());
        ui.advance_cursor_after_rect(rect);
        if request_focus || response.clicked() || response.drag_started() {
            response.request_focus();
        }
        let focused = response.has_focus();
        if response.hovered() {
            ui.ctx().set_cursor_icon(CursorIcon::Text);
        }

        // --- Redimensionado ---
        let pad = 4.0;
        let cols = (((term_rect.width() - 2.0 * pad) / cw).floor() as i32).clamp(10, 1000) as u16;
        let rows = (((rect.height() - 2.0 * pad) / rh).floor() as i32).clamp(3, 500) as u16;
        if (cols, rows) != (self.cols, self.rows) {
            self.cols = cols;
            self.rows = rows;
            self.parser.screen_mut().set_size(nz(rows), nz(cols));
            out.resized = Some((cols, rows));
        }

        let origin = rect.min + Vec2::splat(pad);
        let cell_at = |p: Pos2| -> (u16, u16) {
            let c = ((p.x - origin.x) / cw).floor().clamp(0.0, (cols - 1) as f32) as u16;
            let r = ((p.y - origin.y) / rh).floor().clamp(0.0, (rows - 1) as f32) as u16;
            (r, c)
        };

        // --- Selección con el ratón ---
        if response.drag_started()
            && let Some(p) = response.interact_pointer_pos()
        {
            let c = cell_at(p);
            self.selection = Some((c, c));
        }
        if response.dragged()
            && let (Some(p), Some((start, _))) = (response.interact_pointer_pos(), self.selection)
        {
            self.selection = Some((start, cell_at(p)));
        }
        if response.clicked() {
            self.selection = None;
        }

        // --- Rueda: historial (scrollback) ---
        if response.hovered() || sb_resp.hovered() {
            let dy = ui.input(|i| {
                i.events.iter().fold(0.0, |acc, e| match e {
                    Event::MouseWheel { unit, delta, .. } => {
                        acc + match unit {
                            MouseWheelUnit::Point => delta.y / rh,
                            MouseWheelUnit::Line => delta.y,
                            MouseWheelUnit::Page => delta.y * rows as f32,
                        }
                    }
                    _ => acc,
                })
            });
            self.scroll_accum += dy;
            let lines = self.scroll_accum.trunc() as i32;
            if lines != 0 {
                self.scroll_accum -= lines as f32;
                let screen = self.parser.screen();
                if screen.alternate_screen() {
                    // En programas a pantalla completa (less, vim…) enviamos flechas.
                    let seq: &[u8] = if lines > 0 { b"\x1b[A" } else { b"\x1b[B" };
                    for _ in 0..lines.unsigned_abs().min(10) {
                        out.input.extend_from_slice(seq);
                    }
                } else {
                    let cur = screen.scrollback() as i32;
                    let new = (cur + lines * 3).max(0) as usize;
                    self.parser.screen_mut().set_scrollback(new);
                }
            }
        }

        // --- Teclado ---
        if focused {
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(
                    id,
                    EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true },
                )
            });
            let events = ui.input(|i| i.events.clone());
            let shift = ui.input(|i| i.modifiers.shift);
            for ev in events {
                let before = out.input.len();
                match ev {
                    Event::Text(t) => out.input.extend_from_slice(t.as_bytes()),
                    Event::Paste(t) => out.input.extend(self.paste_bytes(&t)),
                    Event::Copy => {
                        if shift {
                            // Ctrl+Shift+C copia la selección
                            if let Some(t) = self.selected_text() {
                                ui.ctx().copy_text(t);
                            }
                        } else {
                            out.input.push(0x03); // Ctrl+C
                        }
                    }
                    Event::Cut => out.input.push(0x18), // Ctrl+X
                    // Shift+RePág/AvPág/Inicio/Fin recorren el historial.
                    Event::Key { key: key @ (Key::PageUp | Key::PageDown | Key::Home | Key::End), pressed: true, modifiers, .. }
                        if modifiers.shift && !modifiers.ctrl && !self.parser.screen().alternate_screen() =>
                    {
                        let screen = self.parser.screen();
                        let page = rows.saturating_sub(1).max(1) as usize;
                        let new = match key {
                            Key::PageUp => screen.scrollback() + page,
                            Key::PageDown => screen.scrollback().saturating_sub(page),
                            Key::Home => usize::MAX,
                            _ => 0,
                        };
                        self.parser.screen_mut().set_scrollback(new);
                    }
                    Event::Key { key, pressed: true, modifiers, .. } => {
                        let app_cursor = self.parser.screen().application_cursor();
                        if let Some(seq) = key_to_bytes(key, modifiers, app_cursor) {
                            out.input.extend(seq);
                        }
                    }
                    _ => {}
                }
                if out.input.len() > before {
                    self.selection = None;
                }
            }
        }
        if !out.input.is_empty() {
            self.parser.screen_mut().set_scrollback(0);
        }

        // --- Barra de desplazamiento: clic o arrastre ---
        let track = sb_rect.shrink2(Vec2::new(2.0, 2.0));
        let thumb = |len: usize, off: usize| -> Option<Rect> {
            if len == 0 || track.height() < 8.0 {
                return None;
            }
            let total = (len + rows as usize) as f32;
            let h = (track.height() * rows as f32 / total).clamp(20.0_f32.min(track.height()), track.height());
            let travel = track.height() - h;
            let top = track.top() + travel * (len - off.min(len)) as f32 / len as f32;
            Some(Rect::from_min_size(Pos2::new(track.left(), top), Vec2::new(track.width(), h)))
        };
        {
            let screen = self.parser.screen();
            let (len, off) = (screen.scrollback_len(), screen.scrollback());
            if !screen.alternate_screen()
                && (sb_resp.clicked() || sb_resp.dragged())
                && let (Some(p), Some(t)) = (sb_resp.interact_pointer_pos(), thumb(len, off))
            {
                let travel = track.height() - t.height();
                let frac = if travel > 0.0 { ((p.y - track.top() - t.height() / 2.0) / travel).clamp(0.0, 1.0) } else { 1.0 };
                let new = len - (frac * len as f32).round() as usize;
                self.parser.screen_mut().set_scrollback(new);
            }
        }

        // --- Menú contextual ---
        let sel_text = self.selected_text();
        response.context_menu(|ui| {
            if ui.add_enabled(sel_text.is_some(), egui::Button::new("Copiar selección  (Ctrl+Shift+C)")).clicked() {
                if let Some(t) = &sel_text {
                    ui.ctx().copy_text(t.clone());
                }
                ui.close();
            }
            if ui.button("Copiar pantalla completa").clicked() {
                ui.ctx().copy_text(self.parser.screen().contents());
                ui.close();
            }
            ui.separator();
            if ui.button("Limpiar historial").clicked() {
                self.parser.screen_mut().clear_scrollback();
                ui.close();
            }
            ui.horizontal(|ui| {
                ui.label("Fuente:");
                ui.add(egui::Slider::new(&mut self.font_size, 9.0..=28.0));
            });
        });

        // --- Dibujo ---
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, BG);
        let screen = self.parser.screen();
        for row in 0..rows {
            let mut job = LayoutJob::default();
            let mut run = String::new();
            let mut run_fmt: Option<TextFormat> = None;
            for col in 0..cols {
                let Some(cell) = screen.cell(row, col) else { continue };
                if cell.is_wide_continuation() {
                    continue;
                }
                let mut fg = color(cell.fgcolor(), FG, cell.bold());
                let mut bg = color(cell.bgcolor(), BG, false);
                if cell.inverse() {
                    std::mem::swap(&mut fg, &mut bg);
                }
                if cell.dim() {
                    fg = fg.gamma_multiply(0.6);
                }
                if self.in_selection(row, col) {
                    bg = SEL_BG;
                }
                let fmt = TextFormat {
                    font_id: font.clone(),
                    color: fg,
                    background: if bg == BG { Color32::TRANSPARENT } else { bg },
                    italics: cell.italic(),
                    underline: if cell.underline() { Stroke::new(1.0, fg) } else { Stroke::NONE },
                    ..Default::default()
                };
                if run_fmt.as_ref() != Some(&fmt) {
                    if let Some(f) = run_fmt.take() {
                        job.append(&run, 0.0, f);
                        run.clear();
                    }
                    run_fmt = Some(fmt);
                }
                if cell.has_contents() {
                    run.push_str(cell.contents());
                } else {
                    run.push(' ');
                }
            }
            if let Some(f) = run_fmt {
                job.append(&run, 0.0, f);
            }
            let galley = painter.layout_job(job);
            painter.galley(origin + Vec2::new(0.0, row as f32 * rh), galley, FG);
        }

        // Cursor
        if !screen.hide_cursor() && screen.scrollback() == 0 {
            let (cr, cc) = screen.cursor_position();
            let r = Rect::from_min_size(
                origin + Vec2::new(cc as f32 * cw, cr as f32 * rh),
                Vec2::new(cw, rh),
            );
            if focused {
                painter.rect_filled(r, 0.0, Color32::from_rgba_unmultiplied(230, 230, 230, 140));
            } else {
                painter.rect_stroke(r, 0.0, Stroke::new(1.0, FG), StrokeKind::Inside);
            }
        }
        // Barra de desplazamiento
        painter.rect_filled(sb_rect, 0.0, Color32::from_rgb(0x17, 0x18, 0x20));
        if !screen.alternate_screen()
            && let Some(t) = thumb(screen.scrollback_len(), screen.scrollback())
        {
            let c = if sb_resp.dragged() {
                Color32::from_rgb(140, 150, 180)
            } else if sb_resp.hovered() {
                Color32::from_rgb(110, 118, 145)
            } else {
                Color32::from_rgb(75, 80, 100)
            };
            painter.rect_filled(t, 4.0, c);
        }
        if screen.scrollback() > 0 {
            let txt = format!("↑ historial: {} líneas", screen.scrollback());
            painter.text(
                term_rect.right_top() + Vec2::new(-8.0, 6.0),
                egui::Align2::RIGHT_TOP,
                txt,
                FontId::proportional(12.0),
                Color32::YELLOW,
            );
        }
        if focused {
            painter.rect_stroke(rect, 0.0, Stroke::new(1.0, Color32::from_rgb(80, 120, 200)), StrokeKind::Inside);
        }

        out
    }
}

fn key_to_bytes(key: Key, m: Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
    let csi = |s: &str| format!("\x1b[{s}").into_bytes();
    let arrow = |c: char| {
        if m.ctrl {
            format!("\x1b[1;5{c}").into_bytes()
        } else if m.shift {
            format!("\x1b[1;2{c}").into_bytes()
        } else if m.alt {
            format!("\x1b[1;3{c}").into_bytes()
        } else if app_cursor {
            format!("\x1bO{c}").into_bytes()
        } else {
            format!("\x1b[{c}").into_bytes()
        }
    };
    Some(match key {
        Key::Enter => b"\r".to_vec(),
        Key::Backspace => {
            if m.alt { b"\x1b\x7f".to_vec() } else { b"\x7f".to_vec() }
        }
        Key::Tab => {
            if m.shift { csi("Z") } else { b"\t".to_vec() }
        }
        Key::Escape => b"\x1b".to_vec(),
        Key::ArrowUp => arrow('A'),
        Key::ArrowDown => arrow('B'),
        Key::ArrowRight => arrow('C'),
        Key::ArrowLeft => arrow('D'),
        Key::Home => if app_cursor { b"\x1bOH".to_vec() } else { csi("H") },
        Key::End => if app_cursor { b"\x1bOF".to_vec() } else { csi("F") },
        Key::PageUp => csi("5~"),
        Key::PageDown => csi("6~"),
        Key::Insert => csi("2~"),
        Key::Delete => csi("3~"),
        Key::F1 => b"\x1bOP".to_vec(),
        Key::F2 => b"\x1bOQ".to_vec(),
        Key::F3 => b"\x1bOR".to_vec(),
        Key::F4 => b"\x1bOS".to_vec(),
        Key::F5 => csi("15~"),
        Key::F6 => csi("17~"),
        Key::F7 => csi("18~"),
        Key::F8 => csi("19~"),
        Key::F9 => csi("20~"),
        Key::F10 => csi("21~"),
        Key::F11 => csi("23~"),
        Key::F12 => csi("24~"),
        _ => {
            // Ctrl+letra y Alt+letra
            let name = key.name();
            let mut chars = name.chars();
            let (Some(c), None) = (chars.next(), chars.next()) else { return None };
            if m.ctrl && !m.alt {
                return match c.to_ascii_lowercase() {
                    c @ 'a'..='z' => Some(vec![c as u8 - b'a' + 1]),
                    '[' => Some(vec![0x1b]),
                    '\\' => Some(vec![0x1c]),
                    ']' => Some(vec![0x1d]),
                    ' ' => Some(vec![0x00]),
                    _ => None,
                };
            }
            if m.alt && !m.ctrl && c.is_ascii_alphanumeric() {
                let c = if m.shift { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() };
                return Some(vec![0x1b, c as u8]);
            }
            return None;
        }
    })
}

/// Paleta xterm: 16 colores base + cubo 6x6x6 + escala de grises.
fn color(c: vt100::Color, default: Color32, bold: bool) -> Color32 {
    const BASE: [(u8, u8, u8); 16] = [
        (0x1e, 0x1f, 0x29), (0xe0, 0x5f, 0x65), (0x7c, 0xc4, 0x7a), (0xe5, 0xc0, 0x7b),
        (0x61, 0xaf, 0xef), (0xc6, 0x78, 0xdd), (0x56, 0xb6, 0xc2), (0xcc, 0xcc, 0xcc),
        (0x6c, 0x70, 0x86), (0xff, 0x7a, 0x80), (0x98, 0xe0, 0x95), (0xf5, 0xd4, 0x8f),
        (0x82, 0xc4, 0xff), (0xdf, 0x9a, 0xf2), (0x7f, 0xd8, 0xe3), (0xff, 0xff, 0xff),
    ];
    match c {
        vt100::Color::Default => default,
        vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
        vt100::Color::Idx(i) => {
            let i = if bold && i < 8 { i + 8 } else { i };
            match i {
                0..=15 => {
                    let (r, g, b) = BASE[i as usize];
                    Color32::from_rgb(r, g, b)
                }
                16..=231 => {
                    let i = i - 16;
                    let lvl = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
                    Color32::from_rgb(lvl(i / 36), lvl((i / 6) % 6), lvl(i % 6))
                }
                _ => {
                    let v = 8 + (i - 232) * 10;
                    Color32::from_rgb(v, v, v)
                }
            }
        }
    }
}
