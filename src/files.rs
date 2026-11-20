//! Ventana «📁 Archivos» de una sesión: explorador SFTP con subida y descarga.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};

use eframe::egui::{self, Align, Color32, Key, Layout, RichText, ScrollArea, TextEdit, ViewportId};

use crate::sftp::{self, Entry, SftpCmd, SftpEvent, TransferEnd};
use crate::ssh::SessionParams;
use crate::vault::Connection;

const RED: Color32 = Color32::from_rgb(230, 90, 90);
const GREEN: Color32 = Color32::from_rgb(120, 200, 120);

#[derive(PartialEq)]
enum State {
    Connecting,
    Ready,
    Failed(String),
}

enum Status {
    Queued,
    Running,
    Done(String),
    Cancelled,
    Failed(String),
}

struct Transfer {
    id: u64,
    upload: bool,
    name: String,
    total: u64,
    done: u64,
    files: usize,
    current: String,
    status: Status,
    /// Carpeta donde se subió (para refrescar el listado al terminar).
    remote_dir: String,
}

impl Transfer {
    fn finished(&self) -> bool {
        matches!(self.status, Status::Done(_) | Status::Cancelled | Status::Failed(_))
    }
}

enum Dialog {
    Mkdir(String),
    Rename { from: String, to: String },
    Delete(Vec<Entry>),
}

pub struct FilesPanel {
    cmd_tx: Sender<SftpCmd>,
    evt_rx: Receiver<SftpEvent>,
    state: State,
    pub visible: bool,
    cwd: String,
    path_input: String,
    entries: Vec<Entry>,
    loading: bool,
    list_error: Option<String>,
    selected: BTreeSet<String>,
    /// Último elemento pulsado (para Shift+clic).
    anchor: Option<String>,
    show_hidden: bool,
    download_dir: PathBuf,
    transfers: Vec<Transfer>,
    next_id: u64,
    dialog: Option<Dialog>,
    message: Option<(String, bool)>,
}

impl Drop for FilesPanel {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(SftpCmd::Close);
    }
}

fn default_download_dir() -> PathBuf {
    directories::UserDirs::new()
        .and_then(|u| u.download_dir().map(|d| d.to_path_buf()).or_else(|| Some(u.home_dir().to_path_buf())))
        .unwrap_or_else(|| PathBuf::from("."))
}

impl FilesPanel {
    pub fn open(conn: &Connection, ctx: &egui::Context) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let (evt_tx, evt_rx) = mpsc::channel();
        let ctx = ctx.clone();
        let mut params = SessionParams::from_connection(conn, 80, 24);
        params.tunnels.clear();
        sftp::spawn(params, cmd_rx, evt_tx, move || ctx.request_repaint_of(ViewportId::ROOT));
        Self {
            cmd_tx,
            evt_rx,
            state: State::Connecting,
            visible: true,
            cwd: String::new(),
            path_input: String::new(),
            entries: Vec::new(),
            loading: false,
            list_error: None,
            selected: BTreeSet::new(),
            anchor: None,
            show_hidden: false,
            download_dir: default_download_dir(),
            transfers: Vec::new(),
            next_id: 1,
            dialog: None,
            message: None,
        }
    }

    /// La conexión SFTP terminó con error y hay que abrir otra.
    pub fn failed(&self) -> bool {
        matches!(self.state, State::Failed(_))
    }

    /// Transferencias en curso o en cola.
    pub fn active_transfers(&self) -> usize {
        self.transfers.iter().filter(|t| !t.finished()).count()
    }

    fn cmd(&self, c: SftpCmd) {
        let _ = self.cmd_tx.send(c);
    }

    fn navigate(&mut self, path: String) {
        self.loading = true;
        self.path_input = path.clone();
        self.cmd(SftpCmd::List(path));
    }

    fn refresh(&mut self) {
        if self.state == State::Ready {
            let p = self.cwd.clone();
            self.loading = true;
            self.cmd(SftpCmd::List(p));
        }
    }

    fn info(&mut self, m: impl Into<String>) {
        self.message = Some((m.into(), false));
    }

    fn error(&mut self, m: impl Into<String>) {
        self.message = Some((m.into(), true));
    }

    pub fn poll(&mut self) {
        while let Ok(ev) = self.evt_rx.try_recv() {
            match ev {
                SftpEvent::Ready { home } => {
                    self.state = State::Ready;
                    self.navigate(home);
                }
                SftpEvent::Listing { path, entries } => {
                    if path != self.cwd {
                        self.selected.clear();
                    }
                    self.cwd = path.clone();
                    self.path_input = path;
                    self.entries = entries;
                    self.loading = false;
                    self.list_error = None;
                    self.selected.retain(|s| self.entries.iter().any(|e| &e.path == s));
                }
                SftpEvent::ListError { error, .. } => {
                    self.loading = false;
                    self.path_input = self.cwd.clone();
                    self.list_error = Some(error);
                }
                SftpEvent::Started { id, total, files } => {
                    if let Some(t) = self.transfers.iter_mut().find(|t| t.id == id) {
                        t.total = total;
                        t.files = files;
                        t.status = Status::Running;
                    }
                }
                SftpEvent::Progress { id, done, file } => {
                    if let Some(t) = self.transfers.iter_mut().find(|t| t.id == id) {
                        t.done = done;
                        t.current = file;
                        t.status = Status::Running;
                    }
                }
                SftpEvent::Finished { id, end } => {
                    let mut refresh = false;
                    if let Some(t) = self.transfers.iter_mut().find(|t| t.id == id) {
                        refresh = t.upload && t.remote_dir == self.cwd;
                        t.status = match end {
                            TransferEnd::Done(d) => {
                                t.done = t.total;
                                Status::Done(d)
                            }
                            TransferEnd::Cancelled => Status::Cancelled,
                            TransferEnd::Failed(e) => Status::Failed(e),
                        };
                    }
                    if refresh {
                        self.refresh();
                    }
                }
                SftpEvent::OpDone(m) => {
                    self.info(m);
                    self.refresh();
                }
                SftpEvent::OpError(e) => {
                    self.error(e);
                    self.refresh();
                }
                SftpEvent::Error(e) => self.state = State::Failed(e),
                SftpEvent::Closed => {
                    if !self.failed() {
                        self.state = State::Failed("Conexión SFTP cerrada".into());
                    }
                    for t in self.transfers.iter_mut().filter(|t| !t.finished()) {
                        t.status = Status::Failed("Conexión cerrada".into());
                    }
                }
            }
        }
    }

    fn new_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn download(&mut self, e: &Entry) {
        let id = self.new_id();
        self.transfers.push(Transfer {
            id,
            upload: false,
            name: e.name.clone(),
            total: e.size,
            done: 0,
            files: 0,
            current: String::new(),
            status: Status::Queued,
            remote_dir: String::new(),
        });
        self.cmd(SftpCmd::Download { id, remote: e.path.clone(), is_dir: e.is_dir, local_dir: self.download_dir.clone() });
    }

    fn upload(&mut self, local: PathBuf) {
        let id = self.new_id();
        let name = local.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| local.display().to_string());
        self.transfers.push(Transfer {
            id,
            upload: true,
            name,
            total: 0,
            done: 0,
            files: 0,
            current: String::new(),
            status: Status::Queued,
            remote_dir: self.cwd.clone(),
        });
        self.cmd(SftpCmd::Upload { id, local, remote_dir: self.cwd.clone() });
    }

    fn selected_entries(&self) -> Vec<Entry> {
        self.entries.iter().filter(|e| self.selected.contains(&e.path)).cloned().collect()
    }

    /// Dibuja la ventana. `id` debe ser único por sesión.
    pub fn show(&mut self, ctx: &egui::Context, title: &str, id: egui::Id) {
        if !self.visible {
            return;
        }
        let mut open = true;
        egui::Window::new(format!("📁 Archivos — {title}"))
            .id(id)
            .open(&mut open)
            .default_size([720.0, 520.0])
            .min_width(480.0)
            .show(ctx, |ui| self.body(ui));
        self.dialog_ui(ctx, id);
        if !open {
            self.visible = false;
        }
    }

    fn body(&mut self, ui: &mut egui::Ui) {
        match &self.state {
            State::Connecting => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Abriendo conexión SFTP…");
                });
                return;
            }
            State::Failed(e) => {
                ui.colored_label(RED, format!("SFTP: {e}"));
                ui.weak("Cierra esta ventana y vuelve a pulsar «📁 Archivos» para reintentar.");
                if self.transfers.is_empty() {
                    return;
                }
            }
            State::Ready => {}
        }
        let ready = self.state == State::Ready;

        // Archivos soltados desde el explorador del sistema: se suben a la carpeta actual.
        let dropped: Vec<PathBuf> = ui.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).filter(|p| !p.as_os_str().is_empty()).collect());
        if ready && !dropped.is_empty() {
            let n = dropped.len();
            for p in dropped {
                self.upload(p);
            }
            self.info(format!("Subiendo {n} elemento(s) a {}", self.cwd));
        }
        let hovering = ui.input(|i| !i.raw.hovered_files.is_empty());

        ui.add_enabled_ui(ready, |ui| {
            // Barra de navegación
            ui.horizontal(|ui| {
                if ui.button("⬆").on_hover_text("Carpeta superior").clicked() {
                    self.navigate(sftp::remote_parent(&self.cwd));
                }
                if ui.button("🏠").on_hover_text("Carpeta de inicio").clicked() {
                    self.navigate(".".into());
                }
                if ui.button("⟳").on_hover_text("Actualizar").clicked() {
                    self.refresh();
                }
                let r = ui.add(TextEdit::singleline(&mut self.path_input).desired_width(f32::INFINITY).font(egui::TextStyle::Monospace));
                if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                    let p = self.path_input.trim().to_string();
                    if !p.is_empty() {
                        self.navigate(p);
                    }
                }
            });

            // Acciones
            ui.horizontal_wrapped(|ui| {
                if ui.button("⬆ Subir archivos…").clicked()
                    && let Some(files) = rfd::FileDialog::new().set_title("Archivos a subir").pick_files()
                {
                    for f in files {
                        self.upload(f);
                    }
                }
                if ui.button("⬆ Subir carpeta…").clicked()
                    && let Some(dir) = rfd::FileDialog::new().set_title("Carpeta a subir").pick_folder()
                {
                    self.upload(dir);
                }
                let sel = self.selected_entries();
                let label = if sel.is_empty() { "⬇ Descargar".to_string() } else { format!("⬇ Descargar ({})", sel.len()) };
                if ui.add_enabled(!sel.is_empty(), egui::Button::new(label)).clicked() {
                    for e in &sel {
                        self.download(e);
                    }
                }
                if ui.button("📁 Nueva carpeta").clicked() {
                    self.dialog = Some(Dialog::Mkdir(String::new()));
                }
                if ui.add_enabled(!sel.is_empty(), egui::Button::new("🗑 Eliminar")).clicked() {
                    self.dialog = Some(Dialog::Delete(sel));
                }
                ui.checkbox(&mut self.show_hidden, "Ocultos");
            });
            ui.horizontal(|ui| {
                ui.weak("Descargar en:");
                ui.monospace(RichText::new(self.download_dir.display().to_string()).small());
                if ui.small_button("Cambiar…").clicked()
                    && let Some(d) = rfd::FileDialog::new().set_title("Carpeta de descargas").set_directory(&self.download_dir).pick_folder()
                {
                    self.download_dir = d;
                }
                if ui.small_button("📂").on_hover_text("Abrir carpeta").clicked() {
                    open_in_file_manager(&self.download_dir);
                }
            });
        });

        if let Some((m, err)) = &self.message {
            ui.colored_label(if *err { RED } else { GREEN }, m);
        }
        if let Some(e) = &self.list_error {
            ui.colored_label(RED, e);
        }
        ui.separator();

        // Listado
        let transfers_h = if self.transfers.is_empty() { 0.0 } else { (self.transfers.len().min(4) as f32) * 46.0 + 40.0 };
        let list_h = (ui.available_height() - transfers_h - 24.0).max(140.0);
        let frame = egui::Frame::new().stroke(if hovering {
            egui::Stroke::new(2.0, ui.visuals().selection.stroke.color)
        } else {
            egui::Stroke::NONE
        });
        frame.show(ui, |ui| {
            if hovering {
                ui.strong(format!("Suelta para subir a {}", self.cwd));
            }
            self.listing(ui, list_h);
        });
        ui.weak("Doble clic: abrir carpeta / descargar archivo · Ctrl/Shift+clic: selección múltiple · Arrastra archivos aquí para subirlos");

        if !self.transfers.is_empty() {
            ui.separator();
            self.transfers_ui(ui);
        }
    }

    fn listing(&mut self, ui: &mut egui::Ui, height: f32) {
        let mut nav: Option<String> = None;
        let mut downloads: Vec<Entry> = Vec::new();
        let ready = self.state == State::Ready;
        ScrollArea::vertical().id_salt("sftp_list").max_height(height).auto_shrink([false, false]).show(ui, |ui| {
            if self.loading {
                ui.spinner();
            }
            let visible: Vec<&Entry> = self.entries.iter().filter(|e| self.show_hidden || !e.name.starts_with('.')).collect();
            if visible.is_empty() && !self.loading {
                ui.weak("(carpeta vacía)");
            }
            let order: Vec<String> = visible.iter().map(|e| e.path.clone()).collect();
            egui::Grid::new("sftp_grid").num_columns(4).striped(true).spacing([12.0, 2.0]).show(ui, |ui| {
                ui.strong("Nombre");
                ui.strong("Tamaño");
                ui.strong("Modificado");
                ui.strong("Permisos");
                ui.end_row();
                for e in &visible {
                    let icon = match (e.is_dir, e.is_link) {
                        (true, false) => "📁",
                        (true, true) => "🔗📁",
                        (false, true) => "🔗",
                        (false, false) => "📄",
                    };
                    let selected = self.selected.contains(&e.path);
                    let r = ui.add(egui::Button::selectable(selected, format!("{icon} {}", e.name)).wrap_mode(egui::TextWrapMode::Truncate));
                    if r.clicked() && ready {
                        let m = ui.input(|i| i.modifiers);
                        if m.shift
                            && let Some(anchor) = self.anchor.clone()
                        {
                            let (a, b) = (order.iter().position(|p| *p == anchor), order.iter().position(|p| *p == e.path));
                            if let (Some(a), Some(b)) = (a, b) {
                                for p in &order[a.min(b)..=a.max(b)] {
                                    self.selected.insert(p.clone());
                                }
                            }
                        } else if m.command || m.ctrl {
                            if !self.selected.remove(&e.path) {
                                self.selected.insert(e.path.clone());
                            }
                        } else {
                            self.selected.clear();
                            self.selected.insert(e.path.clone());
                        }
                        if !m.shift {
                            self.anchor = Some(e.path.clone());
                        }
                    }
                    if r.double_clicked() && ready {
                        if e.is_dir {
                            nav = Some(e.path.clone());
                        } else {
                            downloads.push((*e).clone());
                        }
                    }
                    r.context_menu(|ui| {
                        if e.is_dir && ui.button("📂 Abrir").clicked() {
                            nav = Some(e.path.clone());
                            ui.close();
                        }
                        if ui.button("⬇ Descargar").clicked() {
                            downloads.push((*e).clone());
                            ui.close();
                        }
                        if ui.button("✏ Renombrar").clicked() {
                            self.dialog = Some(Dialog::Rename { from: e.path.clone(), to: e.name.clone() });
                            ui.close();
                        }
                        if ui.button("📋 Copiar ruta").clicked() {
                            ui.ctx().copy_text(e.path.clone());
                            ui.close();
                        }
                        ui.separator();
                        if ui.button("🗑 Eliminar").clicked() {
                            self.dialog = Some(Dialog::Delete(vec![(*e).clone()]));
                            ui.close();
                        }
                    });
                    ui.label(if e.is_dir { String::new() } else { human_size(e.size) });
                    ui.label(e.mtime.map(format_time).unwrap_or_default());
                    ui.monospace(e.perm.map(format_perm).unwrap_or_default());
                    ui.end_row();
                }
            });
        });
        if let Some(p) = nav {
            self.navigate(p);
        }
        for e in downloads {
            self.download(&e);
        }
    }

    fn transfers_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong("Transferencias");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.small_button("Limpiar terminadas").clicked() {
                    self.transfers.retain(|t| !t.finished());
                }
            });
        });
        let mut cancel = Vec::new();
        ScrollArea::vertical().id_salt("sftp_transfers").max_height(190.0).show(ui, |ui| {
            for t in self.transfers.iter().rev() {
                ui.horizontal(|ui| {
                    ui.label(if t.upload { "⬆" } else { "⬇" });
                    ui.add(egui::Label::new(RichText::new(&t.name).strong()).truncate());
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        match &t.status {
                            Status::Queued | Status::Running => {
                                if ui.small_button("✖").on_hover_text("Cancelar").clicked() {
                                    cancel.push(t.id);
                                }
                            }
                            Status::Done(dest) if !t.upload && ui.small_button("📂").on_hover_text("Mostrar en la carpeta").clicked() => {
                                let p = PathBuf::from(dest);
                                open_in_file_manager(p.parent().unwrap_or(&p));
                            }
                            _ => {}
                        }
                        let text = match &t.status {
                            Status::Queued => RichText::new("En cola").weak(),
                            Status::Running if t.total > 0 => RichText::new(format!("{} / {}", human_size(t.done), human_size(t.total))),
                            Status::Running => RichText::new("Preparando…").weak(),
                            Status::Done(_) => RichText::new(format!("✔ {}", human_size(t.total))).color(GREEN),
                            Status::Cancelled => RichText::new("Cancelado").weak(),
                            Status::Failed(_) => RichText::new("✖ Error").color(RED),
                        };
                        ui.label(text);
                    });
                });
                match &t.status {
                    Status::Running | Status::Queued => {
                        let frac = if t.total > 0 { t.done as f32 / t.total as f32 } else { 0.0 };
                        let detail = if t.files > 1 { format!("{} · {} archivos", t.current, t.files) } else { t.current.clone() };
                        ui.add(egui::ProgressBar::new(frac).desired_height(12.0).text(RichText::new(detail).small()));
                    }
                    Status::Failed(e) => {
                        ui.colored_label(RED, RichText::new(e).small());
                    }
                    Status::Done(d) => {
                        ui.weak(RichText::new(d).small());
                    }
                    Status::Cancelled => {}
                }
            }
        });
        for id in cancel {
            self.cmd(SftpCmd::Cancel(id));
        }
    }

    fn dialog_ui(&mut self, ctx: &egui::Context, id: egui::Id) {
        let Some(d) = &mut self.dialog else { return };
        let mut close = false;
        let mut cmd = None;
        let cwd = self.cwd.clone();
        let title = match d {
            Dialog::Mkdir(_) => "Nueva carpeta",
            Dialog::Rename { .. } => "Renombrar",
            Dialog::Delete(_) => "Eliminar del servidor",
        };
        egui::Window::new(title).id(id.with("dialog")).collapsible(false).resizable(false).show(ctx, |ui| match d {
            Dialog::Mkdir(name) => {
                ui.label(format!("En {cwd}:"));
                let r = ui.add(TextEdit::singleline(name).hint_text("nombre").desired_width(260.0));
                r.request_focus();
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                ui.horizontal(|ui| {
                    if (ui.button("Crear").clicked() || enter) && valid_name(name) {
                        cmd = Some(SftpCmd::Mkdir(sftp::remote_join(&cwd, name.trim())));
                        close = true;
                    }
                    close |= ui.button("Cancelar").clicked();
                });
            }
            Dialog::Rename { from, to } => {
                ui.monospace(from.as_str());
                let r = ui.add(TextEdit::singleline(to).desired_width(260.0));
                r.request_focus();
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                ui.horizontal(|ui| {
                    if (ui.button("Renombrar").clicked() || enter) && valid_name(to) {
                        let dest = sftp::remote_join(&sftp::remote_parent(from), to.trim());
                        cmd = Some(SftpCmd::Rename { from: from.clone(), to: dest });
                        close = true;
                    }
                    close |= ui.button("Cancelar").clicked();
                });
            }
            Dialog::Delete(list) => {
                ui.label("Se eliminará permanentemente:");
                for e in list.iter().take(10) {
                    ui.monospace(if e.is_dir && !e.is_link { format!("📁 {} (y todo su contenido)", e.name) } else { e.name.clone() });
                }
                if list.len() > 10 {
                    ui.weak(format!("… y {} más", list.len() - 10));
                }
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("🗑 Eliminar").color(RED)).clicked() {
                        close = true;
                    }
                    if ui.button("Cancelar").clicked() {
                        list.clear();
                        close = true;
                    }
                });
            }
        });
        if close {
            if let Some(Dialog::Delete(list)) = self.dialog.take() {
                for e in list {
                    self.cmd(SftpCmd::Delete { path: e.path.clone(), is_dir: e.is_dir && !e.is_link });
                    self.selected.remove(&e.path);
                }
            }
            if let Some(c) = cmd {
                self.cmd(c);
            }
        }
    }
}

fn valid_name(n: &str) -> bool {
    let n = n.trim();
    !n.is_empty() && n != "." && n != ".." && !n.contains('/')
}

fn human_size(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{b} B") } else { format!("{v:.1} {}", UNITS[u]) }
}

/// Fecha UTC «AAAA-MM-DD HH:MM» sin dependencias extra.
fn format_time(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Algoritmo civil_from_days de Howard Hinnant.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", rem / 3600, (rem % 3600) / 60)
}

fn format_perm(p: u32) -> String {
    let kind = match p & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        _ => '-',
    };
    let mut s = String::from(kind);
    for shift in [6, 3, 0] {
        let bits = (p >> shift) & 7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        s.push(if bits & 1 != 0 { 'x' } else { '-' });
    }
    s
}

fn open_in_file_manager(path: &std::path::Path) {
    let prog = if cfg!(windows) {
        "explorer"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(prog).arg(path).spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(format_time(0), "1970-01-01 00:00");
        assert_eq!(format_time(1_700_000_000), "2023-11-14 22:13");
        assert_eq!(format_perm(0o100644), "-rw-r--r--");
        assert_eq!(format_perm(0o040755), "drwxr-xr-x");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1536), "1.5 KB");
        assert!(!valid_name("a/b"));
        assert!(valid_name("nueva"));
    }
}
