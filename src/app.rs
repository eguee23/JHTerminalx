use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use eframe::egui::{
    self, Align, Color32, Frame, Key, Layout, Margin, Panel, RichText, ScrollArea, TextEdit,
    ViewportBuilder, ViewportCommand, ViewportId,
};
use uuid::Uuid;

use crate::ssh::{self, SessionCmd, SessionEvent, SessionParams};
use crate::terminal::Terminal;
use crate::tunnel::TunnelInfo;
use crate::vault::{AuthMethod, Connection, Note, Tunnel, Vault};

/// En Windows libssh2 usa WinCNG, que no soporta claves Ed25519.
#[cfg(windows)]
const DEFAULT_KEY: &str = "~/.ssh/id_rsa";
#[cfg(not(windows))]
const DEFAULT_KEY: &str = "~/.ssh/id_ed25519";

// ---------------------------------------------------------------------------
// Sesiones (pestañas)
// ---------------------------------------------------------------------------

#[derive(PartialEq)]
enum TabState {
    Connecting(String),
    Connected,
    Closed,
    Error(String),
}

struct HostPrompt {
    fingerprint: String,
    /// Si es Some, la huella guardada era distinta (posible ataque MITM).
    expected: Option<String>,
}

struct SessionTab {
    uid: u64,
    conn_id: Uuid,
    title: String,
    term: Terminal,
    cmd_tx: Sender<SessionCmd>,
    evt_rx: Receiver<SessionEvent>,
    state: TabState,
    host_prompt: Option<HostPrompt>,
    detached: bool,
    focus_next: bool,
    /// Túneles abiertos en esta sesión (los informa el hilo SSH).
    tunnels: Vec<TunnelInfo>,
    tunnel_input: String,
    tunnel_err: Option<String>,
}

impl SessionTab {
    fn send(&self, bytes: Vec<u8>) {
        if self.state == TabState::Connected && !bytes.is_empty() {
            let _ = self.cmd_tx.send(SessionCmd::Input(bytes));
        }
    }

    fn status_color(&self) -> Color32 {
        match self.state {
            TabState::Connecting(_) => Color32::from_rgb(230, 190, 80),
            TabState::Connected => Color32::from_rgb(110, 200, 110),
            TabState::Closed => Color32::GRAY,
            TabState::Error(_) => Color32::from_rgb(230, 90, 90),
        }
    }
}

impl Drop for SessionTab {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(SessionCmd::Close);
    }
}

fn start_session(conn: &Connection, cols: u16, rows: u16, ctx: &egui::Context) -> (Sender<SessionCmd>, Receiver<SessionEvent>) {
    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (evt_tx, evt_rx) = mpsc::channel();
    let ctx = ctx.clone();
    ssh::spawn(
        SessionParams::from_connection(conn, cols, rows),
        cmd_rx,
        evt_tx,
        move || ctx.request_repaint_of(ViewportId::ROOT),
    );
    (cmd_tx, evt_rx)
}

// ---------------------------------------------------------------------------
// Estado de la UI
// ---------------------------------------------------------------------------

enum Action {
    Send { uid: u64, text: String, enter: bool },
    SendAll { text: String, enter: bool },
    EditNote { conn_id: Uuid, note: Option<Note> },
    DeleteNote { conn_id: Uuid, note_id: Uuid },
    SaveHostKey { conn_id: Uuid, fp: String },
    SaveTunnel { conn_id: Uuid, tunnel: Tunnel },
    Connect(Uuid),
    Reconnect(u64),
    CloseTab(u64),
}

#[derive(Default)]
struct NotesUi {
    filter: String,
    broadcast: bool,
    hidden: bool,
}

struct ConnEditor {
    conn: Connection,
    is_new: bool,
    key_path: String,
    show_secret: bool,
    error: Option<String>,
    tunnel_input: String,
    tunnel_err: Option<String>,
}

struct NoteEditor {
    conn_id: Uuid,
    note: Note,
    is_new: bool,
}

#[derive(Default)]
struct PwdDialog {
    current: String,
    new1: String,
    new2: String,
    error: Option<String>,
}

#[derive(Default)]
struct LockScreen {
    focused_once: bool,
    password: String,
    confirm: String,
    error: Option<String>,
}

pub struct App {
    vault: Option<Vault>,
    vault_path: PathBuf,
    lock: LockScreen,
    tabs: Vec<SessionTab>,
    active: Option<u64>,
    next_uid: u64,
    conn_filter: String,
    notes_ui: NotesUi,
    conn_editor: Option<ConnEditor>,
    note_editor: Option<NoteEditor>,
    notes_window: Option<Uuid>,
    pwd_dialog: Option<PwdDialog>,
    confirm_delete: Option<Uuid>,
    toast: Option<(String, Instant, bool)>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        Self {
            vault: None,
            vault_path: Vault::default_path(),
            lock: LockScreen::default(),
            tabs: Vec::new(),
            active: None,
            next_uid: 1,
            conn_filter: String::new(),
            notes_ui: NotesUi::default(),
            conn_editor: None,
            note_editor: None,
            notes_window: None,
            pwd_dialog: None,
            confirm_delete: None,
            toast: None,
        }
    }

    fn info(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now(), false));
    }

    fn error(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now(), true));
    }

    fn save_vault(&mut self) {
        if let Some(v) = &self.vault
            && let Err(e) = v.save()
        {
            self.error(format!("Error guardando el almacén: {e:#}"));
        }
    }

    fn connect(&mut self, conn_id: Uuid, ctx: &egui::Context) {
        let Some(conn) = self.vault.as_ref().and_then(|v| v.get(conn_id)) else { return };
        let (cols, rows) = (120, 32);
        let (cmd_tx, evt_rx) = start_session(conn, cols, rows, ctx);
        let uid = self.next_uid;
        self.next_uid += 1;
        self.tabs.push(SessionTab {
            uid,
            conn_id,
            title: conn.display_name(),
            term: Terminal::new(cols, rows),
            cmd_tx,
            evt_rx,
            state: TabState::Connecting("Iniciando…".into()),
            host_prompt: None,
            detached: false,
            focus_next: true,
            tunnels: Vec::new(),
            tunnel_input: String::new(),
            tunnel_err: None,
        });
        self.active = Some(uid);
    }

    fn reconnect(&mut self, uid: u64, ctx: &egui::Context) {
        let Some(vault) = &self.vault else { return };
        let Some(tab) = self.tabs.iter_mut().find(|t| t.uid == uid) else { return };
        let Some(conn) = vault.get(tab.conn_id) else { return };
        let _ = tab.cmd_tx.send(SessionCmd::Close);
        let (cols, rows) = tab.term.size();
        let (cmd_tx, evt_rx) = start_session(conn, cols, rows, ctx);
        tab.cmd_tx = cmd_tx;
        tab.evt_rx = evt_rx;
        tab.state = TabState::Connecting("Reconectando…".into());
        tab.host_prompt = None;
        tab.focus_next = true;
        tab.tunnels.clear();
        tab.term.print_local("── Reconectando ──");
    }

    fn lock_vault(&mut self) {
        self.tabs.clear();
        self.active = None;
        self.vault = None;
        self.conn_editor = None;
        self.note_editor = None;
        self.notes_window = None;
        self.pwd_dialog = None;
        self.confirm_delete = None;
        self.lock = LockScreen::default();
    }

    /// Procesa los eventos que llegan de los hilos SSH.
    fn poll_sessions(&mut self, actions: &mut Vec<Action>) {
        for tab in &mut self.tabs {
            while let Ok(ev) = tab.evt_rx.try_recv() {
                match ev {
                    SessionEvent::Output(b) => tab.term.process(&b),
                    SessionEvent::Status(s) => {
                        tab.term.print_local(&s);
                        if tab.state != TabState::Connected {
                            tab.state = TabState::Connecting(s);
                        }
                    }
                    SessionEvent::HostKeyUnknown(fp) => {
                        tab.host_prompt = Some(HostPrompt { fingerprint: fp, expected: None });
                    }
                    SessionEvent::HostKeyMismatch { expected, got } => {
                        tab.host_prompt = Some(HostPrompt { fingerprint: got, expected: Some(expected) });
                    }
                    SessionEvent::HostKeyAccepted(fp) => {
                        tab.host_prompt = None;
                        actions.push(Action::SaveHostKey { conn_id: tab.conn_id, fp });
                    }
                    SessionEvent::Connected => {
                        tab.state = TabState::Connected;
                        tab.focus_next = true;
                        let (cols, rows) = tab.term.size();
                        let _ = tab.cmd_tx.send(SessionCmd::Resize { cols, rows });
                    }
                    SessionEvent::Tunnels(t) => {
                        for info in &t {
                            let known = tab.tunnels.iter().find(|o| o.spec.same_listener(&info.spec));
                            if info.error.is_some() && known.and_then(|o| o.error.as_ref()) != info.error.as_ref() {
                                tab.term.print_local(&format!("Túnel {}: {}", info.spec.label(), info.error.as_deref().unwrap_or("")));
                            } else if info.listening && known.is_none() {
                                tab.term.print_local(&format!("🔀 Túnel activo: {}", info.spec.label()));
                            }
                        }
                        tab.tunnels = t;
                    }
                    SessionEvent::Error(e) => {
                        tab.term.print_local(&format!("Error: {e}"));
                        tab.state = TabState::Error(e);
                    }
                    SessionEvent::Closed => {
                        tab.host_prompt = None;
                        tab.tunnels.clear();
                        if !matches!(tab.state, TabState::Error(_)) {
                            tab.state = TabState::Closed;
                        }
                        tab.term.print_local("── Conexión cerrada ──");
                    }
                }
            }
        }
    }

    fn apply_actions(&mut self, actions: Vec<Action>, ctx: &egui::Context) {
        for a in actions {
            match a {
                Action::Send { uid, text, enter } => {
                    if let Some(tab) = self.tabs.iter_mut().find(|t| t.uid == uid) {
                        let mut bytes = tab.term.paste_bytes(&text);
                        if enter {
                            bytes.push(b'\r');
                        }
                        tab.send(bytes);
                        tab.focus_next = true;
                    }
                }
                Action::SendAll { text, enter } => {
                    let mut n = 0;
                    for tab in self.tabs.iter_mut().filter(|t| t.state == TabState::Connected) {
                        let mut bytes = tab.term.paste_bytes(&text);
                        if enter {
                            bytes.push(b'\r');
                        }
                        tab.send(bytes);
                        n += 1;
                    }
                    self.info(format!("Comando enviado a {n} sesiones"));
                }
                Action::EditNote { conn_id, note } => {
                    let is_new = note.is_none();
                    self.note_editor = Some(NoteEditor { conn_id, note: note.unwrap_or_else(Note::new), is_new });
                }
                Action::DeleteNote { conn_id, note_id } => {
                    if let Some(c) = self.vault.as_mut().and_then(|v| v.get_mut(conn_id)) {
                        c.notes.retain(|n| n.id != note_id);
                    }
                    self.save_vault();
                }
                Action::SaveHostKey { conn_id, fp } => {
                    if let Some(c) = self.vault.as_mut().and_then(|v| v.get_mut(conn_id)) {
                        c.host_key = Some(fp);
                    }
                    self.save_vault();
                }
                Action::SaveTunnel { conn_id, tunnel } => {
                    if let Some(c) = self.vault.as_mut().and_then(|v| v.get_mut(conn_id)) {
                        c.tunnels.retain(|t| !t.same_listener(&tunnel));
                        c.tunnels.push(tunnel);
                    }
                    self.save_vault();
                    self.info("Túnel guardado en la conexión");
                }
                Action::Connect(id) => self.connect(id, ctx),
                Action::Reconnect(uid) => self.reconnect(uid, ctx),
                Action::CloseTab(uid) => {
                    self.tabs.retain(|t| t.uid != uid);
                    if self.active == Some(uid) {
                        self.active = self.tabs.last().map(|t| t.uid);
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Pantalla de desbloqueo
    // -----------------------------------------------------------------------

    fn lock_ui(&mut self, ui: &mut egui::Ui) {
        let exists = Vault::exists(&self.vault_path);
        egui::CentralPanel::default().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() * 0.2);
                ui.heading(RichText::new("🔐 JHTerminalx").size(30.0));
                ui.label("Gestor de conexiones SSH múltiples");
                ui.add_space(20.0);
                ui.label(if exists {
                    "Introduce la contraseña maestra para descifrar tus conexiones"
                } else {
                    "Crea una contraseña maestra (mín. 8 caracteres). Cifrará conexiones, credenciales y notas."
                });
                ui.add_space(8.0);
                let r = ui.add(
                    TextEdit::singleline(&mut self.lock.password)
                        .password(true)
                        .hint_text("Contraseña maestra")
                        .desired_width(280.0),
                );
                if !self.lock.focused_once {
                    r.request_focus();
                    self.lock.focused_once = true;
                }
                let mut submit = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                if !exists {
                    let r2 = ui.add(
                        TextEdit::singleline(&mut self.lock.confirm)
                            .password(true)
                            .hint_text("Repite la contraseña")
                            .desired_width(280.0),
                    );
                    submit |= r2.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                }
                ui.add_space(8.0);
                let label = if exists { "Desbloquear" } else { "Crear almacén" };
                submit |= ui.button(RichText::new(label).size(16.0)).clicked();
                if let Some(e) = &self.lock.error {
                    ui.colored_label(Color32::from_rgb(230, 90, 90), e);
                }
                ui.add_space(16.0);
                ui.small(format!("Almacén: {}", self.vault_path.display()));

                if submit {
                    let result = if exists {
                        Vault::open(self.vault_path.clone(), &self.lock.password)
                    } else if self.lock.password != self.lock.confirm {
                        Err(anyhow::anyhow!("Las contraseñas no coinciden"))
                    } else {
                        Vault::create(self.vault_path.clone(), &self.lock.password)
                    };
                    match result {
                        Ok(v) => {
                            self.vault = Some(v);
                            self.lock = LockScreen::default();
                        }
                        Err(e) => {
                            self.lock.error = Some(format!("{e:#}"));
                            use zeroize::Zeroize;
                            self.lock.password.zeroize();
                        }
                    }
                }
            });
        });
    }

    // -----------------------------------------------------------------------
    // Pantalla principal
    // -----------------------------------------------------------------------

    fn main_ui(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let mut actions = Vec::new();
        self.poll_sessions(&mut actions);

        // Atajos globales
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL | egui::Modifiers::SHIFT, Key::T)) {
            self.open_new_connection();
        }

        // --- Menú ---
        Panel::top("menu").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("Archivo", |ui| {
                    if ui.button("➕ Nueva conexión  (Ctrl+Shift+T)").clicked() {
                        self.open_new_connection();
                        ui.close();
                    }
                    if ui.button("🔑 Cambiar contraseña maestra").clicked() {
                        self.pwd_dialog = Some(PwdDialog::default());
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("🔒 Bloquear").clicked() {
                        self.lock_vault();
                        ui.close();
                    }
                    if ui.button("Salir").clicked() {
                        ctx.send_viewport_cmd(ViewportCommand::Close);
                    }
                });
                ui.menu_button("Ver", |ui| {
                    let mut show = !self.notes_ui.hidden;
                    if ui.checkbox(&mut show, "Panel de notas").changed() {
                        self.notes_ui.hidden = !show;
                    }
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let connected = self.tabs.iter().filter(|t| t.state == TabState::Connected).count();
                    ui.label(format!("{connected} conectadas / {} sesiones", self.tabs.len()));
                });
            });
        });

        // --- Barra de estado ---
        Panel::bottom("status").show(ui, |ui| {
            let mut clear = false;
            if let Some((msg, t, err)) = &self.toast {
                if t.elapsed() > Duration::from_secs(5) {
                    clear = true;
                } else {
                    let c = if *err { Color32::from_rgb(230, 90, 90) } else { Color32::from_rgb(120, 200, 120) };
                    ui.colored_label(c, msg);
                    ctx.request_repaint_after(Duration::from_secs(1));
                }
            } else {
                ui.small("Ctrl+Shift+C copia la selección · Ctrl+V pega · Clic derecho: más opciones");
            }
            if clear {
                self.toast = None;
            }
        });

        // --- Pestañas ---
        if !self.tabs.is_empty() {
            Panel::top("tabs").show(ui, |ui| {
                ScrollArea::horizontal().show(ui, |ui| {
                    ui.horizontal(|ui| {
                        for tab in &self.tabs {
                            let selected = self.active == Some(tab.uid);
                            Frame::new()
                                .inner_margin(Margin::symmetric(6, 2))
                                .corner_radius(4.0)
                                .fill(if selected { ui.visuals().selection.bg_fill } else { ui.visuals().faint_bg_color })
                                .show(ui, |ui| {
                                    ui.colored_label(tab.status_color(), "●");
                                    let label = if tab.detached { format!("⧉ {}", tab.title) } else { tab.title.clone() };
                                    if ui.selectable_label(selected, label).clicked() {
                                        self.active = Some(tab.uid);
                                        if tab.detached {
                                            ctx.send_viewport_cmd_to(viewport_id(tab.uid), ViewportCommand::Focus);
                                        }
                                    }
                                    if ui.small_button("✖").on_hover_text("Cerrar sesión").clicked() {
                                        actions.push(Action::CloseTab(tab.uid));
                                    }
                                });
                        }
                    });
                });
            });
        }

        // --- Lista de conexiones ---
        Panel::left("connections").default_size(240.0).show(ui, |ui| {
            self.connections_ui(ui, &mut actions);
        });

        // --- Sesión activa ---
        egui::CentralPanel::default().frame(Frame::NONE).show(ui, |ui| {
            let App { tabs, vault, notes_ui, active, .. } = self;
            let vault = vault.as_ref().unwrap();
            match tabs.iter_mut().find(|t| Some(t.uid) == *active) {
                Some(tab) if !tab.detached => {
                    let conn = vault.get(tab.conn_id);
                    session_view(ui, tab, conn, notes_ui, &mut actions, true);
                }
                Some(tab) => {
                    ui.centered_and_justified(|ui| {
                        if ui.button(format!("«{}» está en una ventana separada. Pulsa para traerla aquí.", tab.title)).clicked() {
                            tab.detached = false;
                        }
                    });
                }
                None => welcome(ui),
            }
        });

        // --- Ventanas separadas ---
        {
            let App { tabs, vault, notes_ui, active, .. } = self;
            let vault = vault.as_ref().unwrap();
            for tab in tabs.iter_mut().filter(|t| t.detached) {
                let title = format!("{} — JHTerminalx", tab.title);
                let builder = ViewportBuilder::default().with_title(title).with_inner_size([960.0, 600.0]);
                ctx.show_viewport_immediate(viewport_id(tab.uid), builder, |ui, _class| {
                    if ui.ctx().input(|i| i.viewport().close_requested()) {
                        // Cerrar la ventana devuelve la sesión a la ventana principal.
                        tab.detached = false;
                        *active = Some(tab.uid);
                        return;
                    }
                    egui::CentralPanel::default().frame(Frame::NONE).show(ui, |ui| {
                        let conn = vault.get(tab.conn_id);
                        session_view(ui, tab, conn, notes_ui, &mut actions, false);
                    });
                });
            }
        }

        // --- Diálogos ---
        self.conn_editor_ui(&ctx);
        self.note_editor_ui(&ctx);
        self.notes_window_ui(&ctx, &mut actions);
        self.pwd_dialog_ui(&ctx);
        self.confirm_delete_ui(&ctx);

        self.apply_actions(actions, &ctx);
    }

    fn open_new_connection(&mut self) {
        self.conn_editor = Some(ConnEditor {
            conn: Connection::new(),
            is_new: true,
            key_path: DEFAULT_KEY.into(),
            show_secret: false,
            error: None,
            tunnel_input: String::new(),
            tunnel_err: None,
        });
    }

    fn connections_ui(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.heading("Conexiones");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("➕").on_hover_text("Nueva conexión").clicked() {
                    self.open_new_connection();
                }
            });
        });
        ui.add(TextEdit::singleline(&mut self.conn_filter).hint_text("🔍 Buscar…").desired_width(f32::INFINITY));
        ui.separator();

        let Some(vault) = &self.vault else { return };
        let filter = self.conn_filter.to_lowercase();
        let mut groups: BTreeMap<String, Vec<&Connection>> = BTreeMap::new();
        for c in &vault.data.connections {
            let hay = format!("{} {} {} {}", c.name, c.host, c.username, c.group).to_lowercase();
            if filter.is_empty() || hay.contains(&filter) {
                let g = if c.group.trim().is_empty() { "Sin grupo".to_string() } else { c.group.trim().to_string() };
                groups.entry(g).or_default().push(c);
            }
        }
        if vault.data.connections.is_empty() {
            ui.label("Aún no hay conexiones.");
            if ui.button("Crear la primera").clicked() {
                self.open_new_connection();
            }
            return;
        }

        let mut edit: Option<Connection> = None;
        let mut duplicate: Option<Connection> = None;
        ScrollArea::vertical().show(ui, |ui| {
            for (group, conns) in &groups {
                egui::CollapsingHeader::new(RichText::new(format!("📁 {group} ({})", conns.len())).strong())
                    .id_salt(("grp", group))
                    .default_open(true)
                    .show(ui, |ui| {
                        for c in conns {
                            let open = self.tabs.iter().filter(|t| t.conn_id == c.id).count();
                            let text = if open > 0 { format!("🖥 {}  ({open})", c.display_name()) } else { format!("🖥 {}", c.display_name()) };
                            let r = ui
                                .add(egui::Button::selectable(false, text).wrap_mode(egui::TextWrapMode::Truncate))
                                .on_hover_text(format!("{}@{}:{}\nDoble clic para conectar", c.username, c.host, c.port));
                            if r.double_clicked() {
                                actions.push(Action::Connect(c.id));
                            }
                            r.context_menu(|ui| {
                                if ui.button("▶ Conectar").clicked() {
                                    actions.push(Action::Connect(c.id));
                                    ui.close();
                                }
                                if ui.button("✏ Editar").clicked() {
                                    edit = Some((*c).clone());
                                    ui.close();
                                }
                                if ui.button(format!("📝 Notas ({})", c.notes.len())).clicked() {
                                    self.notes_window = Some(c.id);
                                    ui.close();
                                }
                                if ui.button("📋 Duplicar").clicked() {
                                    duplicate = Some((*c).clone());
                                    ui.close();
                                }
                                ui.separator();
                                if ui.button("🗑 Eliminar").clicked() {
                                    self.confirm_delete = Some(c.id);
                                    ui.close();
                                }
                            });
                        }
                    });
            }
        });
        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            ui.small("Doble clic: conectar · Clic derecho: opciones");
        });

        if let Some(c) = edit {
            let key_path = match &c.auth {
                AuthMethod::PrivateKey { path } => path.clone(),
                _ => DEFAULT_KEY.into(),
            };
            self.conn_editor = Some(ConnEditor {
                conn: c,
                is_new: false,
                key_path,
                show_secret: false,
                error: None,
                tunnel_input: String::new(),
                tunnel_err: None,
            });
        }
        if let Some(mut c) = duplicate {
            c.id = Uuid::new_v4();
            c.name = format!("{} (copia)", c.display_name());
            for n in &mut c.notes {
                n.id = Uuid::new_v4();
            }
            if let Some(v) = &mut self.vault {
                v.data.connections.push(c);
            }
            self.save_vault();
        }
    }

    fn conn_editor_ui(&mut self, ctx: &egui::Context) {
        let Some(ed) = &mut self.conn_editor else { return };
        let groups: Vec<String> = {
            let mut g: Vec<String> = self
                .vault
                .as_ref()
                .map(|v| v.data.connections.iter().map(|c| c.group.clone()).filter(|g| !g.is_empty()).collect())
                .unwrap_or_default();
            g.sort();
            g.dedup();
            g
        };
        let mut open = true;
        let mut save = false;
        let mut cancel = false;
        let title = if ed.is_new { "Nueva conexión" } else { "Editar conexión" };
        egui::Window::new(title).open(&mut open).collapsible(false).resizable(false).show(ctx, |ui| {
            egui::Grid::new("conn_grid").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                ui.label("Nombre:");
                ui.add(TextEdit::singleline(&mut ed.conn.name).hint_text("Servidor web").desired_width(260.0));
                ui.end_row();

                ui.label("Grupo:");
                ui.horizontal(|ui| {
                    ui.add(TextEdit::singleline(&mut ed.conn.group).hint_text("Producción").desired_width(225.0));
                    ui.menu_button("▾", |ui| {
                        for g in &groups {
                            if ui.button(g).clicked() {
                                ed.conn.group = g.clone();
                                ui.close();
                            }
                        }
                    });
                });
                ui.end_row();

                ui.label("Host / IP:");
                ui.add(TextEdit::singleline(&mut ed.conn.host).hint_text("192.168.1.10").desired_width(260.0));
                ui.end_row();

                ui.label("Puerto:");
                ui.add(egui::DragValue::new(&mut ed.conn.port).range(1..=65535));
                ui.end_row();

                ui.label("Usuario:");
                ui.add(TextEdit::singleline(&mut ed.conn.username).hint_text("root").desired_width(260.0));
                ui.end_row();

                ui.label("Autenticación:");
                let mut kind = match ed.conn.auth {
                    AuthMethod::Password => 0,
                    AuthMethod::PrivateKey { .. } => 1,
                    AuthMethod::Agent => 2,
                };
                ui.horizontal(|ui| {
                    ui.radio_value(&mut kind, 0, "Contraseña");
                    ui.radio_value(&mut kind, 1, "Clave privada");
                    ui.radio_value(&mut kind, 2, "ssh-agent");
                });
                ui.end_row();
                ed.conn.auth = match kind {
                    0 => AuthMethod::Password,
                    1 => AuthMethod::PrivateKey { path: ed.key_path.clone() },
                    _ => AuthMethod::Agent,
                };

                if kind == 1 {
                    ui.label("Archivo de clave:");
                    if ui.add(TextEdit::singleline(&mut ed.key_path).desired_width(260.0)).changed() {
                        ed.conn.auth = AuthMethod::PrivateKey { path: ed.key_path.clone() };
                    }
                    ui.end_row();
                }
                if kind != 2 {
                    ui.label(if kind == 0 { "Contraseña:" } else { "Frase de paso:" });
                    ui.horizontal(|ui| {
                        ui.add(TextEdit::singleline(&mut ed.conn.secret).password(!ed.show_secret).desired_width(225.0));
                        if ui.selectable_label(ed.show_secret, "👁").on_hover_text("Mostrar").clicked() {
                            ed.show_secret = !ed.show_secret;
                        }
                    });
                    ui.end_row();
                }

                ui.label("Huella del host:");
                ui.horizontal(|ui| match &ed.conn.host_key {
                    Some(fp) => {
                        ui.monospace(RichText::new(fp).small());
                        if ui.small_button("Olvidar").clicked() {
                            ed.conn.host_key = None;
                        }
                    }
                    None => {
                        ui.weak("(se pedirá confirmación al conectar)");
                    }
                });
                ui.end_row();
            });

            ui.separator();
            ui.strong("🔀 Túneles (reenvío de puertos local, como ssh -L)");
            ui.weak("Se abren automáticamente al conectar. Ej.: 2000:localhost:2000");
            let mut remove = None;
            for (i, t) in ed.conn.tunnels.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    ui.checkbox(&mut t.enabled, "").on_hover_text("Abrir al conectar");
                    ui.monospace(format!("-L {}", t.spec()));
                    ui.weak(t.label());
                    if ui.small_button("🗑").on_hover_text("Quitar").clicked() {
                        remove = Some(i);
                    }
                });
            }
            if let Some(i) = remove {
                ed.conn.tunnels.remove(i);
            }
            ui.horizontal(|ui| {
                let r = ui.add(
                    TextEdit::singleline(&mut ed.tunnel_input)
                        .hint_text("[dirección:]puerto_local:host:puerto_remoto")
                        .desired_width(260.0),
                );
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                if (ui.button("➕ Añadir").clicked() || enter) && !ed.tunnel_input.trim().is_empty() {
                    match Tunnel::parse(&ed.tunnel_input) {
                        Ok(t) if ed.conn.tunnels.iter().any(|o| o.same_listener(&t)) => {
                            ed.tunnel_err = Some(format!("Ya hay un túnel en {}:{}", t.bind, t.local_port));
                        }
                        Ok(t) => {
                            ed.conn.tunnels.push(t);
                            ed.tunnel_input.clear();
                            ed.tunnel_err = None;
                        }
                        Err(e) => ed.tunnel_err = Some(format!("{e:#}")),
                    }
                }
            });
            if let Some(e) = &ed.tunnel_err {
                ui.colored_label(Color32::from_rgb(230, 90, 90), e);
            }

            if let Some(e) = &ed.error {
                ui.colored_label(Color32::from_rgb(230, 90, 90), e);
            }
            ui.separator();
            ui.horizontal(|ui| {
                if ui.button("💾 Guardar").clicked() {
                    save = true;
                }
                if ui.button("Cancelar").clicked() {
                    cancel = true;
                }
                ui.weak("Todo se guarda cifrado");
            });
        });

        if save {
            if ed.conn.host.trim().is_empty() || ed.conn.username.trim().is_empty() {
                ed.error = Some("Host y usuario son obligatorios".into());
            } else if let Some(v) = &mut self.vault {
                let c = ed.conn.clone();
                if let Some(existing) = v.get_mut(c.id) {
                    // Conserva las notas actuales (podrían haberse editado mientras tanto).
                    let notes = std::mem::take(&mut existing.notes);
                    *existing = c;
                    existing.notes = notes;
                } else {
                    v.data.connections.push(c);
                }
                self.conn_editor = None;
                self.save_vault();
                self.info("Conexión guardada");
                return;
            }
        }
        if cancel || !open {
            self.conn_editor = None;
        }
    }

    fn note_editor_ui(&mut self, ctx: &egui::Context) {
        let Some(ed) = &mut self.note_editor else { return };
        let categories: Vec<String> = self
            .vault
            .as_ref()
            .map(|v| all_categories(v))
            .unwrap_or_default();
        let mut open = true;
        let mut save = false;
        let mut cancel = false;
        egui::Window::new(if ed.is_new { "Nueva nota de comando" } else { "Editar nota" })
            .open(&mut open)
            .collapsible(false)
            .default_width(480.0)
            .show(ctx, |ui| {
                egui::Grid::new("note_grid").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Categoría:");
                    ui.horizontal(|ui| {
                        ui.add(TextEdit::singleline(&mut ed.note.category).desired_width(260.0));
                        ui.menu_button("▾", |ui| {
                            for c in &categories {
                                if ui.button(c).clicked() {
                                    ed.note.category = c.clone();
                                    ui.close();
                                }
                            }
                        });
                    });
                    ui.end_row();
                    ui.label("Título:");
                    ui.add(TextEdit::singleline(&mut ed.note.title).hint_text("Ver uso de disco").desired_width(300.0));
                    ui.end_row();
                });
                ui.label("Comando(s):");
                ui.add(
                    TextEdit::multiline(&mut ed.note.command)
                        .code_editor()
                        .desired_rows(6)
                        .desired_width(f32::INFINITY)
                        .hint_text("df -h\n# varias líneas se envían en orden"),
                );
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("💾 Guardar").clicked() {
                        save = true;
                    }
                    if ui.button("Cancelar").clicked() {
                        cancel = true;
                    }
                });
            });
        if save && !ed.note.command.trim().is_empty() {
            let mut note = ed.note.clone();
            if note.category.trim().is_empty() {
                note.category = "General".into();
            }
            note.category = note.category.trim().to_string();
            if note.title.trim().is_empty() {
                note.title = note.command.lines().next().unwrap_or("").chars().take(40).collect();
            }
            let conn_id = ed.conn_id;
            if let Some(c) = self.vault.as_mut().and_then(|v| v.get_mut(conn_id)) {
                match c.notes.iter_mut().find(|n| n.id == note.id) {
                    Some(n) => *n = note,
                    None => c.notes.push(note),
                }
            }
            self.note_editor = None;
            self.save_vault();
            return;
        }
        if cancel || !open {
            self.note_editor = None;
        }
    }

    /// Ventana de notas de una conexión (accesible sin sesión abierta).
    fn notes_window_ui(&mut self, ctx: &egui::Context, actions: &mut Vec<Action>) {
        let Some(conn_id) = self.notes_window else { return };
        let Some(conn) = self.vault.as_ref().and_then(|v| v.get(conn_id)) else {
            self.notes_window = None;
            return;
        };
        // Si hay una sesión abierta de esa conexión, los comandos van a ella.
        let target = self
            .tabs
            .iter()
            .find(|t| t.conn_id == conn_id && Some(t.uid) == self.active)
            .or_else(|| self.tabs.iter().find(|t| t.conn_id == conn_id))
            .filter(|t| t.state == TabState::Connected)
            .map(|t| t.uid);
        let mut open = true;
        egui::Window::new(format!("📝 Notas — {}", conn.display_name()))
            .open(&mut open)
            .default_size([380.0, 480.0])
            .show(ctx, |ui| {
                notes_panel(ui, conn, target, &mut self.notes_ui, actions);
            });
        if !open {
            self.notes_window = None;
        }
    }

    fn pwd_dialog_ui(&mut self, ctx: &egui::Context) {
        let Some(d) = &mut self.pwd_dialog else { return };
        let mut open = true;
        let mut submit = false;
        egui::Window::new("Cambiar contraseña maestra").open(&mut open).collapsible(false).resizable(false).show(ctx, |ui| {
            egui::Grid::new("pwd").num_columns(2).show(ui, |ui| {
                ui.label("Actual:");
                ui.add(TextEdit::singleline(&mut d.current).password(true));
                ui.end_row();
                ui.label("Nueva:");
                ui.add(TextEdit::singleline(&mut d.new1).password(true));
                ui.end_row();
                ui.label("Repetir:");
                ui.add(TextEdit::singleline(&mut d.new2).password(true));
                ui.end_row();
            });
            if let Some(e) = &d.error {
                ui.colored_label(Color32::from_rgb(230, 90, 90), e);
            }
            submit = ui.button("Cambiar").clicked();
        });
        if submit {
            let Some(vault) = &mut self.vault else { return };
            if d.new1 != d.new2 {
                d.error = Some("Las contraseñas nuevas no coinciden".into());
            } else if Vault::open(vault.path().to_path_buf(), &d.current).is_err() {
                d.error = Some("La contraseña actual no es correcta".into());
            } else if let Err(e) = vault.change_password(&d.new1) {
                d.error = Some(format!("{e:#}"));
            } else {
                self.pwd_dialog = None;
                self.info("Contraseña maestra cambiada");
                return;
            }
        }
        if !open {
            self.pwd_dialog = None;
        }
    }

    fn confirm_delete_ui(&mut self, ctx: &egui::Context) {
        let Some(id) = self.confirm_delete else { return };
        let name = self.vault.as_ref().and_then(|v| v.get(id)).map(|c| c.display_name()).unwrap_or_default();
        let mut decision = None;
        egui::Window::new("Eliminar conexión").collapsible(false).resizable(false).show(ctx, |ui| {
            ui.label(format!("¿Eliminar «{name}» y todas sus notas?"));
            ui.horizontal(|ui| {
                if ui.button("🗑 Eliminar").clicked() {
                    decision = Some(true);
                }
                if ui.button("Cancelar").clicked() {
                    decision = Some(false);
                }
            });
        });
        match decision {
            Some(true) => {
                if let Some(v) = &mut self.vault {
                    v.data.connections.retain(|c| c.id != id);
                }
                self.confirm_delete = None;
                self.save_vault();
            }
            Some(false) => self.confirm_delete = None,
            None => {}
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.vault.is_none() {
            self.lock_ui(ui);
        } else {
            self.main_ui(ui);
        }
    }
}

fn viewport_id(uid: u64) -> ViewportId {
    ViewportId::from_hash_of(("session", uid))
}

fn all_categories(v: &Vault) -> Vec<String> {
    let mut cats: Vec<String> = v
        .data
        .connections
        .iter()
        .flat_map(|c| c.notes.iter().map(|n| n.category.clone()))
        .collect();
    cats.sort();
    cats.dedup();
    cats
}

fn welcome(ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() * 0.3);
        ui.heading("Bienvenido a JHTerminalx");
        ui.add_space(8.0);
        ui.label("Doble clic en una conexión de la izquierda para abrir una sesión SSH.");
        ui.label("Cada sesión se abre en una pestaña; usa «⧉ Ventana» para separarla en su propia ventana.");
        ui.label("Las notas de comandos de cada conexión aparecen a la derecha de la sesión.");
    });
}

/// Vista de una sesión: barra superior, panel de notas y terminal.
fn session_view(
    ui: &mut egui::Ui,
    tab: &mut SessionTab,
    conn: Option<&Connection>,
    notes_ui: &mut NotesUi,
    actions: &mut Vec<Action>,
    in_main: bool,
) {
    // Barra de la sesión
    Panel::top(("session_bar", tab.uid)).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.colored_label(tab.status_color(), "●");
            ui.strong(&tab.title);
            match &tab.state {
                TabState::Connecting(s) => {
                    ui.spinner();
                    ui.label(s);
                }
                TabState::Connected => {
                    ui.weak(conn.map(|c| format!("{}@{}:{}", c.username, c.host, c.port)).unwrap_or_default());
                }
                TabState::Closed => {
                    ui.weak("Desconectado");
                }
                TabState::Error(e) => {
                    ui.colored_label(Color32::from_rgb(230, 90, 90), e);
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("✖ Cerrar").clicked() {
                    actions.push(Action::CloseTab(tab.uid));
                }
                if matches!(tab.state, TabState::Closed | TabState::Error(_)) && ui.button("⟳ Reconectar").clicked() {
                    actions.push(Action::Reconnect(tab.uid));
                }
                if in_main {
                    if ui.button("⧉ Ventana").on_hover_text("Abrir en ventana separada").clicked() {
                        tab.detached = true;
                    }
                } else if ui.button("⇤ Volver a pestaña").clicked() {
                    tab.detached = false;
                }
                tunnels_menu(ui, tab, conn, actions);
                let notes_label = if notes_ui.hidden { "📝 Mostrar notas" } else { "📝 Ocultar notas" };
                if ui.button(notes_label).clicked() {
                    notes_ui.hidden = !notes_ui.hidden;
                }
            });
        });

        // Confirmación de la clave del host
        if let Some(p) = &tab.host_prompt {
            let mut decision = None;
            Frame::new()
                .fill(if p.expected.is_some() { Color32::from_rgb(90, 20, 20) } else { Color32::from_rgb(60, 50, 15) })
                .inner_margin(8)
                .corner_radius(4.0)
                .show(ui, |ui| {
                    if let Some(exp) = &p.expected {
                        ui.strong("⚠ ¡LA CLAVE DEL HOST HA CAMBIADO! Podría ser un ataque de intermediario (MITM).");
                        ui.monospace(format!("Guardada: {exp}"));
                        ui.monospace(format!("Recibida: {}", p.fingerprint));
                    } else {
                        ui.strong("Primera conexión a este host. Verifica la huella de su clave:");
                        ui.monospace(&p.fingerprint);
                    }
                    ui.horizontal(|ui| {
                        if ui.button("✔ Confiar y continuar").clicked() {
                            decision = Some(true);
                        }
                        if ui.button("✖ Cancelar").clicked() {
                            decision = Some(false);
                        }
                    });
                });
            if let Some(d) = decision {
                let _ = tab.cmd_tx.send(SessionCmd::HostKeyDecision(d));
                tab.host_prompt = None;
            }
        }
    });

    // Panel de notas
    if let Some(conn) = conn
        && !notes_ui.hidden
    {
        Panel::right(("notes", tab.uid)).default_size(320.0).min_size(220.0).show(ui, |ui| {
            let target = (tab.state == TabState::Connected).then_some(tab.uid);
            notes_panel(ui, conn, target, notes_ui, actions);
        });
    }

    // Terminal
    egui::CentralPanel::default().frame(Frame::NONE).show(ui, |ui| {
        let focus = std::mem::take(&mut tab.focus_next);
        let out = tab.term.ui(ui, ui.scope_id().with(("term", tab.uid)), focus);
        if let Some((cols, rows)) = out.resized {
            let _ = tab.cmd_tx.send(SessionCmd::Resize { cols, rows });
        }
        tab.send(out.input);
    });
}

/// Botón «🔀 Túneles» de la barra de sesión: estado de los túneles y alta en caliente.
fn tunnels_menu(ui: &mut egui::Ui, tab: &mut SessionTab, conn: Option<&Connection>, actions: &mut Vec<Action>) {
    use egui::containers::menu::{MenuButton, MenuConfig};

    let active = tab.tunnels.iter().filter(|t| t.listening).count();
    let label = if active > 0 { format!("🔀 Túneles ({active})") } else { "🔀 Túneles".to_string() };
    let connected = tab.state == TabState::Connected;
    MenuButton::new(label)
        .config(MenuConfig::new().close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside))
        .ui(ui, |ui| {
            ui.set_min_width(380.0);
            ui.strong("Reenvío de puertos local (ssh -L)");
            if !connected {
                ui.weak("Conecta la sesión para abrir túneles.");
            }
            if tab.tunnels.is_empty() && connected {
                ui.weak("No hay túneles abiertos en esta sesión.");
            }
            for t in &tab.tunnels {
                ui.horizontal(|ui| {
                    let (dot, color) = match (&t.error, t.listening) {
                        (_, true) if t.active > 0 => ("●", Color32::from_rgb(110, 200, 110)),
                        (_, true) => ("●", Color32::from_rgb(120, 160, 230)),
                        _ => ("●", Color32::from_rgb(230, 90, 90)),
                    };
                    ui.colored_label(color, dot);
                    ui.monospace(t.spec.label());
                    if t.listening {
                        ui.weak(format!("{} abiertas · {} total", t.active, t.total));
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button("✖").on_hover_text("Cerrar túnel").clicked() {
                            let _ = tab.cmd_tx.send(SessionCmd::RemoveTunnel(t.spec.clone()));
                        }
                        let saved = conn.is_some_and(|c| c.tunnels.iter().any(|o| o.same_listener(&t.spec)));
                        if let Some(c) = conn
                            && !saved
                            && ui.small_button("💾").on_hover_text("Guardar en la conexión").clicked()
                        {
                            actions.push(Action::SaveTunnel { conn_id: c.id, tunnel: t.spec.clone() });
                        }
                    });
                });
                if let Some(e) = &t.error {
                    ui.colored_label(Color32::from_rgb(230, 90, 90), RichText::new(e).small());
                }
            }
            ui.separator();
            ui.add_enabled_ui(connected, |ui| {
                ui.horizontal(|ui| {
                    ui.label("-L");
                    let r = ui.add(
                        TextEdit::singleline(&mut tab.tunnel_input)
                            .hint_text("2000:localhost:2000")
                            .desired_width(200.0),
                    );
                    let enter = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                    let open = ui.button("Abrir").on_hover_text("Solo para esta sesión").clicked() || enter;
                    let open_save = ui.button("Abrir y guardar").on_hover_text("Abrir y guardarlo en la conexión").clicked();
                    if (open || open_save) && !tab.tunnel_input.trim().is_empty() {
                        match Tunnel::parse(&tab.tunnel_input) {
                            Ok(t) => {
                                if open_save && let Some(c) = conn {
                                    actions.push(Action::SaveTunnel { conn_id: c.id, tunnel: t.clone() });
                                }
                                let _ = tab.cmd_tx.send(SessionCmd::AddTunnel(t));
                                tab.tunnel_input.clear();
                                tab.tunnel_err = None;
                            }
                            Err(e) => tab.tunnel_err = Some(format!("{e:#}")),
                        }
                    }
                });
            });
            if let Some(e) = &tab.tunnel_err {
                ui.colored_label(Color32::from_rgb(230, 90, 90), e);
            }
            ui.weak("Formato: [dirección:]puerto_local:host_remoto:puerto_remoto");
            ui.weak("El host remoto se resuelve desde el servidor SSH (localhost = el propio servidor).");
        });
}

/// Lista de notas de una conexión, agrupadas por categoría.
fn notes_panel(
    ui: &mut egui::Ui,
    conn: &Connection,
    target: Option<u64>,
    st: &mut NotesUi,
    actions: &mut Vec<Action>,
) {
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.heading("📝 Notas");
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.button("➕ Nueva").clicked() {
                actions.push(Action::EditNote { conn_id: conn.id, note: None });
            }
        });
    });
    ui.add(TextEdit::singleline(&mut st.filter).hint_text("🔍 Filtrar comandos…").desired_width(f32::INFINITY));
    ui.checkbox(&mut st.broadcast, "📡 Enviar a TODAS las sesiones conectadas");
    if target.is_none() && !st.broadcast {
        ui.weak("Sin sesión conectada: los comandos no se pueden enviar.");
    }
    ui.separator();

    let filter = st.filter.to_lowercase();
    let mut cats: BTreeMap<&str, Vec<&Note>> = BTreeMap::new();
    for n in &conn.notes {
        let hay = format!("{} {} {}", n.category, n.title, n.command).to_lowercase();
        if filter.is_empty() || hay.contains(&filter) {
            cats.entry(n.category.as_str()).or_default().push(n);
        }
    }
    if conn.notes.is_empty() {
        ui.label("Esta conexión no tiene notas todavía.");
        ui.weak("Guarda aquí los comandos que usas a menudo, organizados por categoría.");
    }

    let can_send = target.is_some() || st.broadcast;
    let broadcast = st.broadcast;
    let send = |text: &str, enter: bool| match (broadcast, target) {
        (true, _) => Some(Action::SendAll { text: text.to_string(), enter }),
        (false, Some(uid)) => Some(Action::Send { uid, text: text.to_string(), enter }),
        _ => None,
    };

    ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        for (cat, notes) in &cats {
            egui::CollapsingHeader::new(RichText::new(format!("📂 {cat} ({})", notes.len())).strong())
                .id_salt(("cat", conn.id, *cat))
                .default_open(true)
                .show(ui, |ui| {
                    for n in notes {
                        Frame::group(ui.style()).inner_margin(6).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(can_send, egui::Button::new("▶"))
                                    .on_hover_text("Escribir y ejecutar (Enter)")
                                    .clicked()
                                {
                                    actions.extend(send(&n.command, true));
                                }
                                if ui
                                    .add_enabled(can_send, egui::Button::new("⌨"))
                                    .on_hover_text("Escribir en la terminal sin ejecutar")
                                    .clicked()
                                {
                                    actions.extend(send(&n.command, false));
                                }
                                ui.add(egui::Label::new(RichText::new(&n.title).strong()).truncate());
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui.small_button("🗑").on_hover_text("Eliminar").clicked() {
                                        actions.push(Action::DeleteNote { conn_id: conn.id, note_id: n.id });
                                    }
                                    if ui.small_button("✏").on_hover_text("Editar").clicked() {
                                        actions.push(Action::EditNote { conn_id: conn.id, note: Some((*n).clone()) });
                                    }
                                    if ui.small_button("📋").on_hover_text("Copiar al portapapeles").clicked() {
                                        ui.ctx().copy_text(n.command.clone());
                                    }
                                });
                            });
                            let preview: String = n.command.lines().take(3).collect::<Vec<_>>().join("\n");
                            ui.add(egui::Label::new(RichText::new(preview).monospace().small().color(Color32::from_rgb(150, 200, 150))).truncate());
                        });
                    }
                });
        }
    });
}
