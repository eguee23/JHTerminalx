//! Transferencia de archivos por SFTP.
//!
//! Cada explorador de archivos abre su propia conexión SSH (autenticada con
//! las mismas credenciales de la sesión y verificando la huella ya guardada) y
//! trabaja en un hilo en modo bloqueante, así la terminal nunca se congela
//! durante una transferencia grande.
//!
//! - `SftpCmd`   UI -> hilo (listar, subir, descargar, borrar, cancelar…)
//! - `SftpEvent` hilo -> UI (listados, progreso, fin de transferencias)

use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use ssh2::{OpenFlags, OpenType, Session, Sftp};

use crate::ssh::{self, SessionParams};

const BUF_SIZE: usize = 256 * 1024;

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_link: bool,
    pub size: u64,
    pub mtime: Option<u64>,
    pub perm: Option<u32>,
}

pub enum SftpCmd {
    List(String),
    /// Descarga un archivo o una carpeta (recursiva) dentro de `local_dir`.
    Download { id: u64, remote: String, is_dir: bool, local_dir: PathBuf },
    /// Sube un archivo o una carpeta (recursiva) dentro de `remote_dir`.
    Upload { id: u64, local: PathBuf, remote_dir: String },
    Mkdir(String),
    Delete { path: String, is_dir: bool },
    Rename { from: String, to: String },
    Cancel(u64),
    Close,
}

pub enum TransferEnd {
    /// Ruta de destino.
    Done(String),
    Cancelled,
    Failed(String),
}

pub enum SftpEvent {
    Ready { home: String },
    Listing { path: String, entries: Vec<Entry> },
    ListError { error: String },
    /// La transferencia empieza: tamaño total y número de archivos.
    Started { id: u64, total: u64, files: usize },
    Progress { id: u64, done: u64, file: String },
    Finished { id: u64, end: TransferEnd },
    /// Operación (crear, borrar, renombrar) terminada: la UI refresca.
    OpDone(String),
    OpError(String),
    Error(String),
    Closed,
}

pub fn spawn(
    params: SessionParams,
    cmd_rx: Receiver<SftpCmd>,
    evt_tx: Sender<SftpEvent>,
    wake: impl Fn() + Send + 'static,
) {
    thread::Builder::new()
        .name(format!("sftp-{}", params.host))
        .spawn(move || {
            let send = |e: SftpEvent| {
                let _ = evt_tx.send(e);
                wake();
            };
            if let Err(e) = run(&params, &cmd_rx, &send) {
                send(SftpEvent::Error(format!("{e:#}")));
            }
            send(SftpEvent::Closed);
        })
        .expect("no se pudo crear el hilo SFTP");
}

fn run(p: &SessionParams, cmd_rx: &Receiver<SftpCmd>, send: &dyn Fn(SftpEvent)) -> Result<()> {
    let sess = ssh::connect_known_host(p)?;
    sess.set_timeout(30_000);
    sess.set_keepalive(true, 30);
    let sftp = sess.sftp().context("El servidor no admite SFTP")?;
    let home = sftp.realpath(Path::new(".")).map(|p| path_str(&p)).unwrap_or_else(|_| "/".into());
    send(SftpEvent::Ready { home });

    let mut w = Worker { sftp, ctl: Ctl { cmd_rx, send, pending: VecDeque::new(), closing: false } };
    let mut last_keepalive = Instant::now();
    while !w.ctl.closing {
        let cmd = match w.ctl.pending.pop_front() {
            Some(c) => c,
            None => match cmd_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(c) => c,
                Err(RecvTimeoutError::Timeout) => {
                    keepalive(&sess, &mut last_keepalive);
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            },
        };
        w.handle(cmd);
        keepalive(&sess, &mut last_keepalive);
    }
    drop(w);
    sess.set_timeout(2_000);
    let _ = sess.disconnect(None, "bye", None);
    Ok(())
}

fn keepalive(sess: &Session, last: &mut Instant) {
    if last.elapsed() > Duration::from_secs(15) {
        let _ = sess.keepalive_send();
        *last = Instant::now();
    }
}

/// Marca de error para una transferencia cancelada.
#[derive(Debug)]
struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cancelado")
    }
}

impl std::error::Error for Cancelled {}

/// Comunicación con la UI mientras se trabaja.
struct Ctl<'a> {
    cmd_rx: &'a Receiver<SftpCmd>,
    send: &'a dyn Fn(SftpEvent),
    /// Órdenes recibidas durante una transferencia, para después.
    pending: VecDeque<SftpCmd>,
    closing: bool,
}

impl Ctl<'_> {
    fn send(&self, e: SftpEvent) {
        (self.send)(e)
    }

    /// Lee las órdenes llegadas durante la transferencia `current`. Devuelve
    /// error `Cancelled` si hay que abortarla.
    fn check(&mut self, current: u64) -> Result<()> {
        loop {
            match self.cmd_rx.try_recv() {
                Ok(SftpCmd::Cancel(id)) if id == current => return Err(Cancelled.into()),
                Ok(SftpCmd::Cancel(id)) => self.cancel_queued(id),
                Ok(SftpCmd::Close) | Err(TryRecvError::Disconnected) => {
                    self.closing = true;
                    return Err(Cancelled.into());
                }
                Ok(cmd) => self.pending.push_back(cmd),
                Err(TryRecvError::Empty) => return Ok(()),
            }
        }
    }

    fn cancel_queued(&mut self, id: u64) {
        let before = self.pending.len();
        self.pending.retain(|c| !matches!(c, SftpCmd::Download { id: i, .. } | SftpCmd::Upload { id: i, .. } if *i == id));
        if self.pending.len() != before {
            self.send(SftpEvent::Finished { id, end: TransferEnd::Cancelled });
        }
    }
}

struct Worker<'a> {
    sftp: Sftp,
    ctl: Ctl<'a>,
}

/// Un archivo a copiar.
struct Item {
    remote: String,
    local: PathBuf,
    size: u64,
    mode: i32,
}

impl Worker<'_> {
    fn handle(&mut self, cmd: SftpCmd) {
        match cmd {
            SftpCmd::List(path) => match self.list(&path) {
                Ok((path, entries)) => self.ctl.send(SftpEvent::Listing { path, entries }),
                Err(e) => self.ctl.send(SftpEvent::ListError { error: format!("{e:#}") }),
            },
            SftpCmd::Download { id, remote, is_dir, local_dir } => {
                let r = self.download(id, &remote, is_dir, &local_dir);
                self.finish(id, r);
            }
            SftpCmd::Upload { id, local, remote_dir } => {
                let r = self.upload(id, &local, &remote_dir);
                self.finish(id, r);
            }
            SftpCmd::Mkdir(path) => {
                let r = self.sftp.mkdir(Path::new(&path), 0o755).map_err(anyhow::Error::from);
                self.op(r, format!("Carpeta creada: {path}"));
            }
            SftpCmd::Delete { path, is_dir } => {
                let r = if is_dir { remove_tree(&self.sftp, &path) } else { self.sftp.unlink(Path::new(&path)).map_err(Into::into) };
                self.op(r, format!("Eliminado: {path}"));
            }
            SftpCmd::Rename { from, to } => {
                let r = self.sftp.rename(Path::new(&from), Path::new(&to), None).map_err(anyhow::Error::from);
                self.op(r, format!("Renombrado a {to}"));
            }
            SftpCmd::Cancel(id) => self.ctl.cancel_queued(id),
            SftpCmd::Close => self.ctl.closing = true,
        }
    }

    /// Lista una carpeta resolviendo antes su ruta absoluta («.», enlaces…).
    fn list(&self, path: &str) -> Result<(String, Vec<Entry>)> {
        let real = self.sftp.realpath(Path::new(path)).with_context(|| format!("No existe {path}"))?;
        let real = path_str(&real);
        let entries = list_dir(&self.sftp, &real)?;
        Ok((real, entries))
    }

    fn op(&self, r: Result<()>, ok: String) {
        match r {
            Ok(()) => self.ctl.send(SftpEvent::OpDone(ok)),
            Err(e) => self.ctl.send(SftpEvent::OpError(format!("{e:#}"))),
        }
    }

    fn finish(&self, id: u64, r: Result<String>) {
        let end = match r {
            Ok(dest) => TransferEnd::Done(dest),
            Err(e) if e.is::<Cancelled>() => TransferEnd::Cancelled,
            Err(e) => TransferEnd::Failed(format!("{e:#}")),
        };
        self.ctl.send(SftpEvent::Finished { id, end });
    }

    // ----------------------------------------------------------------- bajar

    fn download(&mut self, id: u64, remote: &str, is_dir: bool, local_dir: &Path) -> Result<String> {
        fs::create_dir_all(local_dir).with_context(|| format!("No se pudo crear {}", local_dir.display()))?;
        let name = local_name(remote_name(remote));
        let root = unique_path(&local_dir.join(name));

        let mut dirs = Vec::new();
        let mut items = Vec::new();
        if is_dir {
            dirs.push(root.clone());
            self.plan_download(id, remote, &root, &mut dirs, &mut items)?;
        } else {
            let st = self.sftp.stat(Path::new(remote)).with_context(|| format!("No se pudo leer {remote}"))?;
            items.push(Item { remote: remote.into(), local: root.clone(), size: st.size.unwrap_or(0), mode: 0 });
        }
        let total = items.iter().map(|i| i.size).sum();
        self.ctl.send(SftpEvent::Started { id, total, files: items.len() });

        for d in &dirs {
            fs::create_dir_all(d).with_context(|| format!("No se pudo crear {}", d.display()))?;
        }
        let mut done = 0u64;
        let mut last = Instant::now();
        for it in &items {
            let mut src = self.sftp.open(Path::new(&it.remote)).with_context(|| format!("No se pudo abrir {}", it.remote))?;
            let mut dst = File::create(&it.local).with_context(|| format!("No se pudo crear {}", it.local.display()))?;
            let label = remote_name(&it.remote).to_string();
            if let Err(e) = copy(&mut self.ctl, id, &label, &mut src, &mut dst, &mut done, &mut last) {
                drop(dst);
                let _ = fs::remove_file(&it.local);
                return Err(e.context(format!("Descargando {}", it.remote)));
            }
        }
        Ok(root.display().to_string())
    }

    fn plan_download(&mut self, id: u64, remote: &str, local: &Path, dirs: &mut Vec<PathBuf>, items: &mut Vec<Item>) -> Result<()> {
        self.ctl.check(id)?;
        for e in list_dir(&self.sftp, remote)? {
            let dst = local.join(local_name(&e.name));
            if e.is_dir {
                // Los enlaces a carpetas se omiten para evitar ciclos.
                if !e.is_link {
                    dirs.push(dst.clone());
                    self.plan_download(id, &e.path, &dst, dirs, items)?;
                }
            } else {
                items.push(Item { remote: e.path, local: dst, size: e.size, mode: 0 });
            }
        }
        Ok(())
    }

    // ----------------------------------------------------------------- subir

    fn upload(&mut self, id: u64, local: &Path, remote_dir: &str) -> Result<String> {
        let name = local
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| anyhow!("Ruta no válida: {}", local.display()))?;
        let root = remote_join(remote_dir, &name);
        let meta = fs::metadata(local).with_context(|| format!("No se pudo leer {}", local.display()))?;

        let mut dirs = Vec::new();
        let mut items = Vec::new();
        if meta.is_dir() {
            dirs.push(root.clone());
            self.plan_upload(id, local, &root, &mut dirs, &mut items)?;
        } else {
            items.push(Item { remote: root.clone(), local: local.to_path_buf(), size: meta.len(), mode: file_mode(&meta) });
        }
        let total = items.iter().map(|i| i.size).sum();
        self.ctl.send(SftpEvent::Started { id, total, files: items.len() });

        for d in &dirs {
            if let Err(e) = self.sftp.mkdir(Path::new(d), 0o755) {
                // Si ya existe como carpeta, se reutiliza.
                if !self.sftp.stat(Path::new(d)).is_ok_and(|s| s.is_dir()) {
                    return Err(anyhow::Error::from(e).context(format!("No se pudo crear la carpeta remota {d}")));
                }
            }
        }
        let mut done = 0u64;
        let mut last = Instant::now();
        for it in &items {
            let mut src = File::open(&it.local).with_context(|| format!("No se pudo abrir {}", it.local.display()))?;
            let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE;
            let mut dst = self
                .sftp
                .open_mode(Path::new(&it.remote), flags, it.mode, OpenType::File)
                .with_context(|| format!("No se pudo crear {} en el servidor", it.remote))?;
            let label = it.local.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if let Err(e) = copy(&mut self.ctl, id, &label, &mut src, &mut dst, &mut done, &mut last) {
                drop(dst);
                if e.is::<Cancelled>() {
                    let _ = self.sftp.unlink(Path::new(&it.remote));
                }
                return Err(e.context(format!("Subiendo {}", it.local.display())));
            }
        }
        Ok(root)
    }

    fn plan_upload(&mut self, id: u64, local: &Path, remote: &str, dirs: &mut Vec<String>, items: &mut Vec<Item>) -> Result<()> {
        self.ctl.check(id)?;
        let mut entries: Vec<_> = fs::read_dir(local)
            .with_context(|| format!("No se pudo leer {}", local.display()))?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let path = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            let dst = remote_join(remote, &name);
            let Ok(lmeta) = fs::symlink_metadata(&path) else { continue };
            if lmeta.is_dir() {
                dirs.push(dst.clone());
                self.plan_upload(id, &path, &dst, dirs, items)?;
            } else if let Ok(meta) = fs::metadata(&path)
                && meta.is_file()
            {
                // Enlaces a archivos se siguen; enlaces a carpetas se omiten.
                items.push(Item { remote: dst, local: path, size: meta.len(), mode: file_mode(&meta) });
            }
        }
        Ok(())
    }
}

/// Copia con avisos de progreso (como mucho cada 100 ms) y comprobación de cancelación.
fn copy(
    ctl: &mut Ctl,
    id: u64,
    label: &str,
    src: &mut impl Read,
    dst: &mut impl Write,
    done: &mut u64,
    last: &mut Instant,
) -> Result<()> {
    let mut buf = vec![0u8; BUF_SIZE];
    ctl.send(SftpEvent::Progress { id, done: *done, file: label.to_string() });
    loop {
        ctl.check(id)?;
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("Error de lectura"),
        };
        dst.write_all(&buf[..n]).context("Error de escritura")?;
        *done += n as u64;
        if last.elapsed() > Duration::from_millis(100) {
            ctl.send(SftpEvent::Progress { id, done: *done, file: label.to_string() });
            *last = Instant::now();
        }
    }
    dst.flush().context("Error de escritura")?;
    ctl.send(SftpEvent::Progress { id, done: *done, file: label.to_string() });
    Ok(())
}

fn list_dir(sftp: &Sftp, path: &str) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    for (p, st) in sftp.readdir(Path::new(path)).with_context(|| format!("No se pudo listar {path}"))? {
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        let full = remote_join(path, &name);
        let is_link = st.file_type().is_symlink();
        let (is_dir, size) = if is_link {
            match sftp.stat(Path::new(&full)) {
                Ok(t) => (t.is_dir(), t.size.unwrap_or(0)),
                Err(_) => (false, 0), // enlace roto
            }
        } else {
            (st.is_dir(), st.size.unwrap_or(0))
        };
        out.push(Entry { name, path: full, is_dir, is_link, size, mtime: st.mtime, perm: st.perm });
    }
    out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    Ok(out)
}

fn remove_tree(sftp: &Sftp, path: &str) -> Result<()> {
    for e in list_dir(sftp, path)? {
        if e.is_dir && !e.is_link {
            remove_tree(sftp, &e.path)?;
        } else {
            sftp.unlink(Path::new(&e.path)).with_context(|| format!("No se pudo borrar {}", e.path))?;
        }
    }
    sftp.rmdir(Path::new(path)).with_context(|| format!("No se pudo borrar la carpeta {path}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Rutas
// ---------------------------------------------------------------------------

/// Las rutas remotas siempre usan `/`, también desde Windows.
fn path_str(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

pub fn remote_join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') { format!("{dir}{name}") } else { format!("{dir}/{name}") }
}

pub fn remote_parent(path: &str) -> String {
    let p = path.trim_end_matches('/');
    match p.rfind('/') {
        Some(0) | None => "/".into(),
        Some(i) => p[..i].into(),
    }
}

pub fn remote_name(path: &str) -> &str {
    let p = path.trim_end_matches('/');
    p.rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or("raiz")
}

/// Nombre válido para el sistema de archivos local.
fn local_name(name: &str) -> String {
    let bad: &[char] = if cfg!(windows) { &['<', '>', ':', '"', '/', '\\', '|', '?', '*'] } else { &['/'] };
    let s: String = name.chars().map(|c| if bad.contains(&c) || c.is_control() { '_' } else { c }).collect();
    let s = if cfg!(windows) { s.trim_end_matches(['.', ' ']).to_string() } else { s };
    if s.is_empty() || s == "." || s == ".." { "_".into() } else { s }
}

/// Si el destino ya existe, añade « (1)», « (2)»… para no sobrescribir nada local.
fn unique_path(p: &Path) -> PathBuf {
    if !p.exists() {
        return p.to_path_buf();
    }
    let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = p.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    let parent = p.parent().unwrap_or(Path::new("."));
    (1..)
        .map(|i| parent.join(format!("{stem} ({i}){ext}")))
        .find(|c| !c.exists())
        .unwrap()
}

#[cfg(unix)]
fn file_mode(m: &fs::Metadata) -> i32 {
    use std::os::unix::fs::PermissionsExt;
    (m.permissions().mode() & 0o777) as i32
}

#[cfg(not(unix))]
fn file_mode(_m: &fs::Metadata) -> i32 {
    0o644
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_paths() {
        assert_eq!(remote_join("/", "a"), "/a");
        assert_eq!(remote_join("/home/u", "a"), "/home/u/a");
        assert_eq!(remote_parent("/home/u"), "/home");
        assert_eq!(remote_parent("/home"), "/");
        assert_eq!(remote_parent("/"), "/");
        assert_eq!(remote_parent("/home/u/"), "/home");
        assert_eq!(remote_name("/home/u/f.txt"), "f.txt");
        assert_eq!(remote_name("/home/u/"), "u");
        assert_eq!(local_name(".."), "_");
    }

    #[test]
    fn unique_local_path() {
        let dir = std::env::temp_dir().join(format!("jhx-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.txt");
        assert_eq!(unique_path(&f), f);
        File::create(&f).unwrap();
        assert_eq!(unique_path(&f), dir.join("a (1).txt"));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// SFTP de punta a punta contra un servidor real.
    ///
    /// JHX_HOST=127.0.0.1 JHX_USER=usuario JHX_PASS=clave JHX_FP='SHA256:…' cargo test sftp_e2e -- --ignored --nocapture
    #[test]
    #[ignore]
    fn sftp_e2e() {
        use crate::vault::AuthMethod;
        use std::sync::mpsc;
        let user = std::env::var("JHX_USER").expect("define JHX_USER");
        let (auth, secret) = match std::env::var("JHX_PASS") {
            Ok(p) => (AuthMethod::Password, p),
            Err(_) => (AuthMethod::Agent, String::new()),
        };
        let params = SessionParams {
            host: std::env::var("JHX_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            port: std::env::var("JHX_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(22),
            username: user,
            auth,
            secret,
            host_key: Some(std::env::var("JHX_FP").expect("define JHX_FP")),
            tunnels: Vec::new(),
            cols: 80,
            rows: 24,
        };
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let (evt_tx, evt_rx) = mpsc::channel();
        spawn(params, cmd_rx, evt_tx, || {});

        let work = std::env::temp_dir().join(format!("jhx-sftp-{}", std::process::id()));
        let src = work.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.bin"), vec![7u8; 1_000_000]).unwrap();
        fs::write(src.join("sub/b.txt"), b"hola").unwrap();
        let next = || evt_rx.recv_timeout(Duration::from_secs(30)).expect("timeout");

        let home = loop {
            match next() {
                SftpEvent::Ready { home } => break home,
                SftpEvent::Error(e) => panic!("{e}"),
                _ => {}
            }
        };
        let remote_dir = remote_join(&home, &format!("jhx-sftp-test-{}", std::process::id()));
        cmd_tx.send(SftpCmd::Mkdir(remote_dir.clone())).unwrap();
        cmd_tx.send(SftpCmd::Upload { id: 1, local: src.clone(), remote_dir: remote_dir.clone() }).unwrap();
        cmd_tx.send(SftpCmd::Download { id: 2, remote: remote_join(&remote_dir, "src"), is_dir: true, local_dir: work.join("dst") }).unwrap();
        let mut finished = 0;
        while finished < 2 {
            match next() {
                SftpEvent::Finished { end: TransferEnd::Done(d), id } => {
                    println!("#{id} -> {d}");
                    finished += 1;
                }
                SftpEvent::Finished { end: TransferEnd::Failed(e), .. } | SftpEvent::OpError(e) => panic!("{e}"),
                _ => {}
            }
        }
        assert_eq!(fs::read(work.join("dst/src/a.bin")).unwrap().len(), 1_000_000);
        assert_eq!(fs::read(work.join("dst/src/sub/b.txt")).unwrap(), b"hola");
        cmd_tx.send(SftpCmd::Delete { path: remote_dir, is_dir: true }).unwrap();
        loop {
            match next() {
                SftpEvent::OpDone(m) if m.starts_with("Eliminado") => break,
                SftpEvent::OpError(e) => panic!("{e}"),
                _ => {}
            }
        }
        cmd_tx.send(SftpCmd::Close).unwrap();
        fs::remove_dir_all(&work).unwrap();
    }
}
