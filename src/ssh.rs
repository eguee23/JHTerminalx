//! Hilo de trabajo por sesión SSH (libssh2 vía crate `ssh2`).
//!
//! La UI se comunica con cada sesión mediante canales:
//! - `SessionCmd`  UI -> hilo (teclas, redimensionado, cierre, decisión de host key)
//! - `SessionEvent` hilo -> UI (datos de salida, estado, errores)

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use ssh2::{Channel, ErrorCode, HashType, KeyboardInteractivePrompt, Prompt, Session};

use crate::tunnel::{Forwarder, TunnelInfo};
use crate::vault::{AuthMethod, Connection, Tunnel};

const EAGAIN: i32 = -37; // LIBSSH2_ERROR_EAGAIN

pub enum SessionCmd {
    Input(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    HostKeyDecision(bool),
    /// Abre un túnel `-L` en la sesión ya conectada.
    AddTunnel(Tunnel),
    /// Cierra el túnel que escucha en esa dirección/puerto.
    RemoveTunnel(Tunnel),
    Close,
}

pub enum SessionEvent {
    Status(String),
    /// Huella desconocida (primera conexión): la UI debe confirmar.
    HostKeyUnknown(String),
    /// La huella no coincide con la guardada.
    HostKeyMismatch { expected: String, got: String },
    /// Huella aceptada: la UI la guarda en el almacén.
    HostKeyAccepted(String),
    Connected,
    Output(Vec<u8>),
    /// Estado actual de los túneles de la sesión.
    Tunnels(Vec<TunnelInfo>),
    Error(String),
    Closed,
}

pub struct SessionParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    pub secret: String,
    pub host_key: Option<String>,
    /// Túneles que se abren al conectar.
    pub tunnels: Vec<Tunnel>,
    pub cols: u16,
    pub rows: u16,
}

impl SessionParams {
    pub fn from_connection(c: &Connection, cols: u16, rows: u16) -> Self {
        Self {
            host: c.host.trim().to_string(),
            port: c.port,
            username: c.username.trim().to_string(),
            auth: c.auth.clone(),
            secret: c.secret.clone(),
            host_key: c.host_key.clone(),
            tunnels: c.tunnels.iter().filter(|t| t.enabled).cloned().collect(),
            cols,
            rows,
        }
    }
}

impl Drop for SessionParams {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

/// Lanza el hilo de la sesión. `wake` se llama cada vez que hay un evento
/// nuevo (para pedir a la UI que se repinte).
pub fn spawn(
    params: SessionParams,
    cmd_rx: Receiver<SessionCmd>,
    evt_tx: Sender<SessionEvent>,
    wake: impl Fn() + Send + 'static,
) {
    thread::Builder::new()
        .name(format!("ssh-{}", params.host))
        .spawn(move || {
            let send = |e: SessionEvent| {
                let _ = evt_tx.send(e);
                wake();
            };
            if let Err(e) = run(&params, &cmd_rx, &send) {
                send(SessionEvent::Error(format!("{e:#}")));
            }
            send(SessionEvent::Closed);
        })
        .expect("no se pudo crear el hilo SSH");
}

pub(crate) fn is_eagain(e: &ssh2::Error) -> bool {
    e.code() == ErrorCode::Session(EAGAIN)
}

/// Reintenta una operación libssh2 mientras devuelva EAGAIN (modo no bloqueante).
fn retry<T>(mut f: impl FnMut() -> Result<T, ssh2::Error>) -> Result<T, ssh2::Error> {
    loop {
        match f() {
            Err(e) if is_eagain(&e) => thread::sleep(Duration::from_millis(2)),
            r => return r,
        }
    }
}

struct PasswordPrompter<'a>(&'a str);

impl KeyboardInteractivePrompt for PasswordPrompter<'_> {
    fn prompt<'b>(&mut self, _u: &str, _i: &str, prompts: &[Prompt<'b>]) -> Vec<String> {
        prompts.iter().map(|_| self.0.to_string()).collect()
    }
}

fn fingerprint(sess: &Session) -> Option<String> {
    sess.host_key_hash(HashType::Sha256).map(|h| {
        format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(h)
        )
    })
}

/// Espera la decisión del usuario sobre la clave del host.
fn wait_host_decision(cmd_rx: &Receiver<SessionCmd>) -> Result<bool> {
    loop {
        match cmd_rx.recv_timeout(Duration::from_secs(300)) {
            Ok(SessionCmd::HostKeyDecision(ok)) => return Ok(ok),
            Ok(SessionCmd::Close) => return Ok(false),
            Ok(_) => continue,
            Err(RecvTimeoutError::Timeout) => bail!("Tiempo de espera agotado"),
            Err(RecvTimeoutError::Disconnected) => return Ok(false),
        }
    }
}

fn authenticate(sess: &Session, p: &SessionParams) -> Result<()> {
    let user = p.username.as_str();
    match &p.auth {
        AuthMethod::Password => {
            if sess.userauth_password(user, &p.secret).is_err() {
                // Algunos servidores sólo aceptan keyboard-interactive.
                let methods = sess.auth_methods(user).unwrap_or("").to_string();
                if methods.contains("keyboard-interactive") {
                    let mut pr = PasswordPrompter(&p.secret);
                    let _ = sess.userauth_keyboard_interactive(user, &mut pr);
                }
            }
        }
        AuthMethod::PrivateKey { path } => {
            let path = shellexpand_home(path);
            let pass = (!p.secret.is_empty()).then_some(p.secret.as_str());
            sess.userauth_pubkey_file(user, None, Path::new(&path), pass)
                .with_context(|| {
                    if cfg!(windows) {
                        format!("Fallo con la clave privada {path} (en Windows no se admiten claves Ed25519; usa RSA o ECDSA, o ssh-agent)")
                    } else {
                        format!("Fallo con la clave privada {path}")
                    }
                })?;
        }
        AuthMethod::Agent => {
            sess.userauth_agent(user).context("Fallo de autenticación con ssh-agent")?;
        }
    }
    if !sess.authenticated() {
        bail!("Autenticación rechazada para el usuario «{user}»");
    }
    Ok(())
}

fn shellexpand_home(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/")
        && let Some(home) = directories::BaseDirs::new()
    {
        return home.home_dir().join(rest).to_string_lossy().into_owned();
    }
    p.to_string()
}

/// Conexión TCP + handshake SSH (sin autenticar).
fn handshake(p: &SessionParams) -> Result<Session> {
    let addr = (p.host.as_str(), p.port)
        .to_socket_addrs()
        .with_context(|| format!("No se pudo resolver {}", p.host))?
        .next()
        .ok_or_else(|| anyhow!("Dirección no encontrada"))?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .with_context(|| format!("No se pudo conectar a {addr}"))?;
    let _ = tcp.set_nodelay(true);

    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.set_timeout(15_000);
    sess.handshake().context("Fallo en el handshake SSH")?;
    Ok(sess)
}

/// Abre una conexión adicional y autenticada (p. ej. para SFTP). Sólo acepta
/// la huella ya guardada: la confirmación del usuario se hace en la terminal.
pub(crate) fn connect_known_host(p: &SessionParams) -> Result<Session> {
    if p.host.is_empty() {
        bail!("La conexión no tiene host/IP");
    }
    let sess = handshake(p)?;
    let fp = fingerprint(&sess).ok_or_else(|| anyhow!("El servidor no envió clave de host"))?;
    match &p.host_key {
        Some(known) if *known == fp => {}
        Some(_) => bail!("La clave del host no coincide con la guardada (posible MITM); reconecta la terminal para revisarla"),
        None => bail!("Huella del host desconocida: conecta primero la sesión de terminal y acéptala"),
    }
    authenticate(&sess, p)?;
    Ok(sess)
}

fn run(p: &SessionParams, cmd_rx: &Receiver<SessionCmd>, send: &dyn Fn(SessionEvent)) -> Result<()> {
    if p.host.is_empty() {
        bail!("La conexión no tiene host/IP");
    }
    send(SessionEvent::Status(format!("Conectando a {}:{}…", p.host, p.port)));
    let sess = handshake(p)?;

    // --- Verificación de la clave del host (TOFU) ---
    let fp = fingerprint(&sess).ok_or_else(|| anyhow!("El servidor no envió clave de host"))?;
    match &p.host_key {
        Some(known) if *known == fp => {}
        Some(known) => {
            send(SessionEvent::HostKeyMismatch { expected: known.clone(), got: fp.clone() });
            if !wait_host_decision(cmd_rx)? {
                bail!("Conexión cancelada: la clave del host cambió");
            }
            send(SessionEvent::HostKeyAccepted(fp.clone()));
        }
        None => {
            send(SessionEvent::HostKeyUnknown(fp.clone()));
            if !wait_host_decision(cmd_rx)? {
                bail!("Conexión cancelada: clave de host no aceptada");
            }
            send(SessionEvent::HostKeyAccepted(fp.clone()));
        }
    }

    send(SessionEvent::Status("Autenticando…".into()));
    authenticate(&sess, p)?;

    let mut channel = sess.channel_session()?;
    channel.request_pty(
        "xterm-256color",
        None,
        Some((p.cols as u32, p.rows as u32, 0, 0)),
    )?;
    channel.shell()?;
    sess.set_keepalive(true, 30);
    send(SessionEvent::Connected);

    sess.set_blocking(false);
    let mut fwd = Forwarder::new();
    for t in &p.tunnels {
        fwd.add(t.clone());
    }
    let result = io_loop(&sess, &mut channel, &mut fwd, cmd_rx, send);
    drop(fwd);
    result?;

    sess.set_blocking(true);
    sess.set_timeout(2_000);
    let _ = channel.close();
    let _ = sess.disconnect(None, "bye", None);
    Ok(())
}

fn io_loop(
    sess: &Session,
    channel: &mut Channel,
    fwd: &mut Forwarder,
    cmd_rx: &Receiver<SessionCmd>,
    send: &dyn Fn(SessionEvent),
) -> Result<()> {
    let mut buf = vec![0u8; 32 * 1024];
    let mut last_keepalive = Instant::now();

    loop {
        let mut activity = false;

        // Salida del servidor
        loop {
            match channel.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    send(SessionEvent::Output(buf[..n].to_vec()));
                    activity = true;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e).context("Error leyendo del canal"),
            }
        }
        // stderr (raro con PTY, pero por si acaso)
        loop {
            match channel.stderr().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    send(SessionEvent::Output(buf[..n].to_vec()));
                    activity = true;
                }
                Err(_) => break,
            }
        }

        if channel.eof() {
            send(SessionEvent::Status("Sesión finalizada por el servidor".into()));
            return Ok(());
        }

        // Comandos de la UI
        loop {
            match cmd_rx.try_recv() {
                Ok(SessionCmd::Input(data)) => {
                    write_all_nb(channel, &data)?;
                    activity = true;
                }
                Ok(SessionCmd::Resize { cols, rows }) => {
                    let _ = retry(|| channel.request_pty_size(cols as u32, rows as u32, None, None));
                }
                Ok(SessionCmd::HostKeyDecision(_)) => {}
                Ok(SessionCmd::AddTunnel(t)) => fwd.add(t),
                Ok(SessionCmd::RemoveTunnel(t)) => fwd.remove(&t),
                Ok(SessionCmd::Close) | Err(TryRecvError::Disconnected) => return Ok(()),
                Err(TryRecvError::Empty) => break,
            }
        }

        // Túneles
        activity |= fwd.poll(sess);
        if let Some(info) = fwd.take_changes() {
            send(SessionEvent::Tunnels(info));
        }

        if last_keepalive.elapsed() > Duration::from_secs(10) {
            let _ = sess.keepalive_send();
            last_keepalive = Instant::now();
        }

        if !activity {
            thread::sleep(Duration::from_millis(8));
        }
    }
}

fn write_all_nb(channel: &mut Channel, mut data: &[u8]) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !data.is_empty() {
        match channel.write(data) {
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if Instant::now() > deadline {
                    bail!("Tiempo agotado escribiendo en el canal");
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(e) => return Err(e).context("Error escribiendo en el canal"),
        }
    }
    let _ = channel.flush();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// Requiere un sshd en localhost:22. Ejecutar con `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn handshake_and_host_key_prompt() {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let (evt_tx, evt_rx) = mpsc::channel();
        let params = SessionParams {
            host: "127.0.0.1".into(),
            port: 22,
            username: "nadie".into(),
            auth: AuthMethod::Password,
            secret: "x".into(),
            host_key: None,
            tunnels: Vec::new(),
            cols: 80,
            rows: 24,
        };
        spawn(params, cmd_rx, evt_tx, || {});
        let mut got_prompt = false;
        loop {
            match evt_rx.recv_timeout(Duration::from_secs(20)).expect("timeout") {
                SessionEvent::HostKeyUnknown(fp) => {
                    assert!(fp.starts_with("SHA256:"));
                    println!("huella: {fp}");
                    got_prompt = true;
                    cmd_tx.send(SessionCmd::HostKeyDecision(false)).unwrap();
                }
                SessionEvent::Error(e) => println!("error esperado: {e}"),
                SessionEvent::Closed => break,
                _ => {}
            }
        }
        assert!(got_prompt);
    }

    /// Prueba de punta a punta de un túnel `-L`: reenvía un puerto local al
    /// puerto 22 del propio servidor y comprueba que llega el banner SSH.
    ///
    /// JHX_HOST=127.0.0.1 JHX_USER=usuario JHX_PASS=clave cargo test tunnel_e2e -- --ignored --nocapture
    /// (sin JHX_PASS usa ssh-agent)
    #[test]
    #[ignore]
    fn tunnel_e2e() {
        use std::io::Read;
        let host = std::env::var("JHX_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let user = std::env::var("JHX_USER").expect("define JHX_USER");
        let (auth, secret) = match std::env::var("JHX_PASS") {
            Ok(p) => (AuthMethod::Password, p),
            Err(_) => (AuthMethod::Agent, String::new()),
        };
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let tunnel = Tunnel::parse(&format!("{port}:127.0.0.1:22")).unwrap();

        let (cmd_tx, cmd_rx) = mpsc::channel();
        let (evt_tx, evt_rx) = mpsc::channel();
        let params = SessionParams {
            host,
            port: 22,
            username: user,
            auth,
            secret,
            host_key: None,
            tunnels: vec![tunnel],
            cols: 80,
            rows: 24,
        };
        spawn(params, cmd_rx, evt_tx, || {});
        loop {
            match evt_rx.recv_timeout(Duration::from_secs(20)).expect("timeout") {
                SessionEvent::HostKeyUnknown(_) | SessionEvent::HostKeyMismatch { .. } => {
                    cmd_tx.send(SessionCmd::HostKeyDecision(true)).unwrap();
                }
                SessionEvent::Tunnels(t) if t.iter().any(|t| t.listening) => break,
                SessionEvent::Tunnels(t) => panic!("túnel no abierto: {:?}", t[0].error),
                SessionEvent::Error(e) => panic!("{e}"),
                _ => {}
            }
        }
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut banner = [0u8; 7];
        s.read_exact(&mut banner).unwrap();
        assert_eq!(&banner, b"SSH-2.0");
        println!("banner recibido por el túnel en el puerto {port}");
        cmd_tx.send(SessionCmd::Close).unwrap();
    }
}
