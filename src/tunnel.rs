//! Reenvío de puertos local (equivalente a `ssh -L`).
//!
//! Corre dentro del hilo de la sesión SSH, con la `Session` en modo no
//! bloqueante: cada vuelta del bucle de E/S llama a [`Forwarder::poll`], que
//! acepta conexiones TCP locales, abre un canal `direct-tcpip` por cada una y
//! mueve los datos en ambos sentidos.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use ssh2::{Channel, Session};

use crate::ssh::is_eagain;
use crate::vault::Tunnel;

/// Estado de un túnel, para mostrarlo en la UI.
#[derive(Clone, Debug)]
pub struct TunnelInfo {
    pub spec: Tunnel,
    /// Escuchando en el puerto local.
    pub listening: bool,
    /// Conexiones abiertas ahora mismo.
    pub active: usize,
    /// Conexiones atendidas desde que se abrió.
    pub total: u64,
    pub error: Option<String>,
}

struct Forward {
    spec: Tunnel,
    listener: Option<TcpListener>,
    conns: Vec<FwdConn>,
    total: u64,
    error: Option<String>,
}

pub struct Forwarder {
    forwards: Vec<Forward>,
    buf: Vec<u8>,
    changed: bool,
}

impl Forwarder {
    pub fn new() -> Self {
        Self { forwards: Vec::new(), buf: vec![0u8; 32 * 1024], changed: false }
    }

    /// Abre el puerto local. Si falla (p. ej. puerto ocupado) el túnel queda
    /// en la lista con el error, para que la UI lo muestre.
    pub fn add(&mut self, spec: Tunnel) {
        self.changed = true;
        if self.forwards.iter().any(|f| f.spec.same_listener(&spec)) {
            return;
        }
        let (listener, error) = match bind(&spec) {
            Ok(l) => (Some(l), None),
            Err(e) => (None, Some(e)),
        };
        self.forwards.push(Forward { spec, listener, conns: Vec::new(), total: 0, error });
    }

    /// Cierra el puerto local y todas sus conexiones.
    pub fn remove(&mut self, spec: &Tunnel) {
        self.forwards.retain(|f| !f.spec.same_listener(spec));
        self.changed = true;
    }

    /// Devuelve el estado si cambió desde la última llamada.
    pub fn take_changes(&mut self) -> Option<Vec<TunnelInfo>> {
        if !std::mem::take(&mut self.changed) {
            return None;
        }
        Some(
            self.forwards
                .iter()
                .map(|f| TunnelInfo {
                    spec: f.spec.clone(),
                    listening: f.listener.is_some(),
                    active: f.conns.len(),
                    total: f.total,
                    error: f.error.clone(),
                })
                .collect(),
        )
    }

    /// Una vuelta: acepta conexiones y mueve datos. Devuelve `true` si hubo actividad.
    pub fn poll(&mut self, sess: &Session) -> bool {
        let mut activity = false;
        let buf = &mut self.buf;
        for f in &mut self.forwards {
            // Conexiones nuevas
            if let Some(listener) = &f.listener {
                loop {
                    match listener.accept() {
                        Ok((tcp, peer)) => {
                            activity = true;
                            self.changed = true;
                            match open_channel(sess, &f.spec, peer) {
                                Ok(ch) => {
                                    let _ = tcp.set_nonblocking(true);
                                    let _ = tcp.set_nodelay(true);
                                    f.conns.push(FwdConn::new(tcp, ch));
                                    f.total += 1;
                                    f.error = None;
                                }
                                Err(e) => {
                                    f.error = Some(format!(
                                        "No se pudo abrir {}:{} desde el servidor: {e}",
                                        f.spec.remote_host, f.spec.remote_port
                                    ));
                                }
                            }
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                        Err(e) => {
                            f.error = Some(format!("Error aceptando conexión: {e}"));
                            self.changed = true;
                            break;
                        }
                    }
                }
            }

            // Tráfico de las conexiones abiertas
            let before = f.conns.len();
            f.conns.retain_mut(|c| match c.pump(buf) {
                Ok((act, done)) => {
                    activity |= act;
                    !done
                }
                Err(_) => false,
            });
            if f.conns.len() != before {
                self.changed = true;
            }
        }
        activity
    }
}

fn bind(spec: &Tunnel) -> Result<TcpListener, String> {
    let host = spec.bind.trim();
    let addr = if host.contains(':') { format!("[{host}]:{}", spec.local_port) } else { format!("{host}:{}", spec.local_port) };
    let listener = TcpListener::bind(&addr).map_err(|e| {
        if e.kind() == ErrorKind::AddrInUse {
            format!("El puerto local {addr} ya está en uso")
        } else {
            format!("No se pudo escuchar en {addr}: {e}")
        }
    })?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    Ok(listener)
}

/// Abre el canal `direct-tcpip`. En modo no bloqueante libssh2 devuelve EAGAIN
/// hasta que el servidor responde, así que se reintenta con un límite de tiempo.
fn open_channel(sess: &Session, spec: &Tunnel, peer: SocketAddr) -> Result<Channel, ssh2::Error> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let src_ip = peer.ip().to_string();
    loop {
        match sess.channel_direct_tcpip(&spec.remote_host, spec.remote_port, Some((&src_ip, peer.port()))) {
            Err(e) if is_eagain(&e) && Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
            r => return r,
        }
    }
}

struct FwdConn {
    tcp: TcpStream,
    ch: Channel,
    /// Datos pendientes TCP local -> canal SSH.
    up: Vec<u8>,
    /// Datos pendientes canal SSH -> TCP local.
    down: Vec<u8>,
    tcp_eof: bool,
    eof_sent: bool,
    ch_eof: bool,
}

impl FwdConn {
    fn new(tcp: TcpStream, ch: Channel) -> Self {
        Self { tcp, ch, up: Vec::new(), down: Vec::new(), tcp_eof: false, eof_sent: false, ch_eof: false }
    }

    /// Devuelve (hubo_actividad, terminada).
    fn pump(&mut self, buf: &mut [u8]) -> std::io::Result<(bool, bool)> {
        let mut act = false;

        // TCP local -> canal
        if self.up.is_empty() && !self.tcp_eof {
            match self.tcp.read(buf) {
                Ok(0) => self.tcp_eof = true,
                Ok(n) => {
                    self.up.extend_from_slice(&buf[..n]);
                    act = true;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                Err(e) => return Err(e),
            }
        }
        while !self.up.is_empty() {
            match self.ch.write(&self.up) {
                Ok(0) => break,
                Ok(n) => {
                    self.up.drain(..n);
                    act = true;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        if self.tcp_eof && self.up.is_empty() && !self.eof_sent {
            match self.ch.send_eof() {
                Err(e) if is_eagain(&e) => {}
                _ => self.eof_sent = true,
            }
        }

        // Canal -> TCP local
        if self.down.is_empty() && !self.ch_eof {
            match self.ch.read(buf) {
                Ok(n) if n > 0 => {
                    self.down.extend_from_slice(&buf[..n]);
                    act = true;
                }
                Ok(_) => self.ch_eof = self.ch.eof(),
                Err(e) if e.kind() == ErrorKind::WouldBlock => self.ch_eof = self.ch.eof(),
                Err(e) => return Err(e),
            }
        }
        while !self.down.is_empty() {
            match self.tcp.write(&self.down) {
                Ok(0) => break,
                Ok(n) => {
                    self.down.drain(..n);
                    act = true;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => break,
                Err(e) => return Err(e),
            }
        }

        // El servidor cerró su lado y ya entregamos todo: fin de la conexión.
        let done = self.ch_eof && self.down.is_empty();
        Ok((act, done))
    }
}

impl Drop for FwdConn {
    fn drop(&mut self) {
        let _ = self.tcp.shutdown(Shutdown::Both);
        // Cierra el canal antes de liberarlo (en modo no bloqueante puede pedir reintento).
        let deadline = Instant::now() + Duration::from_millis(200);
        loop {
            match self.ch.close() {
                Err(e) if is_eagain(&e) && Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
                _ => break,
            }
        }
    }
}
