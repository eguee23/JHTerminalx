//! Almacén cifrado de conexiones y notas.
//!
//! Formato en disco (JSON):
//! { "version": 1, "kdf": {...}, "salt": b64, "nonce": b64, "data": b64 }
//!
//! - La clave se deriva de la contraseña maestra con Argon2id.
//! - Los datos (conexiones, credenciales y notas) se cifran completos con
//!   XChaCha20-Poly1305 (cifrado autenticado). Cada guardado usa un nonce nuevo.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const VAULT_VERSION: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

// ---------------------------------------------------------------------------
// Modelo de datos
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum AuthMethod {
    Password,
    /// Clave privada (ruta) y frase de paso opcional en `Connection::secret`.
    PrivateKey { path: String },
    /// Usa el agente SSH del sistema.
    Agent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Note {
    pub id: Uuid,
    pub category: String,
    pub title: String,
    pub command: String,
}

impl Note {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            category: "General".into(),
            title: String::new(),
            command: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Connection {
    pub id: Uuid,
    pub name: String,
    /// Grupo/categoría de la conexión (p. ej. "Producción", "Clientes").
    #[serde(default)]
    pub group: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    /// Contraseña o frase de paso de la clave privada.
    #[serde(default)]
    pub secret: String,
    /// Huella SHA-256 de la clave del host (TOFU).
    #[serde(default)]
    pub host_key: Option<String>,
    #[serde(default)]
    pub notes: Vec<Note>,
}

impl Connection {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: String::new(),
            group: String::new(),
            host: String::new(),
            port: 22,
            username: String::new(),
            auth: AuthMethod::Password,
            secret: String::new(),
            host_key: None,
            notes: Vec::new(),
        }
    }

    pub fn display_name(&self) -> String {
        if self.name.trim().is_empty() {
            format!("{}@{}", self.username, self.host)
        } else {
            self.name.clone()
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VaultData {
    pub connections: Vec<Connection>,
}

// ---------------------------------------------------------------------------
// Archivo cifrado
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct KdfParams {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // 64 MiB, 3 iteraciones, 1 hilo.
        Self { m_cost: 64 * 1024, t_cost: 3, p_cost: 1 }
    }
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    kdf: KdfParams,
    salt: String,
    nonce: String,
    data: String,
}

/// Almacén abierto: contiene los datos descifrados y la clave derivada,
/// para poder guardar sin volver a pedir la contraseña.
pub struct Vault {
    pub data: VaultData,
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    salt: [u8; SALT_LEN],
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| anyhow!("RNG: {e}"))?;
    Ok(buf)
}

fn derive_key(password: &str, salt: &[u8], p: &KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(p.m_cost, p.t_cost, p.p_cost, Some(32))
        .map_err(|e| anyhow!("Parámetros Argon2: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow!("Argon2: {e}"))?;
    Ok(key)
}

impl Vault {
    pub fn default_path() -> PathBuf {
        if let Some(dirs) = directories::ProjectDirs::from("co", "JH", "JHTerminalx") {
            dirs.data_dir().join("vault.jhx")
        } else {
            PathBuf::from("vault.jhx")
        }
    }

    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    /// Crea un almacén nuevo vacío protegido con `password`.
    pub fn create(path: PathBuf, password: &str) -> Result<Self> {
        if password.chars().count() < 8 {
            bail!("La contraseña maestra debe tener al menos 8 caracteres");
        }
        let salt = random_bytes::<SALT_LEN>()?;
        let key = derive_key(password, &salt, &KdfParams::default())?;
        let vault = Self { data: VaultData::default(), path, key, salt };
        vault.save()?;
        Ok(vault)
    }

    /// Abre y descifra un almacén existente.
    pub fn open(path: PathBuf, password: &str) -> Result<Self> {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("No se pudo leer {}", path.display()))?;
        let file: VaultFile = serde_json::from_str(&raw).context("Archivo del almacén corrupto")?;
        if file.version != VAULT_VERSION {
            bail!("Versión de almacén no soportada: {}", file.version);
        }
        let salt_vec = B64.decode(&file.salt)?;
        let nonce = B64.decode(&file.nonce)?;
        let ciphertext = B64.decode(&file.data)?;
        if salt_vec.len() != SALT_LEN || nonce.len() != NONCE_LEN {
            bail!("Archivo del almacén corrupto");
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&salt_vec);

        let key = derive_key(password, &salt, &file.kdf)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| anyhow!("Clave inválida"))?;
        let nonce_arr: [u8; NONCE_LEN] = nonce.as_slice().try_into()?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(&nonce_arr.into(), ciphertext.as_ref())
                .map_err(|_| anyhow!("Contraseña maestra incorrecta o archivo alterado"))?,
        );
        let data: VaultData = serde_json::from_slice(&plaintext).context("Datos descifrados inválidos")?;
        Ok(Self { data, path, key, salt })
    }

    /// Cifra y guarda los datos de forma atómica (archivo temporal + rename).
    pub fn save(&self) -> Result<()> {
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.data)?);
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| anyhow!("Clave inválida"))?;
        let nonce = random_bytes::<NONCE_LEN>()?;
        let ciphertext = cipher
            .encrypt(&nonce.into(), plaintext.as_ref())
            .map_err(|_| anyhow!("Error al cifrar"))?;

        let file = VaultFile {
            version: VAULT_VERSION,
            kdf: KdfParams::default(),
            salt: B64.encode(self.salt),
            nonce: B64.encode(nonce),
            data: B64.encode(ciphertext),
        };
        let json = serde_json::to_string_pretty(&file)?;

        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("jhx.tmp");
        {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Cambia la contraseña maestra (nueva sal y nueva clave).
    pub fn change_password(&mut self, new_password: &str) -> Result<()> {
        if new_password.chars().count() < 8 {
            bail!("La contraseña maestra debe tener al menos 8 caracteres");
        }
        self.salt = random_bytes::<SALT_LEN>()?;
        self.key = derive_key(new_password, &self.salt, &KdfParams::default())?;
        self.save()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, id: Uuid) -> Option<&Connection> {
        self.data.connections.iter().find(|c| c.id == id)
    }

    pub fn get_mut(&mut self, id: Uuid) -> Option<&mut Connection> {
        self.data.connections.iter_mut().find(|c| c.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong_password() {
        let dir = std::env::temp_dir().join(format!("jhx-test-{}", Uuid::new_v4()));
        let path = dir.join("vault.jhx");
        let mut v = Vault::create(path.clone(), "contraseña-segura").unwrap();
        let mut c = Connection::new();
        c.host = "10.0.0.1".into();
        c.username = "root".into();
        c.secret = "s3cr3t".into();
        c.notes.push(Note { id: Uuid::new_v4(), category: "Red".into(), title: "ip".into(), command: "ip a".into() });
        v.data.connections.push(c);
        v.save().unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("s3cr3t") && !raw.contains("10.0.0.1"));

        let v2 = Vault::open(path.clone(), "contraseña-segura").unwrap();
        assert_eq!(v2.data.connections[0].secret, "s3cr3t");
        assert_eq!(v2.data.connections[0].notes[0].command, "ip a");
        assert!(Vault::open(path, "otra-clave-mala").is_err());
        let _ = fs::remove_dir_all(dir);
    }
}
