# JHTerminalx

Gestor de conexiones SSH múltiples escrito en Rust (GUI con egui).

## Funciones

- **Varias sesiones SSH a la vez**: cada una se abre en una pestaña; con **⧉ Ventana** se separa en su propia ventana nativa (cerrar esa ventana la devuelve a una pestaña).
- **Conexiones guardadas**: nombre, grupo, host/IP, puerto, usuario y autenticación (contraseña, clave privada con frase de paso, o ssh-agent). Se agrupan por categoría en la barra lateral.
- **Almacén cifrado**: todo (conexiones, contraseñas y notas) se guarda en un único archivo cifrado con **XChaCha20-Poly1305**. La clave se deriva de una contraseña maestra con **Argon2id** (64 MiB, 3 iteraciones). El archivo tiene permisos `0600` y se escribe de forma atómica.
- **Notas de comandos por conexión**, organizadas por categoría:
  - **▶** escribe el comando en la sesión y lo ejecuta (Enter).
  - **⌨** solo lo escribe, sin ejecutarlo, para que lo revises o edites.
  - **📋** lo copia al portapapeles.
  - **📡 Enviar a TODAS** manda el comando a todas las sesiones conectadas.
  - Admite comandos de varias líneas.
- **Túneles SSH (reenvío de puertos local, como `ssh -L 2000:localhost:2000 user@ip`)**:
  - En **Editar conexión → Túneles** se guardan los túneles de cada conexión y se abren automáticamente al conectar (se pueden desactivar con la casilla).
  - En la barra de la sesión, **🔀 Túneles** muestra su estado (conexiones abiertas, errores como «puerto en uso») y permite abrir o cerrar túneles en caliente, sin reconectar.
  - Formato: `[dirección:]puerto_local:host_remoto:puerto_remoto`. También acepta pegar `-L 2000:localhost:2000` o el comando `ssh -L …` completo. Por defecto escucha solo en `127.0.0.1`; usa `0.0.0.0:2000:…` para exponerlo a la red local.
- **Verificación de la clave del host (TOFU)**: en la primera conexión muestra la huella SHA-256 para que la confirmes; si después cambia, avisa de un posible ataque MITM.
- Terminal xterm-256color: colores, programas a pantalla completa (vim, htop, less), historial con la rueda del ratón, **barra de desplazamiento** (arrastrable) y Shift+RePág/AvPág, y selección con el ratón.

## Compilar y ejecutar

```bash
cargo run --release
```

Requisitos:

- **Linux/macOS**: `cc`, `make` y `perl`. OpenSSL se compila y se incluye en el binario (`vendored-openssl`).
- **Windows**: Rust con el toolchain MSVC (Visual Studio Build Tools, "Desarrollo para el escritorio con C++"). No hace falta OpenSSL ni Perl: libssh2 usa la criptografía nativa de Windows (WinCNG).
  - Limitación: WinCNG no admite claves privadas **Ed25519**. Usa claves RSA o ECDSA, o autenticación por contraseña o ssh-agent. Los servidores con clave de host Ed25519 funcionan igual, porque negocian RSA o ECDSA.

## Publicar una versión (instaladores para Linux, Windows y macOS)

Los instaladores **no se guardan en el repositorio git** (son binarios grandes): se publican en **GitHub Releases**, la sección «Releases» del repositorio, asociados a cada tag. El workflow `.github/workflows/release.yml` lo hace solo:

```bash
git tag v0.2.0
git push origin v0.2.0
```

Al subir el tag, GitHub Actions compila en las tres plataformas y crea la release `v0.2.0` con:

| Plataforma | Archivos |
|---|---|
| Windows | `JHTerminalx-0.2.0-windows-x64-setup.exe` (instalador) y `…-portable.zip` |
| Linux | `jhterminalx_0.2.0_amd64.deb` y `JHTerminalx-0.2.0-linux-x64.tar.gz` |
| macOS | `JHTerminalx-0.2.0-macos-universal.dmg` (Intel + Apple Silicon) |

y un `SHA256SUMS.txt`. La versión se toma del tag (no hace falta editar `Cargo.toml`). Los tags con guion (`v0.2.0-beta1`) se marcan como pre-release. También se puede lanzar a mano desde la pestaña **Actions → Release → Run workflow**: entonces solo deja los archivos como artefactos descargables, sin crear release.

Notas: los binarios no están firmados. En Windows SmartScreen puede avisar («Más información → Ejecutar de todas formas»); en macOS la primera vez hay que abrirla con clic derecho → Abrir (o `xattr -dr com.apple.quarantine /Applications/JHTerminalx.app`).

## Icono

`assets/icon.ico` se incrusta en el `.exe` de Windows (`build.rs`); `assets/icon.png` es el icono de la ventana y del paquete de Linux, y `assets/icon.icns` el de macOS. Se regeneran con `python3 assets/make_icon.py` (requiere Pillow) o puedes sustituirlos por tu propio diseño manteniendo los nombres.

## Atajos

| Acción | Tecla |
|---|---|
| Nueva conexión | Ctrl+Shift+T |
| Copiar selección | Ctrl+Shift+C |
| Pegar | Ctrl+V / Ctrl+Shift+V |
| Ctrl+C (SIGINT) | Ctrl+C |
| Recorrer el historial | Rueda · barra de scroll · Shift+RePág / Shift+AvPág · Shift+Inicio / Shift+Fin |
| Más opciones (tamaño de fuente, copiar pantalla, limpiar historial) | Clic derecho en la terminal |

## Dónde se guardan los datos

- Linux: `~/.local/share/jhterminalx/vault.jhx`
- Windows: `%APPDATA%\JH\JHTerminalx\data\vault.jhx`
- macOS: `~/Library/Application Support/co.JH.JHTerminalx/vault.jhx`

Si olvidas la contraseña maestra, los datos no se pueden recuperar.

## Estructura

- `src/vault.rs`: modelo de datos y cifrado/descifrado del almacén.
- `src/ssh.rs`: un hilo por sesión (libssh2), con PTY, redimensionado y keepalive.
- `src/tunnel.rs`: túneles `-L` (escucha local + canales `direct-tcpip`) dentro del hilo de cada sesión.
- `src/terminal.rs`: emulador `vt100`, dibujado en egui y traducción del teclado.
- `src/app.rs`: interfaz (desbloqueo, lista de conexiones, pestañas, ventanas, notas y diálogos).
