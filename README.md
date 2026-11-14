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
- **Verificación de la clave del host (TOFU)**: en la primera conexión muestra la huella SHA-256 para que la confirmes; si después cambia, avisa de un posible ataque MITM.
- Terminal xterm-256color: colores, programas a pantalla completa (vim, htop, less), historial con la rueda del ratón y selección con el ratón.

## Compilar y ejecutar

```bash
cargo run --release
```

Requisitos en Linux: `cc`, `make` y `perl` (OpenSSL se compila incluido en el binario mediante `vendored-openssl`).

## Atajos

| Acción | Tecla |
|---|---|
| Nueva conexión | Ctrl+Shift+T |
| Copiar selección | Ctrl+Shift+C |
| Pegar | Ctrl+V / Ctrl+Shift+V |
| Ctrl+C (SIGINT) | Ctrl+C |
| Más opciones (tamaño de fuente, copiar pantalla, limpiar historial) | Clic derecho en la terminal |

## Dónde se guardan los datos

- Linux: `~/.local/share/jhterminalx/vault.jhx`
- Windows: `%APPDATA%\JH\JHTerminalx\data\vault.jhx`
- macOS: `~/Library/Application Support/co.JH.JHTerminalx/vault.jhx`

Si olvidas la contraseña maestra, los datos no se pueden recuperar.

## Estructura

- `src/vault.rs`: modelo de datos y cifrado/descifrado del almacén.
- `src/ssh.rs`: un hilo por sesión (libssh2), con PTY, redimensionado y keepalive.
- `src/terminal.rs`: emulador `vt100`, dibujado en egui y traducción del teclado.
- `src/app.rs`: interfaz (desbloqueo, lista de conexiones, pestañas, ventanas, notas y diálogos).
