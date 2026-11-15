//! Incrusta el icono (assets/icon.ico) y los metadatos en el .exe de Windows.

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");

    // CARGO_CFG_TARGET_OS es el sistema de destino (no el del que compila).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico")
            .set("ProductName", "JHTerminalx")
            .set("FileDescription", "JHTerminalx — gestor de conexiones SSH múltiples");
        if let Err(e) = res.compile() {
            println!("cargo:warning=No se pudo incrustar el icono de Windows: {e}");
        }
    }
}
