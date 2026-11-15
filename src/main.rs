#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod ssh;
mod terminal;
mod tunnel;
mod vault;

fn main() -> eframe::Result {
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_title("JHTerminalx — SSH múltiple")
        .with_app_id("jhterminalx")
        .with_inner_size([1280.0, 800.0])
        .with_min_inner_size([700.0, 400.0]);
    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png")) {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native("JHTerminalx", options, Box::new(|cc| Ok(Box::new(app::App::new(cc)))))
}
