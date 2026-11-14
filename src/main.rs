#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod ssh;
mod terminal;
mod vault;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("JHTerminalx — SSH múltiple")
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([700.0, 400.0]),
        ..Default::default()
    };
    eframe::run_native("JHTerminalx", options, Box::new(|cc| Ok(Box::new(app::App::new(cc)))))
}
