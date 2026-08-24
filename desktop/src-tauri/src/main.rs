// Menu-bar utility: no console window on any platform.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    secretctl_desktop::run()
}
