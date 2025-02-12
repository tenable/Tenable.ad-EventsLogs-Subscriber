#[cfg(windows)]
extern crate winresource;

use std::env;
use std::path::PathBuf;

fn main() {
    if cfg!(target_os = "windows") {
        let curr_dir = env::current_dir().unwrap();
        let icon_path: PathBuf = [
            curr_dir.to_str().unwrap(),
            "images",
            "msi_company_icons.ico",
        ]
        .iter()
        .collect();
        winresource::WindowsResource::new()
            .set("OriginalFileName", "Register-TenableADEventsListener")
            .set("ProductName", "Tenable Identity Exposure")
            .set("LegalCopyright", "© Tenable, Inc. All rights reserved.")
            .set("FileDescription", "Tenable - IOA Events Listener") // This information is used as the application display name in the Task Manager for some reason
            .set("CompanyName", "Tenable")
            .set("Comments", "Source code is available publicly here: https://github.com/tenable/Tenable.ad-EventsLogs-Subscriber")
            .set_icon(icon_path.to_str().unwrap())
            .compile().expect("Failed to compile resource");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
