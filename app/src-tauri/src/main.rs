#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use autopilot_recovery_lab::host::Host;
use std::path::PathBuf;
use tauri::WebviewUrl;
mod paths;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    let mut root: Option<PathBuf> = None;
    let mut ready_file: Option<PathBuf> = None;
    let mut data_directory: Option<PathBuf> = None;
    let mut headless = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--project-root" => root = Some(args.next().ok_or("Missing project root")?.into()),
            "--data-dir" => {
                data_directory = Some(args.next().ok_or("Missing data directory")?.into())
            }
            "--ready-file" => {
                ready_file = Some(args.next().ok_or("Missing readiness file")?.into())
            }
            "--headless" => headless = true,
            _ => return Err("Unsupported argument".into()),
        }
    }
    let paths = paths::resolve(
        root,
        data_directory,
        &std::env::current_exe()?,
        std::env::var_os("LOCALAPPDATA").as_deref(),
    )?;
    let host = rt.block_on(Host::start_mainnet(
        paths.data,
        paths.binaries,
        include_str!("../../web/index.html").into(),
        0,
    ))?;
    let url = host.url.clone();
    if let Some(path) = &ready_file {
        std::fs::write(
            path,
            serde_json::to_vec(
                &serde_json::json!({"url":url,"pid":std::process::id(),"desktop":!headless,"mode":"desktop","network":"mainnet","version":env!("CARGO_PKG_VERSION"),"paymentsEnabled":true,"startupBlocked":host.startup_issue.is_some()}),
            )?,
        )?;
    }
    let shutdown = host.shutdown.clone();
    let finished = host.finished.clone();
    if headless {
        rt.block_on(async {tokio::select!{_ = finished.cancelled()=>{}, _=tokio::signal::ctrl_c()=>{shutdown.cancel();finished.cancelled().await;}}});
    } else {
        let window_url: tauri::Url = url.parse()?;
        let allowed_origin = window_url.origin();
        let window_finished = finished.clone();
        let handle = rt.handle().clone();
        let application = tauri::Builder::default()
            .setup(move |app| {
                let window =
                    tauri::WebviewWindowBuilder::new(app, "main", WebviewUrl::External(window_url))
                        .title("Monero AutoPilot")
                        .inner_size(1180.0, 820.0)
                        .min_inner_size(760.0, 620.0)
                        .on_navigation(move |destination| destination.origin() == allowed_origin)
                        .build()?;
                window.show()?;
                window.set_focus()?;
                let app_handle = app.handle().clone();
                handle.spawn(async move {
                    window_finished.cancelled().await;
                    app_handle.exit(0);
                });
                Ok(())
            })
            .build(tauri::generate_context!())?;
        // Tauri's run() exits the process directly and skips the cleanup below.
        // Return from the event loop so both the host and readiness file close.
        let _ = application.run_return(move |_app, event| match event {
            tauri::RunEvent::WindowEvent {
                event: tauri::WindowEvent::CloseRequested { api, .. },
                ..
            } => {
                api.prevent_close();
                shutdown.cancel();
            }
            tauri::RunEvent::ExitRequested { api, .. } if !finished.is_cancelled() => {
                api.prevent_exit();
                shutdown.cancel();
            }
            _ => {}
        });
    }
    rt.block_on(host.stop());
    if let Some(path) = ready_file {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}
