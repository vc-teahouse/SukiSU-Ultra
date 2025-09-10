use anyhow::Result;
use anyhow::anyhow;
use notify::{RecursiveMode, Watcher};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::process::Command;

pub const KPM_DIR: &str = "/data/adb/kpm";
pub const KPMMGR_PATH: &str = "/data/adb/ksu/bin/kpmmgr";

// 启动 KPM 监视器
pub fn start_kpm_watcher() -> Result<()> {

    // 检查 KPM 是否启用
    if !is_kpm_enabled()? {
        log::warn!("KPM is not enabled. Disabling all KPM-related functionality.");
        return Ok(());
    }

    // 检查是否处于安全模式
    if crate::utils::is_safe_mode() {
        log::warn!("The system is in safe mode and is deleting all KPM modules...");
        if let Err(e) = remove_all_kpms() {
            log::error!("Error deleting all KPM modules: {}", e);
        }
        return Ok(());
    }

    // 启动文件系统监视器
    let mut watcher = notify::recommended_watcher(|res| match res {
        Ok(event) => handle_kpm_event(event),
        Err(e) => log::error!("monitoring error: {:?}", e),
    })?;

    watcher.watch(Path::new(KPM_DIR), RecursiveMode::NonRecursive)?;
    Ok(())
}

// 检查 KPM 版本
pub fn is_kpm_enabled() -> Result<bool> {

    // KPM 文件夹不存在则视为未启用
    if !Path::new(KPM_DIR).exists() {
        return Ok(false);
    }

    let output = Command::new(KPMMGR_PATH)
        .args(["version"])
        .output()?;

    if output.status.success() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.to_lowercase().contains("error") {
            Ok(false)
        } else {
            Ok(true)
        }
    } else {
        Err(anyhow!("Failed to check KPM version: {:?}", output.stderr))
    }
}

// 处理 KPM 事件
fn handle_kpm_event(event: notify::Event) {
    match event.kind {
        notify::EventKind::Create(_) => handle_create_event(event.paths),
        notify::EventKind::Modify(_) => handle_modify_event(event.paths),
        _ => {}
    }
}

// 处理创建事件
fn handle_create_event(paths: Vec<std::path::PathBuf>) {
    for path in paths {
        if path.extension() == Some(OsStr::new("kpm")) {
            if let Err(e) = load_kpm(&path) {
                log::warn!("Failed to load {}: {}", path.display(), e);
            }
        }
    }
}

// 处理修改事件
fn handle_modify_event(paths: Vec<std::path::PathBuf>) {
    for path in paths {
        log::info!("Modified file: {}", path.display());
    }
}

// 加载单个 KPM 模块
fn load_kpm(path: &Path) -> Result<()> {
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow!("Invalid path: {}", path.display()))?;
    let status = Command::new(KPMMGR_PATH)
        .args(["load", path_str, ""])
        .status()?;

    if status.success() {
        log::info!("Loaded KPM: {}", path.display());
    } else {
        log::warn!("KPM unloading may have failed: {}", path.display());
    }
    Ok(())
}

// 安全模式下删除所有 KPM 模块
fn remove_all_kpms() -> Result<()> {
    for entry in fs::read_dir(KPM_DIR)? {
    let path = entry?.path();
    if path.extension().is_some_and(|ext| ext == "kpm") {
        if let Err(e) = fs::remove_file(&path) {
            log::error!("Failed to delete file: {}: {}", path.display(), e);
            }
        }
    }
    Ok(())
}

// 遍历加载所有 KPM 模块
pub fn load_kpm_modules() -> Result<()> {
   if !is_kpm_enabled()? {
        log::warn!("KPM is not enabled. Disabling all KPM-related functionality.");
        return Ok(());
    }

    for entry in std::fs::read_dir(KPM_DIR)? {
        let path = entry?.path();
        if let Some(file_name) = path.file_stem() {
            if let Some(file_name_str) = file_name.to_str() {
                if file_name_str.is_empty() {
                    log::warn!("Invalid KPM file name: {}", path.display());
                    continue;
                }
            }
        }
        if path.extension().is_some_and(|ext| ext == "kpm") {
            match load_kpm(&path) {
                Ok(()) => log::info!("Successfully loaded KPM module: {}", path.display()),
                Err(e) => log::warn!("Failed to load KPM module {}: {}", path.display(), e),
            }
        }
    }

    Ok(())
}
