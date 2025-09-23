use anyhow::{anyhow, Result};
use libc::{prctl, c_char, c_void, c_int};
use notify::{RecursiveMode, Watcher};
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::path::Path;
use std::ptr;
use std::os::unix::fs::PermissionsExt;

pub const KPM_DIR: &str = "/data/adb/kpm";

const KSU_OPTIONS: u32 = 0xdeadbeef;
const SUKISU_KPM_LOAD: i32 = 28;
const SUKISU_KPM_UNLOAD: i32 = 29;
const SUKISU_KPM_VERSION: i32 = 34;

pub fn check_kpm_version() -> Result<String> {
    let mut buffer: [u8; 1024] = [0; 1024];
    let mut out: c_int = -1;
    
    let _ret = unsafe {
        prctl(
            KSU_OPTIONS as c_int,
            SUKISU_KPM_VERSION,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as *mut c_void,
            &mut out as *mut c_int as *mut c_void,
        )
    };

    if out < 0 {
        return Err(anyhow!("KPM: prctl returned error: {}", out));
    }

    let version_str = unsafe {
        CStr::from_ptr(buffer.as_ptr() as *const c_char)
    }.to_string_lossy().to_string();

    log::info!("KPM: Version check result: {}", version_str);
    
    // 检查版本是否有效（不为空且不以Error开头）
    if version_str.is_empty() || version_str.starts_with("Error") {
        return Err(anyhow!("KPM: Invalid version response: {}", version_str));
    }

    Ok(version_str)
}

// 确保 KPM 目录存在,并设置777权限
pub fn ensure_kpm_dir() -> Result<()> {
    let path = Path::new(KPM_DIR);
    
    if path.exists() {
        let meta = fs::metadata(path)?;
        let current = meta.permissions().mode() & 0o777;
        if current != 0o777 {
            log::info!("KPM: Fixing permissions to 777 for {}", KPM_DIR);
            fs::set_permissions(path, fs::Permissions::from_mode(0o777))?;
        }
    }
    Ok(())
}

pub fn start_kpm_watcher() -> Result<()> {
    match check_kpm_version() {
        Ok(version) => {
            log::info!("KPM: Version check passed, version: {}", version);
        }
        Err(e) => {
            log::warn!("KPM: Version check failed, skipping KPM functionality: {}", e);
            return Ok(())
        }
    }

    ensure_kpm_dir()?;

    // 检查是否处于安全模式
    if crate::utils::is_safe_mode() {
        log::warn!("KPM: System is in safe mode, removing all KPM modules");
        if let Err(e) = remove_all_kpms() {
            log::error!("KPM: Error removing all KPM modules: {}", e);
        }
        return Ok(());
    }

    let mut watcher = notify::recommended_watcher(|res| match res {
        Ok(event) => handle_kpm_event(event),
        Err(e) => log::error!("KPM: File monitoring error: {:?}", e),
    })?;

    watcher.watch(Path::new(KPM_DIR), RecursiveMode::NonRecursive)?;
    log::info!("KPM: Started file watcher for directory: {}", KPM_DIR);
    Ok(())
}

// 处理 KPM 事件
pub fn handle_kpm_event(event: notify::Event) {
    match event.kind {
        notify::EventKind::Create(_) => handle_create_event(event.paths),
        notify::EventKind::Remove(_) => handle_remove_event(event.paths),
        notify::EventKind::Modify(_) => handle_modify_event(event.paths),
        _ => {}
    }
}

fn handle_create_event(paths: Vec<std::path::PathBuf>) {
    for path in paths {
        if path.extension() == Some(OsStr::new("kpm")) {
            log::info!("KPM: Detected new KPM file: {}", path.display());
            if let Err(e) = load_kpm(&path) {
                log::warn!("KPM: Failed to load {}: {}", path.display(), e);
            }
        }
    }
}

fn handle_remove_event(paths: Vec<std::path::PathBuf>) {
    for path in paths {
        if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
            log::info!("KPM: Detected KPM file removal: {}", name);
            if let Err(e) = unload_kpm(name) {
                log::warn!("KPM: Failed to unload {}: {}", name, e);
            }
        }
    }
}

fn handle_modify_event(paths: Vec<std::path::PathBuf>) {
    for path in paths {
        log::info!("KPM: Modified file detected: {}", path.display());
    }
}

// 加载 KPM 模块
pub fn load_kpm(path: &Path) -> Result<()> {
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow!("KPM: Invalid path: {}", path.display()))?;
    
    let path_cstring = CString::new(path_str)
        .map_err(|e| anyhow!("KPM: Failed to convert path to CString: {}", e))?;
    
    let mut out: c_int = -1;

    let _ret = unsafe {
        prctl(
            KSU_OPTIONS as c_int,
            SUKISU_KPM_LOAD,
            path_cstring.as_ptr() as *mut c_void,
            ptr::null_mut::<c_void>(),
            &mut out as *mut c_int as *mut c_void,
        )
    };

    if out < 0 {
        return Err(anyhow!("KPM: prctl returned error: {}", out));
    }

    if out > 0 {
        log::info!("KPM: Successfully loaded module: {}", path.display());
    }

    Ok(())
}

// 卸载 KPM 模块
pub fn unload_kpm(name: &str) -> Result<()> {
    let name_cstring = CString::new(name)
        .map_err(|e| anyhow!("KPM: Failed to convert name to CString: {}", e))?;

    let mut out: c_int = -1;

    let _ret = unsafe {
        prctl(
            KSU_OPTIONS as c_int,
            SUKISU_KPM_UNLOAD,
            name_cstring.as_ptr() as *mut c_void,
            ptr::null_mut::<c_void>(),
            &mut out as *mut c_int as *mut c_void,
        )
    };

    if out < 0 {
        log::warn!("KPM: prctl returned error for unload: {}", out);
        return Err(anyhow!("KPM: prctl returned error: {}", out));
    }

    // 尝试删除对应的KPM文件
    if let Ok(Some(path)) = find_kpm_file(name) {
        if let Err(e) = fs::remove_file(&path) {
            log::warn!("KPM: Failed to delete KPM file {}: {}", path.display(), e);
        } else {
            log::info!("KPM: Deleted KPM file: {}", path.display());
        }
    }

    log::info!("KPM: Successfully unloaded module: {}", name);
    Ok(())
}

// 通过名称查找 KPM 文件
fn find_kpm_file(name: &str) -> Result<Option<std::path::PathBuf>> {
    let kpm_dir = Path::new(KPM_DIR);
    if !kpm_dir.exists() {
        return Ok(None);
    }

    for entry in fs::read_dir(kpm_dir)? {
        let path = entry?.path();
        if let Some(file_name) = path.file_stem() {
            if let Some(file_name_str) = file_name.to_str() {
                if file_name_str == name && path.extension() == Some(OsStr::new("kpm")) {
                    return Ok(Some(path));
                }
            }
        }
    }
    Ok(None)
}

// 安全模式下删除所有 KPM 模块
pub fn remove_all_kpms() -> Result<()> {
    let kpm_dir = Path::new(KPM_DIR);
    if !kpm_dir.exists() {
        log::info!("KPM: KPM directory does not exist, nothing to remove");
        return Ok(());
    }

    for entry in fs::read_dir(KPM_DIR)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "kpm") {
            if let Some(name) = path.file_stem() {
                let name_str = name.to_string_lossy();
                log::info!("KPM: Removing module in safe mode: {}", name_str);
                if let Err(e) = unload_kpm(&name_str) {
                    log::error!("KPM: Failed to remove module {}: {}", name_str, e);
                }
                if let Err(e) = fs::remove_file(&path) {
                    log::error!("KPM: Failed to delete file {}: {}", path.display(), e);
                }
            }
        }
    }
    Ok(())
}

// 加载所有 KPM 模块
pub fn load_kpm_modules() -> Result<()> {
    match check_kpm_version() {
        Ok(version) => {
            log::info!("KPM: Version check passed before loading modules, version: {}", version);
        }
        Err(e) => {
            log::warn!("KPM: Version check failed, skipping module loading: {}", e);
            return Ok(());
        }
    }

    ensure_kpm_dir()?;

    let kpm_dir = Path::new(KPM_DIR);
    if !kpm_dir.exists() {
        log::info!("KPM: KPM directory does not exist, no modules to load");
        return Ok(());
    }

    let mut loaded_count = 0;
    let mut failed_count = 0;

    for entry in std::fs::read_dir(KPM_DIR)? {
        let path = entry?.path();
        if let Some(file_name) = path.file_stem() {
            if let Some(file_name_str) = file_name.to_str() {
                if file_name_str.is_empty() {
                    log::warn!("KPM: Invalid KPM file name: {}", path.display());
                    continue;
                }
            }
        }
        if path.extension().is_some_and(|ext| ext == "kpm") {
            match load_kpm(&path) {
                Ok(()) => {
                    log::info!("KPM: Successfully loaded module: {}", path.display());
                    loaded_count += 1;
                }
                Err(e) => {
                    log::warn!("KPM: Failed to load module {}: {}", path.display(), e);
                    failed_count += 1;
                }
            }
        }
    }

    log::info!("KPM: Module loading completed - loaded: {}, failed: {}", loaded_count, failed_count);
    Ok(())
}
