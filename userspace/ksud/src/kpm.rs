use anyhow::{anyhow, bail, Result};
use libc::{c_char, c_int, c_void, prctl};
use notify::{RecursiveMode, Watcher};
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::ptr;

pub const KPM_DIR: &str = "/data/adb/kpm";

const KSU_OPTIONS: u32 = 0xdeadbeef;
const SUKISU_KPM_LOAD:   i32 = 28;
const SUKISU_KPM_UNLOAD: i32 = 29;
const SUKISU_KPM_NUM:    i32 = 30;
const SUKISU_KPM_LIST:   i32 = 31;
const SUKISU_KPM_INFO:   i32 = 32;
const SUKISU_KPM_CONTROL:i32 = 33;
const SUKISU_KPM_VERSION:i32 = 34;

#[inline(always)]
unsafe fn kpm_prctl(
    cmd: i32,
    arg1: *const c_void,
    arg2: *const c_void,
) -> Result<i32> {
    let mut out: c_int = -1;
    let ret = unsafe {
        prctl(
            KSU_OPTIONS as c_int,
            cmd as c_int,
            arg1,
            arg2,
            &mut out as *mut c_int as *mut c_void,
        )
    };
    if ret != 0 || out < 0 {
        bail!("KPM prctl error: {}", std::io::Error::from_raw_os_error(-out));
    }
    Ok(out)
}

fn str_to_cstr<R, F: FnOnce(*const c_char) -> R>(s: &str, f: F) -> Result<R> {
    let cs = CString::new(s)?;
    Ok(f(cs.as_ptr()))
}

fn cbuf_to_string(buf: &[u8]) -> String {
    unsafe { CStr::from_ptr(buf.as_ptr() as *const c_char) }
        .to_string_lossy()
        .into_owned()
}

pub fn kpm_load(path: &str, args: Option<&str>) -> Result<()> {
    str_to_cstr(path, |p_path| {
        let _args_cstring;
        let p_args = match args {
            Some(a) => {
                _args_cstring = CString::new(a)?;
                _args_cstring.as_ptr()
            }
            None => ptr::null(),
        };
        unsafe { kpm_prctl(SUKISU_KPM_LOAD, p_path as _, p_args as _) }?;
        println!("Success");
        Ok(())
    })?
}

pub fn kpm_unload(name: &str) -> Result<()> {
    let _ = str_to_cstr(name, |p| unsafe {
        kpm_prctl(SUKISU_KPM_UNLOAD, p as _, ptr::null())
    })?;
    Ok(())
}

pub fn kpm_num() -> Result<i32> {
    let n = unsafe { kpm_prctl(SUKISU_KPM_NUM, ptr::null(), ptr::null())? };
    println!("{}", n);
    Ok(n)
}

pub fn kpm_list() -> Result<()> {
    let mut buf = vec![0u8; 1024];
    unsafe {
        kpm_prctl(
            SUKISU_KPM_LIST,
            buf.as_mut_ptr() as _,
            buf.len() as *const c_void,
        )?;
    }
    print!("{}", cbuf_to_string(&buf));
    Ok(())
}

pub fn kpm_info(name: &str) -> Result<()> {
    let mut buf = vec![0u8; 256];
    let _ = str_to_cstr(name, |p| unsafe {
        kpm_prctl(SUKISU_KPM_INFO, p as _, buf.as_mut_ptr() as _)
    })?;
    println!("{}", cbuf_to_string(&buf));
    Ok(())
}

pub fn kpm_control(name: &str, args: &str) -> Result<i32> {
    str_to_cstr(name, |p_name| {
        str_to_cstr(args, |p_args| unsafe {
            kpm_prctl(SUKISU_KPM_CONTROL, p_name as _, p_args as _)
        })?
    })?
}

pub fn kpm_version_loader() -> Result<()> {
    let mut buf = vec![0u8; 1024];
    unsafe {
        kpm_prctl(
            SUKISU_KPM_VERSION,
            buf.as_mut_ptr() as _,
            buf.len() as *const c_void,
        )?;
    }
    print!("{}", cbuf_to_string(&buf));
    Ok(())
}

pub fn check_kpm_version() -> Result<String> {
    let mut buf = vec![0u8; 1024];
    unsafe {
        kpm_prctl(
            SUKISU_KPM_VERSION,
            buf.as_mut_ptr() as _,
            buf.len() as *const c_void,
        )?;
    }
    let ver = cbuf_to_string(&buf);
    if ver.is_empty() || ver.starts_with("Error") {
        bail!("KPM: Invalid version response: {}", ver);
    }
    log::info!("KPM: Version check result: {}", ver);
    Ok(ver)
}

pub fn ensure_kpm_dir() -> Result<()> {
    let path = Path::new(KPM_DIR);
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    let meta = fs::metadata(path)?;
    if meta.permissions().mode() & 0o777 != 0o777 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o777))?;
    }
    Ok(())
}

pub fn start_kpm_watcher() -> Result<()> {
    check_kpm_version()?;
    ensure_kpm_dir()?;
    if crate::utils::is_safe_mode() {
        log::warn!("KPM: Safe mode – removing all KPM modules");
        remove_all_kpms()?;
        return Ok(());
    }

    let mut watcher = notify::recommended_watcher(|res| match res {
        Ok(event) => handle_kpm_event(event),
        Err(e) => log::error!("KPM: File monitor error: {:?}", e),
    })?;
    watcher.watch(Path::new(KPM_DIR), RecursiveMode::NonRecursive)?;
    log::info!("KPM: File watcher started on {}", KPM_DIR);
    Ok(())
}

fn handle_kpm_event(event: notify::Event) {
    match event.kind {
        notify::EventKind::Create(_) => {
            for p in event.paths {
                if p.extension() == Some(OsStr::new("kpm")) {
                    if let Err(e) = load_kpm(&p) {
                        log::warn!("KPM: Failed to load {}: {}", p.display(), e);
                    }
                }
            }
        }
        notify::EventKind::Modify(_) => {
            for p in event.paths {
                log::info!("KPM: Modified file: {}", p.display());
            }
        }
        _ => {}
    }
}

pub fn load_kpm(path: &Path) -> Result<()> {
    let path_str = path.to_str().ok_or_else(|| anyhow!("Invalid path"))?;
    kpm_load(path_str, None)
}

pub fn unload_kpm(name: &str) -> Result<()> {
    kpm_unload(name)?;
    if let Some(p) = find_kpm_file(name)? {
        fs::remove_file(&p).ok();
        log::info!("KPM: Deleted file {}", p.display());
    }
    Ok(())
}

fn find_kpm_file(name: &str) -> Result<Option<PathBuf>> {
    let dir = Path::new(KPM_DIR);
    if !dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if p.extension() == Some(OsStr::new("kpm"))
            && p.file_stem().map_or(false, |s| s == name)
        {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

pub fn remove_all_kpms() -> Result<()> {
    let dir = Path::new(KPM_DIR);
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if p.extension() == Some(OsStr::new("kpm")) {
            if let Some(name) = p.file_stem().and_then(|s| s.to_str()) {
                if let Err(e) = unload_kpm(name) {
                    log::error!("KPM: Failed to unload {}: {}", name, e);
                }
            }
        }
    }
    Ok(())
}

pub fn load_kpm_modules() -> Result<()> {
    check_kpm_version()?;
    ensure_kpm_dir()?;
    let dir = Path::new(KPM_DIR);
    if !dir.exists() {
        return Ok(());
    }
    let (mut ok, mut ng) = (0, 0);
    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if p.extension() == Some(OsStr::new("kpm")) {
            match load_kpm(&p) {
                Ok(_) => ok += 1,
                Err(e) => {
                    log::warn!("KPM: Failed to load {}: {}", p.display(), e);
                    ng += 1;
                }
            }
        }
    }
    log::info!("KPM: Load done – ok: {}, failed: {}", ok, ng);
    Ok(())
}
