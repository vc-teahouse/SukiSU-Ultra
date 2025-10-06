use anyhow::{anyhow, bail, Result};
use libc::{c_int, c_ulong, prctl};
use notify::{RecursiveMode, Watcher};
use std::ffi::{CString, OsStr};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::ptr;

pub const KPM_DIR: &str = "/data/adb/kpm";

const KSU_OPTIONS: c_int = 0xdeadbeef_u32 as c_int;
const SUKISU_KPM_LOAD:   c_int = 28;
const SUKISU_KPM_UNLOAD: c_int = 29;
const SUKISU_KPM_NUM:    c_int = 30;
const SUKISU_KPM_LIST:   c_int = 31;
const SUKISU_KPM_INFO:   c_int = 32;
const SUKISU_KPM_CONTROL:c_int = 33;
const SUKISU_KPM_VERSION:c_int = 34;

#[inline(always)]
fn check_out(out: c_int) -> Result<c_int> {
    if out < 0 {
        bail!("KPM error: {}", std::io::Error::from_raw_os_error(-out));
    }
    Ok(out)
}

pub fn kpm_load(path: &str, args: Option<&str>) -> Result<()> {
    let path_c = CString::new(path)?;
    let args_c = args.map(CString::new).transpose()?;

    let mut out: c_int = -1;
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_LOAD,
            path_c.as_ptr() as c_ulong,
            args_c.as_ref()
                  .map_or(ptr::null(), |s| s.as_ptr()) as c_ulong,
            &mut out as *mut c_int as c_ulong,
        );
    }
    check_out(out)?;
    println!("Success");
    Ok(())
}

pub fn kpm_unload(name: &str) -> Result<()> {
    let name_c = CString::new(name)?;
    let mut out: c_int = -1;
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_UNLOAD,
            name_c.as_ptr() as c_ulong,
            0,
            &mut out as *mut c_int as c_ulong,
        );
    }
    check_out(out)?;
    Ok(())
}

pub fn kpm_num() -> Result<i32> {
    let mut out: c_int = -1;
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_NUM,
            0,
            0,
            &mut out as *mut c_int as c_ulong,
        );
    }
    let n = check_out(out)?;
    println!("{}", n);
    Ok(n)
}

pub fn kpm_list() -> Result<()> {
    let mut buf = vec![0u8; 1024];
    let mut out: c_int = -1;
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_LIST,
            buf.as_mut_ptr() as c_ulong,
            buf.len() as c_ulong,
            &mut out as *mut c_int as c_ulong,
        );
    }
    check_out(out)?;
    print!("{}", buf2string(&buf));
    Ok(())
}

pub fn kpm_info(name: &str) -> Result<()> {
    let name_c = CString::new(name)?;
    let mut buf = vec![0u8; 256];
    let mut out: c_int = -1;
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_INFO,
            name_c.as_ptr() as c_ulong,
            buf.as_mut_ptr() as c_ulong,
            &mut out as *mut c_int as c_ulong,
        );
    }
    check_out(out)?;
    println!("{}", buf2string(&buf));
    Ok(())
}

pub fn kpm_control(name: &str, args: &str) -> Result<i32> {
    let name_c = CString::new(name)?;
    let args_c = CString::new(args)?;
    let mut out: c_int = -1;
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_CONTROL,
            name_c.as_ptr() as c_ulong,
            args_c.as_ptr() as c_ulong,
            &mut out as *mut c_int as c_ulong,
        );
    }
    check_out(out)?;
    Ok(out)
}

pub fn kpm_version_loader() -> Result<()> {
    let mut buf = vec![0u8; 1024];
    let mut out: c_int = -1;
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_VERSION,
            buf.as_mut_ptr() as c_ulong,
            buf.len() as c_ulong,
            &mut out as *mut c_int as c_ulong,
        );
    }
    check_out(out)?;
    print!("{}", buf2string(&buf));
    Ok(())
}

pub fn check_kpm_version() -> Result<String> {
    let mut buf = vec![0u8; 1024];
    let mut out: c_int = -1;
    unsafe {
        prctl(
            KSU_OPTIONS,
            SUKISU_KPM_VERSION,
            buf.as_mut_ptr() as c_ulong,
            buf.len() as c_ulong,
            &mut out as *mut c_int as c_ulong,
        );
    }
    check_out(out)?;
    let ver = buf2string(&buf);
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
    check_kpm_version()?; // 版本不对直接返回
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

fn buf2string(buf: &[u8]) -> String {
    unsafe {
        std::ffi::CStr::from_ptr(buf.as_ptr() as *const _)
            .to_string_lossy()
            .into_owned()
    }
}