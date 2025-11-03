use anyhow::{Result, anyhow, bail};
use notify::{RecursiveMode, Watcher};
use std::{
    ffi::{CStr, OsStr},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

pub const KPM_DIR: &str = "/data/adb/kpm";

pub const KSU_IOCTL_KPM_LOAD: u32 = 0xc0004bc8; // _IOC(_IOC_READ|_IOC_WRITE, 'K', 200, 0)
pub const KSU_IOCTL_KPM_UNLOAD: u32 = 0x40004bc9; // _IOC(_IOC_WRITE, 'K', 201, 0)
pub const KSU_IOCTL_KPM_NUM: u32 = 0x80004bca; // _IOC(_IOC_READ, 'K', 202, 0)
pub const KSU_IOCTL_KPM_INFO: u32 = 0xc0004bcb; // _IOC(_IOC_READ|_IOC_WRITE, 'K', 203, 0)
pub const KSU_IOCTL_KPM_LIST: u32 = 0xc0004bcc; // _IOC(_IOC_READ|_IOC_WRITE, 'K', 204, 0)
pub const KSU_IOCTL_KPM_CONTROL: u32 = 0xc0004bcd; // _IOC(_IOC_READ|_IOC_WRITE, 'K', 205, 0)
pub const KSU_IOCTL_KPM_VERSION: u32 = 0xc0004bce; // _IOC(_IOC_READ|_IOC_WRITE, 'K', 206, 0)

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KpmLoadCmd {
    pub path: [u8; 256],
    pub args: [u8; 256],
}

impl Default for KpmLoadCmd {
    fn default() -> Self {
        KpmLoadCmd {
            path: [0; 256],
            args: [0; 256],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KpmUnloadCmd {
    pub name: [u8; 256],
}

impl Default for KpmUnloadCmd {
    fn default() -> Self {
        KpmUnloadCmd { name: [0; 256] }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KpmNumCmd {
    pub num: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KpmListCmd {
    pub buffer: *mut u8,
    pub size: u32,
}

impl Default for KpmListCmd {
    fn default() -> Self {
        KpmListCmd {
            buffer: std::ptr::null_mut(),
            size: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KpmInfoCmd {
    pub name: [u8; 256],
    pub buffer: [u8; 256],
}

impl Default for KpmInfoCmd {
    fn default() -> Self {
        KpmInfoCmd {
            name: [0; 256],
            buffer: [0; 256],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KpmControlCmd {
    pub name: [u8; 256],
    pub args: [u8; 256],
}

impl Default for KpmControlCmd {
    fn default() -> Self {
        KpmControlCmd {
            name: [0; 256],
            args: [0; 256],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KpmVersionCmd {
    pub buffer: [u8; 256],
    pub size: u32,
}

impl Default for KpmVersionCmd {
    fn default() -> Self {
        KpmVersionCmd {
            buffer: [0; 256],
            size: 256,
        }
    }
}

/// Load a `.kpm` into kernel space.
pub fn kpm_load(path: &str, args: Option<&str>) -> Result<()> {
    let mut cmd = KpmLoadCmd {
        path: str2buf256(path),
        args: [0; 256],
    };
    if let Some(a) = args {
        cmd.args = str2buf256(a);
    }
    let ret = crate::ksucalls::ksu_ioctl(KSU_IOCTL_KPM_LOAD, &mut cmd as *mut _ as *mut u8)?;
    if ret != 0 {
        bail!(
            "KPM load error: {}",
            std::io::Error::from_raw_os_error(-ret)
        );
    }
    println!("Success");
    Ok(())
}

/// Unload by module name.
pub fn kpm_unload(name: &str) -> Result<()> {
    let mut cmd = KpmUnloadCmd {
        name: str2buf256(name),
    };
    let ret = crate::ksucalls::ksu_ioctl(KSU_IOCTL_KPM_UNLOAD, &mut cmd as *mut _ as *mut u8)?;
    if ret != 0 {
        bail!(
            "KPM unload error: {}",
            std::io::Error::from_raw_os_error(-ret)
        );
    }
    Ok(())
}

/// Return loaded module count.
pub fn kpm_num() -> Result<i32> {
    let mut cmd = KpmNumCmd { num: 0 };
    crate::ksucalls::ksu_ioctl(KSU_IOCTL_KPM_NUM, &mut cmd as *mut _ as *mut u8)?;
    println!("{}", cmd.num);
    Ok(cmd.num as i32)
}

/// Print name list of loaded modules.
pub fn kpm_list() -> Result<()> {
    let mut buffer = vec![0u8; 4096];
    let mut cmd = KpmListCmd {
        buffer: buffer.as_mut_ptr(),
        size: buffer.len() as u32,
    };
    let ret = crate::ksucalls::ksu_ioctl(KSU_IOCTL_KPM_LIST, &mut cmd as *mut _ as *mut u8)?;
    if ret != 0 {
        bail!(
            "KPM list error: {}",
            std::io::Error::from_raw_os_error(-ret)
        );
    }
    print!("{}", buf2str(&buffer));
    Ok(())
}

/// Print single module info.
pub fn kpm_info(name: &str) -> Result<()> {
    let mut cmd = KpmInfoCmd {
        name: str2buf256(name),
        buffer: [0; 256],
    };
    let ret = crate::ksucalls::ksu_ioctl(KSU_IOCTL_KPM_INFO, &mut cmd as *mut _ as *mut u8)?;
    if ret != 0 {
        bail!(
            "KPM info error: {}",
            std::io::Error::from_raw_os_error(-ret)
        );
    }
    println!("{}", buf2str(&cmd.buffer));
    Ok(())
}

/// Send control string to a module; returns kernel answer.
pub fn kpm_control(name: &str, args: &str) -> Result<i32> {
    let mut cmd = KpmControlCmd {
        name: str2buf256(name),
        args: str2buf256(args),
    };
    let ret = crate::ksucalls::ksu_ioctl(KSU_IOCTL_KPM_CONTROL, &mut cmd as *mut _ as *mut u8)?;
    if ret < 0 {
        bail!(
            "KPM control error: {}",
            std::io::Error::from_raw_os_error(-ret)
        );
    }
    Ok(ret)
}

/// Print loader version string.
pub fn kpm_version_loader() -> Result<()> {
    let mut cmd = KpmVersionCmd {
        buffer: [0; 256],
        size: 256,
    };
    let ret = crate::ksucalls::ksu_ioctl(KSU_IOCTL_KPM_VERSION, &mut cmd as *mut _ as *mut u8)?;
    if ret != 0 {
        bail!(
            "KPM version error: {}",
            std::io::Error::from_raw_os_error(-ret)
        );
    }
    print!("{}", buf2str(&cmd.buffer));
    Ok(())
}

/// Validate loader version; empty or "Error*" => fail.
pub fn check_kpm_version() -> Result<String> {
    let mut cmd = KpmVersionCmd {
        buffer: [0; 256],
        size: 256,
    };
    let ret = crate::ksucalls::ksu_ioctl(KSU_IOCTL_KPM_VERSION, &mut cmd as *mut _ as *mut u8)?;
    if ret != 0 {
        bail!(
            "KPM version error: {}",
            std::io::Error::from_raw_os_error(-ret)
        );
    }
    let ver = buf2str(&cmd.buffer);
    if ver.is_empty() || ver.starts_with("Error") {
        bail!("KPM: invalid version response: {ver}");
    }
    log::info!("KPM: version check ok: {ver}");
    Ok(ver)
}

/// Create `/data/adb/kpm` with 0o777 if missing.
pub fn ensure_kpm_dir() -> Result<()> {
    fs::create_dir_all(KPM_DIR)?;
    let meta = fs::metadata(KPM_DIR)?;
    if meta.permissions().mode() & 0o777 != 0o777 {
        fs::set_permissions(KPM_DIR, fs::Permissions::from_mode(0o777))?;
    }
    Ok(())
}

/// Start file watcher for hot-(un)load.
pub fn start_kpm_watcher() -> Result<()> {
    check_kpm_version()?; // bails if loader too old
    ensure_kpm_dir()?;
    if crate::utils::is_safe_mode() {
        log::warn!("KPM: safe-mode – removing all modules");
        remove_all_kpms()?;
        return Ok(());
    }

    let mut watcher = notify::recommended_watcher(|res: Result<_, _>| match res {
        Ok(evt) => handle_kpm_event(evt),
        Err(e) => log::error!("KPM: watcher error: {e:?}"),
    })?;
    watcher.watch(Path::new(KPM_DIR), RecursiveMode::NonRecursive)?;
    log::info!("KPM: watcher active on {KPM_DIR}");
    Ok(())
}

fn handle_kpm_event(evt: notify::Event) {
    if let notify::EventKind::Create(_) = evt.kind {
        for p in evt.paths {
            if p.extension() == Some(OsStr::new("kpm")) && load_kpm(&p).is_err() {
                log::warn!("KPM: failed to load {}", p.display());
            }
        }
    }
}

/// Load single `.kpm` file.
pub fn load_kpm(path: &Path) -> Result<()> {
    let s = path.to_str().ok_or_else(|| anyhow!("bad path"))?;
    kpm_load(s, None)
}

/// Unload module and delete file.
pub fn unload_kpm(name: &str) -> Result<()> {
    kpm_unload(name)?;
    if let Some(p) = find_kpm_file(name)? {
        let _ = fs::remove_file(&p);
        log::info!("KPM: deleted {}", p.display());
    }
    Ok(())
}

/// Locate `/data/adb/kpm/<name>.kpm`.
fn find_kpm_file(name: &str) -> Result<Option<PathBuf>> {
    let dir = Path::new(KPM_DIR);
    if !dir.is_dir() {
        return Ok(None);
    }
    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if p.extension() == Some(OsStr::new("kpm")) && p.file_stem() == Some(OsStr::new(name)) {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

/// Remove every `.kpm` file and unload it.
pub fn remove_all_kpms() -> Result<()> {
    let dir = Path::new(KPM_DIR);
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if p.extension() == Some(OsStr::new("kpm"))
            && let Some(name) = p.file_stem().and_then(|s| s.to_str())
            && let Err(e) = unload_kpm(name)
        {
            log::error!("KPM: unload {name} failed: {e}");
        }
    }
    Ok(())
}

/// Bulk-load existing `.kpm`s at boot.
pub fn load_kpm_modules() -> Result<()> {
    check_kpm_version()?;
    ensure_kpm_dir()?;
    let dir = Path::new(KPM_DIR);
    if !dir.is_dir() {
        return Ok(());
    }
    let (mut ok, mut ng) = (0, 0);
    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if p.extension() == Some(OsStr::new("kpm")) {
            match load_kpm(&p) {
                Ok(_) => ok += 1,
                Err(e) => {
                    log::warn!("KPM: load {} failed: {e}", p.display());
                    ng += 1;
                }
            }
        }
    }
    log::info!("KPM: bulk-load done – ok: {ok}, failed: {ng}");
    Ok(())
}

fn str2buf256(s: &str) -> [u8; 256] {
    let mut b = [0u8; 256];
    let bytes = s.as_bytes();
    let len = bytes.len().min(255);
    b[..len].copy_from_slice(&bytes[..len]);
    b
}

/// Convert zero-padded kernel buffer to owned String.
fn buf2str(buf: &[u8]) -> String {
    // SAFETY: buffer is always NUL-terminated by kernel.
    unsafe {
        CStr::from_ptr(buf.as_ptr().cast())
            .to_string_lossy()
            .into_owned()
    }
}
