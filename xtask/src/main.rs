// xtask/src/main.rs

use {
    log::{debug, info, warn},
    std::{
        error::Error,
        fs,
        io::{BufRead, BufReader},
        path::PathBuf,
        thread,
        time::Duration,
    },
};

mod vmware;
use crate::vmware::VMWare;

// ====== CONFIG (tweak for your machine) ======
const BUILD_TYPE: &str = "release"; // or "debug"
const EFI_BUILD_DIR: &str = r"..\target\x86_64-unknown-uefi";
const USB_DRIVE: &str = r"D:\";

const VMX_PATH: &str = r"C:\Users\YourName\Documents\VMware VMs\illusion\illusion.vmx";
const VMRUN_PATH: &str = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe";
const LOG_FILE_PATH: &str = r".\logs.txt";
// ============================================

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    // 1) copy .efi files
    let src_dir = PathBuf::from(EFI_BUILD_DIR).join(BUILD_TYPE);
    let dst_dir = PathBuf::from(USB_DRIVE);
    info!("Copying EFI files from {:?} to {:?}", src_dir, dst_dir);
    copy_efi_files(&src_dir, &dst_dir)?;

    // 2) make VMware object
    let vm = VMWare::new(&PathBuf::from(VMX_PATH))?
        .with_vmrun(PathBuf::from(VMRUN_PATH))
        .with_log_path(PathBuf::from(LOG_FILE_PATH));

    // 3) force firmware once
    info!("Enabling firmware setup once…");
    vm.enable_firmware_once()?;

    // 4) clear old log
    info!("Clearing old log…");
    vm.clear_log()?;

    // 5) start VM
    info!("Starting VM…");
    vm.start_gui()?;

    // 6) wait for log to appear, then tail forever
    info!("Waiting for log file {:?} …", vm.log_path());
    vm.wait_for_log(Duration::from_millis(800))?;

    info!("Tailing log (Ctrl+C to stop) …");
    tail_log(vm.log_path())?;
    Ok(())
}

fn copy_efi_files(src_dir: &PathBuf, dst_dir: &PathBuf) -> Result<(), Box<dyn Error>> {
    if !src_dir.exists() {
        return Err(format!("EFI build dir {:?} does not exist", src_dir).into());
    }
    if !dst_dir.exists() {
        return Err(format!("Destination USB/virtual drive {:?} does not exist", dst_dir).into());
    }

    for entry in fs::read_dir(src_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map(|e| e.eq_ignore_ascii_case("efi")) == Some(true) {
            let file_name = path.file_name().ok_or("file has no name")?.to_owned();
            let dest = dst_dir.join(file_name);
            fs::copy(&path, &dest)?;
            info!("Copied {:?} -> {:?}", path, dest);
        }
    }

    Ok(())
}

fn tail_log(log_path: &PathBuf) -> Result<(), Box<dyn Error>> {
    loop {
        match std::fs::File::open(log_path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    match line {
                        Ok(l) => println!("{l}"),
                        Err(e) => {
                            warn!("error reading log line: {e}");
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                // if log not ready yet, keep waiting
                thread::sleep(Duration::from_millis(500));
            }
        }

        thread::sleep(Duration::from_millis(250));
        debug!("re-checking log file…");
    }
}
