// xtask/src/vmware/mod.rs

use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    process::Command,
    thread,
    time::Duration,
};

pub struct VMWare {
    vmx_path: PathBuf,
    vmrun_path: PathBuf,
    log_path: PathBuf,
}

impl VMWare {
    pub fn new(vmx_path: &PathBuf) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            vmx_path: vmx_path.clone(),
            vmrun_path: PathBuf::from(r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"),
            log_path: PathBuf::from(".\\logs.txt"),
        })
    }

    pub fn with_vmrun(mut self, vmrun_path: PathBuf) -> Self {
        self.vmrun_path = vmrun_path;
        self
    }

    pub fn with_log_path(mut self, log_path: PathBuf) -> Self {
        self.log_path = log_path;
        self
    }

    pub fn log_path(&self) -> &PathBuf {
        &self.log_path
    }

    pub fn enable_firmware_once(&self) -> Result<(), Box<dyn Error>> {
        let content = b"bios.forceSetupOnce = \"TRUE\"\r\n";
        let mut file = OpenOptions::new().create(true).append(true).open(&self.vmx_path)?;
        file.write_all(content)?;
        Ok(())
    }

    pub fn clear_log(&self) -> Result<(), Box<dyn Error>> {
        if self.log_path.exists() {
            fs::remove_file(&self.log_path)?;
        }
        Ok(())
    }

    pub fn start_gui(&self) -> Result<(), Box<dyn Error>> {
        let status = Command::new(&self.vmrun_path)
            .args(["-T", "ws", "start", self.vmx_path.to_string_lossy().as_ref(), "gui"])
            .status()?;

        if !status.success() {
            return Err(format!("vmrun failed with status: {status}").into());
        }

        Ok(())
    }

    pub fn wait_for_log(&self, interval: Duration) -> Result<(), Box<dyn Error>> {
        loop {
            if self.log_path.exists() {
                break;
            }
            thread::sleep(interval);
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn open_log(&self) -> Result<std::fs::File, Box<dyn Error>> {
        let file = OpenOptions::new().read(true).open(&self.log_path)?;
        Ok(file)
    }

    #[allow(dead_code)]
    pub fn state(&self) -> Result<String, Box<dyn Error>> {
        let output = Command::new(&self.vmrun_path).args(["-T", "ws", "list"]).output()?;

        let out = String::from_utf8_lossy(&output.stdout);
        let running = out
            .lines()
            .any(|line| line.trim().eq_ignore_ascii_case(self.vmx_path.to_string_lossy().as_ref()));

        Ok(if running { "running".into() } else { "stopped".into() })
    }
}
