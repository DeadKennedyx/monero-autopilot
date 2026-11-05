//! Windows DPAPI, private data directory, and owned process lifetime.
use crate::LabResult;
use std::{mem, path::Path, process::Stdio, ptr};
use tokio::process::Command;
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, HANDLE},
    Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    },
    System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    },
};
use zeroize::{Zeroize, Zeroizing};

pub const HIDDEN: u32 = 0x08000000;
pub async fn private_directory(path: &Path) -> LabResult<()> {
    std::fs::create_dir_all(path).map_err(|_| "Could not create the private lab directory.")?;
    // Only this data directory is affected. The path is an environment value, never script text.
    let script = "$ErrorActionPreference='Stop'; $p=$env:AUTOPILOT_PRIVATE_DIR; $sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User; $acl=Get-Acl -LiteralPath $p; $acl.SetAccessRuleProtection($true,$false); foreach($entry in @($acl.Access)){$acl.RemoveAccessRuleSpecific($entry)}; $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'); $acl.AddAccessRule($rule); [System.IO.Directory]::SetAccessControl($p,$acl)";
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("AUTOPILOT_PRIVATE_DIR", path)
        .env_remove("PSModulePath")
        .creation_flags(HIDDEN)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .await
        .map_err(|_| "Could not set private directory permissions.")?;
    if !status.success() {
        return Err("Could not restrict the lab directory to the current Windows user.");
    }
    Ok(())
}
pub fn protect(data: &[u8]) -> LabResult<Vec<u8>> {
    crypt(data, true)
}
pub fn unprotect(data: &[u8]) -> LabResult<Zeroizing<Vec<u8>>> {
    crypt(data, false).map(Zeroizing::new)
}
fn crypt(data: &[u8], encrypt: bool) -> LabResult<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len().try_into().map_err(|_| "Secret is too large.")?,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output: CRYPT_INTEGER_BLOB = unsafe { mem::zeroed() };
    // DPAPI allocates output; copy, clear its native buffer, and free it exactly once.
    let ok = unsafe {
        if encrypt {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 {
        return Err("Windows could not protect or unlock this lab credential.");
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize).zeroize();
        LocalFree(output.pbData.cast());
    }
    Ok(result)
}
pub struct Job(HANDLE);
// The handle is owned, immutable after initialization, and Windows job operations are thread safe.
unsafe impl Send for Job {}
unsafe impl Sync for Job {}
impl Job {
    pub fn new() -> LabResult<Self> {
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            return Err("Could not create process supervision job.");
        }
        let job = Self(handle);
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                mem::size_of_val(&info) as u32,
            )
        } == 0
        {
            return Err("Could not configure process cleanup.");
        }
        Ok(job)
    }
    pub fn assign(&self, child: &tokio::process::Child) -> LabResult<()> {
        let handle = child
            .raw_handle()
            .ok_or("Child process handle is missing.")?;
        if unsafe { AssignProcessToJobObject(self.0, handle) } == 0 {
            Err("Could not supervise the child process.")
        } else {
            Ok(())
        }
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
