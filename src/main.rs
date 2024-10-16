use std::env;
use std::process::{ Command, ExitStatus, Stdio };
use log::{ debug, error, info, trace, warn };
use crossterm::execute;
use crossterm::style::{ Color, ResetColor, SetForegroundColor };
use std::fs::OpenOptions;
use std::io::{ self, Read };
use std::io::{ BufRead, BufReader };
use windows::Win32::System::Threading::{GetCurrentThread, ResumeThread};
use core::ffi::c_ulong;
use core::ptr;
use windows::Win32::Foundation::{HANDLE, NTSTATUS};
use windows::Wdk::System::Threading::{NtQueryInformationThread, THREADINFOCLASS};
const THREAD_SUSPEND_COUNT: c_ulong = 0x0000000A;
#[derive(Debug)]
struct SystemCommand<'a> {
    program: &'a str,
    args: Vec<&'a str>,
}
use std::error::Error;
use std::thread;
fn exec_command(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| child.wait_with_output())
        .map_err(|e| format!("Failed to start '{}': {}", program, e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    log::info!("Output from {}: {}", program, stdout);
    if !stderr.is_empty() {
        log::error!("Error from {}: {}", program, stderr);
    }

    println!("Output: {}", stdout);
    if !stderr.is_empty() {
        eprintln!("Error: {}", stderr);
    }

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "'{}' failed with exit code {:?}: Output: {}, Error: {}",
            program,
            output.status.code(),
            stdout,
            stderr
        ))
    }
}

fn execute_commands(commands: &[SystemCommand], error_messages: &mut Vec<String>) {
    for command in commands {
        if let Err(e) = exec_command(command.program, &command.args) {
            error_messages.push(format!("Error executing {:?}: {}", command, e));
        }
    }
}
fn perform_disk_cleanup(error_messages: &mut Vec<String>) {
    trace!("Performing disk cleanup.");
    let disk_cleanup_command = vec![SystemCommand {
        program: "cleanmgr",
        args: vec!["/sagerun:1"],
    }];
    execute_commands(&disk_cleanup_command, error_messages);
}
fn cleanup_prefetch_files(system_root: &str, error_messages: &mut Vec<String>) {
    trace!("Deleting Prefetch files.");
    let prefetch_path = format!("{}\\Prefetch\\*", system_root);
    let remove_prefetch_command_str =
        format!("Remove-Item -Path '{}' -Recurse -Force -ErrorAction SilentlyContinue", prefetch_path);
    let prefetch_cleanup_command = vec![SystemCommand {
        program: "powershell",
        args: vec!["-command", &remove_prefetch_command_str],
    }];
    execute_commands(&prefetch_cleanup_command, error_messages);
}

fn cleanup_windows_update_cache(system_root: &str, error_messages: &mut Vec<String>) {
    trace!("Cleaning up Windows Update cache.");
    let windows_update_command_str = format!(
        "rd /s /q {}",
        system_root.to_owned() + "\\SoftwareDistribution"
    );
    let windows_update_cleanup_commands = vec![
        SystemCommand { program: "cmd", args: vec!["/c", &windows_update_command_str] },
        SystemCommand { program: "net", args: vec!["stop", "wuauserv"] },
        SystemCommand { program: "net", args: vec!["stop", "bits"] },
        SystemCommand { program: "net", args: vec!["start", "wuauserv"] },
        SystemCommand { program: "net", args: vec!["start", "bits"] }
    ];
    execute_commands(&windows_update_cleanup_commands, error_messages);
}
fn remove_temporary_files(temp: &str, system_root: &str, error_messages: &mut Vec<String>) {
    trace!("Removing temporary files.");

    let temp_files_pattern = format!("{}\\*", temp);
    let temp_system_pattern = format!("{}\\temp\\*", system_root);

    let temp_files_command =
        format!("Remove-Item -Path '{}' -Recurse -Force -ErrorAction SilentlyContinue", temp_files_pattern);
    let temp_system_command =
        format!("Remove-Item -Path '{}' -Recurse -Force -ErrorAction SilentlyContinue", temp_system_pattern);

    let delete_temp_commands = vec![
        SystemCommand { program: "powershell", args: vec!["-command", &temp_files_command] },
        SystemCommand { program: "powershell", args: vec!["-command", &temp_system_command] },
        SystemCommand {
            program: "cmd",
            args: vec!["/c", "for /d %i in (C:\\Users\\*) do rd /s /q \"%i\\AppData\\Local\\Temp\""]
        },
        SystemCommand {
            program: "net",
            args: vec!["stop", "wsearch"],
        },
        SystemCommand {
            program: "cmd",
            args: vec!["/c", "del /f /s /q %ProgramData%\\Microsoft\\Search\\Data\\Applications\\Windows\\*"],
        },
        SystemCommand {
            program: "net",
            args: vec!["start", "wsearch"],
        }
    ];

    execute_commands(&delete_temp_commands, error_messages);
}

fn cleanup_font_cache(system_root: &str, error_messages: &mut Vec<String>) {
    trace!("Cleaning up font cache.");
    let font_cache_path =
        format!("{}\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache\\*", system_root);
    let font_cache_system_path =
        format!("{}\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache-System\\*", system_root);

    let remove_font_cache_command =
        format!("Remove-Item -Path '{}' -Recurse -Force -ErrorAction SilentlyContinue", font_cache_path);
    let remove_font_cache_system_command =
        format!("Remove-Item -Path '{}' -Recurse -Force -ErrorAction SilentlyContinue", font_cache_system_path);

    let font_cache_cleanup_commands = vec![
        SystemCommand {
            program: "powershell",
            args: vec!["-command", "Stop-Service -Name 'fontcache' -Force"],
        },
        SystemCommand { program: "powershell", args: vec!["-command", &remove_font_cache_command] },
        SystemCommand {
            program: "powershell",
            args: vec!["-command", &remove_font_cache_system_command],
        },
        SystemCommand {
            program: "powershell",
            args: vec!["-command", "Start-Service -Name 'fontcache'"],
        }
    ];
    execute_commands(&font_cache_cleanup_commands, error_messages);
}


fn delete_old_log_files(error_messages: &mut Vec<String>) {
    trace!("Deleting log files older than 7 days");
    let delete_log_files_command = vec![SystemCommand {
        program: "forfiles",
        args: vec![
            "/p",
            "C:\\Windows\\Logs",
            "/s",
            "/m",
            "*.log",
            "/d",
            "-7",
            "/c",
            "cmd /c del @path"
        ],
    }];
    execute_commands(&delete_log_files_command, error_messages);
}

fn optimize_system(error_messages: &mut Vec<String>) {
    trace!("Optimizing system.");
    let clear_recycle_bin_command = "Clear-RecycleBin -Confirm:$false -Force";

    let optimization_commands = vec![
        SystemCommand {
            program: "powershell",
            args: vec!["-command", "Optimize-Volume -DriveLetter C -Defrag -ReTrim"],
        },
        SystemCommand { program: "bcdedit", args: vec!["/set", "bootux", "disabled"] },
        SystemCommand {
            program: "powershell",
            args: vec!["-command", clear_recycle_bin_command],
        }
    ];
    execute_commands(&optimization_commands, error_messages);
}

fn fix_components(error_messages: &mut Vec<String>) {
    trace!("Checking for system file componentstore corruption");
    let sfc_commands = vec![
        SystemCommand {
            program: "dism",
            args: vec!["/online", "/cleanup-image", "/startcomponentcleanup"],
        },
        SystemCommand {
            program: "dism",
            args: vec!["/online", "/cleanup-image", "/startcomponentcleanup", "/resetbase"],
        },
        SystemCommand {
            program: "dism",
            args: vec!["/online", "/cleanup-image", "/restorehealth"],
        },
        SystemCommand { program: "sfc", args: vec!["/scannow"] },
        SystemCommand {
            program: "dism",
            args: vec!["/online", "/cleanup-image", "/spsuperseded"],
        }
    ];

    execute_commands(&sfc_commands, error_messages);
}
fn update_drivers(error_messages: &mut Vec<String>) {
    trace!("Checking for signed driver updates");
    let driver_update_command = vec![SystemCommand {
        program: "powershell",
        args: vec![
            "-command",
            "Get-WmiObject Win32_PnPSignedDriver | foreach { $infPath = Get-ChildItem -Path C:\\Windows\\INF -Filter $_.InfName -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName; if ($infPath) { Invoke-Expression ('pnputil /add-driver ' + $infPath + ' /install') } }"
        ],
    }];
    execute_commands(&driver_update_command, error_messages);
}
fn enable_full_memory_dumps(error_messages: &mut Vec<String>) {
    trace!("Enabling full memory dumps.");

    let enable_dump_command =
        r"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' -Name 'CrashDumpEnabled' -Value 1";
    let set_dump_file_command =
        r"Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' -Name 'DumpFile' -Value 'C:\\Windows\\MEMORY.DMP'";

    let registry_commands = vec![
        SystemCommand { program: "powershell", args: vec!["-command", enable_dump_command] },
        SystemCommand { program: "powershell", args: vec!["-command", set_dump_file_command] }
    ];

    execute_commands(&registry_commands, error_messages);
}


fn harden_system(error_messages: &mut Vec<String>) {
let harden_commands = vec![
    SystemCommand {
        program: "netsh",
        args: vec!["advfirewall", "set", "allprofiles", "state", "on"],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\RemoteRegistry",
            "/v",
            "Start",
            "/t",
            "REG_DWORD",
            "/d",
            "4",
            "/f",
        ],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            "/v",
            "SMB2",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ],
    },
    /*
    SystemCommand {
        program: "powershell",
        args: vec![
            "-command",
            "Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI",
        ],
    },
    */
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
            "/v",
            "UseLogonCredential",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation",
            "/v",
            "SecureFirmwareUpdate",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            "/v",
            "RestrictAnonymous",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f"
        ],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization",
            "/v",
            "DODownloadMode",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f"
        ],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Device Guard",
            "/v",
            "EnableVirtualizationBasedSecurity",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\\",
            "/v",
            "Enabled",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f"
        ],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config",
            "/v",
            "AnnounceFlags",
            "/t",
            "REG_DWORD",
            "/d",
            "5",
            "/f",
        ],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
            "/v",
            "NtlmMinClientSec",
            "/t",
            "REG_DWORD",
            "/d",
            "537395200",
            "/f",
        ],
    },
    
    SystemCommand {
    program: "reg",
    args: vec![
        "add",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
        "/v",
        "ClearPageFileAtShutdown",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
        ],
    },
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            r"HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg",
            "/f",
            "/t", "REG_SZ", // Change to REG_SZ for string data
            "/v", "AllowedPaths",
            "/d", r"System\CurrentControlSet\Control" // Ensure this is correctly escaped in context or use raw strings
        ],
    },
    /*
    SystemCommand {
        program: "reg",
        args: vec![
            "add",
            r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
            "/v", "Start",  // Specifies the name of the registry entry to add/modify
            "/t", "REG_DWORD",  // Specifies the type of the registry entry
            "/d", "4",  // Disables USB storage devices
            "/f"  // Forces overwriting the existing registry entry without prompt
        ],
    },
    */

    
    SystemCommand {
        program: "wevtutil",
        args: vec!["sl", "Security", "/ca:O:BAG:SYD:(A;;0x7;;;BA)(A;;0x7;;;SO)"],
    }
    
    ];
    execute_commands(&harden_commands, error_messages);
}

fn setup_logging() -> Result<(), fern::InitError> {
    fern::Dispatch
        ::new()
        // Format the logs
        .format(|out, message, record| {
            out.finish(
                format_args!(
                    "{}[{}][{}] {}",
                    chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                    record.target(),
                    record.level(),
                    message
                )
            )
        })
        // Add stdout logger
        .chain(std::io::stdout())
        // Add file logger
        .chain(OpenOptions::new().write(true).create(true).append(true).open("output.log")?)
        // Apply the configuration
        .apply()?;

    Ok(())
}


fn is_thread_suspended(thread_handle: HANDLE) -> bool {
    let mut suspend_count: c_ulong = 0;

    let status = unsafe {
        NtQueryInformationThread(
            thread_handle,
            THREADINFOCLASS(THREAD_SUSPEND_COUNT.try_into().unwrap()),
            &mut suspend_count as *mut c_ulong as *mut _,
            std::mem::size_of_val(&suspend_count) as u32,
            ptr::null_mut(),
        )
    };

    status == NTSTATUS(0) && suspend_count > 0
}
fn main() -> Result<(), String> {
    if let Err(e) = setup_logging() {
        eprintln!("Error setting up logging: {}", e);
        let _ = Ok::<bool, ()>(false);
    }
    execute!(std::io::stdout(), SetForegroundColor(Color::Magenta)).unwrap();
    let system_root = env::var("SYSTEMROOT").expect("Failed to get system root");
    let temp = env::var("TEMP").expect("Failed to get temp directory");
    let mut error_messages: Vec<String> = Vec::new();
    let handle = thread::spawn( move || {
    // Execute initial series of commands
    fix_components(&mut error_messages);
    cleanup_prefetch_files(&system_root, &mut error_messages);
    cleanup_windows_update_cache(&system_root, &mut error_messages);
    perform_disk_cleanup(&mut error_messages);
    remove_temporary_files(&temp, &system_root, &mut error_messages);
    cleanup_font_cache(&system_root, &mut error_messages);
    delete_old_log_files(&mut error_messages);
    optimize_system(&mut error_messages);
    update_drivers(&mut error_messages);
    enable_full_memory_dumps(&mut error_messages);
    harden_system(&mut error_messages);

    // Handle errors
    let _ = execute!(std::io::stdout(), ResetColor);
    if !error_messages.is_empty() {
        for error_message in error_messages {
            error!("Error: {}", error_message);
        }
        return Err("Some tasks failed".to_string());
    }
    Ok(())
});

let current_thread = unsafe { GetCurrentThread() };
    if is_thread_suspended(current_thread) {
        unsafe {
            ResumeThread(current_thread);
        }
    }
    let _ = handle.join().unwrap();
    Ok(())
}
