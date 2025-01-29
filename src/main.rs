use std::fs;
use std::io::{self, Write};
use std::process;

#[cfg(target_family = "unix")]
use libc::{kill, SIGTERM, SIGKILL};

#[cfg(target_family = "windows")]
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
#[cfg(target_family = "windows")]
use windows::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(target_family = "windows")]
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};

fn main() -> io::Result<()> {
    display_processes();

    println!("\nDo you want to terminate a process or all processes? (Enter PID or type 'ALL'): ");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice = input.trim();

    if choice.eq_ignore_ascii_case("ALL") {
        terminate_all_processes();
    } else if let Ok(pid) = choice.parse::<i32>() {
        terminate_process(pid);
    } else {
        println!("Invalid input!");
    }

    Ok(())
}

fn display_processes() {
    #[cfg(target_family = "unix")]
    display_processes_unix();

    #[cfg(target_family = "windows")]
    display_processes_windows();
}

#[cfg(target_family = "unix")]
fn display_processes_unix() {
    println!("{:<10} {:<25} {:<15}", "PID", "Process Name", "Memory (KB)");
    println!("========================================================");

    if let Ok(paths) = fs::read_dir("/proc") {
        for path in paths {
            if let Ok(entry) = path {
                let pid_path = entry.path();
                if let Some(pid_str) = pid_path.file_name().and_then(|f| f.to_str()) {
                    if pid_str.chars().all(char::is_numeric) {
                        let pid = pid_str;

                        let process_name = fs::read_to_string(format!("/proc/{}/comm", pid))
                            .unwrap_or_else(|_| "Unknown".to_string())
                            .trim()
                            .to_string();

                        let memory_info = fs::read_to_string(format!("/proc/{}/statm", pid))
                            .unwrap_or_else(|_| "0".to_string());

                        let memory_kb: u64 = memory_info.split_whitespace()
                            .next()
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0) * 4;

                        println!("{:<10} {:<25} {:<15}", pid, process_name, memory_kb);
                    }
                }
            }
        }
    }
}

#[cfg(target_family = "windows")]
fn display_processes_windows() {
    println!("{:<10} {:<25}", "PID", "Process Name");
    println!("===========================================");

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_err() {
            eprintln!("Failed to create process snapshot.");
            return;
        }
        let snapshot = snapshot.unwrap();

        let mut entry = PROCESSENTRY32::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        // Check if Process32First succeeded
        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let process_name = String::from_utf16_lossy(
                    &entry.szExeFile.iter().take_while(|&&c| c != 0).map(|&c| c as u16).collect::<Vec<_>>(),
                );
                println!("{:<10} {:<25}", entry.th32ProcessID, process_name);

                // Check if Process32Next succeeded
                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        } else {
            eprintln!("Failed to read first process.");
        }

        CloseHandle(snapshot);
    }
}

#[cfg(target_family = "unix")]
fn terminate_process(pid: i32) {
    if pid > 1 { // Avoid killing init/system processes
        unsafe {
            if kill(pid, SIGTERM) == 0 {
                println!("Process {} terminated successfully.", pid);
            } else {
                eprintln!("Failed to terminate process {}. Trying force kill...", pid);
                if kill(pid, SIGKILL) == 0 {
                    println!("Process {} forcefully terminated.", pid);
                } else {
                    eprintln!("Failed to forcefully terminate process {}.", pid);
                }
            }
        }
    } else {
        println!("Skipping system-critical process with PID {}", pid);
    }
}

#[cfg(target_family = "unix")]
fn terminate_all_processes() {
    if let Ok(paths) = fs::read_dir("/proc") {
        for path in paths {
            if let Ok(entry) = path {
                let pid_path = entry.path();
                if let Some(pid_str) = pid_path.file_name().and_then(|f| f.to_str()) {
                    if let Ok(pid) = pid_str.parse::<i32>() {
                        terminate_process(pid);
                    }
                }
            }
        }
    }
}

#[cfg(target_family = "windows")]
fn terminate_process(pid: i32) {
    unsafe {
        let handle: Result<HANDLE, _> = OpenProcess(PROCESS_TERMINATE, false, pid as u32);
        match handle {
            Ok(handle) => {
                if TerminateProcess(handle, 0).is_ok() {
                    println!("Process {} terminated successfully.", pid);
                } else {
                    eprintln!("Failed to terminate process {}.", pid);
                }
                CloseHandle(handle).expect("Failed to close handle");
            }
            Err(_) => {
                eprintln!("Unable to open process {}.", pid);
            }
        }
    }
}

#[cfg(target_family = "windows")]
fn terminate_all_processes() {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if let Ok(snapshot) = snapshot {
            let mut entry = PROCESSENTRY32::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

            if Process32First(snapshot, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID as i32;
                    if pid > 4 { // Avoid terminating system processes
                        terminate_process(pid);
                    }
                    if Process32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            CloseHandle(snapshot).expect("Failed to close snapshot handle");
        } else {
            eprintln!("Failed to create process snapshot.");
        }
    }
}
