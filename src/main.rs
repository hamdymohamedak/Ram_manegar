use std::fs;
use std::io::{self, Write};
use std::process;

#[cfg(target_family = "unix")]
use libc::{kill, SIGTERM, SIGKILL};

#[cfg(target_family = "windows")]
use windows::{
    Win32::System::Threading::{OpenProcess, TerminateProcess},
    Win32::Foundation::{CloseHandle, HANDLE},
    Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS},
};

fn main() -> io::Result<()> {
    display_processes();

    println!("\nDo you want to terminate a process? (y/n): ");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice = input.trim();

    if choice.eq_ignore_ascii_case("y") {
        println!("Enter PID of the process to terminate: ");
        input.clear();
        io::stdin().read_line(&mut input)?;
        if let Ok(pid) = input.trim().parse::<i32>() {
            terminate_process(pid);
        } else {
            println!("Invalid PID!");
        }
    }

    Ok(())
}

fn display_processes() {
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

#[cfg(target_family = "unix")]
fn terminate_process(pid: i32) {
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
}

#[cfg(target_family = "windows")]
fn terminate_process(pid: i32) {
    use windows::Win32::Foundation::HANDLE;

    unsafe {
        let handle: HANDLE = OpenProcess(0x0001, false, pid as u32);
        if !handle.is_invalid() {
            if TerminateProcess(handle, 0) != 0 {
                println!("Process {} terminated successfully.", pid);
            } else {
                eprintln!("Failed to terminate process {}.", pid);
            }
            CloseHandle(handle);
        } else {
            eprintln!("Unable to open process {}.", pid);
        }
    }
}