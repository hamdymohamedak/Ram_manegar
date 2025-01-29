use std::fs;
use std::io;

fn main() -> io::Result<()> {
    println!("{:<10} {:<20} {:<15} {:<10}", "PID", "Process Name", "Memory (KB)", "Status");
    println!("==============================================================");

    let paths = fs::read_dir("/proc")?;
    
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
                        .unwrap_or(0) * 4; // تحويل من صفحات إلى KB

                    let status_info = fs::read_to_string(format!("/proc/{}/status", pid))
                        .unwrap_or_else(|_| "Unknown".to_string());

                    let status_line = status_info.lines()
                        .find(|line| line.starts_with("State:"))
                        .unwrap_or("State: Unknown");

                    println!("{:<10} {:<20} {:<15} {:<10}", pid, process_name, memory_kb, status_line);
                }
            }
        }
    }

    Ok(())
}
