use winapi::um::{
    // 导入OpenProcess函数
    processthreadsapi::OpenProcess,
    // 导入GetLastError函数（用于错误码获取）
    errhandlingapi::GetLastError,
    // 导入winnt模块，获取HANDLE类型
    winnt::HANDLE,
};

// 手动定义Windows进程权限常量（加pub，让外部模块访问）
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_CREATE_THREAD: u32 = 0x0002;

// 显式定义 INVALID_HANDLE_VALUE 常量（加pub，让外部模块访问）
pub const INVALID_HANDLE_VALUE: HANDLE = -1i64 as HANDLE;

/// 封装：打开目标进程并获取句柄（加pub，外部模块调用）
pub fn open_target_process(pid: u32) -> Option<HANDLE> {
    // 组合注入必需的完整权限
    let process_rights = PROCESS_QUERY_INFORMATION
        | PROCESS_VM_READ
        | PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE
        | PROCESS_CREATE_THREAD;

    // 调用OpenProcess获取进程句柄
    let h_process = unsafe {
        OpenProcess(
            process_rights,
            0, // 不继承句柄
            pid,
        )
    };

    // 验证句柄有效性
    if h_process == std::ptr::null_mut() || h_process == INVALID_HANDLE_VALUE {
        eprintln!("打开目标进程失败，错误码：{}", unsafe { winapi::um::errhandlingapi::GetLastError() });
        None
    } else {
        println!("成功打开目标进程，句柄：{:p}", h_process);
        Some(h_process)
    }
}