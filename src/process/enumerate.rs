use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use winapi::shared::minwindef::DWORD;
use winapi::um::{
    errhandlingapi::GetLastError,
    handleapi::CloseHandle,
    tlhelp32::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    },
    winnt::HANDLE,
};
const INVALID_HANDLE_VALUE: HANDLE = -1i64 as HANDLE;


/// 枚举Windows系统中所有进程，返回进程信息列表（进程名称、PID、父进程PID）
/// 加pub：让外部模块可以调用
pub fn enum_all_processes() -> Vec<(String, u32, u32)> {
    let mut process_list = Vec::new();

    // 创建进程快照
    let snapshot_handle: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot_handle == INVALID_HANDLE_VALUE {
        eprintln!("创建进程快照失败，错误码：{}", unsafe { GetLastError() });
        return process_list;
    }

    // 初始化进程信息结构体
    let mut process_entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as DWORD,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; 260],
    };

    // 获取第一个进程信息
    let first_process_success = unsafe { Process32FirstW(snapshot_handle, &mut process_entry) };
    if first_process_success == 0 {
        eprintln!("获取第一个进程信息失败，错误码：{}", unsafe { GetLastError() });
        unsafe { CloseHandle(snapshot_handle) };
        return process_list;
    }

    // 遍历所有进程
    loop {
        // 宽字符数组转Rust字符串
        let process_name_os: OsString = unsafe {
            let end_index = process_entry.szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(260);
            OsStringExt::from_wide(&process_entry.szExeFile[0..end_index])
        };
        let process_name = process_name_os.to_string_lossy().into_owned();

        // 提取进程信息
        let process_pid = process_entry.th32ProcessID;
        let parent_pid = process_entry.th32ParentProcessID;
        process_list.push((process_name, process_pid, parent_pid));

        // 获取下一个进程
        let next_process_success = unsafe { Process32NextW(snapshot_handle, &mut process_entry) };
        if next_process_success == 0 {
            let last_error = unsafe { GetLastError() };
            if last_error != 18 {
                eprintln!("遍历进程时出错，错误码：{}", last_error);
            }
            break;
        }
    }

    // 释放快照句柄
    unsafe { CloseHandle(snapshot_handle) };
    process_list
}

/// 从进程列表中根据进程名称查找对应的PID（兼容忽略.exe后缀）
/// 加pub：让外部模块可以调用
pub fn find_process_pid(process_list: &[(String, u32, u32)], target_name: &str) -> Option<u32> {
    // 兼容两种名称：带.exe和不带.exe
    let target_names = [
        target_name.to_string(),
        format!("{}.exe", target_name),
    ];
    process_list
        .iter()
        .find(|(name, _, _)| target_names.contains(name) || name.contains(target_name))
        .map(|(_, pid, _)| *pid)
}