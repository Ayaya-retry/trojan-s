use chrono::{Local};

pub fn out(msg: &str) {
    let str_time = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let str_log = format!("[{}] {}", str_time, msg);
    println!("{}", str_log);
}