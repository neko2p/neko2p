use chrono::Local;

const COLOR_RED: &str = "31";
const COLOR_BLUE: &str = "34";

fn color_print(_color: &str, msg: &str) {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    print!("\x1b[{}m{}\x1b[0m", _color, msg);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    print!("{}", msg);
}

#[derive(Default)]
pub struct Log {}

impl Log {
    pub fn info(&self, info: &str) {
        let now = Local::now();
        color_print(COLOR_BLUE, "INFO");
        println!("[{}] {}", now.to_rfc3339(), info);
    }
    pub fn log_error(&self, err: std::io::Error) {
        let now = Local::now();
        color_print(COLOR_RED, "ERROR");
        println!("[{}] {}", now.to_rfc3339(), err);
    }
}
