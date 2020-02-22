mod control;
pub mod data;

pub use self::data::{connect, INTERRUPTED};

pub fn serve(port: u16, secret: &str, reserved_ids: Option<crate::utils::IdRange>) {
    if cfg!(not(target_os = "linux")) {
        panic!("Server mode is only available in Linux!");
    }
    crossbeam::scope(|scope| {
        scope.spawn(|| data::serve(port, secret, reserved_ids));
        scope.spawn(|| control::serve(port, secret));
    });
}
