use std::{
    io::{Error, ErrorKind, Result as IOResult},
    net::Ipv6Addr,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn get_sys_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn to_sock_addr(host: &str, port: u16) -> String {
    /* is ipv6 address */
    if Ipv6Addr::from_str(host).is_ok() {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/**
 * Similar to `bytes::Buf`, but returns `UnexpectedEof` when meeting unenough buffer rather than panic.
 */
pub trait Buf {
    fn get_u8(&mut self) -> IOResult<u8>;
    fn get_u16(&mut self) -> IOResult<u16>;
    fn get_u32(&mut self) -> IOResult<u32>;
    fn get_u64(&mut self) -> IOResult<u64>;
}

macro_rules! impl_get {
    ($self:tt, $t:tt) => {{
        let size = std::mem::size_of::<$t>();
        if $self.len() < size {
            Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!(
                    "Expect {} bytes, but only {} bytes available",
                    size,
                    $self.len()
                ),
            ))
        } else {
            let num = $t::from_be_bytes($self[..size].try_into().unwrap());
            *$self = &$self[size..];
            Ok(num)
        }
    }};
}

impl Buf for &[u8] {
    fn get_u8(&mut self) -> IOResult<u8> {
        impl_get!(self, u8)
    }
    fn get_u16(&mut self) -> IOResult<u16> {
        impl_get!(self, u16)
    }
    fn get_u32(&mut self) -> IOResult<u32> {
        impl_get!(self, u32)
    }
    fn get_u64(&mut self) -> IOResult<u64> {
        impl_get!(self, u64)
    }
}
