# neko2p

A universal proxy tool written in Rust, with various built-in supported proxy protocols.

## Protocol supports

|Protocol   |Inbound|Outbound|TCP    |UDP    |Implementation|
|-----------|-------|--------|-------|-------|--------------|
|direct     |N/A    |&check; |&check;|       |built-in      |
|hysteria2  |       |&check; |&check;|       |built-in (with [quinn](https://github.com/quinn-rs/quinn))|
|reject     |N/A    |&check; |&check;|&check;|built-in      |
|shadowsocks|&check;|&check; |&check;|       |built-in      |
|socks5     |&check;|&check; |&check;|       |built-in      |
|trojan     |&check;|&check; |&check;|&check;|built-in (with [tokio-rustls](https://github.com/rustls/tokio-rustls))|
|vless      |&check;|&check; |&check;|       |built-in      |

## Supported rule patterns

* IP CIDR
* Domain
* Domain suffix

## Build

```shell
cargo build --release
```
