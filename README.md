# neko2p

A universal proxy tool written in Rust, with various built-in supported proxy protocols.

## Protocol supports

|Protocol   |Inbound|Outbound|TCP    |UDP    |Implementation|
|-----------|:-----:|:------:|:-----:|:-----:|--------------|
|anytls     |       |&check; |&check;|N/A    |built-in (with [tokio-rustls](https://github.com/rustls/tokio-rustls))|
|direct     |N/A    |&check; |&check;|       |built-in      |
|hysteria2  |       |&check; |&check;|       |built-in (with [quinn](https://github.com/quinn-rs/quinn))|
|reject     |N/A    |&check; |&check;|&check;|built-in      |
|shadowsocks|&check;|&check; |&check;|       |built-in      |
|ssh        |       |&check; |&check;|       |[russh](https://github.com/Eugeny/russh)|
|socks5     |&check;|&check; |&check;|       |built-in      |
|trojan     |&check;|&check; |&check;|&check;|built-in (with [tokio-rustls](https://github.com/rustls/tokio-rustls))|
|tun        |&check;|N/A     |&check;|&check;|[tun](https://github.com/meh/rust-tun)|
|vless      |&check;|&check; |&check;|       |built-in      |
|vmess      |       |&check; |&check;|       |built-in      |

## Supported rule patterns

* IP CIDR
* Domain
* Domain suffix

## Build

```shell
cargo build --release
```
