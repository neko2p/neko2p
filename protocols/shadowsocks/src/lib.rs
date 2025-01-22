use bytes::{Buf, BufMut};
use common::{Addr, Network, ProxyConnection, ProxyServer};
use std::{
    io::Cursor,
    io::{Error, ErrorKind, Result as IOResult},
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    task::{ready, Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream, ToSocketAddrs},
};

use aes_gcm::{aead::Aead, Aes128Gcm, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;

const MAX_KEY_SIZE: usize = AES256_KEY_SZIE;
const MAX_SALT_SIZE: usize = AES256GCM_SALT_SIZE;

const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

const AES128_KEY_SZIE: usize = 16;
const AES128GCM_SALT_SIZE: usize = 16;

const AES256_KEY_SZIE: usize = 32;
const AES256GCM_SALT_SIZE: usize = 32;

const CHACHA20POLY1305_SALT_SIZE: usize = 32;

/* shadowsocks 2022 edition constants */
const FIXED_HEADER_SIZE: usize = 11;
const TYPE_REQUEST: u8 = 0;
const RESPONSE_128_SIZE: usize = 27;
const RESPONSE_256_SIZE: usize = 43;
const TIME_CHECK_DURATION: u64 = 30;

#[derive(Default, PartialEq, Clone, Copy)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20poly1305,
    #[default]
    Plain,
    Blake3AES256GCM,
    Blake3AES128GCM,
}

impl FromStr for Method {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "aes-128-gcm" => Ok(Method::Aes128Gcm),
            "aes-256-gcm" => Ok(Method::Aes256Gcm),
            "chacha20-poly1305" => Ok(Method::Chacha20poly1305),
            "2022-blake3-aes-128-gcm" => Ok(Method::Blake3AES128GCM),
            "2022-blake3-aes-256-gcm" => Ok(Method::Blake3AES256GCM),
            "plain" | "none" => Ok(Method::Plain),
            _ => Err(format!("Unsupported cipher {}.", s)),
        }
    }
}

impl Method {
    fn password_to_key(&self, password: &str, key: &mut [u8; MAX_KEY_SIZE]) {
        use base64::engine::{general_purpose::STANDARD, Engine};

        match self {
            Method::Aes128Gcm => {
                openssl_bytes_to_key(password.as_bytes(), &mut key[..AES128_KEY_SZIE])
            }
            Method::Aes256Gcm | Method::Chacha20poly1305 => {
                openssl_bytes_to_key(password.as_bytes(), key)
            }
            Method::Plain => {}
            Method::Blake3AES128GCM => {
                key[..AES128_KEY_SZIE].copy_from_slice(&STANDARD.decode(password).unwrap())
            }
            Method::Blake3AES256GCM => key.copy_from_slice(&STANDARD.decode(password).unwrap()),
        }
    }
}

fn aes128gcm_decrypt(nonce: u64, key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let subkey: [u8; AES128_KEY_SZIE] = key[..AES128_KEY_SZIE].try_into().unwrap();
    Aes128Gcm::new(&subkey.into())
        .decrypt(&make_nonce(nonce).into(), ciphertext)
        .unwrap()
}

fn aes256gcm_decrypt(nonce: u64, key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    Aes256Gcm::new(key.into())
        .decrypt(&make_nonce(nonce).into(), ciphertext)
        .unwrap()
}

fn chacha20poly1305_decrypt(nonce: u64, key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(&make_nonce(nonce).into(), ciphertext)
        .unwrap()
}

/** A u64 nonce to [u8; 12] array */
fn make_nonce(nonce_num: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0; NONCE_SIZE];
    nonce[..8].copy_from_slice(&nonce_num.to_le_bytes());
    nonce
}

fn kdf128(salt: &[u8], key: &[u8]) -> [u8; AES128_KEY_SZIE] {
    let mut subkey = [0; AES128_KEY_SZIE];
    let hk =
        hkdf::Hkdf::<sha1::Sha1>::new(Some(&salt[..AES128GCM_SALT_SIZE]), &key[..AES128_KEY_SZIE]);
    hk.expand(b"ss-subkey", &mut subkey).unwrap();
    subkey
}

fn kdf256(salt: &[u8], key: &[u8]) -> [u8; AES256_KEY_SZIE] {
    let mut subkey = [0; AES256_KEY_SZIE];
    let hk = hkdf::Hkdf::<sha1::Sha1>::new(Some(salt), &key[..AES256_KEY_SZIE]);
    hk.expand(b"ss-subkey", &mut subkey).unwrap();
    subkey
}

fn blake3_derive_key(key: &[u8], salt: &[u8]) -> [u8; MAX_KEY_SIZE] {
    let mut key_material = Vec::new();
    key_material.extend(key);
    key_material.extend(salt);
    blake3::derive_key("shadowsocks 2022 session subkey", &key_material)
}

fn get_sys_time() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/**
 * Key derivation of OpenSSL's [EVP_BytesToKey](https://wiki.openssl.org/index.php/Manual:EVP_BytesToKey(3))
 */
fn openssl_bytes_to_key(password: &[u8], key: &mut [u8]) {
    use md5::{Digest, Md5};

    let key_len = key.len();

    let mut last_digest = None;

    let mut offset = 0;
    while offset < key_len {
        let mut m = Md5::new();
        if let Some(digest) = last_digest {
            m.update(digest);
        }

        m.update(password);

        let digest = m.finalize();

        let amt = std::cmp::min(key_len - offset, digest.len());
        key[offset..offset + amt].copy_from_slice(&digest[..amt]);

        offset += amt;
        last_digest = Some(digest);
    }
}

#[derive(Default)]
struct RequestHeader {
    payload: Vec<u8>,
    addr: Vec<u8>,
}

impl RequestHeader {
    fn build(&self) -> (Vec<u8>, Vec<u8>) {
        let mut header = Vec::new();
        header.put_u8(TYPE_REQUEST);
        header.put_u64(get_sys_time());

        let mut var_header = Vec::new();
        var_header.put_slice(&self.addr);
        var_header.put_u16(0);
        var_header.put_slice(&self.payload);
        header.put_u16(var_header.len() as u16);

        (header, var_header)
    }
}

struct ResponseHeader {
    timestamp: u64,
    salt: [u8; MAX_SALT_SIZE],
    len: u16,
}

impl ResponseHeader {
    fn build128(&self) -> Vec<u8> {
        let mut pack = Vec::new();
        pack.put_u8(1);
        pack.put_u64(self.timestamp);
        pack.put_slice(&self.salt[..AES128GCM_SALT_SIZE]);
        pack.put_u16(self.len);

        pack
    }
    fn build256(&self) -> Vec<u8> {
        let mut pack = Vec::new();
        pack.put_u8(1);
        pack.put_u64(self.timestamp);
        pack.put_slice(&self.salt);
        pack.put_u16(self.len);

        pack
    }
    fn parse128(bytes: &[u8]) -> Self {
        use std::io::Read;

        let mut bytes = Cursor::new(bytes);
        bytes.set_position(1);
        let mut timestamp = [0_u8; 8];
        bytes.read_exact(&mut timestamp).unwrap();
        let mut salt = [0_u8; MAX_SALT_SIZE];
        bytes.read_exact(&mut salt[..AES128_KEY_SZIE]).unwrap();
        let mut len_buf = [0_u8; 2];
        bytes.read_exact(&mut len_buf).unwrap();
        Self {
            salt,
            timestamp: u64::from_be_bytes(timestamp),
            len: u16::from_be_bytes(len_buf),
        }
    }
    fn parse256(bytes: &[u8]) -> Self {
        use std::io::Read;

        let mut bytes = Cursor::new(bytes);
        bytes.set_position(1);
        let mut timestamp = [0_u8; 8];
        bytes.read_exact(&mut timestamp).unwrap();
        let mut salt = [0_u8; AES256_KEY_SZIE];
        bytes.read_exact(&mut salt).unwrap();
        let mut len_buf = [0_u8; 2];
        bytes.read_exact(&mut len_buf).unwrap();

        Self {
            salt,
            timestamp: u64::from_be_bytes(timestamp),
            len: u16::from_be_bytes(len_buf),
        }
    }
    /** check timestamp */
    fn check_timestamp(&self) -> IOResult<()> {
        if self.timestamp > get_sys_time() || self.timestamp < get_sys_time() - TIME_CHECK_DURATION
        {
            Err(Error::new(
                ErrorKind::PermissionDenied,
                "timestamp check failed",
            ))
        } else {
            Ok(())
        }
    }
    /** check is equal to request salt */
    fn check_salt(&self, salt: &[u8]) -> IOResult<()> {
        if salt != self.salt {
            Err(Error::new(
                ErrorKind::InvalidData,
                "request salt check failed",
            ))
        } else {
            Ok(())
        }
    }
}

pub struct ShadowsocksServer {
    method: Method,
    listener: TcpListener,
    password: String,
}

impl ShadowsocksServer {
    pub async fn bind<A>(server: A, method: Method, password: &str) -> IOResult<Self>
    where
        A: ToSocketAddrs,
    {
        let listener = TcpListener::bind(server).await?;
        Ok(Self {
            listener,
            method,
            password: password.to_owned(),
        })
    }
    async fn receive_request(
        &self,
        stream: &mut TcpStream,
        method: Method,
        key: &[u8],
    ) -> IOResult<(Addr, u16, Vec<u8>)> {
        use tokio::io::AsyncReadExt;

        /* decrypt payload length */
        let len = match method {
            Method::Aes128Gcm => {
                let mut len = [0; 2 + TAG_SIZE];
                stream.read_exact(&mut len).await?;
                u16::from_be_bytes(aes128gcm_decrypt(0, key, &len).try_into().unwrap())
            }
            Method::Aes256Gcm => {
                let mut len = [0; 2 + TAG_SIZE];
                stream.read_exact(&mut len).await?;
                u16::from_be_bytes(aes256gcm_decrypt(0, key, &len).try_into().unwrap())
            }
            Method::Chacha20poly1305 => {
                let mut len = [0; 2 + TAG_SIZE];
                stream.read_exact(&mut len).await?;
                u16::from_be_bytes(chacha20poly1305_decrypt(0, key, &len).try_into().unwrap())
            }
            Method::Blake3AES128GCM => {
                let mut fixed_header = [0; FIXED_HEADER_SIZE + TAG_SIZE];
                stream.read_exact(&mut fixed_header).await?;
                let fixed_header = aes128gcm_decrypt(0, key, &fixed_header);

                let mut buf = fixed_header.as_slice();
                buf.get_u8(); // type
                buf.get_u64(); // timestamp
                buf.get_u16()
            }
            Method::Blake3AES256GCM => {
                let mut fixed_header = [0; FIXED_HEADER_SIZE + TAG_SIZE];
                stream.read_exact(&mut fixed_header).await?;
                let fixed_header = aes256gcm_decrypt(0, key, &fixed_header);

                let mut buf = fixed_header.as_slice();
                buf.get_u8(); // type
                buf.get_u64(); // timestamp
                buf.get_u16()
            }
            _ => unimplemented!(),
        };

        let mut payload = vec![0; len as usize + TAG_SIZE];
        stream.read_exact(&mut payload).await?;

        /* decrypt payload */
        let payload = match method {
            Method::Aes128Gcm | Method::Blake3AES128GCM => aes128gcm_decrypt(1, key, &payload),
            Method::Aes256Gcm | Method::Blake3AES256GCM => aes256gcm_decrypt(1, key, &payload),
            Method::Chacha20poly1305 => chacha20poly1305_decrypt(1, key, &payload),
            _ => unimplemented!(),
        };

        let mut bytes = payload.as_slice();

        let atype = bytes.get_u8();

        let addr;
        match atype {
            ATYP_IPV4 => {
                let mut ipv4 = [0; 4];
                for i in &mut ipv4 {
                    *i = bytes.get_u8();
                }
                addr = Addr::IPv4(ipv4);
            }
            ATYP_DOMAIN => {
                let len = bytes.get_u8() as usize;
                let mut domain = String::new();
                for _ in 0..len {
                    domain.push(bytes.get_u8() as char);
                }
                addr = Addr::Domain(domain);
            }
            ATYP_IPV6 => {
                let mut ipv6 = [0; 8];
                for i in &mut ipv6 {
                    *i = bytes.get_u16();
                }
                addr = Addr::IPv6(ipv6);
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Invalid ATYP 0x{:02x}", atype),
                ))
            }
        }
        let port = bytes.get_u16();

        if method == Method::Blake3AES128GCM || method == Method::Blake3AES256GCM {
            let padding_len = bytes.get_u16() as usize;
            for _ in 0..padding_len {
                bytes.get_u8();
            }
        }

        Ok((addr, port, bytes.to_owned()))
    }
}

impl ProxyServer for ShadowsocksServer {
    async fn accept(
        &self,
    ) -> IOResult<(
        impl ProxyConnection + Send + Unpin + 'static,
        (Addr, u16),
        SocketAddr,
    )> {
        use tokio::io::AsyncReadExt;

        let (mut stream, addr) = self.listener.accept().await?;

        let mut key = [0; MAX_KEY_SIZE];
        self.method.password_to_key(&self.password, &mut key);

        let mut salt = [0; MAX_SALT_SIZE];
        let mut subkey_remote = [0; MAX_KEY_SIZE];

        let (dst_addr, dst_port, decrypted_data);
        match self.method {
            Method::Aes128Gcm => {
                stream.read_exact(&mut salt[..AES128GCM_SALT_SIZE]).await?;
                subkey_remote[..AES128_KEY_SZIE].copy_from_slice(&kdf128(&salt, &key));
                (dst_addr, dst_port, decrypted_data) = self
                    .receive_request(&mut stream, self.method, &subkey_remote[..AES128_KEY_SZIE])
                    .await?;
            }
            Method::Aes256Gcm | Method::Chacha20poly1305 => {
                stream.read_exact(&mut salt).await?;
                subkey_remote = kdf256(&salt, &key);
                (dst_addr, dst_port, decrypted_data) = self
                    .receive_request(&mut stream, self.method, &subkey_remote)
                    .await?;
            }
            Method::Blake3AES128GCM => {
                stream.read_exact(&mut salt[..AES128GCM_SALT_SIZE]).await?;
                subkey_remote =
                    blake3_derive_key(&key[..AES128_KEY_SZIE], &salt[..AES128GCM_SALT_SIZE]);
                (dst_addr, dst_port, decrypted_data) = self
                    .receive_request(&mut stream, self.method, &subkey_remote[..AES128_KEY_SZIE])
                    .await?;
            }
            Method::Blake3AES256GCM => {
                stream.read_exact(&mut salt).await?;
                subkey_remote = blake3_derive_key(&key, &salt);
                (dst_addr, dst_port, decrypted_data) = self
                    .receive_request(&mut stream, self.method, &subkey_remote)
                    .await?;
            }
            _ => unimplemented!(),
        }

        Ok((
            ShadowsocksClient {
                stream,
                dst_addr: dst_addr.clone(),
                dst_port,
                method: self.method,
                is_server: true,
                is_handshaked: false,

                salt,
                key,
                subkey: [0; MAX_KEY_SIZE],
                subkey_remote,
                nonce: 0,
                nonce_remote: 2,
                data_pending: Vec::new(),
                decrypted_data,
            },
            (dst_addr, dst_port),
            addr,
        ))
    }
}

#[derive(Default)]
pub struct ShadowsocksConnector {
    method: Method,
    password: String,
}

impl ShadowsocksConnector {
    pub fn password(mut self, password: &str) -> Self {
        self.password = password.to_owned();
        self
    }
    pub fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }
    pub async fn connect<A>(
        self,
        server: A,
        dst: Addr,
        dst_port: u16,
    ) -> IOResult<ShadowsocksClient>
    where
        A: ToSocketAddrs,
    {
        let stream = TcpStream::connect(server).await?;
        let mut key = [0; MAX_KEY_SIZE];
        self.method.password_to_key(&self.password, &mut key);

        Ok(ShadowsocksClient {
            stream,
            dst_addr: dst,
            dst_port,
            method: self.method,
            is_server: false,
            is_handshaked: false,

            salt: [0; MAX_SALT_SIZE],
            key,
            subkey: [0; MAX_SALT_SIZE],
            subkey_remote: [0; MAX_SALT_SIZE],
            nonce: 0,
            nonce_remote: 0,
            data_pending: Vec::new(),
            decrypted_data: Vec::new(),
        })
    }
}

/** # Shadowsocks client
 * Protocol details at:
 * * `AEAD`: <https://shadowsocks.org/doc/aead.html>
 * * `AEAD-2022`: <https://shadowsocks.org/doc/sip022.html>
 *
 * Supported ciphers:
 * * plain
 * * aes-128-gcm
 * * aes-256-gcm
 * * chacha20-poly1305
 * * 2022-blake3-aes-128-gcm
 * * 2022-blake3-aes-256-gcm
 */
pub struct ShadowsocksClient {
    pub dst_addr: Addr,
    pub dst_port: u16,

    method: Method,
    stream: TcpStream,
    key: [u8; MAX_KEY_SIZE],
    is_server: bool,
    is_handshaked: bool,

    salt: [u8; MAX_SALT_SIZE],
    subkey: [u8; MAX_KEY_SIZE],
    subkey_remote: [u8; MAX_KEY_SIZE],
    nonce: u64,
    nonce_remote: u64,
    data_pending: Vec<u8>,
    decrypted_data: Vec<u8>,
}

impl ShadowsocksClient {
    #[inline]
    fn max_payload_size(&self) -> usize {
        match self.method {
            Method::Aes128Gcm | Method::Aes256Gcm | Method::Chacha20poly1305 => 0x3fff,
            Method::Blake3AES128GCM | Method::Blake3AES256GCM => 0xffff,
            _ => 0,
        }
    }
    fn aes128gcm_encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let subkey: [u8; AES128_KEY_SZIE] = self.subkey[..AES128_KEY_SZIE].try_into().unwrap();
        self.nonce += 1;
        Aes128Gcm::new(&subkey.into())
            .encrypt(&make_nonce(self.nonce - 1).into(), plaintext)
            .unwrap()
    }
    fn aes256gcm_encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.nonce += 1;
        Aes256Gcm::new(&self.subkey.into())
            .encrypt(&make_nonce(self.nonce - 1).into(), plaintext)
            .unwrap()
    }
    fn chacha20poly1305_encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.nonce += 1;
        ChaCha20Poly1305::new(&self.subkey.into())
            .encrypt(&make_nonce(self.nonce - 1).into(), plaintext)
            .unwrap()
    }
    fn build_request(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut pack = Vec::new();
        let mut header_2022 = RequestHeader::default();

        if !self.is_handshaked && !self.is_server {
            match &self.dst_addr {
                Addr::IPv4(ipv4) => {
                    pack.put_u8(ATYP_IPV4);
                    pack.put_slice(ipv4);
                }
                Addr::Domain(domain) => {
                    pack.put_u8(ATYP_DOMAIN);
                    pack.put_u8(domain.len() as u8);
                    pack.put_slice(domain.as_bytes());
                }
                Addr::IPv6(ipv6) => {
                    pack.push(ATYP_IPV6);
                    for i in ipv6 {
                        pack.put_u16(*i);
                    }
                }
            }
            pack.put_u16(self.dst_port);
            if self.method == Method::Blake3AES128GCM || self.method == Method::Blake3AES256GCM {
                header_2022.addr = pack.clone();
                pack.clear();
            }
        }

        pack.extend(payload);

        match self.method {
            Method::Aes128Gcm | Method::Blake3AES128GCM => {
                let mut encrypted_pack = Vec::new();

                if !self.is_handshaked {
                    let req_salt = self.salt;
                    let salt: [u8; AES128GCM_SALT_SIZE] = rand::random();
                    self.salt[..AES128GCM_SALT_SIZE].copy_from_slice(&salt);
                    encrypted_pack.extend(&self.salt[..AES128GCM_SALT_SIZE]);
                    if self.method == Method::Blake3AES128GCM {
                        self.subkey = blake3_derive_key(
                            &self.key[..AES128_KEY_SZIE],
                            &self.salt[..AES128GCM_SALT_SIZE],
                        );

                        if !self.is_server {
                            header_2022.payload = pack.clone();
                            pack.clear();

                            let (fixed_header, var_header) = header_2022.build();

                            let encrypted_fixed_header = self.aes128gcm_encrypt(&fixed_header);
                            encrypted_pack.extend(encrypted_fixed_header);

                            let encrypted_var_header = self.aes128gcm_encrypt(&var_header);
                            encrypted_pack.extend(encrypted_var_header);
                        } else {
                            let res = ResponseHeader {
                                timestamp: get_sys_time(),
                                salt: req_salt,
                                len: pack.len() as u16,
                            };

                            let encrypted_res = self.aes128gcm_encrypt(&res.build128());
                            encrypted_pack.extend(encrypted_res);
                            encrypted_pack.extend(self.aes128gcm_encrypt(&pack));
                            pack.clear();
                        }
                    } else {
                        self.subkey[..AES128_KEY_SZIE]
                            .copy_from_slice(&kdf128(&self.salt, &self.key));
                    }
                }

                let mut chunk_payload = &pack[..std::cmp::min(pack.len(), self.max_payload_size())];
                while !chunk_payload.is_empty() {
                    let payload_len = (chunk_payload.len() as u16).to_be_bytes();
                    let payload_len = self.aes128gcm_encrypt(&payload_len);

                    let payload = self.aes128gcm_encrypt(&pack);

                    encrypted_pack.extend(payload_len);
                    encrypted_pack.extend(payload);

                    pack.drain(0..chunk_payload.len());
                    chunk_payload = &pack[..std::cmp::min(pack.len(), self.max_payload_size())];
                }

                pack = encrypted_pack
            }
            Method::Aes256Gcm | Method::Blake3AES256GCM => {
                let mut encrypted_pack = Vec::new();

                if !self.is_handshaked {
                    let req_salt = self.salt;
                    self.salt = rand::random();
                    encrypted_pack.extend(self.salt);
                    if self.method == Method::Blake3AES256GCM {
                        self.subkey = blake3_derive_key(&self.key, &self.salt);
                        if !self.is_server {
                            header_2022.payload = pack.clone();
                            pack.clear();

                            let (fixed_header, var_header) = header_2022.build();

                            let encrypted_fixed_header = self.aes256gcm_encrypt(&fixed_header);
                            encrypted_pack.extend(encrypted_fixed_header);

                            let encrypted_var_header = self.aes256gcm_encrypt(&var_header);
                            encrypted_pack.extend(encrypted_var_header);
                        } else {
                            let res = ResponseHeader {
                                timestamp: get_sys_time(),
                                salt: req_salt,
                                len: pack.len() as u16,
                            };

                            let encrypted_res = self.aes256gcm_encrypt(&res.build256());
                            encrypted_pack.extend(encrypted_res);
                            encrypted_pack.extend(self.aes256gcm_encrypt(&pack));
                            pack.clear();
                        }
                    } else {
                        self.subkey = kdf256(&self.salt, &self.key);
                    }
                }

                let mut chunk_payload = &pack[..std::cmp::min(pack.len(), self.max_payload_size())];
                while !chunk_payload.is_empty() {
                    let payload_len = (chunk_payload.len() as u16).to_be_bytes();
                    let payload_len = self.aes256gcm_encrypt(&payload_len);

                    let payload = self.aes256gcm_encrypt(chunk_payload);

                    encrypted_pack.extend(payload_len);
                    encrypted_pack.extend(payload);

                    pack.drain(0..chunk_payload.len());
                    chunk_payload = &pack[..std::cmp::min(pack.len(), self.max_payload_size())];
                }

                pack = encrypted_pack
            }
            Method::Chacha20poly1305 => {
                let mut encrypted_pack = Vec::new();

                if !self.is_handshaked {
                    let salt: [u8; CHACHA20POLY1305_SALT_SIZE] = rand::random();
                    self.subkey = kdf256(&salt, &self.key);
                    encrypted_pack.extend(salt);
                }

                let mut chunk_payload = &pack[..std::cmp::min(pack.len(), self.max_payload_size())];
                while !chunk_payload.is_empty() {
                    let payload_len = (chunk_payload.len() as u16).to_be_bytes();
                    let payload_len = self.chacha20poly1305_encrypt(&payload_len);

                    let payload = self.chacha20poly1305_encrypt(chunk_payload);

                    encrypted_pack.extend(payload_len);
                    encrypted_pack.extend(payload);

                    pack.drain(0..chunk_payload.len());
                    chunk_payload = &pack[..std::cmp::min(pack.len(), self.max_payload_size())];
                }

                pack = encrypted_pack
            }
            Method::Plain => {}
        }

        pack
    }
    pub fn parse_and_decrypt(&mut self) -> IOResult<Vec<u8>> {
        match self.method {
            Method::Aes128Gcm | Method::Blake3AES128GCM => {
                let mut data = Vec::new();

                /* calculate remote subkey */
                if self.nonce_remote == 0 && self.data_pending.len() >= AES128GCM_SALT_SIZE {
                    let salt = &self.data_pending[..AES128GCM_SALT_SIZE];
                    if self.method == Method::Blake3AES128GCM {
                        self.subkey_remote = blake3_derive_key(&self.key[..AES128_KEY_SZIE], salt);
                    } else {
                        self.subkey_remote[..AES128_KEY_SZIE]
                            .copy_from_slice(&kdf128(salt, &self.key));
                    }
                    self.data_pending.drain(0..AES128GCM_SALT_SIZE);
                }

                loop {
                    let len;
                    /* 2022 edition: decrypt response header */
                    if self.nonce_remote == 0 && self.method == Method::Blake3AES128GCM {
                        if self.data_pending.len() < RESPONSE_128_SIZE + TAG_SIZE {
                            break;
                        }
                        let res_header = ResponseHeader::parse128(&aes128gcm_decrypt(
                            self.nonce_remote,
                            &self.subkey_remote,
                            &self.data_pending[..RESPONSE_128_SIZE + TAG_SIZE],
                        ));

                        res_header.check_timestamp()?;
                        res_header.check_salt(&self.salt)?;

                        len = res_header.len as usize;
                        self.data_pending.drain(..RESPONSE_128_SIZE - 2);
                    } else {
                        /* decrypt length */
                        if self.data_pending.len() < 2 + TAG_SIZE {
                            break;
                        }
                        let len_buf = aes128gcm_decrypt(
                            self.nonce_remote,
                            &self.subkey_remote,
                            &self.data_pending[..2 + TAG_SIZE],
                        );
                        len = u16::from_be_bytes(len_buf.try_into().unwrap()) as usize;
                    }

                    /* decrypt encrypted payload */
                    if self.data_pending.len() < 2 + TAG_SIZE + len + TAG_SIZE {
                        break;
                    }
                    self.nonce_remote += 1;
                    let encrypted_payload =
                        &self.data_pending[2 + TAG_SIZE..2 + TAG_SIZE + len + TAG_SIZE];
                    let chunk_data = aes128gcm_decrypt(
                        self.nonce_remote,
                        &self.subkey_remote,
                        encrypted_payload,
                    );
                    data.extend(chunk_data);
                    self.nonce_remote += 1;

                    self.data_pending.drain(0..2 + TAG_SIZE + len + TAG_SIZE);
                }

                Ok(data)
            }
            Method::Aes256Gcm | Method::Blake3AES256GCM => {
                let mut data = Vec::new();

                /* calculate remote subkey */
                if self.nonce_remote == 0 && self.data_pending.len() >= AES256GCM_SALT_SIZE {
                    let salt = &self.data_pending[..AES256GCM_SALT_SIZE];
                    if self.method == Method::Blake3AES256GCM {
                        self.subkey_remote = blake3_derive_key(&self.key, salt);
                    } else {
                        self.subkey_remote = kdf256(salt, &self.key);
                    }
                    self.data_pending.drain(0..AES256GCM_SALT_SIZE);
                }

                loop {
                    let len;
                    /* 2022 edition: decrypt response header */
                    if self.nonce_remote == 0 && self.method == Method::Blake3AES256GCM {
                        if self.data_pending.len() < RESPONSE_256_SIZE + TAG_SIZE {
                            break;
                        }
                        let res_header = ResponseHeader::parse256(&aes256gcm_decrypt(
                            self.nonce_remote,
                            &self.subkey_remote,
                            &self.data_pending[..RESPONSE_256_SIZE + TAG_SIZE],
                        ));

                        res_header.check_timestamp()?;
                        res_header.check_salt(&self.salt)?;

                        len = res_header.len as usize;
                        self.data_pending.drain(..RESPONSE_256_SIZE - 2);
                    } else {
                        /* decrypt length */
                        if self.data_pending.len() < 2 + TAG_SIZE {
                            break;
                        }
                        let len_buf = aes256gcm_decrypt(
                            self.nonce_remote,
                            &self.subkey_remote,
                            &self.data_pending[..2 + TAG_SIZE],
                        );
                        len = u16::from_be_bytes(len_buf.try_into().unwrap()) as usize;
                    }

                    /* decrypt encrypted payload */
                    if self.data_pending.len() < 2 + TAG_SIZE + len + TAG_SIZE {
                        break;
                    }
                    self.nonce_remote += 1;
                    let encrypted_payload =
                        &self.data_pending[2 + TAG_SIZE..2 + TAG_SIZE + len + TAG_SIZE];
                    let chunk_data = aes256gcm_decrypt(
                        self.nonce_remote,
                        &self.subkey_remote,
                        encrypted_payload,
                    );
                    data.extend(chunk_data);
                    self.nonce_remote += 1;

                    self.data_pending.drain(0..2 + TAG_SIZE + len + TAG_SIZE);
                }

                Ok(data)
            }
            Method::Chacha20poly1305 => {
                let mut data = Vec::new();

                if self.nonce_remote == 0 && self.data_pending.len() >= CHACHA20POLY1305_SALT_SIZE {
                    let salt = &self.data_pending[..CHACHA20POLY1305_SALT_SIZE];
                    self.subkey_remote = kdf256(salt, &self.key);
                    self.data_pending.drain(0..CHACHA20POLY1305_SALT_SIZE);
                }

                loop {
                    /* decrypt length */
                    if self.data_pending.len() < 2 + TAG_SIZE {
                        break;
                    }
                    let len = chacha20poly1305_decrypt(
                        self.nonce_remote,
                        &self.subkey_remote,
                        &self.data_pending[..2 + TAG_SIZE],
                    );
                    let len = u16::from_be_bytes(len.try_into().unwrap()) as usize;

                    /* decrypt encrypted payload */
                    if self.data_pending.len() < 2 + TAG_SIZE + len + TAG_SIZE {
                        break;
                    }
                    self.nonce_remote += 1;
                    let encrypted_payload =
                        &self.data_pending[2 + TAG_SIZE..2 + TAG_SIZE + len + TAG_SIZE];
                    let chunk_data = chacha20poly1305_decrypt(
                        self.nonce_remote,
                        &self.subkey_remote,
                        encrypted_payload,
                    );
                    data.extend(chunk_data);
                    self.nonce_remote += 1;

                    self.data_pending.drain(0..2 + TAG_SIZE + len + TAG_SIZE);
                }

                Ok(data)
            }
            Method::Plain => {
                let data = self.data_pending.clone();
                self.data_pending.clear();
                Ok(data)
            }
        }
    }
}

impl ProxyConnection for ShadowsocksClient {
    fn poll_receive(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IOResult<(usize, Network)>> {
        if !self.decrypted_data.is_empty() {
            let written_len = std::cmp::min(buf.len(), self.decrypted_data.len());
            buf[..written_len].copy_from_slice(&self.decrypted_data[..written_len]);
            self.decrypted_data.drain(0..written_len);
            return Poll::Ready(Ok((written_len, Network::Tcp)));
        }
        let mut read_buf = ReadBuf::new(buf);

        ready!(Pin::new(&mut self.stream).poll_read(cx, &mut read_buf))?;

        let read_buf = read_buf.filled();

        self.data_pending.extend(read_buf);
        let decrypted_data = self.parse_and_decrypt()?;
        self.decrypted_data.extend(decrypted_data);

        let written_len = std::cmp::min(buf.len(), self.decrypted_data.len());
        buf[..written_len].copy_from_slice(&self.decrypted_data[..written_len]);
        self.decrypted_data.drain(0..written_len);
        Poll::Ready(Ok((written_len, Network::Tcp)))
    }
    fn poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        _network: Network,
    ) -> Poll<IOResult<usize>> {
        let pack = self.build_request(buf);
        self.is_handshaked = true;
        Pin::new(&mut self.stream).poll_write(cx, &pack)
    }
}
