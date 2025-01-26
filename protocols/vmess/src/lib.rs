use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt},
    Aes128,
};
use aes_gcm::{
    aead::{AeadMut, AeadMutInPlace},
    Aes128Gcm,
};
use bytes::BufMut;
use common::{utils::get_sys_time, Addr, Network, ProxyConnection, BUF_SIZE};
use fnv_rs::FnvHasher;
use sha2::{Digest, Sha256};
use std::{
    io::Result as IOResult,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpStream, ToSocketAddrs},
};
use uuid::Uuid;

const AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
const VMESS_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const VMESS_HEADER_LEN_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
const VMESS_HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
const VMESS_HEADER_NONCE: &[u8] = b"VMess Header AEAD Nonce";

const VER: u8 = 1;
const AES128GCM: u8 = 0x03;
const OPT_S: u8 = 0x01;
const CMD_TCP: u8 = 0x01;
const ATYPE_IPV4: u8 = 0x01;
const ATYPE_DOMAIN: u8 = 0x02;
const ATYPE_IPV6: u8 = 0x03;

const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 16;
const IV_SIZE: usize = 16;

trait Hash {
    fn digest(&self, message: &[u8]) -> [u8; 32];
}

struct Sha256Hmac {
    key: Vec<u8>,
}

impl Sha256Hmac {
    fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }
}

impl Hash for Sha256Hmac {
    fn digest(&self, message: &[u8]) -> [u8; 32] {
        let mut ipad = [0x36; 64];
        for (i, byte) in self.key.iter().enumerate() {
            ipad[i] ^= *byte;
        }

        let mut opad = [0x5c; 64];
        for (i, byte) in self.key.iter().enumerate() {
            opad[i] ^= *byte;
        }

        let mut hasher = Sha256::new();
        hasher.update(ipad);
        hasher.update(message);
        let isum = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(opad);
        hasher.update(isum);

        hasher.finalize().into()
    }
}

struct Hmac {
    key: Vec<u8>,
    hasher: Box<dyn Hash>,
}

impl Hmac {
    fn new(hasher: Box<dyn Hash>, key: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
            hasher,
        }
    }
}

impl Hash for Hmac {
    fn digest(&self, message: &[u8]) -> [u8; 32] {
        let mut ipad = [0x36; 64];
        for (i, byte) in self.key.iter().enumerate() {
            ipad[i] ^= *byte;
        }

        let mut opad = [0x5c; 64];
        for (i, byte) in self.key.iter().enumerate() {
            opad[i] ^= *byte;
        }

        let mut inner = Vec::new();
        inner.extend(ipad);
        inner.extend(message);
        let isum = self.hasher.digest(&inner);

        let mut outer = Vec::new();
        outer.extend(opad);
        outer.extend(isum);

        self.hasher.digest(&outer)
    }
}

fn cmdkey(uuid: Uuid) -> [u8; 16] {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(uuid);
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    hasher.finalize().into()
}

/** VMessAEAD's kdf function */
fn kdf(uuid: Uuid, path: &[&[u8]]) -> [u8; 32] {
    let key = cmdkey(uuid);
    let mut hasher: Box<dyn Hash> = Box::new(Sha256Hmac::new(b"VMess AEAD KDF"));
    for p in path {
        hasher = Box::new(Hmac::new(hasher, p));
    }
    hasher.digest(&key)
}

fn gen_nonce(counter: u16, iv: &[u8; IV_SIZE]) -> [u8; NONCE_SIZE] {
    let mut nonce = [0; NONCE_SIZE];
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);

    nonce
}

/**
 * VMess's 16 bytes authorization header
 */
#[derive(Debug)]
struct VMessAuthID {
    uuid: Uuid,
    timestamp: u64,
}

impl VMessAuthID {
    pub fn to_bytes(&self) -> [u8; 16] {
        use aes::cipher::KeyInit;

        let mut auth_id = [0; 16];
        auth_id[..8].copy_from_slice(&self.timestamp.to_be_bytes());
        let rand: [u8; 4] = rand::random();
        auth_id[8..12].copy_from_slice(&rand);

        let crc32_sum = crc32fast::hash(&auth_id[..12]).to_be_bytes();
        auth_id[12..].clone_from_slice(&crc32_sum);

        let key = &kdf(self.uuid, &[AUTH_ID_ENCRYPTION_KEY])[..16];
        let mut block = GenericArray::from(auth_id);
        Aes128::new(key.into()).encrypt_block(&mut block);

        block.into()
    }
}

#[derive(Debug)]
struct VMessRequest {
    key: [u8; 16],
    iv: [u8; 16],
    dst: Addr,
    dst_port: u16,
}

impl VMessRequest {
    fn build(&self) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.put_u8(VER);
        packet.put_slice(&self.iv);
        packet.put_slice(&self.key);
        packet.put_u8(rand::random());
        packet.put_u8(OPT_S); // opt = S
        packet.put_u8(AES128GCM);
        packet.put_u8(0); // reserved
        packet.put_u8(CMD_TCP);
        packet.put_u16(self.dst_port);
        match &self.dst {
            Addr::IPv4(ipv4) => {
                packet.put_u8(ATYPE_IPV4);
                packet.put_slice(ipv4);
            }
            Addr::IPv6(ipv6) => {
                for seg in ipv6 {
                    packet.put_u8(ATYPE_IPV6);
                    packet.put_u16(*seg);
                }
            }
            Addr::Domain(domain) => {
                packet.put_u8(ATYPE_DOMAIN);
                packet.put_u8(domain.len() as u8);
                packet.put_slice(domain.as_bytes());
            }
        }
        let mut fnv_hasher = fnv_rs::Fnv32::new();
        fnv_hasher.update(&packet);
        packet.put_slice(fnv_hasher.finalize().as_bytes());

        packet
    }
}

#[derive(Default)]
pub struct VMessConnector {
    uuid: Uuid,
}

impl VMessConnector {
    pub fn uuid(mut self, uuid: Uuid) -> Self {
        self.uuid = uuid;
        self
    }
    pub async fn connect<A>(self, addr: A, dst: Addr, dst_port: u16) -> IOResult<VMessClient>
    where
        A: ToSocketAddrs,
    {
        use aes_gcm::KeyInit;

        let mut stream = TcpStream::connect(addr).await?;

        let rand: [u8; 8] = rand::random();
        let key = rand::random();
        let iv = rand::random();

        let eauid = VMessAuthID {
            uuid: self.uuid,
            timestamp: get_sys_time(),
        }
        .to_bytes();
        let mut request = VMessRequest {
            key,
            iv,
            dst,
            dst_port,
        }
        .build();

        /* encrypt length */
        let enc_key = &kdf(self.uuid, &[VMESS_HEADER_LEN_KEY, &eauid, &rand])[..KEY_SIZE];
        let nonce = &kdf(self.uuid, &[VMESS_HEADER_LEN_NONCE, &eauid, &rand])[..NONCE_SIZE];
        let mut length = (request.len() as u16).to_be_bytes().to_vec();
        Aes128Gcm::new(enc_key.into())
            .encrypt_in_place(nonce.into(), &eauid, &mut length)
            .unwrap();

        /* encrypt request header */
        let enc_key = &kdf(self.uuid, &[VMESS_HEADER_KEY, &eauid, &rand])[..KEY_SIZE];
        let nonce = &kdf(self.uuid, &[VMESS_HEADER_NONCE, &eauid, &rand])[..NONCE_SIZE];
        Aes128Gcm::new(enc_key.into())
            .encrypt_in_place(nonce.into(), &eauid, &mut request)
            .unwrap();

        let mut header = Vec::new();
        header.extend(eauid);
        header.extend(length);
        header.extend(rand);
        header.extend(request);

        stream.write_all(&header).await?;

        Ok(VMessClient {
            stream,
            key,
            iv,
            key_remote: Sha256::digest(key)[..KEY_SIZE].try_into().unwrap(),
            iv_remote: Sha256::digest(iv)[..IV_SIZE].try_into().unwrap(),
            counter: 0,
            counter_remote: 0,
            received_response: false,

            data_pending: Vec::default(),
            decrypted_data: Vec::default(),
        })
    }
}

/**
 * # VLESS client
 * Protocol details at:
 * * VMessLegacy: <https://www.v2fly.org/developer/protocols/vmess.html>
 * * VMessAEAD: <https://github.com/v2fly/v2fly-github-io/issues/20>
 */
pub struct VMessClient {
    stream: TcpStream,
    key: [u8; KEY_SIZE],
    iv: [u8; IV_SIZE],
    key_remote: [u8; KEY_SIZE],
    iv_remote: [u8; IV_SIZE],
    counter: u16,
    counter_remote: u16,
    received_response: bool,

    data_pending: Vec<u8>,
    decrypted_data: Vec<u8>,
}

impl ProxyConnection for VMessClient {
    fn poll_send(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        _network: Network,
    ) -> Poll<IOResult<usize>> {
        use aes_gcm::{aead::Aead, KeyInit};

        let payload = Aes128Gcm::new(self.key.as_slice().into())
            .encrypt(gen_nonce(self.counter, &self.iv).as_slice().into(), buf)
            .unwrap();
        self.counter += 1;

        let mut pack = (payload.len() as u16).to_be_bytes().to_vec();
        pack.extend(payload);
        Pin::new(&mut self.stream).poll_write(cx, &pack)
    }
    fn poll_receive(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<IOResult<Network>> {
        use aes_gcm::KeyInit;

        let mut read_buf1 = vec![0; BUF_SIZE];
        let mut read_buf = ReadBuf::new(&mut read_buf1);

        if !self.decrypted_data.is_empty() {
            let written_len = std::cmp::min(buf.remaining(), self.decrypted_data.len());
            buf.put_slice(&self.decrypted_data[..written_len]);
            self.decrypted_data.drain(..written_len);
            return Poll::Ready(Ok(Network::Tcp));
        }

        if !self.received_response {
            /* here we expect `cmd` in response header is 0x00 that the response header length is always fixed 38 bytes */
            while self.data_pending.len() < 38 {
                read_buf.clear();
                ready!(Pin::new(&mut self.stream).poll_read(cx, &mut read_buf))?;
                self.data_pending.extend(read_buf.filled());
            }
            self.received_response = true;
            self.data_pending.drain(..38);
        }

        while self.data_pending.len() < 2 {
            read_buf.clear();
            ready!(Pin::new(&mut self.stream).poll_read(cx, &mut read_buf))?;
            self.data_pending.extend(read_buf.filled());
        }
        let len = u16::from_be_bytes(self.data_pending[..2].try_into().unwrap()) as usize;

        while self.data_pending.len() < 2 + len {
            read_buf.clear();
            ready!(Pin::new(&mut self.stream).poll_read(cx, &mut read_buf))?;
            self.data_pending.extend(read_buf.filled());
        }
        let decrypted_data = Aes128Gcm::new(&self.key_remote.into())
            .decrypt(
                gen_nonce(self.counter_remote, &self.iv_remote)
                    .as_slice()
                    .into(),
                &self.data_pending[2..2 + len],
            )
            .unwrap();
        self.counter_remote += 1;

        self.decrypted_data.extend(decrypted_data);
        self.data_pending.drain(..2 + len);

        let written_len = std::cmp::min(buf.remaining(), self.decrypted_data.len());
        buf.put_slice(&self.decrypted_data[..written_len]);
        self.decrypted_data.drain(..written_len);
        Poll::Ready(Ok(Network::Tcp))
    }
}
