use crate::{Network, ProxyConnection};
use std::{
    future::Future,
    io::Result as IOResult,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll},
};
use tokio::io::ReadBuf;

pub struct ReadHalf<T> {
    pub inner: Arc<Mutex<T>>,
}

impl<T> ReadHalf<T>
where
    T: ProxyConnection,
{
    pub fn receive<'a>(&self, buf: &'a mut [u8]) -> Read<'a, T> {
        Read {
            inner: Arc::clone(&self.inner),
            buf,
        }
    }
}

pub struct Read<'a, T> {
    inner: Arc<Mutex<T>>,
    buf: &'a mut [u8],
}

impl<T> Future for Read<'_, T>
where
    T: ProxyConnection,
{
    type Output = IOResult<(usize, Network)>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let poll_result;
        let mut buf1 = vec![0; self.buf.len()];
        let mut buf = ReadBuf::new(buf1.as_mut_slice());
        {
            let mut stream_m = self.inner.lock().unwrap();
            let stream = Pin::new(stream_m.deref_mut());

            poll_result = ready!(stream.poll_receive(cx, &mut buf))?;
        }
        let size = buf.filled().len();
        self.buf[..size].copy_from_slice(buf.filled());
        Poll::Ready(Ok((buf.filled().len(), poll_result)))
    }
}

pub struct WriteHalf<T> {
    pub inner: Arc<Mutex<T>>,
}

impl<T> WriteHalf<T> {
    pub fn send<'a>(&self, buf: &'a [u8], network: Network) -> Write<'a, T> {
        Write {
            inner: Arc::clone(&self.inner),
            buf,
            network,
        }
    }
}

pub struct Write<'a, T> {
    inner: Arc<Mutex<T>>,
    buf: &'a [u8],
    network: Network,
}

impl<T> Future for Write<'_, T>
where
    T: ProxyConnection,
{
    type Output = IOResult<usize>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut stream_m = self.inner.lock().unwrap();
        let stream = Pin::new(stream_m.deref_mut());
        stream.poll_send(cx, self.buf, self.network.clone())
    }
}
