use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};

use crate::{stack::IfaceEvent, tcp_listener::TcpStreamHandle};

pub struct TcpStream {
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) handle: Arc<TcpStreamHandle>,
    pub(crate) stack_notifier: tokio::sync::mpsc::Sender<IfaceEvent<'static>>,
}

impl TcpStream {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn split(self) -> (ReadHalf<Self>, WriteHalf<Self>) {
        tokio::io::split(self)
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let read_buf = &self.handle.recv_buffer;

        if read_buf.is_empty() {
            self.handle.recv_waker.register(cx.waker());
            return Poll::Pending;
        }

        let unfilled_slice = buf.initialize_unfilled();
        let n = read_buf.dequeue_slice(unfilled_slice);
        buf.advance(n);

        let _ = self.stack_notifier.try_send(IfaceEvent::TcpSocketReady);

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let send_buf = &self.handle.send_buffer;

        if send_buf.is_full() {
            self.handle.send_waker.register(cx.waker());
            let _ = self.stack_notifier.try_send(IfaceEvent::TcpSocketReady);
            return Poll::Pending;
        }

        let n = send_buf.enqueue_slice(buf);
        let _ = self.stack_notifier.try_send(IfaceEvent::TcpSocketReady);

        Poll::Ready(Ok(n))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let _ = self.stack_notifier.try_send(IfaceEvent::TcpSocketReady);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::task::ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.handle
            .socket_dropped
            .store(true, std::sync::atomic::Ordering::Release);

        let _ = self.stack_notifier.try_send(IfaceEvent::TcpSocketClosed);
    }
}
