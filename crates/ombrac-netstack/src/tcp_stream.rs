use std::net::SocketAddr;
use std::sync::{Arc, atomic::AtomicBool};
use std::task::{Context, Poll};

use futures::task::AtomicWaker;
use ringbuf::HeapRb;
use ringbuf::traits::{Consumer, Observer, Producer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::mpsc::Sender;

use crate::stack::IfaceEvent;

pub(crate) type RbProducer = ringbuf::Prod<Arc<HeapRb<u8>>>;
pub(crate) type RbConsumer = ringbuf::Cons<Arc<HeapRb<u8>>>;

pub(crate) struct SharedState {
    pub(crate) recv_waker: AtomicWaker,
    pub(crate) send_waker: AtomicWaker,
    pub(crate) socket_dropped: AtomicBool,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            recv_waker: AtomicWaker::new(),
            send_waker: AtomicWaker::new(),
            socket_dropped: AtomicBool::new(false),
        }
    }
}

pub struct TcpStream {
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) recv_buffer_cons: RbConsumer,
    pub(crate) send_buffer_prod: RbProducer,
    pub(crate) shared_state: Arc<SharedState>,
    pub(crate) stack_notifier: Sender<IfaceEvent<'static>>,
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
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.recv_buffer_cons.is_empty() {
            self.shared_state.recv_waker.register(cx.waker());
            return Poll::Pending;
        }

        let unfilled_slice = buf.initialize_unfilled();
        let n = self.recv_buffer_cons.pop_slice(unfilled_slice);
        buf.advance(n);

        let _ = self.stack_notifier.try_send(IfaceEvent::TcpSocketReady);

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.send_buffer_prod.is_full() {
            self.shared_state.send_waker.register(cx.waker());
            let _ = self.stack_notifier.try_send(IfaceEvent::TcpSocketReady);
            return Poll::Pending;
        }

        let n = self.send_buffer_prod.push_slice(buf);
        if n > 0 {
            match self.stack_notifier.try_send(IfaceEvent::TcpSocketReady) {
                Ok(()) => {}
                Err(_) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "Stack task has terminated",
                    )));
                }
            }
        }

        Poll::Ready(Ok(n))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.stack_notifier.try_send(IfaceEvent::TcpSocketReady) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Stack task has terminated",
            ))),
        }
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
        self.shared_state
            .socket_dropped
            .store(true, std::sync::atomic::Ordering::Release);

        let _ = self.stack_notifier.try_send(IfaceEvent::TcpSocketClosed);
    }
}
