use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use bytes::{BufMut, BytesMut};
use crossbeam_queue::SegQueue;

#[derive(Clone)]
pub struct BufferPool {
    pool: Arc<SegQueue<BytesMut>>,
    max_pool_size: usize,
    default_buffer_size: usize,
}

impl BufferPool {
    pub fn new(max_pool_size: usize, default_buffer_size: usize) -> Self {
        Self {
            pool: Arc::new(SegQueue::new()),
            max_pool_size,
            default_buffer_size,
        }
    }

    pub fn get(&self, capacity: usize) -> PooledBytesMut {
        let mut buffer = self.pool.pop().unwrap_or_else(|| {
            BytesMut::with_capacity(std::cmp::max(capacity, self.default_buffer_size))
        });

        let required_capacity = std::cmp::max(capacity, self.default_buffer_size);
        if buffer.capacity() < required_capacity {
            buffer.reserve(required_capacity - buffer.capacity());
        }

        buffer.clear();

        PooledBytesMut {
            buffer: Some(buffer),
            pool: self.clone(),
        }
    }

    fn release(&self, buffer: BytesMut) {
        if self.pool.len() < self.max_pool_size {
            self.pool.push(buffer);
        }
    }
}

pub struct PooledBytesMut {
    buffer: Option<BytesMut>,
    pool: BufferPool,
}

impl Drop for PooledBytesMut {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.pool.release(buffer);
        }
    }
}

impl Deref for PooledBytesMut {
    type Target = BytesMut;
    fn deref(&self) -> &Self::Target {
        self.buffer.as_ref().unwrap()
    }
}

impl DerefMut for PooledBytesMut {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.as_mut().unwrap()
    }
}

impl io::Write for PooledBytesMut {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.put_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
