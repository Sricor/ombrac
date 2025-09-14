use std::cell::UnsafeCell;
use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::{BufMut, BytesMut};
use crossbeam_queue::SegQueue;

pub struct LockFreeRingBuffer {
    buffer: UnsafeCell<Box<[u8]>>,
    capacity: usize,
    write_pos: AtomicUsize,
    read_pos: AtomicUsize,
}

unsafe impl Send for LockFreeRingBuffer {}
unsafe impl Sync for LockFreeRingBuffer {}

impl LockFreeRingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: UnsafeCell::new(vec![0u8; capacity].into_boxed_slice()),
            capacity,
            write_pos: AtomicUsize::new(0),
            read_pos: AtomicUsize::new(0),
        }
    }

    pub fn enqueue_slice(&self, data: &[u8]) -> usize {
        let write_pos = self.write_pos.load(Ordering::Relaxed);
        let read_pos = self.read_pos.load(Ordering::Acquire);

        let available = if read_pos <= write_pos {
            self.capacity - write_pos + read_pos - 1
        } else {
            read_pos - write_pos - 1
        };

        let to_write = std::cmp::min(data.len(), available);
        if to_write == 0 {
            return 0;
        }

        unsafe {
            let buffer = &mut *self.buffer.get();

            if write_pos + to_write <= self.capacity {
                buffer[write_pos..write_pos + to_write].copy_from_slice(&data[..to_write]);
            } else {
                let first_part = self.capacity - write_pos;
                buffer[write_pos..].copy_from_slice(&data[..first_part]);
                buffer[..to_write - first_part].copy_from_slice(&data[first_part..to_write]);
            }
        }

        let new_write_pos = (write_pos + to_write) % self.capacity;
        self.write_pos.store(new_write_pos, Ordering::Release);

        to_write
    }

    pub fn dequeue_slice(&self, buf: &mut [u8]) -> usize {
        let read_pos = self.read_pos.load(Ordering::Relaxed);
        let write_pos = self.write_pos.load(Ordering::Acquire);

        let available = if write_pos >= read_pos {
            write_pos - read_pos
        } else {
            self.capacity - read_pos + write_pos
        };

        let to_read = std::cmp::min(buf.len(), available);
        if to_read == 0 {
            return 0;
        }

        unsafe {
            let buffer = &*self.buffer.get();

            if read_pos + to_read <= self.capacity {
                buf[..to_read].copy_from_slice(&buffer[read_pos..read_pos + to_read]);
            } else {
                let first_part = self.capacity - read_pos;
                buf[..first_part].copy_from_slice(&buffer[read_pos..]);
                buf[first_part..to_read].copy_from_slice(&buffer[..to_read - first_part]);
            }
        }

        let new_read_pos = (read_pos + to_read) % self.capacity;
        self.read_pos.store(new_read_pos, Ordering::Release);

        to_read
    }

    pub fn is_empty(&self) -> bool {
        self.read_pos.load(Ordering::Acquire) == self.write_pos.load(Ordering::Acquire)
    }

    pub fn is_full(&self) -> bool {
        let read_pos = self.read_pos.load(Ordering::Acquire);
        let write_pos = self.write_pos.load(Ordering::Acquire);
        ((write_pos + 1) % self.capacity) == read_pos
    }
}

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
