use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use dashmap::mapref::one::Ref;
use ombrac_macros::debug;

const DEFAULT_DNS_ENTRY_TTL: Duration = Duration::from_secs(30);

pub struct DnsEntry {
    pub domain: Bytes,
    pub expires_at: Instant,
}

pub struct FakeDns {
    map: DashMap<IpAddr, DnsEntry>,
    ip_counter: AtomicU32,
    ip_pool_base: u32,
    ip_pool_size: u32,
}

impl FakeDns {
    pub fn new(ip_pool_base_addr: Ipv4Addr, prefix_len: u8) -> Self {
        if !(1..=32).contains(&prefix_len) {
            panic!("Prefix length must be between 1 and 32");
        }

        let ip_pool_size = 2u32.saturating_pow(32 - prefix_len as u32);

        Self {
            map: DashMap::new(),
            ip_counter: AtomicU32::new(1),
            ip_pool_base: u32::from(ip_pool_base_addr),
            ip_pool_size,
        }
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<Ref<'_, IpAddr, DnsEntry>> {
        self.map.get(ip)
    }

    pub fn generate_fake_response(&self, query_bytes: &[u8]) -> Option<Vec<u8>> {
        if query_bytes.len() < 12 {
            return None;
        }

        let transaction_id = &query_bytes[0..2];
        let qd_count = u16::from_be_bytes([query_bytes[4], query_bytes[5]]);
        if qd_count != 1 {
            return None;
        }

        let question_bytes = &query_bytes[12..];
        let mut domain_bytes = Vec::with_capacity(question_bytes.len());
        let mut current_pos = 0;
        loop {
            let len = *question_bytes.get(current_pos)? as usize;
            if len == 0 {
                current_pos += 1;
                break;
            }
            current_pos += 1;

            let part = question_bytes.get(current_pos..current_pos + len)?;

            if !domain_bytes.is_empty() {
                domain_bytes.push(b'.');
            }
            domain_bytes.extend_from_slice(part);

            current_pos += len;
        }

        let qtype = u16::from_be_bytes([
            *question_bytes.get(current_pos)?,
            *question_bytes.get(current_pos + 1)?,
        ]);
        if qtype != 1 {
            return None;
        }

        let _qclass = u16::from_be_bytes([
            *question_bytes.get(current_pos + 2)?,
            *question_bytes.get(current_pos + 3)?,
        ]);

        let fake_ip = self.next_fake_ip();

        let entry = DnsEntry {
            domain: domain_bytes.into(),
            expires_at: Instant::now() + DEFAULT_DNS_ENTRY_TTL,
        };

        debug!(
            "FakeDNS: Mapped domain '{}' -> '{}'. Current map size: {}",
            String::from_utf8_lossy(&entry.domain),
            fake_ip,
            self.map.len()
        );

        self.map.insert(IpAddr::V4(fake_ip), entry);

        let question_section_len = current_pos + 4;
        let response_len = 12 + question_section_len + 16; // Header + Question + Answer
        let mut response_bytes = Vec::with_capacity(response_len);

        // --- Header Section ---
        response_bytes.extend_from_slice(transaction_id); // Transaction ID
        response_bytes.extend_from_slice(&[0x81, 0x80]); // Flags: Response, Recursion Desired, Recursion Available
        response_bytes.extend_from_slice(&1u16.to_be_bytes()); // Questions: 1
        response_bytes.extend_from_slice(&1u16.to_be_bytes()); // Answer RRs: 1
        response_bytes.extend_from_slice(&0u16.to_be_bytes()); // Authority RRs: 0
        response_bytes.extend_from_slice(&0u16.to_be_bytes()); // Additional RRs: 0

        // --- Question Section ---
        response_bytes.extend_from_slice(&query_bytes[12..12 + question_section_len]);

        // --- Answer Section ---
        response_bytes.extend_from_slice(&[0xc0, 0x0c]); // Pointer to domain name at offset 12
        response_bytes.extend_from_slice(&1u16.to_be_bytes()); // Type: A
        response_bytes.extend_from_slice(&1u16.to_be_bytes()); // Class: IN
        response_bytes.extend_from_slice(&10u32.to_be_bytes()); // TTL: 10 seconds
        response_bytes.extend_from_slice(&4u16.to_be_bytes()); // Data length: 4 bytes for IPv4
        response_bytes.extend_from_slice(&fake_ip.octets()); // Fake IP address

        Some(response_bytes)
    }

    pub fn cleanup_expired_entries(&self) {
        let now = Instant::now();
        self.map.retain(|_ip, entry| entry.expires_at > now);
    }

    fn next_fake_ip(&self) -> Ipv4Addr {
        let count = self.ip_counter.fetch_add(1, Ordering::Relaxed);

        let offset = if self.ip_pool_size > 2 {
            1 + (count % (self.ip_pool_size - 2))
        } else {
            count % self.ip_pool_size
        };

        let next_ip_u32 = self.ip_pool_base + offset;

        Ipv4Addr::from(next_ip_u32)
    }
}

impl Default for FakeDns {
    fn default() -> Self {
        Self::new(Ipv4Addr::new(198, 18, 0, 0), 16)
    }
}
