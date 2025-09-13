use dashmap::DashMap;
use std::time::{Duration, Instant};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::atomic::{AtomicU32, Ordering},
};
use tokio::task::JoinHandle;
use tracing::{info, warn};

const DNS_ENTRY_TTL: Duration = Duration::from_secs(5 * 60);

struct DnsEntry {
    domain: String,
    expires_at: Instant,
}

pub struct FakeDns {
    map: DashMap<IpAddr, DnsEntry>,
    ip_counter: AtomicU32,
}

impl FakeDns {
    pub fn new() -> Self {
        Self {
            map: DashMap::new(),
            ip_counter: AtomicU32::new(1),
        }
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        self.map.get(ip).map(|entry| entry.value().domain.clone())
    }

    fn next_fake_ip(&self) -> Ipv4Addr {
        let count = self.ip_counter.fetch_add(1, Ordering::Relaxed);

        let octet3 = ((count >> 8) & 0xFF) as u8;
        let octet4 = (count & 0xFF) as u8;

        Ipv4Addr::new(198, 18, octet3, octet4)
    }

    /// 解析DNS查询，生成一个伪造的A记录响应，并存储映射关系。
    /// 这个方法现在是 FakeDns 的一部分，可以直接访问 `self.map` 和 `self.ip_counter`。
    pub fn generate_fake_response(&self, query_bytes: &[u8]) -> Option<Vec<u8>> {
        // DNS头部固定为12字节
        if query_bytes.len() < 12 {
            return None;
        }

        // --- 1. 解析头部 ---
        let transaction_id = &query_bytes[0..2];
        let qd_count = u16::from_be_bytes([query_bytes[4], query_bytes[5]]);
        if qd_count != 1 {
            return None;
        }

        // --- 2. 解析问题部分 (Question Section) ---
        let question_bytes = &query_bytes[12..];
        let mut domain_parts = Vec::new();
        let mut current_pos = 0;

        loop {
            let len = *question_bytes.get(current_pos)? as usize;
            if len == 0 {
                current_pos += 1; // 跳过最后的0字节
                break;
            }
            current_pos += 1;
            let part = question_bytes.get(current_pos..current_pos + len)?;
            domain_parts.push(String::from_utf8_lossy(part).to_string());
            current_pos += len;
        }
        let domain_name = domain_parts.join(".");

        // 确认是 A 记录查询
        let qtype = u16::from_be_bytes([
            *question_bytes.get(current_pos)?,
            *question_bytes.get(current_pos + 1)?,
        ]);
        if qtype != 1 {
            // 1 for A record
            return None;
        }

        info!("Intercepted DNS A record query for: {}", domain_name);

        // --- 关键步骤: 分配假 IP 并存储映射 ---
        let fake_ip = self.next_fake_ip();
        let entry = DnsEntry {
            domain: domain_name.clone(),
            expires_at: Instant::now() + DNS_ENTRY_TTL, // 设置过期时间
        };
        self.map.insert(IpAddr::V4(fake_ip), entry);
        warn!(
            "FakeDNS: Mapped domain '{}' -> IP '{}'. Current map size: {}",
            domain_name,
            fake_ip,
            self.map.len()
        );

        // --- 3. 构建伪造的响应 ---
        let mut response_bytes = Vec::new();

        // 响应头部 (12 bytes)
        response_bytes.extend_from_slice(transaction_id); // 原始事务ID
        response_bytes.extend_from_slice(&[0x81, 0x80]); // 标志位: 响应, 权威, 无错误
        response_bytes.extend_from_slice(&1u16.to_be_bytes()); // 问题数: 1
        response_bytes.extend_from_slice(&1u16.to_be_bytes()); // 回答数: 1
        response_bytes.extend_from_slice(&0u16.to_be_bytes()); // 权威记录数: 0
        response_bytes.extend_from_slice(&0u16.to_be_bytes()); // 附加记录数: 0

        // 响应的问题部分 (直接从查询中复制)
        let question_section_len = current_pos + 4; // +4 for QTYPE and QCLASS
        response_bytes.extend_from_slice(&query_bytes[12..12 + question_section_len]);

        // 响应的回答部分 (Answer Section)
        response_bytes.extend_from_slice(&[0xc0, 0x0c]); // 域名指针
        response_bytes.extend_from_slice(&1u16.to_be_bytes()); // 类型: A
        response_bytes.extend_from_slice(&1u16.to_be_bytes()); // 类: IN
        response_bytes.extend_from_slice(&60u32.to_be_bytes()); // TTL: 60 秒
        response_bytes.extend_from_slice(&4u16.to_be_bytes()); // 数据长度: 4 (IPv4)
        response_bytes.extend_from_slice(&fake_ip.octets()); // IP 地址

        Some(response_bytes)
    }

    pub fn cleanup_expired_entries(&self) {
        let now = Instant::now();
        let initial_size = self.map.len();

        // `retain` 是一个非常高效的方法，它会遍历 map 并只保留那些
        // 闭包返回 `true` 的条目。
        self.map.retain(|_ip, entry| entry.expires_at > now);

        let final_size = self.map.len();
        if initial_size > final_size {
            info!(
                "FakeDNS cleanup: Removed {} expired entries. Current size: {}",
                initial_size - final_size,
                final_size
            );
        }
    }
}

// 为 Default trait 实现，使得 FakeDns::new() 可以被简化为 FakeDns::default()
impl Default for FakeDns {
    fn default() -> Self {
        Self::new()
    }
}
