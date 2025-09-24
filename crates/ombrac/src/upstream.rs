use serde::{Deserialize, Serialize};
use tokio_util::codec::LengthDelimitedCodec;

use crate::protocol::{ClientConnect, ClientHello};

/// 顶层枚举，用于在控制流上传输的所有消息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpstreamMessage {
    Hello(ClientHello),
    Connect(ClientConnect),
}

/// 创建一个为我们的协议预先配置好的、基于长度分隔的编解码器。
///
/// 我们的协议使用一个4字节（u32）的大端序（Big-Endian）长度前缀。
pub fn new_codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_offset(0) // 长度字段位于帧的起始位置。
        .length_field_length(4) // 长度字段本身为4字节。
        .length_adjustment(0) // 负载紧跟在长度字段之后。
        // **修正点**: 将 num_skip 设置为长度字段的长度（4字节）。
        // 这可以确保编解码器返回的缓冲区只包含消息负载，而不包含长度前缀本身，
        // 这正是 bincode 解码器所期望的。
        .num_skip(4)
        // 设置一个合理的最大帧长度以防止DoS攻击。
        .max_frame_length(8 * 1024 * 1024) // 8 MiB
        .new_codec()
}