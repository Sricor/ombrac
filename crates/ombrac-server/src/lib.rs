pub mod server;

// async fn run(
//     endpoint: Arc<quinn::Endpoint>,
//     stream_sender: Sender<Stream>,
//     mut shutdown_receiver: watch::Receiver<()>,
// ) {
//     loop {
//         let stream_sender = stream_sender.clone();
//         let endpoint = endpoint.clone();

//         tokio::select! {
//             Some(conn) = endpoint.accept() => {
//                 tokio::spawn(async move {
//                     match conn.await {
//                         Ok(new_connection) => {
//                             info!("New connection from: {}", new_connection.remote_address());
//                             let connection = Arc::new(new_connection);

//                             tokio::spawn(handle_full_cone_proxy(connection.clone()));

//                             loop {
//                                 tokio::select! {
//                                     Ok((send, recv)) = connection.accept_bi() => {
//                                         if stream_sender.send(Stream(send, recv)).await.is_err() {
//                                             error!("Stream receiver dropped, cannot accept new streams");
//                                             break;
//                                         }
//                                     }
//                                     else => {
//                                         debug!("Connection handling loop finished for {}", connection.remote_address());
//                                         break;
//                                     }
//                                 }
//                             }
//                         }
//                         Err(_err) => {
//                             error!("Connection error: {}", _err);
//                         }
//                     }
//                 });
//             }
//             _ = shutdown_receiver.changed() => {
//                 endpoint.close(0u32.into(), b"Server shutting down");
//                 break;
//             }
//         }
//     }
// }

// async fn handle_full_cone_proxy(conn: Arc<quinn::Connection>) {
//     // 1. 创建专用的 UDP 套接字
//     let proxy_socket = match UdpSocket::bind("0.0.0.0:0").await {
//         Ok(s) => Arc::new(s),
//         Err(e) => {
//             error!("Failed to bind UDP socket for proxy: {}", e);
//             conn.close(1u32.into(), b"Internal Server Error");
//             return;
//         }
//     };
//     info!(
//         "Created UDP proxy socket at {} for client {}",
//         proxy_socket.local_addr().unwrap(),
//         conn.remote_address()
//     );

//     // 2. 启动两个任务进行双向数据转发
//     // 任务1: 从 QUIC 读取数据报, 解码目标地址, 然后通过 UDP 套接字发送出去
//     let fwd_conn = conn.clone();
//     let fwd_socket = proxy_socket.clone();
//     let fwd_task = tokio::spawn(async move {
//         loop {
//             match fwd_conn.read_datagram().await {
//                 Ok(datagram) => {
//                     if let Some((dest_addr, payload)) = decode_addr(&datagram) {
//                         info!(
//                             "Server Read Datagram dest: {}, playload: {}",
//                             dest_addr,
//                             payload.len()
//                         );
//                         if let Err(e) = fwd_socket.send_to(payload, dest_addr).await {
//                             warn!("Failed to send UDP packet to {}: {}", dest_addr, e);
//                         }
//                     } else {
//                         warn!(
//                             "Received invalid datagram from client {}",
//                             fwd_conn.remote_address()
//                         );
//                     }
//                 }
//                 Err(e) => {
//                     debug!("QUIC datagram read error (connection closing?): {}", e);
//                     break;
//                 }
//             }
//         }
//     });

//     // 任务2: 从 UDP 套接字读取数据, 编码源地址, 然后通过 QUIC 数据报发回客户端
//     let bwd_conn = conn.clone();
//     let bwd_socket = proxy_socket.clone();
//     let bwd_task = tokio::spawn(async move {
//         let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
//         loop {
//             match bwd_socket.recv_from(&mut buf).await {
//                 Ok((len, source_addr)) => {
//                     let payload = &buf[..len];
//                     let mut response_datagram = encode_addr(&source_addr);
//                     response_datagram.extend_from_slice(payload);

//                     info!(
//                         "Server Send Datagram dest: {}, playload: {}",
//                         source_addr,
//                         payload.len()
//                     );

//                     // Datagram too large
//                     // 为了避免过大 MAX_DATAGRAM_SIZE 的大小非常重要？
//                     // 有办法拿到 quinn 的自适应 MTU 吗？
//                     if let Err(e) = bwd_conn.send_datagram(response_datagram.into()) {
//                         debug!("Failed to send QUIC datagram (connection closing?): {}", e);
//                         break;
//                     }
//                 }
//                 Err(e) => {
//                     error!("UDP socket recv_from error: {}", e);
//                     break;
//                 }
//             }
//         }
//     });

//     // 等待任一任务结束. 如果一个方向的转发停止 (通常是由于QUIC连接断开), 我们就清理所有资源.
//     tokio::select! {
//         _ = fwd_task => {},
//         _ = bwd_task => {},
//     }

//     info!("Closing UDP proxy for client {}", conn.remote_address());
// }
