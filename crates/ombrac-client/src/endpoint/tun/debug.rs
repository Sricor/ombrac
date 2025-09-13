use tracing::trace;

pub(crate) fn trace_ip_packet(message: &str, packet: &[u8]) {
    use smoltcp::wire::*;

    match IpVersion::of_packet(packet) {
        Ok(IpVersion::Ipv4) => trace!(
            "{}: {}",
            message,
            PrettyPrinter::<Ipv4Packet<&mut [u8]>>::new("", &packet)
        ),
        Ok(IpVersion::Ipv6) => trace!(
            "{}: {}",
            message,
            PrettyPrinter::<Ipv6Packet<&mut [u8]>>::new("", &packet)
        ),
        _ => {}
    }
}
