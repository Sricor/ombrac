use std::net::SocketAddr;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ombrac::prelude::*;

// Benchmark tests using criterion
pub fn request_serialization_benchmark(c: &mut Criterion) {
    let request = Connect::with([0u8; 32], "example.com".parse::<SocketAddr>().unwrap());

    c.bench_function("serialize domain request", |b| {
        b.iter(|| {
            let bytes = black_box(request).to_bytes();
            black_box(bytes);
        });
    });
}

criterion_group!(benches, request_serialization_benchmark);
criterion_main!(benches);
