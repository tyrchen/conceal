use conceal_core::{generate_keypair, Header, Session, SessionConfig};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::RngCore;
use std::{fmt, fs, path::Path};
use tokio::runtime::Runtime;

criterion_group!(benches, encrypt);
criterion_main!(benches);

#[derive(Copy, Clone)]
struct Params {
    size: usize,
}

impl fmt::Debug for Params {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(size {})", self.size)
    }
}

fn encrypt(c: &mut Criterion) {
    let params = &[
        Params { size: 32 * 1024 },
        Params { size: 64 * 1024 },
        Params { size: 256 * 1024 },
        Params { size: 1024 * 1024 },
        Params {
            size: 4 * 1024 * 1024,
        },
    ];

    fs::create_dir_all("/tmp/conceal").unwrap();

    let mut group = c.benchmark_group("different size");
    for param in params.iter() {
        group.bench_function(&format!("{:?}", &param), move |b| {
            let infile = "/tmp/conceal/bench_encrypt_cleartext";
            let outfile = "/tmp/conceal/bench_decrypt_ciphertext";
            let mut buf = vec![0u8; param.size as usize];
            fill_file(&infile, &mut buf);
            let client_keypair = generate_keypair().unwrap();
            let server_keypair = generate_keypair().unwrap();

            let header = Header::default();
            let config =
                SessionConfig::new(header, Some(server_keypair.public), client_keypair, None);
            let mut session = Session::new(config).unwrap();

            let rt = Runtime::new().unwrap();
            b.iter(move || {
                rt.block_on(session.encrypt_file(infile, outfile)).unwrap();
            });
        });
    }
    group.finish();
}

fn fill_file(name: impl AsRef<Path>, buf: &mut [u8]) {
    let mut rng = rand::thread_rng();
    rng.fill_bytes(buf);
    fs::write(name, buf).unwrap();
}
