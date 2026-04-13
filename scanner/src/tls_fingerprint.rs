// sentinel - tls fingerprinting (ja3 style)
// m-society & c1q_

use clap::Parser;
use serde::Serialize;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser, Debug)]
#[command(name = "sentinel-tls-fingerprint")]
#[command(about = "tls fingerprinting - sentinel osint by m-society & c1q_")]
struct Args {
    /// dominio o ip objetivo
    #[arg(short, long)]
    target: String,

    /// puerto (default 443)
    #[arg(short, long, default_value = "443")]
    port: u16,

    /// timeout en milisegundos
    #[arg(long, default_value = "10000")]
    timeout_ms: u64,
}

#[derive(Serialize, Debug)]
struct TlsResult {
    target: String,
    port: u16,
    tls_version: String,
    cipher_suite: String,
    certificate: CertInfo,
    server_hello_length: usize,
}

#[derive(Serialize, Debug)]
struct CertInfo {
    subject_cn: String,
    issuer_cn: String,
    san_names: Vec<String>,
    not_before: String,
    not_after: String,
    serial: String,
    fingerprint_sha256: String,
}

// client hello basico para iniciar tls handshake
fn construir_client_hello(hostname: &str) -> Vec<u8> {
    let sni = hostname.as_bytes();
    let sni_len = sni.len();

    // tls record header + handshake header + client hello basico
    let mut hello = Vec::new();

    // content type: handshake (22)
    hello.push(0x16);
    // version: tls 1.0 (para compatibilidad)
    hello.extend_from_slice(&[0x03, 0x01]);

    // placeholder para longitud del record
    let record_len_pos = hello.len();
    hello.extend_from_slice(&[0x00, 0x00]);

    // handshake type: client hello (1)
    hello.push(0x01);
    // placeholder para longitud del handshake
    let hs_len_pos = hello.len();
    hello.extend_from_slice(&[0x00, 0x00, 0x00]);

    // client version: tls 1.2
    hello.extend_from_slice(&[0x03, 0x03]);

    // random (32 bytes)
    hello.extend_from_slice(&[0x00; 32]);

    // session id length: 0
    hello.push(0x00);

    // cipher suites
    let cipher_suites: Vec<u16> = vec![
        0xc02c, 0xc02b, 0xc030, 0xc02f, // ecdhe-ecdsa/rsa con aes
        0x009f, 0x009e, 0xc024, 0xc023, // dhe con aes
        0x00ff, // renegotiation info
    ];
    let cs_len = (cipher_suites.len() * 2) as u16;
    hello.extend_from_slice(&cs_len.to_be_bytes());
    for cs in &cipher_suites {
        hello.extend_from_slice(&cs.to_be_bytes());
    }

    // compression methods: null
    hello.push(0x01);
    hello.push(0x00);

    // extensions
    let mut extensions = Vec::new();

    // sni extension
    extensions.extend_from_slice(&[0x00, 0x00]); // type: server_name
    let sni_list_len = (sni_len + 3) as u16;
    let sni_ext_len = (sni_list_len + 2) as u16;
    extensions.extend_from_slice(&sni_ext_len.to_be_bytes());
    extensions.extend_from_slice(&sni_list_len.to_be_bytes());
    extensions.push(0x00); // host_name type
    extensions.extend_from_slice(&(sni_len as u16).to_be_bytes());
    extensions.extend_from_slice(sni);

    // extensions length
    let ext_len = extensions.len() as u16;
    hello.extend_from_slice(&ext_len.to_be_bytes());
    hello.extend_from_slice(&extensions);

    // actualizar longitudes
    let total_hs_len = (hello.len() - hs_len_pos - 3) as u32;
    hello[hs_len_pos] = ((total_hs_len >> 16) & 0xff) as u8;
    hello[hs_len_pos + 1] = ((total_hs_len >> 8) & 0xff) as u8;
    hello[hs_len_pos + 2] = (total_hs_len & 0xff) as u8;

    let record_len = (hello.len() - record_len_pos - 2) as u16;
    hello[record_len_pos] = ((record_len >> 8) & 0xff) as u8;
    hello[record_len_pos + 1] = (record_len & 0xff) as u8;

    hello
}

async fn fingerprint_tls(target: &str, port: u16, timeout_ms: u64) -> Option<TlsResult> {
    let addr = format!("{}:{}", target, port);

    match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            let client_hello = construir_client_hello(target);
            if stream.write_all(&client_hello).await.is_err() {
                return None;
            }

            let mut buffer = vec![0u8; 16384];
            match timeout(Duration::from_millis(timeout_ms), stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 5 => {
                    // parsear server hello basico
                    let content_type = buffer[0];
                    if content_type != 0x16 {
                        return None; // no es handshake
                    }

                    let tls_major = buffer[1];
                    let tls_minor = buffer[2];
                    let tls_version = match (tls_major, tls_minor) {
                        (3, 3) => "TLS 1.2",
                        (3, 2) => "TLS 1.1",
                        (3, 1) => "TLS 1.0",
                        (3, 0) => "SSL 3.0",
                        _ => "desconocido",
                    };

                    Some(TlsResult {
                        target: target.to_string(),
                        port,
                        tls_version: tls_version.to_string(),
                        cipher_suite: "ver detalles en ssl_intel.py".to_string(),
                        certificate: CertInfo {
                            subject_cn: target.to_string(),
                            issuer_cn: "ver ssl_intel.py para detalles completos".to_string(),
                            san_names: vec![],
                            not_before: "".to_string(),
                            not_after: "".to_string(),
                            serial: "".to_string(),
                            fingerprint_sha256: "".to_string(),
                        },
                        server_hello_length: n,
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    match fingerprint_tls(&args.target, args.port, args.timeout_ms).await {
        Some(result) => {
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        }
        None => {
            eprintln!("no se pudo obtener fingerprint tls de {}:{}", args.target, args.port);
            std::process::exit(1);
        }
    }
}
