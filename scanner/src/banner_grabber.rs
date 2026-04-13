// sentinel - banner grabbing de servicios
// c1q_ (M-Society team)

use clap::Parser;
use serde::Serialize;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Parser, Debug)]
#[command(name = "sentinel-banner-grabber")]
#[command(about = "banner grabbing de servicios - sentinel osint by c1q_ (M-Society team)")]
struct Args {
    /// ip objetivo
    #[arg(short, long)]
    target: String,

    /// puertos a capturar banners (separados por coma)
    #[arg(short, long)]
    ports: String,

    /// timeout en milisegundos
    #[arg(long, default_value = "5000")]
    timeout_ms: u64,
}

#[derive(Serialize, Debug)]
struct BannerResult {
    target: String,
    port: u16,
    banner: String,
    service_guess: String,
    raw_bytes: usize,
}

#[derive(Serialize)]
struct BannerReport {
    target: String,
    results: Vec<BannerResult>,
    total_grabbed: usize,
}

// probes conocidos para diferentes servicios
fn obtener_probe(port: u16) -> &'static [u8] {
    match port {
        80 | 8080 | 8443 => b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: SENTINEL/1.0\r\n\r\n",
        21 => b"",     // ftp envia banner al conectar
        22 => b"",     // ssh envia banner al conectar
        25 => b"EHLO sentinel.local\r\n",
        110 => b"",    // pop3 envia banner al conectar
        143 => b"",    // imap envia banner al conectar
        3306 => b"",   // mysql envia banner al conectar
        _ => b"\r\n",
    }
}

fn adivinar_servicio(banner: &str, port: u16) -> String {
    let banner_lower = banner.to_lowercase();
    if banner_lower.contains("ssh") { return "ssh".to_string(); }
    if banner_lower.contains("http") { return "http".to_string(); }
    if banner_lower.contains("ftp") { return "ftp".to_string(); }
    if banner_lower.contains("smtp") || banner_lower.contains("postfix") || banner_lower.contains("exim") {
        return "smtp".to_string();
    }
    if banner_lower.contains("mysql") || banner_lower.contains("mariadb") { return "mysql".to_string(); }
    if banner_lower.contains("postgresql") { return "postgresql".to_string(); }
    if banner_lower.contains("redis") { return "redis".to_string(); }
    if banner_lower.contains("nginx") { return "nginx".to_string(); }
    if banner_lower.contains("apache") { return "apache".to_string(); }
    if banner_lower.contains("imap") { return "imap".to_string(); }
    if banner_lower.contains("pop3") { return "pop3".to_string(); }

    match port {
        22 => "ssh",
        80 | 8080 => "http",
        443 | 8443 => "https",
        21 => "ftp",
        25 => "smtp",
        _ => "unknown",
    }.to_string()
}

async fn capturar_banner(target: &str, port: u16, timeout_ms: u64) -> Option<BannerResult> {
    let addr = format!("{}:{}", target, port);

    match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            let probe = obtener_probe(port);
            if !probe.is_empty() {
                let _ = stream.write_all(probe).await;
            }

            let mut buffer = vec![0u8; 4096];
            match timeout(Duration::from_millis(timeout_ms), stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner_raw = String::from_utf8_lossy(&buffer[..n]).to_string();
                    let banner_limpio = banner_raw
                        .chars()
                        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                        .take(512)
                        .collect::<String>();

                    Some(BannerResult {
                        target: target.to_string(),
                        port,
                        service_guess: adivinar_servicio(&banner_limpio, port),
                        banner: banner_limpio,
                        raw_bytes: n,
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
    let puertos: Vec<u16> = args
        .ports
        .split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect();

    let mut tareas = Vec::new();
    for &port in &puertos {
        let target = args.target.clone();
        let timeout_ms = args.timeout_ms;
        tareas.push(tokio::spawn(
            async move { capturar_banner(&target, port, timeout_ms).await },
        ));
    }

    let resultados_raw = futures::future::join_all(tareas).await;
    let mut resultados: Vec<BannerResult> = Vec::new();

    for r in resultados_raw {
        if let Ok(Some(banner)) = r {
            resultados.push(banner);
        }
    }

    let reporte = BannerReport {
        target: args.target,
        total_grabbed: resultados.len(),
        results: resultados,
    };

    println!("{}", serde_json::to_string_pretty(&reporte).unwrap());
}
