// sentinel - port scanner masivo con tokio
// m-society & c1q_
// tcp connect scan de alta velocidad

use clap::Parser;
use serde::Serialize;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "sentinel-port-scanner")]
#[command(about = "port scanner masivo - sentinel osint by m-society & c1q_")]
struct Args {
    /// ip o rango a escanear
    #[arg(short, long)]
    target: String,

    /// puertos a escanear (ej: 1-1000 o 80,443,8080)
    #[arg(short, long, default_value = "1-1000")]
    ports: String,

    /// conexiones concurrentes maximas
    #[arg(short, long, default_value = "500")]
    concurrency: usize,

    /// timeout por conexion en milisegundos
    #[arg(long, default_value = "3000")]
    timeout_ms: u64,

    /// output en formato json
    #[arg(long, default_value = "true")]
    json: bool,
}

#[derive(Serialize, Debug)]
struct ScanResult {
    target: String,
    port: u16,
    state: String, // open, closed, filtered
    service: String,
}

#[derive(Serialize)]
struct ScanReport {
    target: String,
    total_ports_scanned: usize,
    open_ports: Vec<ScanResult>,
    scan_duration_ms: u128,
}

// servicios conocidos por puerto
fn servicio_por_puerto(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        443 => "https",
        445 => "microsoft-ds",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5672 => "amqp",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-proxy",
        8443 => "https-alt",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => "unknown",
    }
}

fn parsear_puertos(spec: &str) -> Vec<u16> {
    let mut puertos = Vec::new();
    for parte in spec.split(',') {
        let parte = parte.trim();
        if parte.contains('-') {
            let rango: Vec<&str> = parte.split('-').collect();
            if rango.len() == 2 {
                if let (Ok(inicio), Ok(fin)) = (rango[0].parse::<u16>(), rango[1].parse::<u16>()) {
                    for p in inicio..=fin {
                        puertos.push(p);
                    }
                }
            }
        } else if let Ok(p) = parte.parse::<u16>() {
            puertos.push(p);
        }
    }
    puertos
}

async fn escanear_puerto(target: &str, port: u16, timeout_ms: u64) -> Option<ScanResult> {
    let addr = format!("{}:{}", target, port);
    if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
        match timeout(
            Duration::from_millis(timeout_ms),
            TcpStream::connect(socket_addr),
        )
        .await
        {
            Ok(Ok(_stream)) => {
                return Some(ScanResult {
                    target: target.to_string(),
                    port,
                    state: "open".to_string(),
                    service: servicio_por_puerto(port).to_string(),
                });
            }
            Ok(Err(_)) => return None, // conexion rechazada = cerrado
            Err(_) => return None,     // timeout = filtrado
        }
    }
    None
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let puertos = parsear_puertos(&args.ports);
    let total = puertos.len();
    let semaforo = Arc::new(Semaphore::new(args.concurrency));
    let inicio = std::time::Instant::now();

    let mut tareas = Vec::new();

    for puerto in puertos {
        let target = args.target.clone();
        let sem = semaforo.clone();
        let timeout_ms = args.timeout_ms;

        tareas.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            escanear_puerto(&target, puerto, timeout_ms).await
        }));
    }

    let resultados = futures::future::join_all(tareas).await;
    let duracion = inicio.elapsed().as_millis();

    let mut puertos_abiertos: Vec<ScanResult> = Vec::new();
    for resultado in resultados {
        if let Ok(Some(scan)) = resultado {
            puertos_abiertos.push(scan);
        }
    }

    puertos_abiertos.sort_by_key(|r| r.port);

    let reporte = ScanReport {
        target: args.target,
        total_ports_scanned: total,
        open_ports: puertos_abiertos,
        scan_duration_ms: duracion,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&reporte).unwrap());
    }
}
