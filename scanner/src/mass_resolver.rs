// sentinel - resolucion dns masiva
// m-society & c1q_

use clap::Parser;
use serde::Serialize;
use std::io::{self, BufRead};
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Parser, Debug)]
#[command(name = "sentinel-mass-resolver")]
#[command(about = "dns resolution masiva - sentinel osint by m-society & c1q_")]
struct Args {
    /// archivo con dominios (uno por linea), o - para stdin
    #[arg(short, long, default_value = "-")]
    input: String,

    /// conexiones concurrentes
    #[arg(short, long, default_value = "200")]
    concurrency: usize,

    /// servidor dns a usar
    #[arg(long, default_value = "8.8.8.8")]
    dns_server: String,
}

#[derive(Serialize, Debug)]
struct DnsResult {
    domain: String,
    resolved: bool,
    ips: Vec<String>,
    cnames: Vec<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct ResolverReport {
    total_domains: usize,
    resolved: usize,
    failed: usize,
    results: Vec<DnsResult>,
}

async fn resolver_dominio(dominio: String) -> DnsResult {
    // usar el resolver del sistema como fallback simple
    match tokio::net::lookup_host(format!("{}:80", &dominio)).await {
        Ok(addrs) => {
            let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            DnsResult {
                domain: dominio,
                resolved: !ips.is_empty(),
                ips,
                cnames: vec![],
                error: None,
            }
        }
        Err(e) => DnsResult {
            domain: dominio,
            resolved: false,
            ips: vec![],
            cnames: vec![],
            error: Some(e.to_string()),
        },
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // leer dominios desde stdin o archivo
    let dominios: Vec<String> = if args.input == "-" {
        io::stdin()
            .lock()
            .lines()
            .filter_map(|l| l.ok())
            .filter(|l| !l.trim().is_empty())
            .collect()
    } else {
        match std::fs::read_to_string(&args.input) {
            Ok(contenido) => contenido
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(String::from)
                .collect(),
            Err(e) => {
                eprintln!("error leyendo archivo {}: {}", args.input, e);
                std::process::exit(1);
            }
        }
    };

    let total = dominios.len();
    let semaforo = Arc::new(Semaphore::new(args.concurrency));

    let mut tareas = Vec::new();
    for dominio in dominios {
        let sem = semaforo.clone();
        tareas.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            resolver_dominio(dominio).await
        }));
    }

    let resultados_raw = futures::future::join_all(tareas).await;
    let mut resultados: Vec<DnsResult> = Vec::new();
    let mut resueltos = 0;
    let mut fallidos = 0;

    for r in resultados_raw {
        if let Ok(dns_result) = r {
            if dns_result.resolved {
                resueltos += 1;
            } else {
                fallidos += 1;
            }
            resultados.push(dns_result);
        }
    }

    let reporte = ResolverReport {
        total_domains: total,
        resolved: resueltos,
        failed: fallidos,
        results: resultados,
    };

    println!("{}", serde_json::to_string_pretty(&reporte).unwrap());
}
