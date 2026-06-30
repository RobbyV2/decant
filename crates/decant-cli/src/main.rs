use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use decant_client::Client;
use decant_protocol::{Pid, Request, Response};

#[derive(Debug, Parser)]
#[command(name = "decant-cli", about = "Drive the Decant daemon")]
struct Cli {
    #[arg(long, env = "DECANT_ENDPOINT", default_value = "127.0.0.1:7878")]
    endpoint: String,

    #[arg(long)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    Processes,
    Modules {
        pid: u32,
    },
    Exports {
        pid: u32,
        module: String,
    },
    Read {
        pid: u32,
        addr: String,
        len: String,
    },
    Write {
        pid: u32,
        addr: String,
        hexbytes: String,
    },
    MemoryMap {
        pid: u32,
    },
    Diagnostics,
    Scan {
        pid: u32,
        pattern: String,
    },
    Resolve {
        pid: u32,
        base: String,
        offsets: Vec<String>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("decant-cli: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let mut client = Client::new(&cli.endpoint);

    let (req, read_base): (Request, Option<u64>) = match cli.cmd {
        Cmd::Processes => (Request::ListProcesses, None),
        Cmd::Modules { pid } => (Request::ModuleList(Pid(pid)), None),
        Cmd::Exports { pid, module } => (Request::ModuleExports(Pid(pid), module), None),
        Cmd::Read { pid, addr, len } => {
            let addr = parse_u64(&addr).context("parsing ADDR")?;
            let len = parse_u64(&len).context("parsing LEN")?;
            (
                Request::Read {
                    pid: Pid(pid),
                    addr,
                    len,
                },
                Some(addr),
            )
        }
        Cmd::Write {
            pid,
            addr,
            hexbytes,
        } => {
            let addr = parse_u64(&addr).context("parsing ADDR")?;
            let data = parse_hex(&hexbytes).context("parsing hex bytes")?;
            (
                Request::Write {
                    pid: Pid(pid),
                    addr,
                    data,
                },
                None,
            )
        }
        Cmd::MemoryMap { pid } => (Request::MemoryMap(Pid(pid)), None),
        Cmd::Diagnostics => (Request::Diagnostics, None),
        Cmd::Scan { pid, pattern } => (
            Request::Scan {
                pid: Pid(pid),
                pattern,
            },
            None,
        ),
        Cmd::Resolve { pid, base, offsets } => {
            let base = parse_u64(&base).context("parsing BASE")?;
            let offsets = offsets
                .iter()
                .map(|o| parse_u64(o))
                .collect::<Result<Vec<_>>>()
                .context("parsing offsets")?;
            (
                Request::Resolve {
                    pid: Pid(pid),
                    base,
                    offsets,
                },
                None,
            )
        }
    };

    let resp = client.send(req).context("daemon request")?;
    emit(resp, cli.json, read_base)
}

fn emit(resp: Response, json: bool, read_base: Option<u64>) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }
    match resp {
        Response::Processes(ps) => {
            for p in ps {
                println!("{:<8} {}", p.pid, p.name);
            }
        }
        Response::Modules(ms) => {
            for m in ms {
                println!("{:#018x}  {:>10}  {}", m.base, m.size, m.name);
            }
        }
        Response::Exports(ex) => {
            for (name, addr) in ex {
                println!("{addr:#018x}  {name}");
            }
        }
        Response::Data(bytes) => hexdump(read_base.unwrap_or(0), &bytes),
        Response::Written(n) => println!("wrote {n} bytes"),
        Response::MemoryMap(regions) => {
            for r in regions {
                let perms: String = [
                    if r.readable { 'r' } else { '-' },
                    if r.writable { 'w' } else { '-' },
                    if r.executable { 'x' } else { '-' },
                ]
                .iter()
                .collect();
                println!(
                    "{:#018x}-{:#018x}  {perms}  ({} bytes)",
                    r.base,
                    r.base + r.size,
                    r.size
                );
            }
        }
        Response::Diagnostics(d) => {
            println!("connector:       {}", d.connector);
            println!("reads:           {}", d.reads);
            println!("writes:          {}", d.writes);
            println!("unsupported ops: {}", d.unsupported_ops);
        }
        Response::ScanHits(hits) => {
            if hits.is_empty() {
                println!("(no matches)");
            }
            for addr in hits {
                println!("{addr:#018x}");
            }
        }
        Response::Resolved { address, value } => {
            print!("{address:#018x}");
            if let Ok(bytes) = <[u8; 8]>::try_from(value.as_slice()) {
                let v = u64::from_le_bytes(bytes);
                print!("  ->  u64={v:#x} ({v})");
            }
            println!();
        }
        Response::Err(e) => bail!("daemon error: {e}"),
        other => bail!("unexpected response: {other:?}"),
    }
    Ok(())
}

fn parse_u64(s: &str) -> Result<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => Ok(u64::from_str_radix(hex, 16)?),
        None => Ok(s.parse::<u64>()?),
    }
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .trim()
        .strip_prefix("0x")
        .unwrap_or(s)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if cleaned.len() % 2 != 0 {
        bail!("hex string has an odd number of digits");
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|e| anyhow!("invalid hex byte {:?}: {e}", &cleaned[i..i + 2]))
        })
        .collect()
}

fn hexdump(base: u64, bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let off = base + (i * 16) as u64;
        let mut hex = String::new();
        for (j, b) in chunk.iter().enumerate() {
            if j == 8 {
                hex.push(' ');
            }
            hex.push_str(&format!("{b:02x} "));
        }
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("{off:#018x}  {hex:<49} |{ascii}|");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_u64_handles_hex_and_decimal() {
        assert_eq!(parse_u64("0x1400010100").unwrap(), 0x1400010100);
        assert_eq!(parse_u64("4096").unwrap(), 4096);
    }

    #[test]
    fn parse_hex_variants() {
        assert_eq!(parse_hex("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            parse_hex("de ad be ef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(parse_hex("0xDEAD").unwrap(), vec![0xde, 0xad]);
        assert!(parse_hex("abc").is_err());
    }
}
