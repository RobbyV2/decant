use std::io::Write as _;
use std::net::TcpStream;
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use decant_protocol::{read_msg, write_msg, Pid, Request, Response};

#[derive(Debug, Parser)]
#[command(name = "decant-cli", about = "Drive the Decant daemon")]
struct Cli {
    #[arg(long, env = "DECANT_ENDPOINT", default_value = "127.0.0.1:7878")]
    endpoint: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    Processes,
    Modules { pid: u32 },
    Exports { pid: u32, module: String },
    Read { pid: u32, addr: String, len: String },
    Write { pid: u32, addr: String, hexbytes: String },
    MemoryMap { pid: u32 },
    Diagnostics,
    Scan { pid: u32, pattern: String },
    Resolve { pid: u32, base: String, offsets: Vec<String> },
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
    match cli.cmd {
        Cmd::Processes => {
            let resp = request(&cli.endpoint, Request::ListProcesses)?;
            for p in expect_processes(resp)? {
                println!("{:<8} {}", p.pid, p.name);
            }
        }
        Cmd::Modules { pid } => {
            let resp = request(&cli.endpoint, Request::ModuleList(Pid(pid)))?;
            match resp {
                Response::Modules(ms) => {
                    for m in ms {
                        println!("{:#018x}  {:>10}  {}", m.base, m.size, m.name);
                    }
                }
                other => bail!(unexpected(other)),
            }
        }
        Cmd::Exports { pid, module } => {
            let resp = request(&cli.endpoint, Request::ModuleExports(Pid(pid), module))?;
            match resp {
                Response::Exports(ex) => {
                    for (name, addr) in ex {
                        println!("{addr:#018x}  {name}");
                    }
                }
                other => bail!(unexpected(other)),
            }
        }
        Cmd::Read { pid, addr, len } => {
            let addr = parse_u64(&addr).context("parsing ADDR")?;
            let len = parse_u64(&len).context("parsing LEN")?;
            let resp = request(&cli.endpoint, Request::Read { pid: Pid(pid), addr, len })?;
            match resp {
                Response::Data(bytes) => hexdump(addr, &bytes),
                other => bail!(unexpected(other)),
            }
        }
        Cmd::Write { pid, addr, hexbytes } => {
            let addr = parse_u64(&addr).context("parsing ADDR")?;
            let data = parse_hex(&hexbytes).context("parsing hex bytes")?;
            let resp = request(&cli.endpoint, Request::Write { pid: Pid(pid), addr, data })?;
            match resp {
                Response::Written(n) => println!("wrote {n} bytes at {addr:#x}"),
                other => bail!(unexpected(other)),
            }
        }
        Cmd::MemoryMap { pid } => {
            let resp = request(&cli.endpoint, Request::MemoryMap(Pid(pid)))?;
            match resp {
                Response::MemoryMap(regions) => {
                    for r in regions {
                        let perms = [
                            if r.readable { 'r' } else { '-' },
                            if r.writable { 'w' } else { '-' },
                            if r.executable { 'x' } else { '-' },
                        ];
                        let perms: String = perms.iter().collect();
                        println!(
                            "{:#018x}-{:#018x}  {perms}  ({} bytes)",
                            r.base,
                            r.base + r.size,
                            r.size
                        );
                    }
                }
                other => bail!(unexpected(other)),
            }
        }
        Cmd::Diagnostics => {
            let resp = request(&cli.endpoint, Request::Diagnostics)?;
            match resp {
                Response::Diagnostics(d) => {
                    println!("connector:       {}", d.connector);
                    println!("reads:           {}", d.reads);
                    println!("writes:          {}", d.writes);
                    println!("unsupported ops: {}", d.unsupported_ops);
                }
                other => bail!(unexpected(other)),
            }
        }
        Cmd::Scan { pid, pattern } => {
            let resp = request(&cli.endpoint, Request::Scan { pid: Pid(pid), pattern })?;
            match resp {
                Response::ScanHits(hits) => {
                    if hits.is_empty() {
                        println!("(no matches)");
                    }
                    for addr in hits {
                        println!("{addr:#018x}");
                    }
                }
                other => bail!(unexpected(other)),
            }
        }
        Cmd::Resolve { pid, base, offsets } => {
            let base = parse_u64(&base).context("parsing BASE")?;
            let offsets = offsets
                .iter()
                .map(|o| parse_u64(o))
                .collect::<Result<Vec<_>>>()
                .context("parsing offsets")?;
            let resp = request(&cli.endpoint, Request::Resolve { pid: Pid(pid), base, offsets })?;
            match resp {
                Response::Resolved { address, value } => {
                    print!("{address:#018x}");
                    if value.len() == 8 {
                        let v = u64::from_le_bytes(value.clone().try_into().unwrap());
                        print!("  ->  u64={v:#x} ({v})");
                    }
                    println!();
                }
                other => bail!(unexpected(other)),
            }
        }
    }
    Ok(())
}

fn request(endpoint: &str, req: Request) -> Result<Response> {
    let mut stream = TcpStream::connect(endpoint)
        .with_context(|| format!("connecting to daemon at {endpoint}"))?;
    write_msg(&mut stream, &req).context("sending request")?;
    stream.flush().ok();
    let resp: Response = read_msg(&mut stream).context("reading response")?;
    Ok(resp)
}

fn expect_processes(resp: Response) -> Result<Vec<decant_protocol::ProcessInfo>> {
    match resp {
        Response::Processes(p) => Ok(p),
        other => Err(anyhow!(unexpected(other))),
    }
}

fn unexpected(resp: Response) -> String {
    match resp {
        Response::Err(e) => format!("daemon error: {e}"),
        other => format!("unexpected response: {other:?}"),
    }
}

fn parse_u64(s: &str) -> Result<u64> {
    let s = s.trim();
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)?
    } else {
        s.parse::<u64>()?
    };
    Ok(v)
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
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
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
        assert_eq!(parse_hex("de ad be ef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(parse_hex("0xDEAD").unwrap(), vec![0xde, 0xad]);
        assert!(parse_hex("abc").is_err());
    }
}
