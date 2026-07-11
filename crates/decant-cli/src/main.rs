use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand, ValueEnum};
use decant_client::Client;
use decant_inject::DecantConfig;
use decant_inject::guest::GuestInjectionPlan;
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
    GuestInject {
        config: PathBuf,
    },
    GuestUnmap {
        config: PathBuf,
    },
    /// List imported IAT entries that can be used as execution triggers.
    IatHooks {
        pid: u32,
        #[arg(long)]
        module: Option<String>,
    },
    /// Verify that one IAT entry is called within a bounded interval.
    IatProbe {
        pid: u32,
        #[arg(long)]
        module: String,
        #[arg(long)]
        import_module: String,
        #[arg(long)]
        function: String,
        #[arg(long)]
        stage_base: Option<String>,
        #[arg(long)]
        result_base: Option<String>,
        #[arg(long, default_value_t = 1_000)]
        timeout_ms: u32,
    },
    /// Send one fixed diagnostic request to a guest-inject fixture mailbox.
    FixtureControl {
        pid: u32,
        #[arg(value_enum)]
        request: FixtureControlRequest,
        #[arg(long, default_value_t = 2_000)]
        timeout_ms: u32,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FixtureControlRequest {
    Ping,
    FileIo,
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
        Cmd::GuestInject { config } => return guest_inject(&mut client, cli.json, &config),
        Cmd::GuestUnmap { config } => return guest_unmap(&mut client, cli.json, &config),
        Cmd::FixtureControl {
            pid,
            request,
            timeout_ms,
        } => return fixture_control(&mut client, cli.json, pid, request, timeout_ms),
        Cmd::IatHooks { pid, module } => (
            Request::GuestIatHooks {
                pid: Pid(pid),
                module,
            },
            None,
        ),
        Cmd::IatProbe {
            pid,
            module,
            import_module,
            function,
            stage_base,
            result_base,
            timeout_ms,
        } => (
            Request::GuestIatProbe {
                pid: Pid(pid),
                source_module: module,
                import_module,
                symbol: function,
                stage_base: stage_base
                    .as_deref()
                    .map(parse_u64)
                    .transpose()
                    .context("parsing --stage-base")?,
                result_base: result_base
                    .as_deref()
                    .map(parse_u64)
                    .transpose()
                    .context("parsing --result-base")?,
                timeout_ms,
            },
            None,
        ),
    };

    if let Request::GuestIatProbe { timeout_ms, .. } = &req {
        client.set_timeout(Duration::from_millis(
            u64::from(*timeout_ms).saturating_add(5_000),
        ));
    }

    let resp = client.send(req).context("daemon request")?;
    emit(resp, cli.json, read_base)
}

const FIXTURE_DIAGNOSTIC_MAGIC: &str = "44 45 43 41 4e 54 3a 3a 44 49 41 47 30 30 30 31";
const FIXTURE_DIAGNOSTIC_MAILBOX_LEN: usize = 120;
const FIXTURE_DIAGNOSTIC_REQUEST_OFFSET: u64 = 16;
const FIXTURE_DIAGNOSTIC_REQUEST_ID_OFFSET: u64 = 24;
const FIXTURE_DIAGNOSTIC_COMPLETED_ID_OFFSET: u64 = 32;
const FIXTURE_DIAGNOSTIC_STATUS_OFFSET: u64 = 40;
const FIXTURE_DIAGNOSTIC_TICK_OFFSET: u64 = 48;
const FIXTURE_DIAGNOSTIC_PAYLOAD_OFFSET: usize = 56;

fn fixture_control(
    client: &mut Client,
    json: bool,
    pid: u32,
    request: FixtureControlRequest,
    timeout_ms: u32,
) -> Result<()> {
    let pid = Pid(pid);
    let matches = client
        .scan(pid, FIXTURE_DIAGNOSTIC_MAGIC)
        .context("scanning fixture diagnostic mailbox")?;
    let mailbox = match matches.as_slice() {
        [mailbox] => *mailbox,
        [] => bail!("fixture diagnostic mailbox was not found"),
        _ => bail!(
            "fixture diagnostic mailbox is ambiguous; {} matches found",
            matches.len()
        ),
    };
    let initial = client
        .read(pid, mailbox, FIXTURE_DIAGNOSTIC_MAILBOX_LEN)
        .context("reading fixture diagnostic mailbox")?;
    let request_id = next_fixture_request_id(
        read_u64_at(&initial, FIXTURE_DIAGNOSTIC_REQUEST_ID_OFFSET as usize)?,
        read_u64_at(&initial, FIXTURE_DIAGNOSTIC_COMPLETED_ID_OFFSET as usize)?,
    );
    let request_code = match request {
        FixtureControlRequest::Ping => 1u64,
        FixtureControlRequest::FileIo => 2u64,
    };

    client
        .write(
            pid,
            mailbox + FIXTURE_DIAGNOSTIC_REQUEST_OFFSET,
            &request_code.to_le_bytes(),
        )
        .context("writing fixture diagnostic request")?;
    client
        .write(
            pid,
            mailbox + FIXTURE_DIAGNOSTIC_REQUEST_ID_OFFSET,
            &request_id.to_le_bytes(),
        )
        .context("committing fixture diagnostic request")?;

    let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
    loop {
        let state = client
            .read(pid, mailbox, FIXTURE_DIAGNOSTIC_MAILBOX_LEN)
            .context("reading fixture diagnostic result")?;
        let completed_id = read_u64_at(&state, FIXTURE_DIAGNOSTIC_COMPLETED_ID_OFFSET as usize)?;
        if completed_id == request_id {
            let status = read_u64_at(&state, FIXTURE_DIAGNOSTIC_STATUS_OFFSET as usize)?;
            let tick = read_u64_at(&state, FIXTURE_DIAGNOSTIC_TICK_OFFSET as usize)?;
            let payload = fixture_payload(&state)?;
            if status != 2 {
                bail!(
                    "fixture diagnostic {:?} failed with status={status}, payload={payload:?}",
                    request
                );
            }
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "pid": pid.0,
                        "mailbox": mailbox,
                        "request": request_name(request),
                        "request_id": request_id,
                        "status": status,
                        "tick": tick,
                        "payload": payload,
                    })
                );
            } else {
                println!("mailbox:    {mailbox:#018x}");
                println!("request:    {}", request_name(request));
                println!("request id: {request_id}");
                println!("status:     ok");
                println!("tick:       {tick}");
                println!("payload:    {payload}");
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "fixture diagnostic {} timed out after {timeout_ms} ms",
                request_name(request)
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn read_u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| anyhow!("fixture diagnostic offset overflow"))?;
    let value: [u8; 8] = bytes
        .get(offset..end)
        .ok_or_else(|| anyhow!("fixture diagnostic mailbox is truncated"))?
        .try_into()
        .map_err(|_| anyhow!("fixture diagnostic u64 is truncated"))?;
    Ok(u64::from_le_bytes(value))
}

fn next_fixture_request_id(request_id: u64, completed_id: u64) -> u64 {
    request_id.max(completed_id).wrapping_add(1).max(1)
}

fn fixture_payload(bytes: &[u8]) -> Result<String> {
    let payload = bytes
        .get(FIXTURE_DIAGNOSTIC_PAYLOAD_OFFSET..)
        .ok_or_else(|| anyhow!("fixture diagnostic payload is missing"))?;
    let end = payload
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(payload.len());
    Ok(String::from_utf8_lossy(&payload[..end]).into_owned())
}

fn request_name(request: FixtureControlRequest) -> &'static str {
    match request {
        FixtureControlRequest::Ping => "ping",
        FixtureControlRequest::FileIo => "file-io",
    }
}

fn guest_inject(client: &mut Client, json: bool, config_path: &Path) -> Result<()> {
    let config_toml = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let config = DecantConfig::from_toml_str(&config_toml)
        .map_err(|e| anyhow!("{e}"))
        .with_context(|| format!("loading {}", config_path.display()))?;
    let plan = GuestInjectionPlan::from_config(&config).map_err(|e| anyhow!("{e}"))?;
    let request_timeout_ms = u64::from(plan.timeout_ms)
        .saturating_add(u64::from(plan.execution.timeout_ms))
        .saturating_add(30_000)
        .max(300_000);
    client.set_timeout(Duration::from_millis(request_timeout_ms));
    let image = std::fs::read(&plan.payload_path)
        .with_context(|| format!("reading {}", plan.payload_path.display()))?;
    let resp = client
        .send(Request::GuestInject {
            config_toml,
            payload_image: image,
        })
        .context("guest injection request")?;
    let info = match resp {
        Response::GuestInjected(info) => info,
        Response::Err(e) => bail!("daemon error: {e}"),
        other => bail!("unexpected response: {other:?}"),
    };
    let image_allocation = match plan.image_backing.label() {
        "sec-image" => "sec-image",
        _ => plan.allocation.label(),
    };
    match json {
        true => {
            println!(
                "{}",
                serde_json::json!({
                    "target": plan.target.label(),
                    "payload_path": plan.payload_path,
                    "method": info.method,
                    "pid": info.pid.0,
                    "remote_base": info.remote_base,
                    "allocation": plan.allocation.label(),
                    "image_allocation": image_allocation,
                    "dependency_policy": plan.dependency_policy.label(),
                    "execution": plan.execution.method.label(),
                    "tls": plan.tls.label(),
                    "final_protections": plan.final_protections.label(),
                    "loader_metadata": plan.loader_metadata.label(),
                    "call_stack": plan.call_stack.label(),
                    "permission_transitions": plan.permission_transitions.label(),
                    "thread_starts": plan.thread_starts.label(),
                    "image_backing": plan.image_backing.label(),
                    "base_address": plan.base_address.label(),
                    "header_wipe": plan.header_wipe.label(),
                    "loader_entries": plan.loader_entries.label(),
                    "stack_shaping": plan.stack_shaping.label(),
                    "cleanup": plan.cleanup.label(),
                    "vad_spoof": plan.vad_spoof.label(),
                    "notes": info.notes,
                })
            );
        }
        false => {
            println!("target:          {}", plan.target.label());
            println!("payload:         {}", plan.payload_path.display());
            println!("method:          {}", info.method);
            println!("pid:             {}", info.pid);
            match info.remote_base {
                Some(base) => println!("remote base:     {base:#018x}"),
                None => println!("remote base:     <none>"),
            }
            println!("allocation:      {}", plan.allocation.label());
            println!("image allocation: {image_allocation}");
            println!("dependencies:    {}", plan.dependency_policy.label());
            println!("execution:       {}", plan.execution.method.label());
            println!("tls:             {}", plan.tls.label());
            println!("protections:     {}", plan.final_protections.label());
            println!("loader metadata: {}", plan.loader_metadata.label());
            println!("call stack:      {}", plan.call_stack.label());
            println!("perm transitions: {}", plan.permission_transitions.label());
            println!("thread starts:   {}", plan.thread_starts.label());
            println!("image backing:   {}", plan.image_backing.label());
            println!("base address:    {}", plan.base_address.label());
            println!("header wipe:     {}", plan.header_wipe.label());
            println!("loader entries:  {}", plan.loader_entries.label());
            println!("stack shaping:   {}", plan.stack_shaping.label());
            println!("cleanup:         {}", plan.cleanup.label());
            println!("vad spoof:       {}", plan.vad_spoof.label());
            for note in info.notes {
                println!("note:            {note}");
            }
        }
    }
    Ok(())
}

fn guest_unmap(client: &mut Client, json: bool, config_path: &Path) -> Result<()> {
    let config_toml = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let config = DecantConfig::from_toml_str(&config_toml)
        .map_err(|e| anyhow!("{e}"))
        .with_context(|| format!("loading {}", config_path.display()))?;
    let plan = GuestInjectionPlan::from_config(&config).map_err(|e| anyhow!("{e}"))?;
    let request_timeout_ms = u64::from(plan.timeout_ms)
        .saturating_add(u64::from(plan.execution.timeout_ms))
        .saturating_add(30_000)
        .max(300_000);
    client.set_timeout(Duration::from_millis(request_timeout_ms));
    let resp = client
        .send(Request::GuestUnmap { config_toml })
        .context("guest unmap request")?;
    let info = match resp {
        Response::GuestUnmapped(info) => info,
        Response::Err(e) => bail!("daemon error: {e}"),
        other => bail!("unexpected response: {other:?}"),
    };
    if json {
        println!(
            "{}",
            serde_json::json!({
                "target": plan.target.label(),
                "pid": info.pid.0,
                "modules_unmapped": info.modules_unmapped,
            })
        );
    } else {
        println!("target:          {}", plan.target.label());
        println!("pid:             {}", info.pid);
        println!("modules unmapped: {}", info.modules_unmapped);
    }
    Ok(())
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
        Response::GuestUnmapped(info) => {
            println!("pid:             {}", info.pid);
            println!("modules unmapped: {}", info.modules_unmapped);
        }
        Response::GuestIatHooks(candidates) => {
            if candidates.is_empty() {
                println!("(no IAT hook candidates)");
            }
            for candidate in candidates {
                println!(
                    "priority={:<3}  {}: {}!{}  slot={:#018x} target={:#018x}",
                    candidate.priority,
                    candidate.source_module,
                    candidate.import_module,
                    candidate.symbol,
                    candidate.iat_slot,
                    candidate.original_target,
                );
            }
        }
        Response::GuestIatProbe(probe) => {
            let candidate = probe.candidate;
            println!(
                "candidate:       {}: {}!{}",
                candidate.source_module, candidate.import_module, candidate.symbol
            );
            println!("IAT slot:        {:#018x}", candidate.iat_slot);
            println!("original target: {:#018x}", candidate.original_target);
            println!("observed:        {}", probe.observed);
            match probe.servicing_tid {
                Some(tid) => println!("servicing tid:   {tid}"),
                None => println!("servicing tid:   <none>"),
            }
            println!("timeout:         {} ms", probe.timeout_ms);
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

    #[test]
    fn fixture_request_id_advances_without_using_zero() {
        assert_eq!(next_fixture_request_id(0, 0), 1);
        assert_eq!(next_fixture_request_id(4, 7), 8);
        assert_eq!(next_fixture_request_id(u64::MAX, u64::MAX), 1);
    }

    #[test]
    fn fixture_payload_stops_at_nul() {
        let mut mailbox = vec![0u8; FIXTURE_DIAGNOSTIC_MAILBOX_LEN];
        mailbox[FIXTURE_DIAGNOSTIC_PAYLOAD_OFFSET..FIXTURE_DIAGNOSTIC_PAYLOAD_OFFSET + 4]
            .copy_from_slice(b"pong");
        assert_eq!(fixture_payload(&mailbox).unwrap(), "pong");
    }
}
