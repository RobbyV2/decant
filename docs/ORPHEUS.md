# Orpheus integration

Decant exposes a native [LeechCore](https://github.com/ufrisk/LeechCore) device named
`decant`. This lets [Orpheus](https://github.com/super2xl/orpheus) keep using its bundled
MemProcFS engine while Decant supplies the physical memory from a memflow connector.
No Orpheus fork or replacement `vmm.dll` is required.

```text
Orpheus -> vmm / MemProcFS -> leechcore_device_decant -> Decant RPC
                                                        |
                                                        v
                                             memflow qemu/kvm connector
                                                        |
                                                        v
                                                  Windows VM RAM
```

This is preferable to translating Orpheus's `VMMDLL_*` calls individually: MemProcFS still
owns page-table translation, process metadata, VAD discovery, DTBs, and refresh behavior.
The adapter only implements the raw physical scatter reads and writes LeechCore expects.

## Install

For a native Linux Orpheus build:

```bash
scripts/decant.sh orpheus install
```

This builds the plugin and installs it as
`~/.orpheus/dlls/leechcore_device_decant.so`. Orpheus preserves additional files in that
directory when it refreshes its bundled DLLs.

For Orpheus running under Decant's Wine prefix:

```bash
scripts/decant.sh orpheus install --platform windows
```

For native Windows, build the same DLL and copy it beside Orpheus's extracted
`leechcore.dll`:

```bash
scripts/decant.sh orpheus build windows
# artifact: target/x86_64-pc-windows-gnu/release/leechcore_device_decant.dll
```

The destination on Windows is `%APPDATA%\Orpheus\dlls`. `--dir PATH` overrides the
installer destination for portable or mounted Windows installations.

## Run

Start the memflow-backed daemon as usual:

```bash
MEMFLOW_PLUGIN_PATH=/opt/memflow \
  scripts/decant.sh daemon --connector qemu --vm win10
```

Then start Orpheus and ask it to connect with this LeechCore device string:

```text
decant://127.0.0.1:7878
```

Orpheus's current UI button sends the fixed device name `fpga`. With its MCP HTTP server
enabled, the supplied helper selects the custom device without changing Orpheus:

```bash
ORPHEUS_API_KEY='key from Orpheus Settings > MCP Server' \
  scripts/decant.sh orpheus connect
```

Set `ORPHEUS_MCP_URL` if Orpheus is not listening at `http://127.0.0.1:8765`, and set
`DECANT_ENDPOINT` when the daemon is elsewhere. The equivalent HTTP request is:

```bash
curl -H "Authorization: Bearer $ORPHEUS_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"device_type":"decant://127.0.0.1:7878"}' \
  http://127.0.0.1:8765/tools/connect_dma
```

When Orpheus and the daemon are on different machines, prefer a tunnel or private network.
The Decant TCP protocol is intentionally a local trusted transport and does not provide
authentication or encryption.

## Compatibility contract

- LeechCore external-device ABI: `LC_CONTEXT_VERSION` `0xc0e10004` (header 2.5). The plugin
  checks this at load time and fails closed on an incompatible ABI.
- Scatter ranges are capped at LeechCore's 4096-byte per-range limit and sent to the daemon
  in batches rather than one TCP round trip per page.
- Physical metadata and access are available only on a backend that exposes memflow's
  `PhysicalMemory` trait. The mock backend and ordinary high-level backends reject the
  Orpheus device cleanly.
- Orpheus remains responsible for its own caching and OS analysis. Decant does not fabricate
  process metadata for this path.

The adapter was designed against Orpheus's dynamically loaded `VMMDLL_*` surface and
LeechCore's documented external device mechanism. If a future LeechCore changes its context
ABI, update the C prefix declaration and version check together.
