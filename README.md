# cfscan_proto

> **⚠️ EDUCATIONAL AND RESEARCH USE ONLY — NOT FOR UNAUTHORIZED SCANNING ⚠️**
>
> This project is provided **strictly for educational, academic research, and authorized security testing purposes**.
>
> - You may only use this tool on infrastructure that you **own** or for which you have obtained **explicit, written authorization** to test.
> - Scanning IP addresses, networks, or services without authorization is illegal in most jurisdictions and may violate computer fraud, unauthorized access, or cybersecurity laws.
> - The authors and contributors accept **no liability** for any misuse, damage, legal consequences, or harm arising from the use of this software.
> - If you are unsure whether your intended use is authorized, **do not use this tool**.
>
> By using this software you acknowledge that you understand and will comply with all applicable laws and that you are using it solely for legitimate educational or research purposes on authorized targets.

`cfscan_proto` is a single-connection Cloudflare edge probe that classifies target IPs from a JSONL output stream. It is written in Go, builds without cgo, and cross-compiles to Linux, macOS, and Windows.

**Use this tool only on infrastructure you own or are authorized to test.**

## What it does

For each target IP, the scanner:

1. Opens one TCP connection to port `443`
2. Negotiates TLS 1.3 with the configured Cloudflare worker hostname as SNI
3. Sends an HTTP `GET` to the worker path
4. Reads the response in fixed-size time buckets
5. Emits a verdict and diagnostic timing data as JSONL

Candidates can then be rechecked with a spaced verify pass.

## Build

```sh
make
```

This produces `./cfscan_proto` for the host platform.

To cross-compile release binaries:

```sh
mkdir -p dist
make all
```

Artifacts are written to `dist/`:

- `cfscan_proto-linux-amd64`
- `cfscan_proto-linux-arm64`
- `cfscan_proto-darwin-amd64`
- `cfscan_proto-darwin-arm64`
- `cfscan_proto-windows-amd64.exe`
- `cfscan_proto-windows-arm64.exe`

To clean local build outputs:

```sh
make clean
```

## Requirements

- Go 1.24 or newer
- A Cloudflare Worker or Pages deployment to use as the probe endpoint
- A target file containing IPv4 addresses and/or CIDR ranges

## Worker endpoint

The scanner requires a grey Cloudflare worker hostname. A sample worker is included in [`worker_firehose.js`](worker_firehose.js).

Deploy it through the Cloudflare dashboard or with Wrangler:

```toml
# wrangler.toml
name = "firehose"
main = "worker_firehose.js"
compatibility_date = "2024-01-01"
```

```sh
wrangler deploy
```

Pass the resulting `*.workers.dev` hostname with `-worker-host`.

## Targets file

`-targets` accepts one IPv4 address or CIDR per line. Blank lines and comments are ignored.

```text
8.48.131.1
8.39.126.0/24
104.16.0.0/12
192.0.2.0/30
```

CIDRs are expanded, deduplicated, and then shuffled by default so probes are spread across the full set instead of hitting one `/24` sequentially.

## Run

Minimal example:

```sh
./cfscan_proto \
  -worker-host your-worker.example.workers.dev \
  -targets targets.txt \
  -out results.jsonl
```

The scanner performs a preflight check by default. If you already know the probe environment is acceptable, `-skip-preflight` disables it.

Common flags:

- `-worker-host` Cloudflare worker hostname used for SNI and `Host`
- `-get-path` request path on the worker, default `/stream`
- `-dial-to` TCP dial timeout, default `500ms`
- `-tls-to` TLS handshake and write deadline, default `1.5s`
- `-first-byte-to` maximum wait for the first response byte, default `400ms`
- `-stream-secs` response read window after the first byte, default `1.5`
- `-bucket-ms` bucket width in milliseconds, default `250`
- `-c` concurrency, default `64`
- `-skip-24-after` skip the rest of a `/24` after repeated unusable hits, default `5`
- `-verify` run the verify pass on `clean-candidate` results, default `true`
- `-verify-intervals` comma-separated retry delays, default `30s,60s,2m,5m,10m`
- `-verify-pass-min` minimum clean retries required to confirm `CLEAN`, default `4`
- `-no-shuffle` preserve input order
- `-shuffle-seed` set a reproducible shuffle seed
- `-out` JSONL output path, default `cfscan_proto.jsonl`

## Verdicts

Main-pass rows are classified into:

- `tcp-dead`
- `tls-fail`
- `starved`
- `gray`
- `clean-candidate`
- `partial`
- `skipped-24-saturated`

If `-verify` is enabled, each `clean-candidate` is retried on the configured schedule. A candidate is marked `CLEAN` when it reaches at least `-verify-pass-min` clean-candidate verdicts.

## Output format

Output is newline-delimited JSON.

The first line is always a metadata object:

```json
{
  "kind": "meta",
  "tool_version": "s9-cfscan-proto-2026-05-31-cidr",
  "host_os": "linux",
  "host_arch": "amd64",
  "unix_ms_start": 1748678400000,
  "worker_host": "your-worker.example.workers.dev",
  "get_path": "/stream",
  "dial_to": "500ms",
  "tls_to": "1.5s",
  "first_byte_to": "400ms",
  "stream_secs": 1.5,
  "bucket_ms": 250,
  "c": 64,
  "skip_24_after": 5,
  "verify_intervals": "30s,60s,2m,5m,10m",
  "verify_pass_min": 4,
  "preflight_ip": "104.19.229.21",
  "skip_preflight": false,
  "n_targets": 12345,
  "n_input_lines": 12000,
  "n_cidrs": 300,
  "shuffled": true,
  "shuffle_seed": 123456789,
  "targets_path": "targets.txt"
}
```

Each subsequent line is a probe result:

```json
{
  "ip": "8.48.131.1",
  "stage": "main",
  "delay_secs": 0,
  "tcp_ok": true,
  "tls_ok": true,
  "http_code": 200,
  "server": "cloudflare",
  "total_bytes": 1234567,
  "bucket_ms": 250,
  "buckets": [475157, 2146296, 4847583],
  "verdict": "clean-candidate",
  "rtt_ms": 157,
  "tls_ms": 89,
  "first_byte_ms": 78,
  "unix_ms": 1748678400000
}
```

Important fields:

- `stage` is `main` or `verify-N`
- `delay_secs` is only used for verify retries
- `verdict` is the scanner classification for that row
- `rtt_ms`, `tls_ms`, and `first_byte_ms` are diagnostic timing values

When parsing results, skip the first line if `kind == "meta"`.

## Example workflow

```sh
make
./cfscan_proto \
  -worker-host your-worker.example.workers.dev \
  -targets cf_full.txt \
  -out run.jsonl
```

If you want reproducible ordering for comparison runs:

```sh
./cfscan_proto \
  -worker-host your-worker.example.workers.dev \
  -targets cf_full.txt \
  -shuffle-seed 12345 \
  -out run.jsonl
```

## Repository files

- [`main.go`](main.go) scanner implementation
- [`worker_firehose.js`](worker_firehose.js) sample Cloudflare Worker
- [`cf_full.txt`](cf_full.txt) example Cloudflare target list
- [`Makefile`](Makefile) build and cross-build targets
