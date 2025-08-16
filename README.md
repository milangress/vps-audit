## vps-audit

Self-contained VPS security and performance audit CLI.

### Install & Run (one-liner)

Linux x86_64:
```bash
curl -sL https://github.com/milangress/vps-audit/releases/latest/download/vps-audit-linux-x86_64 -o /usr/local/bin/vps-audit && chmod +x /usr/local/bin/vps-audit && vps-audit --help
```

### Build from source
```bash
cargo build --release
./target/release/vps-audit --help
```

### Examples
```bash
vps-audit --verbose
vps-audit --format json --strict
vps-audit --interactive --categories security,linux
```


