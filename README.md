## vps-audit

Self-contained VPS security and performance audit CLI.

### Install & Run (one-liner)

Linux (detect arch):
```bash
ARCH=$(uname -m); URL="";
if [ "$ARCH" = "x86_64" ] || [ "$ARCH" = "amd64" ]; then URL="https://github.com/milangress/vps-audit/releases/latest/download/vps-audit-linux-x86_64"; fi
if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then URL="https://github.com/milangress/vps-audit/releases/latest/download/vps-audit-linux-aarch64"; fi
curl -sL "$URL" -o /usr/local/bin/vps-audit && chmod +x /usr/local/bin/vps-audit && vps-audit --help
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


