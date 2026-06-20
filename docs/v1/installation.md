# Installation v1

## Distribution Status

Versioned binaries and Linux packages are published through
[GitHub Releases](https://github.com/sayseven7/frameseven/releases).

GitHub Releases is the official distribution channel. Use a release artifact
or build the project from source for development.

Each release provides:

- CLI and MCP Linux binaries for `amd64` and `arm64`
- CLI and MCP macOS binaries for `amd64` and `arm64`
- CLI and MCP Windows binaries for `amd64`
- Debian packages for `amd64` and `arm64`
- RPM packages for `amd64` and `arm64`
- Arch Linux packages for `amd64` and `arm64`
- Docker image v1 for `linux/amd64` and `linux/arm64`
- A `SHA256SUMS` file for artifact verification

Release tags use the `vX.Y.Z` format. Artifact and package versions omit the
leading `v`.

Release assets follow this naming convention:

```text
frameseven_<component>_<version>_<os>_<arch>.<format>
```

The component is `cli` or `mcp`. Linux packages currently install the CLI
binary and therefore use the `cli` component.

The public operating system names are `linux`, `macos`, and `windows`.

## Requirements

- A supported Linux, macOS, or Windows system
- Network access to the authorized scan target
- Python 3 with `fpdf2` for PDF report generation

Building from source additionally requires Git and Go 1.26.4 or later in the
Go 1.26 release line.

Install the Python PDF dependency with your environment manager of choice, for
example:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install "fpdf2>=2.8"
```

CLI v1 and MCP report rendering use `FRAMESEVEN_PYTHON` when set, then
`.venv/bin/python`, then `python3`. If Python is missing, `fpdf2` is not
installed, or the Python renderer fails, PDF generation returns a clear error
through the Go wrapper.

## Debian and Ubuntu

Download the `.deb` file for your architecture from the
[release page](https://github.com/sayseven7/frameseven/releases), then install
it:

```bash
sudo apt install ./frameseven_cli_<version>_linux_amd64.deb
```

Use the `arm64` package instead when running a 64-bit ARM system.

Verify the installation:

```bash
frameseven -h
```

## Red Hat, Fedora, and RPM-Based Distributions

Download the `.rpm` file for your architecture from the release page, then
install it:

```bash
sudo dnf install ./frameseven_cli_<version>_linux_amd64.rpm
```

Use the `arm64` package instead when running a 64-bit ARM system.

## Arch Linux

Download the `.pkg.tar.zst` file for your architecture from the release page,
then install it:

```bash
sudo pacman -U ./frameseven_cli_<version>_linux_amd64.pkg.tar.zst
```

Use the `arm64` package instead when running a 64-bit ARM system.

## Linux and macOS Archive

Download the archive for your operating system and architecture, extract it,
and install the binary in a directory included in `PATH`:

```bash
tar -xzf frameseven_cli_<version>_linux_amd64.tar.gz
sudo install -m 0755 \
  frameseven_cli_<version>_linux_amd64/frameseven-cli \
  /usr/local/bin/frameseven
```

For the MCP server, download the `mcp` archive instead:

```bash
tar -xzf frameseven_mcp_<version>_linux_amd64.tar.gz
sudo install -m 0755 \
  frameseven_mcp_<version>_linux_amd64/frameseven-mcp \
  /usr/local/bin/frameseven-mcp
```

## Windows Archive

Download and extract the Windows `.zip` file from the release page. Add the
directory containing `frameseven-cli.exe` or `frameseven-mcp.exe` to `PATH`.

## Docker Image v1

Release images are published to GitHub Container Registry:

```text
ghcr.io/sayseven7/frameseven
```

The image includes the CLI v1 command, the MCP server, Python 3 with `fpdf2`,
Nmap, sqlmap, Chromium for browser authentication capture, certificates, and
font packages required by the runtime.

For release `v1.2.3`, the Docker tags are `v1.2.3` and `1.2.3`. Stable
releases also update `latest`.

Pull a versioned release image:

```bash
docker pull ghcr.io/sayseven7/frameseven:v<version>
```

Run a CLI scan and keep reports on the host:

```bash
mkdir -p reports
docker run --rm \
  -v "$PWD/reports:/workspace/reports" \
  ghcr.io/sayseven7/frameseven:v<version> \
  -url https://target.example \
  -out /workspace/reports
```

Run all Framework v1 tools, including the external `nmap` and `sqlmap`
modules:

```bash
docker run --rm \
  -v "$PWD/reports:/workspace/reports" \
  ghcr.io/sayseven7/frameseven:v<version> \
  -url https://target.example \
  -tools all \
  -out /workspace/reports
```

Start the MCP server from the same image by overriding the entrypoint:

```bash
docker run --rm -i \
  --entrypoint frameseven-mcp \
  ghcr.io/sayseven7/frameseven:v<version> \
  -transport stdio
```

Run the MCP server over Streamable HTTP:

```bash
docker run --rm \
  -p 127.0.0.1:8080:8080 \
  --entrypoint frameseven-mcp \
  ghcr.io/sayseven7/frameseven:v<version> \
  -transport http \
  -addr 0.0.0.0:8080
```

The HTTP MCP endpoint is `/mcp`. Keep the port bound to localhost or another
access-controlled network.

For authenticated scans with `-auth-browser`, the container must be able to
open a visible Chromium window through your host display server. On Linux/X11:

```bash
xhost +local:
docker run --rm -it \
  -e DISPLAY="$DISPLAY" \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  -v "$PWD/reports:/workspace/reports" \
  ghcr.io/sayseven7/frameseven:v<version> \
  -url https://target.example \
  -auth-browser \
  -out /workspace/reports
```

If the host reports directory is not writable by the image user, pass your user
and group IDs:

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/reports:/workspace/reports" \
  ghcr.io/sayseven7/frameseven:v<version> \
  -url https://target.example \
  -out /workspace/reports
```

## Verify a Download

Download `SHA256SUMS` alongside the selected artifact:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

## Build from Source

```bash
git clone https://github.com/sayseven7/frameseven.git
cd frameseven
go test ./...
go build -o bin/frameseven/cli/v1 cmd/cli/v1/main.go
go build -o bin/frameseven/mcp cmd/mcp/main.go
```

Run the built command:

```bash
./bin/frameseven/cli/v1 -url https://target.example
```

Run the MCP server over stdin/stdout:

```bash
./bin/frameseven/mcp
```

Run the MCP server over Streamable HTTP for remote agents:

```bash
./bin/frameseven/mcp -transport http -addr 127.0.0.1:8080
```

The HTTP MCP endpoint is `/mcp`.

## Install a Development Build

Install the current build as `frameseven` in a directory already included in
your `PATH`:

```bash
mkdir -p "$HOME/.local/bin"
install -m 0755 bin/frameseven/cli/v1 "$HOME/.local/bin/frameseven"
```

Verify the command:

```bash
frameseven -h
```

This installs a local development build instead of a versioned release
artifact.

## Optional NVD API Key

The CVE tool can use an NVD API key to increase the API request limit:

```bash
export NVD_API_KEY=your-key
```

The key is optional and is read at runtime.
