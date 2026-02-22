# Arch-Sysup (Rust Edition)

A port of the Arch-Sysup system manager to Rust using [egui](https://github.com/emilk/egui)/eframe.
Produces a single self-contained binary with no Python or Tkinter dependency.

## Features

All tabs from the Python version:
- **Updates** — check and apply system/AUR updates with live log output
- **Search & Install** — search pacman + AUR, install or remove packages
- **Package Info** — look up any package's details and installed files
- **System Stats** — disk usage, package counts, uptime, kernel, charts
- **Orphans** — find and remove orphaned packages
- **Repositories** — enable/disable/add repos in `/etc/pacman.conf`
- **Mirrors** — configure and run reflector, edit `/etc/xdg/reflector/reflector.conf`

## Dependencies

Runtime:
```
gcc-libs  glibc  libxkbcommon  wayland  libGL
```

Optional:
```
yay or paru   — AUR helper (required for AUR updates/search)
reflector     — mirror management
librsvg       — rsvg-convert for SVG icon (sudo pacman -S librsvg)
```

Build:
```
rust  cargo
```

## Building from source

```bash
# Clone and build
git clone https://github.com/yourusername/arch-sysup-rs
cd arch-sysup-rs
cargo build --release

# Run directly
./target/release/arch-sysup

# Or install system-wide
sudo install -Dm755 target/release/arch-sysup /usr/bin/arch-sysup-rs
```

## Building with makepkg (AUR-style)

```bash
cd arch-sysup-rs
makepkg -si
```

> **Note:** The first build will download Rust crates (~150 MB). Subsequent builds
> use the cargo cache and are much faster.

## Running alongside the Python version

The binary installs as `arch-sysup-rs` so it does not conflict with the Python
`arch-sysup` package. Both can be installed simultaneously. The desktop entry
appears as **"Arch-Sysup (Rust)"**.

## Release build size

With `lto = true` and `strip = true` the binary is typically **~8–12 MB** on x86_64.

## Wayland vs X11

eframe supports both. On a Wayland session it uses the native Wayland backend
automatically. To force X11 (XWayland):
```bash
WAYLAND_DISPLAY="" arch-sysup-rs
```
