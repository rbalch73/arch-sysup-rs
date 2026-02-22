# Maintainer: Your Name <you@example.com>
pkgname=arch-sysup-rs
pkgver=1.0.0
pkgrel=1
pkgdesc="Arch Linux GUI system manager — Rust/egui edition"
arch=('x86_64')
license=('MIT')
depends=(
    'gcc-libs'
    'glibc'
    'libxkbcommon'
    'wayland'
    'libgl'
)
optdepends=(
    'yay: AUR helper support'
    'paru: AUR helper support (alternative to yay)'
    'reflector: mirror management support'
    'librsvg: SVG icon rendering (rsvg-convert)'
)
makedepends=('rust' 'cargo')

# No source= array — makepkg builds from the directory it lives in
source=()
sha256sums=()

build() {
    # Build from the repo root (where Cargo.toml lives)
    cd "$startdir"
    cargo build --release 2>&1
}

package() {
    cd "$startdir"

    # Binary — installs as arch-sysup-rs to avoid conflict with the Python package
    install -Dm755 "target/release/arch-sysup" \
        "$pkgdir/usr/bin/arch-sysup-rs"

    # Desktop entry
    install -Dm644 /dev/stdin \
        "$pkgdir/usr/share/applications/arch-sysup-rs.desktop" << DESKTOP
[Desktop Entry]
Name=Arch-Sysup (Rust)
Comment=Arch Linux system manager — Rust edition
Exec=/usr/bin/arch-sysup-rs
Icon=arch-sysup
Terminal=false
Type=Application
Categories=System;PackageManager;
Keywords=pacman;arch;update;packages;
DESKTOP

    # Icon (shared with the Python package — safe since it's identical)
    install -Dm644 "arch-sysup.svg" \
        "$pkgdir/usr/share/icons/hicolor/scalable/apps/arch-sysup.svg"
}
