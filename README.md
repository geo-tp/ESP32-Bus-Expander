# ESP32 Bus Expander - Upstream firmware

Firmware components generated automatically from the latest commit
on the `main` branch.

**These files are development builds, not stable releases.**

- Branch: `main`
- Commit: [`fb272c1d25baaa179c7099864f7a51053f0b6176`](https://github.com/geo-tp/ESP32-Bus-Expander/commit/fb272c1d25baaa179c7099864f7a51053f0b6176)
- Build date: `2026-09-04T14:43:55Z`

## Flashing

Each environment contains four separate files:

- `boot_app0.bin`
- `bootloader.bin`
- `firmware.bin`
- `partitions.bin`

Flash offsets:

| Environment | bootloader | partitions | boot_app0 | firmware |
|---|---:|---:|---:|---:|
| `c5slave` | `0x2000` | `0x8000` | `0xE000` | `0x10000` |
| `c6slave` | `0x0000` | `0x8000` | `0xE000` | `0x10000` |

## Downloads

### `c5slave`

- [boot_app0.bin](downloads/c5slave/boot_app0.bin)
- [bootloader.bin](downloads/c5slave/bootloader.bin)
- [firmware.bin](downloads/c5slave/firmware.bin)
- [partitions.bin](downloads/c5slave/partitions.bin)

### `c6slave`

- [boot_app0.bin](downloads/c6slave/boot_app0.bin)
- [bootloader.bin](downloads/c6slave/bootloader.bin)
- [firmware.bin](downloads/c6slave/firmware.bin)
- [partitions.bin](downloads/c6slave/partitions.bin)

## Verification

SHA-256 checksums are available in
[SHA256SUMS.txt](SHA256SUMS.txt).

Generated automatically from commit `fb272c1`.
