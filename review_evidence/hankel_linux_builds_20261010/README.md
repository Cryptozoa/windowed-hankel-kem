# Linux builds (October 10, 2026)

`make clean && make && make test` in Docker containers based on `python:3.12-slim` (Debian, GCC 14.2,
Python 3.12.15, NumPy 2.5.3), with the repository mounted read-only and copied into the container:

| Platform | Result | Log |
| :--- | :--- | :--- |
| Linux aarch64 (native on Apple Silicon) | `make test` exit 0; 41 checks pass; the static audit is skipped | `linux_arm64_make_test.txt` |
| Linux x86_64 (emulated) | `make test` exit 0; 41 checks pass; the static audit is skipped | `linux_x86_64_make_test.txt` |

Both builds reproduce every known-answer test of all three parameter sets. On x86-64 the NEON source
compiles to its portable fallback, which `test_hankel_neon.py` still checks (its banner says "ARM64 NEON"
regardless of platform). The static constant-time audit needs `otool` and an ARM64 Mach-O library, so it
runs only on macOS with Apple Silicon. The fixed-versus-random timing tests pass on both, but timings
under emulation say nothing about side channels; the constant-time evidence of the paper is for ARM64.

The ARM64 log ends with a short benchmark: the Linux build, with GCC and generic flags, takes about
132 microseconds per WH-640 handshake, against 51 on macOS with Apple clang.
