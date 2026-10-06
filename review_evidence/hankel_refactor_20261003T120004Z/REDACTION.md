# Redaction note (2026-10-07)

Before the repository was made public, absolute local paths were removed from this directory. Nothing
else changed: no measurement, result or verdict was edited.

- The working-directory prefix of the original runs is written `<workdir>`, and the home directory `~`.
- The two compiled sanitizer harnesses and their `.dSYM` bundles were removed, because their debug
  information embeds the same paths. They are build outputs of `native_sanitizer/tail_harness.c`, which
  remains, together with the compile commands, logs and results of both runs.
- The SHA-256 manifests were updated to the redacted files, and their records of the removed files
  were dropped. Every remaining record still matches the file on disk.

## Files changed (SHA-256 before and after, first 16 hex digits)

| File | Original | Redacted |
| :--- | :--- | :--- |
| `RESULT.json` | `68070348d63660e5…` | `9908e30353e91a60…` |
| `baseline_origin.json` | `2b108dc46b9fe55f…` | `f08daeb1e752871b…` |
| `manifest.json` | `6b3db88ba6077a66…` | `c000bc52618e8759…` |
| `native_candidate/benchmark.json` | `6077eefce130ddf4…` | `3bbcbcfe37298102…` |
| `native_candidate/benchmark_unique.json` | `579169057ac08f36…` | `29ba8c21ef9696fa…` |
| `native_candidate/manifest.json` | `e139b8d9128e42a3…` | `9d540c0c6516cc05…` |
| `native_candidate/verification.json` | `a8b977ec1b667597…` | `fb6848ee311a044b…` |
| `native_candidate/verification.stdout.log` | `eb2f5e80711b02fb…` | `cd7de22c5df40fa6…` |
| `native_candidate/verification_final.json` | `3d5e5418c909401a…` | `b5d24f7765177560…` |
| `native_candidate/verification_final.stdout.log` | `54d310f35d14e23a…` | `6b30931dc398195e…` |
| `native_sanitizer/all_runs_manifest.json` | `a0fb8335ab9e3ffa…` | `53868fc1dfc83341…` |
| `native_sanitizer/arm64/compile.log` | `78c6734e1e944178…` | `c920c45cb180f225…` |
| `native_sanitizer/arm64/manifest.json` | `627d70dab8c594c2…` | `7bb8a93281d44011…` |
| `native_sanitizer/arm64/results.json` | `5ac3316f05184484…` | `d8b9238001427fa1…` |
| `native_sanitizer/compile.log` | `e15202ba3c1c8d82…` | `8cc6718c09e75af2…` |
| `native_sanitizer/manifest.json` | `0a8370c4b1951aa0…` | `90b5cf4047189b5d…` |
| `native_sanitizer/results.json` | `6f43c4470f17951d…` | `70dd978e8adb7086…` |
| `new_vector_generation.log` | `c0eeaa7e218cbd9a…` | `e2f139bceff30695…` |
| `original_vs_refactor_handshake.json` | `1f21e89553d3f28d…` | `9455a289e020089a…` |
| `regressions.status.json` | `e975ec78b1cee03c…` | `063e1cc78f7c80ff…` |
| `retained_kat_failure.json` | `12ae1dbeb17f2df0…` | `7d1ade36d7d245da…` |
| `retained_kat_failure.log` | `3876262d72b170ab…` | `1b1d4a9a2c2dc382…` |

## Files removed (original SHA-256)

| File | SHA-256 |
| :--- | :--- |
| `native_sanitizer/arm64/tail_harness_asan_ubsan` | `4f2d3e3c2cb41336b1ac6286beb773d26d0b82c7ad7a83db9324fc777b966a20` |
| `native_sanitizer/arm64/tail_harness_asan_ubsan.dSYM/Contents/Info.plist` | `100a2a9d5bf9b08fd67b1ec14f7602f50c1d1f527a44ca3966a9c75fc4e625f0` |
| `native_sanitizer/arm64/tail_harness_asan_ubsan.dSYM/Contents/Resources/DWARF/tail_harness_asan_ubsan` | `31b33a8d7f98f19d1f31385485a3839529675deb7a547d169cfc797052cb44e7` |
| `native_sanitizer/arm64/tail_harness_asan_ubsan.dSYM/Contents/Resources/Relocations/aarch64/tail_harness_asan_ubsan.yml` | `ea10980cb32ee24309bca5494e43107bd03f1a861c07e9c230e5fb4cf6df015b` |
| `native_sanitizer/tail_harness_asan_ubsan` | `e44194570b80357098cf4a12a40f3a9ecc223d11885a8c2b44d41f10d5202883` |
| `native_sanitizer/tail_harness_asan_ubsan.dSYM/Contents/Info.plist` | `100a2a9d5bf9b08fd67b1ec14f7602f50c1d1f527a44ca3966a9c75fc4e625f0` |
| `native_sanitizer/tail_harness_asan_ubsan.dSYM/Contents/Resources/DWARF/tail_harness_asan_ubsan` | `7593ec546eaf7dd48d4ea54391ffb6b13e408e00226951c073bd3059e6b35e5f` |
| `native_sanitizer/tail_harness_asan_ubsan.dSYM/Contents/Resources/Relocations/x86_64/tail_harness_asan_ubsan.yml` | `bb723324d959368ace3282954ba67610374af462fe37f9a29e94bae938a99e3a` |
