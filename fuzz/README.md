# Fuzzing mdns-sd

The targets here run under [`cargo-fuzz`] (libFuzzer). They are a separate crate
with their own workspace, so `cargo build` and `cargo clippy` at the repo root
never build them, and the crate's MSRV is unaffected.

## Setup

```sh
cargo install cargo-fuzz
rustup toolchain install nightly   # libFuzzer needs nightly
```

## Running

```sh
cargo +nightly fuzz run parse_packet
```

That is the whole command. cargo-fuzz supplies the corpus directory
(`fuzz/corpus/<target>`, created if absent) and the artifact prefix, and the run
continues until interrupted. Pass libFuzzer's own options after a `--`:
`-max_total_time=60` to bound a run, `-jobs=8` to use more cores.

New inputs accumulate in `fuzz/corpus/`, which is not tracked by git, so later
runs build on whatever earlier ones found.

Two options worth *not* reaching for on this target. A dictionary made no
measurable difference: over 30-second cold starts it landed within noise of the
bare command. Neither did `-max_len`, because `DnsIncoming::new` has no
size-dependent branch — `MAX_PKT_ABSOLUTE_IPV4` bounds the encoder, not the
parser — so libFuzzer's default 4096-byte cap costs nothing here. A future
target that exercises `DnsOutgoing::to_packets` would want `-max_len=8972`.

## Targets

| Target | What it covers |
| --- | --- |
| `parse_packet` | `DnsIncoming::new` on raw bytes — the code that `ServiceDaemon` runs on whatever arrives on its UDP socket. |

## Reaching crate internals

`dns_parser` is private, so a fuzz target — a separate crate — cannot call it.
The `unstable-fuzz-api` feature exposes [`src/fuzz_api.rs`](../src/fuzz_api.rs),
a `#[doc(hidden)]` module of thin wrappers. It is not public API and carries no
stability guarantee. Targets that need to reach further in (`dns_cache`, say)
should add a wrapper there rather than widening any module's visibility.

## When a target finds something

libFuzzer writes the input to `fuzz/artifacts/<target>/`. Reproduce it with:

```sh
cargo +nightly fuzz run parse_packet fuzz/artifacts/parse_packet/crash-<hash>
```

Once fixed, add a regression test to the crate so the case is covered by
`cargo test` on stable, the way `test_hinfo_char_string_at_end_of_packet` covers
the first crash this target found.

[`cargo-fuzz`]: https://github.com/rust-fuzz/cargo-fuzz
