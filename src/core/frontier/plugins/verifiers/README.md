# Neural-Mesh WASM Verifiers

This directory contains hardware-isolated security verifiers used by the Autonomous Exploitation & Verification Engine (AEVE).

## Architecture
Verifiers are compiled to WebAssembly (WASM) and executed within a restricted `wasmtime` sandbox. This ensures that even complex PoC logic (e.g., protocol-level fuzzing or state-machine analysis) cannot compromise the host node.

## Contract
WASM modules must export the following functions:
- `allocate(size: i32) -> i32`: Reserve memory for input.
- `run_detector(ptr: i32, len: i32) -> i32`: Execute verification logic. Returns a pointer to a buffer where the first 4 bytes are the length of the resulting JSON string, followed by the JSON data.
- `deallocate(ptr: i32)`: Release memory.
- `memory`: The linear memory instance.

## Development
To build a new verifier:
1. Write the logic in C, Rust, or AssemblyScript.
2. Compile to `wasm32-wasi`.
3. Place the `.wasm` file in this directory named as `{category}_verifier.wasm`.

The generic verifier (`generic_verifier.wasm`) is used as a fallback for unsupported vulnerability categories.
