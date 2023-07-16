# There are 3 compilation configurations:
# 1. building the wasm verifier binary (no features)
# 2. building the proof
# 3. (compile and) execute the wasm binary with wasmer with the proof as input

wasm:
	cargo build --release --target wasm32-unknown-unknown
	cp ./target/wasm32-unknown-unknown/release/wasm_verifier_arithmetic.wasm ./

run-wasm: wasm
	wasmer run wasm_verifier_arithmetic.wasm --singlepass --entrypoint entrypoint

gen-proof:
	cargo test --features gen_proof test_circuit -- --nocapture
	cp ./target/layout.png .
	
wasm-verify: wasm
	cargo test --features wasm_verify test_wasm_verify -- --nocapture
