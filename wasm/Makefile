
all: wasm

wasm:
	rustup target add wasm32-unknown-unknown --toolchain nightly
	cargo +nightly build --target wasm32-unknown-unknown --release
	cp target/wasm32-unknown-unknown/release/credential.wasm ./
	cargo install wasm-bindgen-cli
	wasm-bindgen credential.wasm --out-dir site
