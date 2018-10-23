
all: wasm

wasm:
	rustup target add wasm32-unknown-unknown --toolchain nightly
	-cargo install wasm-bindgen-cli
	cargo +nightly build --target wasm32-unknown-unknown --release
	cp target/wasm32-unknown-unknown/release/credential.wasm src
	wasm-bindgen --no-modules src/credential.wasm --out-dir src
