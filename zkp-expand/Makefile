
all: zkp-expand

FEATURES:=u64_backend

dependencies:
	rustup component add rustfmt-preview --toolchain nightly

expand-aeonflux:
	cp ../aeonflux/src/proofs.rs ./src/
	cargo expand --features="$(FEATURES)" > aeonflux_proofs.rs

expand-signal-credential:
	cp ../signal-credential/src/proofs.rs ./src/
	cargo expand --features="$(FEATURES)" > signal_credential_proofs.rs

expand: expand-aeonflux expand-signal-credential

format:
	rustfmt aeonflux_proofs.rs
	rustfmt signal_credential_proofs.rs

zkp-expand: expand clean

clean:
	-rm src/proofs.rs
