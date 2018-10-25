
clean-android:
	-rm -rf .cargo
	-rm -rf NDK
	cargo clean

android:
	cargo build --features=u32_backend --target armv7-linux-androideabi --release
	mkdir -p ../jni/Credential/rust/src/main/jniLibs/armeabi-v7a/
	cp target/armv7-linux-androideabi/release/libcredential.so ../jni/Credential/rust/src/main/jniLibs/armeabi-v7a/
	-cargo build --features=u32_backend --target arm-linux-androideabi --release
	-mkdir -p  ../jni/Credential/rust/src/main/jniLibs/armeabi/
	-cp target/arm-linux-androideabi/release/libcredential.so ../jni/Credential/rust/src/main/jniLibs/armeabi/
	-cargo build --features=u64_backend --target x86_64-linux-android --release
	-mkdir -p ../jni/Credential/rust/src/main/jniLibs/x86_64/
	-cp target/x86_64-linux-android/release/libcredential.so  ../jni/Credential/rust/src/main/jniLibs/x86_64/
	cargo build --features=u64_backend --target aarch64-linux-android --release
	mkdir -p ../jni/Credential/rust/src/main/jniLibs/arm64-v8a/
	cp target/aarch64-linux-android/release/libcredential.so ../jni/Credential/rust/src/main/jniLibs/arm64-v8a/
	cargo build --features=u32_backend --target i686-linux-android --release
	mkdir -p ../jni/Credential/rust/src/main/jniLibs/x86/
	cp target/i686-linux-android/release/libcredential.so ../jni/Credential/rust/src/main/jniLibs/x86/

clean-ios:
	cargo clean

override platform=$(shell uname -s)

ios:
ifneq ($(platform),Darwin)
	$(error WARNING: Running `make ios` only works on MacOS machines)
endif
ifndef SIGNAL_CREDENTIAL_IOS_DIR
	$(error Please set the SIGNAL_CREDENTIAL_IOS_DIR environment variable to the output directory for compiled library and header files, e.g. .../signal-credential-swift/Credential/libcredential)
endif
	cargo lipo --release --features=u64_backend
	cp target/universal/release/libcredential.a $(SIGNAL_CREDENTIAL_IOS_DIR)/libcredential-ios.a
	cp src/include/credential.h $(SIGNAL_CREDENTIAL_IOS_DIR)
