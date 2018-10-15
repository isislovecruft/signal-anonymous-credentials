#
#  Be sure to run `pod spec lint credential.podspec' to ensure this is a
#  valid spec and to remove all comments including this before submitting the spec.
#
#  To learn more about Podspec attributes see http://docs.cocoapods.org/specification.html
#  To see working Podspecs in the CocoaPods repo see https://github.com/CocoaPods/Specs/
#

Pod::Spec.new do |s|
  s.name         = "credential"
  s.version      = "0.0.3"
  s.summary      = "A Swift FFI API for working with the Rust signal-credential crate."
  s.homepage     = "https://signal.org/"
  s.license      = "MIT (example)"
  s.license      = { :type => "BSD", :file => "LICENSE" }
  s.authors      = { "isis lovecruft" => "isis@patternsinthevoid.net" }
  s.source = { :git => "https://github.com/signalapp/groupzk.git", :tag => "swift-credential-#{s.version}" }
  s.source_files  = "swift/Credential/**/*.{h,swift}", "swift/Credential/*credential*.{h,a}"

  s.exclude_files = "aeonflux/**/*", "build-test/**/*", "java/**/*", "jni/**/*", "ffi/**/*", "signal-credential/**/*", "wasm/**/*", "zkp-expand/**/*"

  s.ios.deployment_target = "8.0"
  s.osx.deployment_target = "10.10"

  s.ios.vendored_library = "swift/libcredential.a"
  s.osx.vendored_library = "swift/libcredential.a"

  s.private_header_files = "swift/Credential/credential.h"

  # s.library   = "credential"
  # s.libraries = "iconv", "xml2"
  s.libraries = "resolv"

  # ――― Project Settings ――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  If your library depends on compiler flags you can set them in the xcconfig hash
  #  where they will only apply to your library. If you depend on other Podspecs
  #  you can include multiple dependencies to ensure it works.

  # s.requires_arc = true

  # s.xcconfig = { "HEADER_SEARCH_PATHS" => "$(SDKROOT)/usr/include/libxml2" }
  # s.dependency "JSONKit", "~> 1.4"

end
