Pod::Spec.new do |s|
s.name = 'SwiftSRP'
s.version = '0.7.0'
s.summary = 'SwiftSRP provides a Secure Remote Password implementation in Swift.'
s.homepage = 'https://github.com/junelife/SwiftSRP'
s.authors = { 'Joseph Ross' => '' }
s.source = { :git => 'https://github.com/junelife/SwiftSRP',
             :branch => 'podspec' }

s.ios.deployment_target = '10.0'

s.ios.vendored_library    = 'SwiftSRP/openssl/libcrypto.a'

s.source_files = 'SwiftSRP/**/*.{swift,h}'
s.private_header_files = 'SwiftSRP/openssl/openssl/*.h'

s.preserve_paths = 'SwiftSRP/openssl/module.modulemap'
s.pod_target_xcconfig = {
	'SWIFT_INCLUDE_PATHS' => '$(PODS_TARGET_SRCROOT)/SwiftSRP/openssl',
}

s.requires_arc = true
end
