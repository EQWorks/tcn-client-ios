Pod::Spec.new do |s|
  s.name             = 'TCNClient'
  s.version          = '0.1.0'
  s.summary          = 'iOS library that implements TCN protocol for COVID-19 contact tracing'
  s.homepage         = 'https://github.com/TCNCoalition/tcn-client-ios'
  s.license          = { :type => 'Apache', :file => 'LICENSE' }
  s.author           = { 'TCN-Coalition' => 'outreach@tcn-coalition.org' }
  s.source           = { :git => 'https://github.com/TCNCoalition/tcn-client-ios.git', :tag => s.version.to_s }

  s.ios.deployment_target = '12.0'
  s.swift_versions = ['5.0', '5.1', '5.2']
  s.source_files = 'Sources/**/*'

  s.dependency 'ed25519swift', '~> 1.2.5'

end
