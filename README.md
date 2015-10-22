This is a collection of tools, config files, and notes I've developed
while getting IKEv2 with strong encryption working on various platforms.

- build-mobileconfig.py: Builds a .mobileconfig profile to be imported by
  Apple devices running iOS or OS X.

- macos-networkextensiontool.py: Modifies an existing IKEv2 VPN to use
  more secure encryption and integrity algorithms and Diffie Hellman groups.

- macos-sane-defaults.sh: Automatically updates the first IKEv2 VPN
  configuration to use more secure defaults: AES-256, SHA2-256, modp2048.

These scripts are probably helpful when generating many profiles.  For a few
profiles, you can use the [Apple Configurator](https://itunes.apple.com/us/app/apple-configurator-2/id1037126344?mt=12) tool from the App Store.

From there, you'll need to add your device certificate (in PKCS12 form) and
any CA Certificates (in DER form).  The scripts allow PEM format CA
certificiates but Apple Configurator doesn't recognize them.  iOS will
recognize the PEM format CA certificates but seems not to use CA Certificates
embedded in the PKCS12 bundle.  They must be provided separately either
as another certificate payload within the same configuration profile or
loaded onto the device by some other means.

This command:
<code>openssl x509 -in &lt;cacert.pem&gt; -outform DER -out &lt;cacert.cer&gt;</code> will convert from PEM to DER.

Although Apple Configurator claims to only offer support for mobile devices,
the version I tested (2.0 3A291) generates profiles that OS X can read as
well.  This is also the only way I've found (without writing more scripts)
to load 802.1x profiles for use with WPA2 Enterprise.  I found this out
after writing the macos scripts or I probably would've just used
Configurator initially.
