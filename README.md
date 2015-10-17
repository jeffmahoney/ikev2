This is a collection of tools, config files, and notes I've developed
while getting IKEv2 with strong encryption working on various platforms.

- ios-build-profile.py: Builds a .mobileconfig profile to be imported by
  Apple devices running iOS.

- macos-networkextensiontool.py: Modifies an existing IKEv2 VPN to use
  more secure encryption and integrity algorithms and Diffie Hellman groups.

- macos-sane-defaults.sh: Automatically updates the first IKEv2 VPN
  configuration to use more secure defaults: AES-256, SHA2-256, modp2048.
