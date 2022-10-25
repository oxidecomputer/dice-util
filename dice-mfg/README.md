# dice-mfg

This crate hosts tools used by the manufacturing side of the DeviceId certification process.
It uses the serial-rs crate to exchange messages from the dice-mfg-msgs crate with RoTs.
The manufacturing commands should be invoked as follows:
- dice-mfg-liveness
- dice-mfg set-serial-number <rfd219-SN>
- dice-mfg get-csr <CSR-file>
- dice-mfg-sign --openssl-cfg <openssl-cfg-file> --csr-in <CSR-file> --cert-out <cert-file>
NOTE: The 'openssl-cfg-file' must be functional. See
`init-dice-intermediate-ca.sh` for an example.
- dice-mfg set-device-id <cert>
NOTE: The 'cert' provided to the 'set-device-id' subcommand should be a DICE
DeviceId cert with the required x509 constraits and v3 extensions.
- dice-mfg set-intermediate <cert>
NOTE: The 'cert' provided to the 'set-intermediate' subcommand should be the
cert for the intermediate CA used to sign DeviceId certs.
