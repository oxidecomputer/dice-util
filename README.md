# dice-utils

This repo hosts software supporting the DICE measured boot in Hubris.
That mostly includes:
- generating templates used by hubris stage0 to generate X.509 / PKCS#10 structures
- tools to certify the DeviceId key that acts as the platform identity
Components in this workspace are here mostly because they don't belong in the hubris repo.
More detailed docs are included in each subdirectory / crate as needed.

This top level directory hosts several scripts:
- init-dice-root-ca.sh - This script creates a simple root certificate
authority (self-signed) that can be used to certify the intermediate CA used
to certify DeviceIds.
- init-dice-intermediate-ca.sh - This script creates a simple intermediate
certificate authority that is intended to be used to sign DeviceId
certificates as part of the manufacturing process. Unlike the root ca script
the intermediate CA must have a cert signed by the root and so an output from
this script is a CSR. This CSR may be signed by the root generated with the
previous script or through other means.

NOTE: Both of these scripts generate "opinionated" openssl config files. The
root directory for the CA files is included as an absolute path. Using
relative paths makes the config more flexible but requires that invocations
of the `openssl ca` command be done from the root of the CA directory.

- dice-ca-sign.sh - This script is a thin wrapper around the `openssl ca`
command. Given a sufficiently complete openssl config file this script can
be used to sign CSRs and create x509 certs. Default behavior of this script
is to use the defaults from the provided openssl config. This can be
overridden by supplying the script with different CA and x509 v3 config
sections.
- mfg-run.sh - This scripts the manufacturing side of the DeviceId
certification pocess.
