# dice-cert-tmpl

This directory contains tools used to create templates and a small amount of of
Rust code used by Hubris stage0 to generate the ASN.1 DER encoded structures
required by DICE. The eventual end state for this work should be the generation
of these X.509 and PKCS#10 structures from configuration data in Rust. The
approach taken in the initial implementation however is more "rough and ready"
relying on the output from the scripted use of the OpenSSL tools from the
`ca-scripts` directory.
