# dice-utils

This repo hosts software supporting the DICE measured boot in Hubris.
That mostly includes:
- generating templates used by hubris stage0 to generate X.509 / PKCS#10 structures
- tools to certify the DeviceId key that acts as the platform identity
Components in this workspace are here mostly because they don't belong in the hubris repo.
More detailed docs are included in each subdirectory / crate as needed.
