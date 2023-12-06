# verifier

This crate hosts a command line tool for:
- getting attestations & other supporting data from the Hubris `Attest` task
- performing an analysis of the attestation

## Humility Attest API

All interaction with Hubris is driven by the `humility` `hiffy` command. We use
hiffy and the `Attest` IDL as a CLI API to the `Attest` task. This API allows
us to support communication with the RoT directly or through the SP `Sprot`
task. This interface is how we get attestations and supporting data.

## Attestation Analysis

Before analyzing the measurements produced by the RoT, we must establish that
the attestation is authentic, fresh, and analyzable.

### Fresh

The freshness property is intended to prevent reply attacks. In this scenario
the compromise of a system is obscured by the attacker replaying old valid
attestations. The attestation API requires the caller provide nonce when
requesting an attestation. This nonce is included in the signed data that makes
up the attestation. Reuse of a nonce exposes the caller to replay attacks from
past attestations produced using the same nonce.

```shell
$ dd if=/dev/urandom of=nonce.bin bs=32 count=1
$ cargo run --package verifier -- get attestation nonce.bin > attestation.bin
```

We prove the attestation includes the nonce using a mechanism described in the
following sections.

### Analyzable

The measured boot implementation in the RoT records the hashes of the layers of
firmware executed by the microcontroller as it boots. We analyze this log and
use the output of this analysis as the basis for trust decisions (access
control etc). The measurement log produced by the RoT comes with no integrity
guarantees and so we cannot trust any analysis of it until we've established a
basis for trusting its accuracy.

```shell
$ cargo run --package verifier -- get log > log.bin
```

An attestation is a detached signature over the measurement log. By verifying
this signature we prove the accuracy of the log. We prove the freshness of the
attestation at the same time by including the nonce in the signed data as the
RoT does:

```shell
$ cargo run --package verifier -- get cert --index 0 > alias.pem
$ cargo run --package verifier -- verify attestation --alias_cert alias.pem --log log.bin --nonce nonce.bin attestation.bin
```

The signature verification boils down to:
```
message = sha3_256(log | nonce)
attestation = sign(alias_priv, message)
verify(alias_pub, message, attestaton)
```

### Authentic

We say an attestation is authentic once we've convinced ourselves that we trust
the key used to sign the attestation for the purpose of attestation. We do so
by first establishing trust in the certificate chain from the RoT:

```shell
$ cargo run --package verifier -- get cert-chain > cert-chain.pem
$ cargo run --package verifier -- verify cert-chain --ca-cert ca-root.pem cert-chain.pem
```
