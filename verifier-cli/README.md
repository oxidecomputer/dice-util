# verifier

This crate hosts a command line tool for:
- getting attestations & other supporting data from the Hubris `Attest` task
- performing an analysis of the attestation

## Humility Attest API

All interaction with Hubris is driven by the `humility` `hiffy` command. We use
`hiffy` and the `Attest` IDL as a CLI API to the `Attest` task. This API allows
us to support communication with the RoT directly or through the SP `Sprot`
task. This interface is how we get attestations and supporting data.

Since we're using `humility` to drive all of this, the `verifier-cli` needs a
mechanism to tell `humility` how to find the board / probe we want it to use.
Similarly, `humility` needs access to the hubris image that's executing on the
target board in order to invoke `hif` functions. The most direct approach and
the one implemented in this tool is to rely on the caller to provide this
information through the environment.

The caller can accomplish this in a number of ways but the approach we
recommend is to create a `humility` environment file as described here:
https://github.com/oxidecomputer/humility#environment. Once the environment
file is setup and exported via `HUMILITY_ENVIRONMENT`, the caller must set the
intended target and archive using `HUMILITY_TARGET` and `HUMILITY_ARCHIVE`
environment variables respectively. When executing `verifier-cli` commands
`humility` will get the required data from the environment transparent to the
caller.

The remainder of this document assumes the caller has exported these variables
correctly for the command being invoked as well as the callers hardware
configuration ... YMMV and all applicable disclaimers.

## TL;DR

### Get an Attestation

```shell
$ dd if=/dev/urandom of=nonce.bin bs=32 count=1
$ cargo run --package verifier-cli -- attest nonce.bin > attestation.json
```

### Get the cert chain

Trust always boils down to PKI.

```shell
$ cargo run --package verifier-cli -- cert-chain > cert-chain.pem
```

### Get the Measurement Log

```shell
$ cargo run --package verifier-cli -- log > log.json
```

### Verify the Attestation
NOTE: The following awk script extracts the leaf from the cert chain obtained [above](#get-the-cert-chain).
This is the certiticate for the attestation signing key.

```shell
$ awk '\
BEGIN { done = 0 } \
{ if (done != 1) print $0 } \
/-----END CERTIFICATE-----/ { done = 1 } \
' cert-chain.pem > alias.pem
$ cargo run --package verifier-cli -- verify-attestation --alias-cert alias.pem --log log.json --nonce nonce.bin attestation.json
```

### Verify the cert chain

#### dice-mfg

If your RoT has been manufactured and you've got a root cert:

```shell
$ cargo run --package verifier-cli -- verify-cert-chain --ca-cert root.cert.pem cert-chain.pem
```

#### dice-self

If your hubris kernel was built with the `dice-self` feature then the cert
chain will be self signed:

```shell
$ cargo run --package verifier -- verify-cert-chain --self-signed cert-chain.pem
```

NOTE: The `--self-signed` flag here will verify the signatures through the cert
chain. The root is however inherently untrusted and so are the associated
measurements.

### Appraise the Measurement Log

TODO

## Attestation Analysis

The TL;DR above is limited to the commands required to verify an attestation
from the RoT. This section describes the process in greater detail.

Our eventual goal is to appraise the measurements in the measurement log.
Before we can do that we need to establish that the attestation is authentic,
fresh, and analyzable. Effectively, we need to convince ourselves that we trust
the data in the measurement log. The following sections will walk through the
details.

### Fresh

The freshness property is intended to prevent reply attacks. In this scenario
the compromise of a system is obscured by the attacker replaying old valid
attestations. The attestation API requires the caller provide nonce when
requesting an attestation. This nonce is included in the signed data that makes
up the attestation. Reuse of a nonce exposes the caller to replay attacks from
past attestations produced using the same nonce.

The attestation / signature we get back from the RoT with [this
command](#get-an-attestation) includes the provided nonce but we must prove
this to ourselves before we've proven the attestation is fresh. We do this in a
future section.

### Analyzable

The measured boot implementation in the RoT records the hashes of the layers of
firmware executed by the microcontroller as it boots. To analyze the log we've
gotta get it with [this command](#get-the-measurement-log). Our end goal is to
analyze this log and use the output of this analysis as the basis for trust
decisions (access control etc). The measurement log comes with no integrity
guarantees and so we cannot trust any analysis of it until we've established a
basis for trusting its accuracy.

An attestation is a detached signature over the measurement log. By verifying
this signature we prove the accuracy of the log. We prove the freshness of the
attestation at the same time by including the nonce in the signed data as the
RoT does with [this command](#verify-the-attestation).

The signature verification boils down to:
```
message = sha3_256(log | nonce)
attestation = sign(alias_priv, message)
verify(alias_pub, message, attestaton)
```

### Authentic

The authenticity of an attestation comes from knowledge of / trust in the source.
Our platform identity PKI is used to certify RoT platform identity keys.
This certification binds the attestation from the RoT to a trusted key.

We establish the authenticity of an attestation by verifying the cert chain
from the RoT attestation signing key back to the platform identity PKI root.
