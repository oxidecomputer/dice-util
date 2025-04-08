#!/usr/bin/env bash

set -eou pipefail

error() {
    >&2 command echo ["$(date --utc +%FT%TZ)" ERROR "${0##*/}"] "$@"
}

command_on_path() {
    if ! command -v "$1" &> /dev/null; then
        error "missing required command: $1"
        exit 1
    fi
}

command_on_path pki-playground

CONFIG=platform-identity-self.kdl
if [[ ! -f  "$CONFIG" ]]; then
    error "missing required file: $CONFIG"
    exit 1
fi

pki-playground --config "$CONFIG" generate-key-pairs
pki-playground --config "$CONFIG" generate-certificate-requests
pki-playground --config "$CONFIG" generate-certificates

PLATFORM_ID_CSR=platform-identity.csr.pem
PLATFORM_ID_CSR_TMPL=platform_identity_csr_tmpl.rs
if [[ -f "$PLATFORM_ID_CSR" ]]; then
    cargo run --bin dice-cert-tmpl -- csr tmpl-gen --subject-cn \
        "$PLATFORM_ID_CSR" > "$PLATFORM_ID_CSR_TMPL"
else
    error "missing generated file: $PLATFORM_ID_CSR"
fi

PLATFORM_ID_SELF_CERT=platform-identity-self-signed.cert.pem
PLATFORM_ID_SELF_CERT_TMPL=platform_identity_self_signed_tmpl.rs
if [[ -f "$PLATFORM_ID_SELF_CERT" ]]; then
    cargo run --bin dice-cert-tmpl -- cert tmpl-gen --subject-cn --issuer-cn \
        "$PLATFORM_ID_SELF_CERT" > "$PLATFORM_ID_SELF_CERT_TMPL"
else
    error "missing generated file: $PLATFORM_ID_SELF_CERT"
fi

DEVICE_ID_CERT=device-id.cert.pem
DEVICE_ID_CERT_TMPL=device_id_cert_tmpl.rs
if [[ -f "$DEVICE_ID_CERT" ]]; then
    cargo run --bin dice-cert-tmpl -- cert tmpl-gen --issuer-cn \
        "$DEVICE_ID_CERT" > "$DEVICE_ID_CERT_TMPL"
else
    error "missing generated file: $DEVICE_ID_CERT"
fi

ALIAS_CERT=alias.cert.pem
ALIAS_CERT_TMPL=alias_cert_tmpl.rs
if [[ -f "$ALIAS_CERT" ]]; then
    cargo run --bin dice-cert-tmpl -- cert tmpl-gen --fwid \
        "$ALIAS_CERT" > "$ALIAS_CERT_TMPL"
else
    error "missing generated file: $ALIAS_CERT"
fi

TRUST_QUORUM_DHE_CERT=trust-quorum-dhe.cert.pem
TRUST_QUORUM_DHE_CERT_TMPL=trust_quorum_dhe_cert_tmpl.rs
if [[ -f "$TRUST_QUORUM_DHE_CERT" ]]; then
    cargo run --bin dice-cert-tmpl -- cert tmpl-gen --fwid \
        "$TRUST_QUORUM_DHE_CERT" > "$TRUST_QUORUM_DHE_CERT_TMPL"
else
    error "missing generated file: $TRUST_QUORUM_DHE_CERT"
fi
