#!/bin/bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# not much error handling here so fail hard
set -e

DIR=./cas
ROOT_PREFIX=dice-ca-root
ROOT_DIR=$DIR/$ROOT_PREFIX
INT0_PREFIX=dice-ca-int0
INT0_DIR=$DIR/$INT0_PREFIX
INT1_PREFIX=dice-ca-int1
INT1_DIR=$DIR/$INT1_PREFIX
SUBJ_PREFIX="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=test"

TMP=$(mktemp -d -t ${0##*/}-XXXXXXXXXX)

mkdir -p $ROOT_DIR $INT0_DIR $INT1_DIR

# root CA
./dice-ca-init.sh \
    --self-signed \
    --dir $ROOT_DIR \
    --archive-prefix $ROOT_PREFIX \
    --slot 9a \
    --subject "$SUBJ_PREFIX/CN=dice-root"
tar --extract --auto-compress --directory $TMP --file $ROOT_PREFIX.tar.xz 
pushd $TMP/$ROOT_PREFIX
./verify-attestation.sh
popd

# first intermediate CA
./dice-ca-init.sh \
    --dir $INT0_DIR \
    --archive-prefix $INT0_PREFIX \
    --slot 9d \
    --subject "$SUBJ_PREFIX/CN=dice-intermediate0"
tar --extract --auto-compress --directory $TMP --file $INT0_PREFIX.tar.xz 
pushd $TMP/$INT0_PREFIX
./verify-attestation.sh
popd
# acting as the root CA, sign cert & send to first intermediate
cargo run --bin dice-mfg -- \
    sign-cert \
    --openssl-cnf $ROOT_DIR/openssl.cnf \
    --csr-in $TMP/$INT0_PREFIX/ca.csr.pem \
    --cert-out $INT0_DIR/certs/ca.cert.pem

# second intermediate CA
./dice-ca-init.sh \
    --dir $INT1_DIR \
    --archive-prefix $INT1_PREFIX \
    --slot 82 \
    --subject "$SUBJ_PREFIX/CN=dice-intermediate1"
tar --extract --auto-compress --directory $TMP --file $INT1_PREFIX.tar.xz 
pushd $TMP/$INT1_PREFIX
./verify-attestation.sh
popd
# acting as the fist intermediate, sign cert & send to second intermediate
cargo run --bin dice-mfg -- \
    sign-cert \
    --openssl-cnf $INT0_DIR/openssl.cnf \
    --ca-section ca_intermediate \
    --csr-in $TMP/$INT1_PREFIX/ca.csr.pem \
    --cert-out $INT1_DIR/certs/ca.cert.pem
