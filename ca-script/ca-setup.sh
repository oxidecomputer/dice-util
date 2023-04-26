#!/bin/bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

set -e

# All openssl commands in this script are configured by the file `openssl.cnf`.
# This script creates a hierarchy of certificates as follows:
#
# - root CA
# Root / self signed certificate authority key & cert.
# CA configuration section: [ ca_root ]
# v3 extension section: [v3_root_ca]
#
# - intermediate CA
# Intermediate CA used to certify DeviceId certs.
# CA configuration section: [ ca_intermediate ]
# v3 extension section [v3_deviceid_ca]
#
# - DeviceId embedded CA (ECA)
# Another intermediate CA, this one represents the platform identity / DeviceId.
# CA configuration section: [ ca_deviceid_eca ]
# v3 extension section: [v3_deviceid_eca]
#

OPENSSL_CNF=openssl.cnf

KEY_ALG_RSA=RSA
KEY_OPTS_RSA4K="-pkeyopt rsa_keygen_bits:4096"

KEY_ALG_EC=EC
KEY_OPTS_ECP384="-pkeyopt ec_paramgen_curve:P-384 \
    -pkeyopt ec_param_enc:named_curve"

KEY_ALG_ED25519=ED25519
KEY_OPTS_ED25519=

KEY_ALG=$KEY_ALG_ED25519
KEY_OPTS=$KEY_OPTS_ED25519

# ref rfd 219 & 308
# SN is 11 characters from the code 39 alphabet
SERIAL_NUMBER="00000000000"
# part number (PN) is 10 characters from the code 39 alphabet with a hyphen
# as the 4th character
# revision number (RN) is 3 code 39 characters, we concatinate the RN to
# the PN joining the two with a ':'
PART_REVISION_NUMBER="000-0000000:000"

TMPL_DIR=tmpls
if [ ! -d $TMPL_DIR ]; then
    mkdir $TMPL_DIR
fi

# private keys used in CA hierarchy
KEY_DIR=keys

# create key directory
if [ ! -d $KEY_DIR ]; then
    mkdir $KEY_DIR
fi

#######
# self-signed persistent identity CA root
#######

# create key for root CA if not already done
PERSISTENT_ID_SELF_CA_KEY=$KEY_DIR/persistentid-ca.key.pem
if [ ! -f $PERSISTENT_ID_SELF_CA_KEY ]; then
    openssl genpkey \
        -algorithm $KEY_ALG $KEY_OPTS \
        -out $PERSISTENT_ID_SELF_CA_KEY
    chmod 400 $PERSISTENT_ID_SELF_CA_KEY
fi

PERSISTENT_ID_SELF_CA_DIR=./persistentid-self-ca
mkdir $PERSISTENT_ID_SELF_CA_DIR
pushd $PERSISTENT_ID_SELF_CA_DIR
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo "unique_subject = yes" > index.txt.attr
# keep sn small to save a byte
echo 10 > serial
echo 10 > crlnumber
popd

PERSISTENT_ID_CA_CSR_PEM=$PERSISTENT_ID_SELF_CA_DIR/csr/ca.csr.pem
SUBJ="/C=US/O=Oxide Computer Company/CN=$PART_REVISION_NUMBER/serialNumber=$SERIAL_NUMBER"
openssl req \
    -new \
    -config $OPENSSL_CNF \
    -subj "$SUBJ" \
    -key $PERSISTENT_ID_SELF_CA_KEY \
    -out $PERSISTENT_ID_CA_CSR_PEM

PERSISTENT_ID_SELF_CA_CERT_PEM=$PERSISTENT_ID_SELF_CA_DIR/certs/ca.cert.pem
openssl ca \
    -config $OPENSSL_CNF \
    -batch \
    -selfsign \
    -name ca_selfsigned_persistentid \
    -extensions v3_persistentid_ca \
    -in $PERSISTENT_ID_CA_CSR_PEM \
    -out $PERSISTENT_ID_SELF_CA_CERT_PEM

cargo run --bin dice-cert-tmpl -- cert tmpl-gen --subject-sn --issuer-sn $PERSISTENT_ID_SELF_CA_CERT_PEM > $TMPL_DIR/persistentid_cert_tmpl.rs

#######
# root CA
#######
# this CA is the root of the key hierarchy, it is self signed
# this key is only used to sign certs for intermediate CAs, never leaf certs
# we use the same key for the self-signed DeviceId CA above
ROOT_CA_DIR=./root-ca
mkdir $ROOT_CA_DIR
pushd $ROOT_CA_DIR
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
popd

ROOT_CA_KEY=$KEY_DIR/root-ca.key.pem
if [ ! -f $ROOT_CA_KEY ]; then
    openssl genpkey \
        -algorithm $KEY_ALG $KEY_OPTS \
        -out $ROOT_CA_KEY
    chmod 400 $ROOT_CA_KEY
fi

ROOT_CA_CERT_PEM=$ROOT_CA_DIR/certs/ca.cert.pem
ROOT_CA_SUBJ="/C=US/O=Oxide Computer Company/OU=faux-mfg/CN=root-ca"
openssl req \
      -config $OPENSSL_CNF \
      -subj "$ROOT_CA_SUBJ" \
      -key $ROOT_CA_KEY \
      -new \
      -x509 \
      -days 3650 \
      -extensions v3_root_ca \
      -out $ROOT_CA_CERT_PEM

######
# Identity CA
######
# The Identity ECA is certified during the manufacturing process. This CA
# is an embedded CA in that it's embedded in the RoT. It is not however an
# ECA per the DICE definition.  It will certify the DeviceId key that will in
# turn certify keys derived from CDI~L1~.
# We use this CA to create template that the RoT uses to create CSRs for
# DeviceId certs signed by the intermediate CA.
PERSISTENT_ID_CA_DIR=./persistentid-ca
mkdir $PERSISTENT_ID_CA_DIR
pushd $PERSISTENT_ID_CA_DIR
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 10 > serial
echo 10 > crlnumber
popd

PERSISTENT_ID_CA_KEY=$KEY_DIR/persistentid-ca.key.pem
if [ ! -f $PERSISTENT_ID_CA_KEY ]; then
    openssl genpkey \
        -algorithm $KEY_ALG $KEY_OPTS \
        -out $PERSISTENT_ID_CA_KEY
fi

PERSISTENT_ID_CA_CSR_PEM=$PERSISTENT_ID_CA_DIR/csr/persistentid-ca.csr.pem
PERSISTENT_ID_CA_SUBJ="/C=US/O=Oxide Computer Company/CN=$PART_REVISION_NUMBER/serialNumber=$SERIAL_NUMBER"
openssl req \
      -config $OPENSSL_CNF \
      -subj "$PERSISTENT_ID_CA_SUBJ" \
      -new \
      -key $PERSISTENT_ID_CA_KEY \
      -out $PERSISTENT_ID_CA_CSR_PEM

cargo run --bin dice-cert-tmpl -- csr tmpl-gen $PERSISTENT_ID_CA_CSR_PEM > $TMPL_DIR/persistentid_csr_tmpl.rs

PERSISTENT_ID_CA_CERT_PEM=$PERSISTENT_ID_CA_DIR/certs/ca.cert.pem
openssl ca \
      -config $OPENSSL_CNF \
      -batch \
      -name ca_root \
      -extensions v3_persistentid_ca \
      -notext \
      -in $PERSISTENT_ID_CA_CSR_PEM \
      -out $PERSISTENT_ID_CA_CERT_PEM

######
# DeviceId ECA
######
# certs signed by the identity ECA.
DEVICEID_ECA_DIR=./deviceid-eca
mkdir $DEVICEID_ECA_DIR
pushd $DEVICEID_ECA_DIR
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 10 > serial
echo 10 > crlnumber
popd

# deviceid ca_intermediate
DEVICEID_ECA_KEY=$KEY_DIR/deviceid-eca.key.pem
if [ ! -f $DEVICEID_ECA_KEY ]; then
    openssl genpkey \
        -algorithm $KEY_ALG $KEY_OPTS \
        -out $DEVICEID_ECA_KEY
fi

DEVICEID_ECA_CSR_PEM="$PERSISTENT_ID_CA_DIR/csr/deviceid.csr.pem"
DEVICEID_ECA_SUBJ="/C=US/O=Oxide Computer Company/CN=device-id"
openssl req \
      -config $OPENSSL_CNF \
      -subj "$DEVICEID_ECA_SUBJ" \
      -new \
      -key $DEVICEID_ECA_KEY \
      -out $DEVICEID_ECA_CSR_PEM

DEVICEID_ECA_CERT_PEM="$DEVICEID_ECA_DIR/certs/ca.cert.pem"
openssl ca \
      -config $OPENSSL_CNF \
      -batch \
      -name ca_intermediate \
      -extensions v3_deviceid_eca \
      -notext \
      -in $DEVICEID_ECA_CSR_PEM \
      -out $DEVICEID_ECA_CERT_PEM

cargo run --bin dice-cert-tmpl -- cert tmpl-gen --issuer-cn --issuer-sn $DEVICEID_ECA_CERT_PEM > $TMPL_DIR/deviceid_cert_tmpl.rs

######
# Alias
######
# Create and sign cert for client cert / mock Alias cert.

ALIAS_KEY="$KEY_DIR/alias.key.pem"
if [ ! -f $ALIAS_KEY ]; then
    openssl genpkey \
        -algorithm $KEY_ALG $KEY_OPTS \
        -out $ALIAS_KEY
fi

ALIAS_CSR_PEM="$DEVICEID_ECA_DIR/csr/alias.csr.pem"
ALIAS_SUBJ="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/CN=alias"
openssl req \
      -config $OPENSSL_CNF \
      -subj "$ALIAS_SUBJ" \
      -new \
      -key $ALIAS_KEY \
      -out $ALIAS_CSR_PEM

ALIAS_CERT_PEM="$DEVICEID_ECA_DIR/certs/alias.cert.pem"
openssl ca \
      -config $OPENSSL_CNF \
      -batch \
      -name ca_deviceid_eca \
      -extensions v3_alias \
      -notext \
      -in $ALIAS_CSR_PEM \
      -out $ALIAS_CERT_PEM

cargo run --bin dice-cert-tmpl -- cert tmpl-gen --fwid $ALIAS_CERT_PEM > $TMPL_DIR/alias_cert_tmpl.rs

######
# SP-MEASURE
######
# Create and sign cert for client cert / mock SP-MEASURE cert.
SP_MEASURE_KEY="$KEY_DIR/sp-measure.key.pem"
if [ ! -f $SP_MEASURE_KEY ]; then
    openssl genpkey \
        -algorithm $KEY_ALG $KEY_OPTS \
        -out $SP_MEASURE_KEY
fi

SP_MEASURE_CSR_PEM="$DEVICEID_ECA_DIR/csr/sp-measure.csr.pem"
SP_MEASURE_SUBJ="/C=US/O=Oxide Computer Company/CN=sp-measure"
openssl req \
      -config $OPENSSL_CNF \
      -subj "$SP_MEASURE_SUBJ" \
      -new \
      -key $SP_MEASURE_KEY \
      -out $SP_MEASURE_CSR_PEM

SP_MEASURE_CERT_PEM="$DEVICEID_ECA_DIR/certs/sp-measure.cert.pem"
openssl ca \
      -config $OPENSSL_CNF \
      -batch \
      -name ca_deviceid_eca \
      -extensions v3_spmeasure \
      -notext \
      -in $SP_MEASURE_CSR_PEM \
      -out $SP_MEASURE_CERT_PEM

cargo run --bin dice-cert-tmpl -- cert tmpl-gen --fwid $SP_MEASURE_CERT_PEM > $TMPL_DIR/spmeasure_cert_tmpl.rs

######
# trust-quorum-dhe
######
# Create and sign cert for client cert / mock SP-MEASURE cert.
TQDHE_KEY="$KEY_DIR/trust-quorum-dhe.key.pem"
if [ ! -f $TQDHE_KEY ]; then
    openssl genpkey \
        -algorithm $KEY_ALG $KEY_OPTS \
        -out $TQDHE_KEY
fi

TQDHE_CSR_PEM="$DEVICEID_ECA_DIR/csr/trust-quorum-dhe.csr.pem"
TQDHE_SUBJ="/C=US/O=Oxide Computer Company/CN=trust-quorum-dhe"
openssl req \
      -config $OPENSSL_CNF \
      -subj "$TQDHE_SUBJ" \
      -new \
      -key $TQDHE_KEY \
      -out $TQDHE_CSR_PEM

TQDHE_CERT_PEM="$DEVICEID_ECA_DIR/certs/trust-quorum-dhe.cert.pem"
openssl ca \
      -config $OPENSSL_CNF \
      -batch \
      -name ca_deviceid_eca \
      -extensions v3_trust_quorum_dhe \
      -notext \
      -in $TQDHE_CSR_PEM \
      -out $TQDHE_CERT_PEM

cargo run --bin dice-cert-tmpl -- cert tmpl-gen --fwid $TQDHE_CERT_PEM > $TMPL_DIR/trust_quorum_dhe_cert_tmpl.rs
