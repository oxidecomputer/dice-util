#!/bin/bash

set -e

HASH=sha3-256
KEY_ALG_RSA=RSA
KEY_OPTS_RSA4K="-pkeyopt rsa_keygen_bits:4096"

KEY_ALG_EC=EC
KEY_OPTS_ECP384="-pkeyopt ec_paramgen_curve:P-384 \
    -pkeyopt ec_param_enc:named_curve"

KEY_ALG_ED25519=ED25519
KEY_OPTS_ED25519=

KEY_ALG=$KEY_ALG_ED25519
KEY_OPTS=$KEY_OPTS_ED25519

ROOT_CA_DIR=./root-ca
# setup root CA
mkdir $ROOT_CA_DIR
pushd $ROOT_CA_DIR
mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

# create root CA key
openssl genpkey \
	-algorithm $KEY_ALG $KEY_OPTS \
	-out private/ca.key.pem
chmod 400 private/ca.key.pem
popd

# create CSR for root CA - self signed
ROOT_CA_SUBJ="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=Manufacturing/CN=root-ca"
openssl req \
      -config openssl.cnf \
      -subj "$ROOT_CA_SUBJ" \
      -key $ROOT_CA_DIR/private/ca.key.pem \
      -new -x509 \
      -days 7300 \
      -$HASH \
      -extensions v3_root_ca \
      -out $ROOT_CA_DIR/certs/ca.cert.pem
openssl x509 \
	-in $ROOT_CA_DIR/certs/ca.cert.pem \
	-noout \
	-text \
	> $ROOT_CA_DIR/certs/ca.cert.txt
openssl x509 \
	-outform der \
	-in $ROOT_CA_DIR/certs/ca.cert.pem \
	-out $ROOT_CA_DIR/certs/ca.cert.der
chmod 400 $ROOT_CA_DIR/certs/*

echo "ROOT CA CERT:"
cat $ROOT_CA_DIR/certs/ca.cert.txt
# wait for keypress
read -t 3 -n 1

# setup intermediate CA
DEVICEID_CA_DIR=./deviceid-ca
mkdir $DEVICEID_CA_DIR
pushd $DEVICEID_CA_DIR
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber

# create intermediate CA key
openssl genpkey -algorithm $KEY_ALG $KEY_OPTS -out private/ca.key.pem
chmod 400 private/ca.key.pem
popd

# create CSR for intermediate
# interactive
DEVICEID_CA_SUBJ="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=Manufacturing/CN=deviceid-ca"
openssl req \
      -config openssl.cnf \
      -subj "$DEVICEID_CA_SUBJ" \
      -new \
      -$HASH \
      -key $DEVICEID_CA_DIR/private/ca.key.pem \
      -out $DEVICEID_CA_DIR/csr/ca.csr.pem

# create and sign cert for intermediate key with root ca
# interactive
openssl ca \
      -config openssl.cnf \
      -batch \
      -name ca_root \
      -extensions v3_deviceid_ca \
      -days 3650 \
      -notext \
      -md $HASH \
      -in $DEVICEID_CA_DIR/csr/ca.csr.pem \
      -out $DEVICEID_CA_DIR/certs/ca.cert.pem

openssl x509 \
	-in $DEVICEID_CA_DIR/certs/ca.cert.pem \
	-noout \
	-text \
	> $DEVICEID_CA_DIR/certs/ca.cert.txt
openssl x509 \
	-outform der \
	-in $DEVICEID_CA_DIR/certs/ca.cert.pem \
	-out $DEVICEID_CA_DIR/certs/ca.cert.der
chmod 444 $DEVICEID_CA_DIR/certs/*
