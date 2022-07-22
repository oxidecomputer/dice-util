#!/usr/bin/bash

KEY_ALG_ED25519=ED25519
KEY_OPTS_ED25519=

KEY_ALG=$KEY_ALG_ED25519
KEY_OPTS=$KEY_OPTS_ED25519

HASH=sha3-256

# setup CA dir
DEVICEID_CA_DIR=./deviceid-selfsigned-embedded-ca
mkdir $DEVICEID_CA_DIR
pushd $DEVICEID_CA_DIR
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo "unique_subject = yes" > index.txt.attr
# keep sn small to save a byte
echo 10 > serial
echo 10 > crlnumber

popd

# self signed device-id
# create key
# TODO: use a consistent key to minimize churn in tests
if [ ! -d keys ]; then
    mkdir keys
fi

if [ ! -f keys/self-ca.key.pem ]; then
    openssl genpkey \
        -algorithm $KEY_ALG $KEY_OPTS \
        -out keys/self-ca.key.pem
fi
cp keys/self-ca.key.pem $DEVICEID_CA_DIR/private/ca.key.pem

SUBJ="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=Manufacturing/serialNumber=000000000000/CN=device-id"
openssl req \
    -new \
    -config openssl.cnf \
    -subj "$SUBJ" \
    -key $DEVICEID_CA_DIR/private/ca.key.pem \
    -$HASH \
    -out $DEVICEID_CA_DIR/csr/ca.csr.pem
openssl ca \
    -config openssl.cnf \
    -batch \
    -selfsign \
    -startdate "$(date -u +%Y%m%d%H%M%SZ)" \
    -enddate '99991231235959Z' \
    -name ca_selfsigned_deviceid_embedded \
    -extensions v3_deviceid_embedded_ca \
    -in $DEVICEID_CA_DIR/csr/ca.csr.pem \
    -out $DEVICEID_CA_DIR/certs/ca.cert.pem
openssl x509 \
    -in $DEVICEID_CA_DIR/certs/ca.cert.pem \
    -outform DER \
    -out $DEVICEID_CA_DIR/certs/ca.cert.der

# leaf cert
# create key
if [ ! -f keys/leaf.key.pem ]; then
    openssl genpkey \
        -algorithm $KEY_ALG $KEY_OPTS \
        -out keys/leaf.key.pem
fi
cp keys/leaf.key.pem $DEVICEID_CA_DIR/private/

# create CSR
SUBJ="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=Manufacturing/serialNumber=000000000000/CN=alias"
openssl req \
    -new \
    -config openssl.cnf \
    -subj "$SUBJ" \
    -key $DEVICEID_CA_DIR/private/leaf.key.pem \
    -$HASH \
    -out $DEVICEID_CA_DIR/csr/leaf.csr.pem
# generate certificatae
openssl ca \
    -config openssl.cnf \
    -batch \
    -name ca_selfsigned_deviceid_embedded \
    -extensions v3_deviceid_leaf_cert \
    -startdate "$(date -u +%Y%m%d%H%M%SZ)" \
    -enddate '99991231235959Z' \
    -notext \
    -md $HASH \
    -in $DEVICEID_CA_DIR/csr/leaf.csr.pem \
    -out $DEVICEID_CA_DIR/certs/leaf.cert.pem
openssl x509 \
    -in $DEVICEID_CA_DIR/certs/leaf.cert.pem \
    -outform DER \
    -out $DEVICEID_CA_DIR/certs/leaf.cert.der
