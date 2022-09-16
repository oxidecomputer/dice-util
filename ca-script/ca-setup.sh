#!/bin/bash

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

# private keys used in CA hierarchy
KEY_DIR=keys

# create key directory
if [ ! -d $KEY_DIR ]; then
    mkdir $KEY_DIR
fi

#######
# self-signed DeviceId root
#######

# create key for root CA if not already done
DEVICEID_ECA_SELF_KEY=$KEY_DIR/deviceid-eca.key.pem
if [ ! -f $DEVICEID_ECA_SELF_KEY ]; then
    openssl genpkey \
        -algorithm $KEY_ALG $KEY_OPTS \
        -out $DEVICEID_ECA_SELF_KEY
    chmod 400 $DEVICEID_ECA_SELF_KEY
fi

DEVICEID_SELF_CA_DIR=./deviceid-eca-self
mkdir $DEVICEID_SELF_CA_DIR
pushd $DEVICEID_SELF_CA_DIR
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo "unique_subject = yes" > index.txt.attr
# keep sn small to save a byte
echo 10 > serial
echo 10 > crlnumber
popd

DEVICEID_CA_CSR_PEM=$DEVICEID_SELF_CA_DIR/csr/ca.cert.pem
DEVICEID_CA_CERT_PEM=$DEVICEID_SELF_CA_DIR/certs/ca.cert.pem
DEVICEID_CA_CERT_DER=$DEVICEID_SELF_CA_DIR/certs/ca.cert.der
DEVICEID_CA_CERT_TXT=$DEVICEID_SELF_CA_DIR/certs/ca.cert.txt

SUBJ="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=Manufacturing/serialNumber=000000000000/CN=device-id"
openssl req \
    -new \
    -config $OPENSSL_CNF \
    -subj "$SUBJ" \
    -key $DEVICEID_ECA_SELF_KEY \
    -$HASH \
    -out $DEVICEID_CA_CSR_PEM
openssl ca \
    -config $OPENSSL_CNF \
    -batch \
    -selfsign \
    -startdate "$(date -u +%Y%m%d%H%M%SZ)" \
    -enddate '99991231235959Z' \
    -name ca_selfsigned_deviceid_embedded \
    -extensions v3_deviceid_eca \
    -in $DEVICEID_CA_CSR_PEM \
    -out $DEVICEID_CA_CERT_PEM
openssl x509 \
    -in $DEVICEID_CA_CERT_PEM \
    -outform DER \
    -out $DEVICEID_CA_CERT_DER
openssl x509 \
    -in $DEVICEID_CA_CERT_PEM \
    -noout \
    -text \
    > $DEVICEID_CA_CERT_TXT

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
ROOT_CA_CERT_DER=$ROOT_CA_DIR/certs/ca.cert.der
ROOT_CA_CERT_TXT=$ROOT_CA_DIR/certs/ca.cert.txt

# create CSR for root CA - self signed
ROOT_CA_SUBJ="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=Manufacturing/CN=root-ca"
openssl req \
      -config $OPENSSL_CNF \
      -subj "$ROOT_CA_SUBJ" \
      -key $ROOT_CA_KEY \
      -new -x509 \
      -days 7300 \
      -$HASH \
      -extensions v3_root_ca \
      -out $ROOT_CA_CERT_PEM
openssl x509 \
	-in $ROOT_CA_CERT_PEM \
	-noout \
	-text \
	> $ROOT_CA_CERT_TXT
openssl x509 \
	-outform der \
	-in $ROOT_CA_CERT_PEM \
	-out $ROOT_CA_CERT_DER

######
# intermediate CA
######
# this is the CA that signs device-id certs on the mfg line
INT_CA_DIR=./intermediate-ca
mkdir $INT_CA_DIR
pushd $INT_CA_DIR
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber
popd

# create intermediate CA key
INT_CA_KEY=$KEY_DIR/int-ca.key.pem
if [ ! -f $INT_CA_KEY ]; then
    openssl genpkey \
        -algorithm $KEY_ALG $KEY_OPTS \
        -out $INT_CA_KEY
    chmod 400 $INT_CA_KEY
fi

INT_CA_CSR=$ROOT_CA_DIR/csr/intermediate-ca.csr.pem

INT_CA_SUBJ="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=Manufacturing/CN=intermediate-ca"
openssl req \
      -config $OPENSSL_CNF \
      -subj "$INT_CA_SUBJ" \
      -new \
      -$HASH \
      -key $INT_CA_KEY \
      -out $INT_CA_CSR

INT_CA_CERT_PEM=$INT_CA_DIR/certs/ca.cert.pem
INT_CA_CERT_DER=$INT_CA_DIR/certs/ca.cert.der
INT_CA_CERT_TXT=$INT_CA_DIR/certs/ca.cert.txt

# create and sign cert for intermediate key with root ca
# NOTE the -name ca_root field, this causes `openssl ca` to get the signing
# key for the CA from the config file section `ca_root`.
openssl ca \
      -config $OPENSSL_CNF \
      -batch \
      -name ca_root \
      -extensions v3_intermediate_ca \
      -days 3650 \
      -notext \
      -md $HASH \
      -in $INT_CA_CSR \
      -out $INT_CA_CERT_PEM
openssl x509 \
	-in $INT_CA_CERT_PEM \
	-noout \
	-text \
	> $INT_CA_CERT_TXT
openssl x509 \
	-outform der \
	-in $INT_CA_CERT_PEM \
	-out $INT_CA_CERT_DER

######
# DeviceId ECA
######
# This CA is an embedded CA (ECA) according to DICE.
# We use this to create template that the RoT uses to create CSRs for DeviceId
# certs signed by the intermediate CA.
DEVICEID_ECA_DIR=./deviceid-eca
mkdir $DEVICEID_ECA_DIR
pushd $DEVICEID_ECA_DIR
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 10 > serial
echo 10 > crlnumber
popd

DEVICEID_ECA_KEY=$KEY_DIR/deviceid-eca.key.pem
if [ ! -f $DEVICEID_ECA_KEY ]; then
    openssl genpkey \
        -algorithm $KEY_ALG $KEY_OPTS \
        -out $DEVICEID_ECA_KEY
fi

# create and sign cert for intermediate key with root ca
# NOTE the -name ca_root field, this causes `openssl ca` to get the signing
# key for the CA from the config file section `ca_root`.
DEVICEID_ECA_CSR_PEM=$INT_CA_DIR/csr/deviceid-eca.csr.pem
DEVICEID_ECA_CSR_DER=$INT_CA_DIR/csr/deviceid-eca.csr.der
DEVICEID_ECA_CSR_TXT=$INT_CA_DIR/csr/deviceid-eca.csr.txt

DEVICEID_ECA_SUBJ="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=Manufacturing/serialNumber=000000000000/CN=device-id"
openssl req \
      -config $OPENSSL_CNF \
      -subj "$DEVICEID_ECA_SUBJ" \
      -new \
      -$HASH \
      -key $DEVICEID_ECA_KEY \
      -out $DEVICEID_ECA_CSR_PEM
openssl req \
	-outform der \
	-in $DEVICEID_ECA_CSR_PEM \
	-out $DEVICEID_ECA_CSR_DER
openssl req \
	-noout \
	-text \
	-in $DEVICEID_ECA_CSR_PEM \
	> $DEVICEID_ECA_CSR_TXT

DEVICEID_ECA_CERT_PEM=$DEVICEID_ECA_DIR/certs/ca.cert.pem
DEVICEID_ECA_CERT_DER=$DEVICEID_ECA_DIR/certs/ca.cert.der
DEVICEID_ECA_CERT_TXT=$DEVICEID_ECA_DIR/certs/ca.cert.txt

# Create and sign cert for mock DeviceId ECA.
# Sign DeviceId ECA cert with intermediate CA.
openssl ca \
      -config $OPENSSL_CNF \
      -batch \
      -name ca_intermediate \
      -extensions v3_deviceid_eca \
      -enddate '99991231235959Z' \
      -notext \
      -md $HASH \
      -in $DEVICEID_ECA_CSR_PEM \
      -out $DEVICEID_ECA_CERT_PEM

openssl x509 \
	-in $DEVICEID_ECA_CERT_PEM \
	-noout \
	-text \
	> $DEVICEID_ECA_CERT_TXT
openssl x509 \
	-outform der \
	-in $DEVICEID_ECA_CERT_PEM \
	-out $DEVICEID_ECA_CERT_DER

# create file with cert chain: intermediate & deviceid-eca
DEVICEID_ECA_CERT_CHAIN_PEM=$DEVICEID_ECA_DIR/certs/deviceid-cert-chain.pem
cat $INT_CA_CERT_PEM $DEVICEID_ECA_CERT_PEM > $DEVICEID_ECA_CERT_CHAIN_PEM

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

ALIAS_SUBJ="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=Manufacturing/serialNumber=000000000000/CN=alias"
openssl req \
      -config $OPENSSL_CNF \
      -subj "$ALIAS_SUBJ" \
      -new \
      -$HASH \
      -key $ALIAS_KEY \
      -out $ALIAS_CSR_PEM

ALIAS_CERT_PEM="$DEVICEID_ECA_DIR/certs/alias.cert.pem"
ALIAS_CERT_DER="$DEVICEID_ECA_DIR/certs/alias.cert.der"
ALIAS_CERT_TXT="$DEVICEID_ECA_DIR/certs/alias.cert.txt"

openssl ca \
      -config $OPENSSL_CNF \
      -batch \
      -name ca_deviceid_eca \
      -extensions v3_alias \
      -enddate '99991231235959Z' \
      -notext \
      -md $HASH \
      -in $ALIAS_CSR_PEM \
      -out $ALIAS_CERT_PEM

openssl x509 \
	-in $ALIAS_CERT_PEM \
	-noout \
	-text \
	> $ALIAS_CERT_TXT
openssl x509 \
	-outform der \
	-in $ALIAS_CERT_PEM \
	-out $ALIAS_CERT_DER

# create file with cert chain: intermediate & deviceid-eca
ALIAS_CERT_CHAIN_PEM=$DEVICEID_ECA_DIR/certs/alias-cert-chain.pem
cat $INT_CA_CERT_PEM $DEVICEID_ECA_CERT_PEM $ALIAS_CERT_PEM > $ALIAS_CERT_CHAIN_PEM

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

SP_MEASURE_SUBJ="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=Manufacturing/serialNumber=000000000000/CN=sp-measure"
openssl req \
      -config $OPENSSL_CNF \
      -subj "$SP_MEASURE_SUBJ" \
      -new \
      -$HASH \
      -key $SP_MEASURE_KEY \
      -out $SP_MEASURE_CSR_PEM

SP_MEASURE_CERT_PEM="$DEVICEID_ECA_DIR/certs/sp-measure.cert.pem"
SP_MEASURE_CERT_DER="$DEVICEID_ECA_DIR/certs/sp-measure.cert.der"
SP_MEASURE_CERT_TXT="$DEVICEID_ECA_DIR/certs/sp-measure.cert.txt"

openssl ca \
      -config $OPENSSL_CNF \
      -batch \
      -name ca_deviceid_eca \
      -extensions v3_spmeasure \
      -enddate '99991231235959Z' \
      -notext \
      -md $HASH \
      -in $SP_MEASURE_CSR_PEM \
      -out $SP_MEASURE_CERT_PEM

openssl x509 \
	-in $SP_MEASURE_CERT_PEM \
	-noout \
	-text \
	> $SP_MEASURE_CERT_TXT
openssl x509 \
	-outform der \
	-in $SP_MEASURE_CERT_PEM \
	-out $SP_MEASURE_CERT_DER

# create file with cert chain: intermediate & deviceid-eca
SP_MEASURE_CERT_CHAIN_PEM=$DEVICEID_ECA_DIR/certs/sp-measure-cert-chain.pem
cat $INT_CA_CERT_PEM $DEVICEID_ECA_CERT_PEM $SP_MEASURE_CERT_PEM > $SP_MEASURE_CERT_CHAIN_PEM
