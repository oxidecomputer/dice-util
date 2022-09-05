#!/usr/bin/bash

ROOT_CA_DIR=./root-ca
DEVICEID_CA_DIR=./deviceid-ca
DEVICEID_EMBEDDED_CA_DIR=./deviceid-embedded-ca

openssl verify \
    -CAfile $ROOT_CA_DIR/certs/ca.cert.pem \
    -untrusted $DEVICEID_CA_DIR/certs/ca.cert.pem \
    -untrusted $DEVICEID_EMBEDDED_CA_DIR/certs/ca.cert.pem \
    $DEVICEID_EMBEDDED_CA_DIR/certs/leaf.cert.pem
