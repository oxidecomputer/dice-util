#!/bin/bash

# params / config file?
# - intermediate cert
# - CA root
# - serial dev
# - baud
# - serial number

# this should be 11
SN_LEN=12
SN="$(cat /dev/urandom | tr -dc '[:alnum:]' | fold -w $SN_LEN | head -n 1)"
INTERMEDIATE_CERT=./ca-script/intermediate-ca/certs/ca.cert.pem

if [ ! -f $INTERMEDIATE_CERT ]; then
    >&2 echo "intermediate cert doesn't exist"
    exit 1
fi

echo "setting SN to: $SN"
# set random serial number
cargo run --bin dicemfg-set-sn -- \
    --serial-dev /dev/ttyUSB0 \
    --baud 9600 \
    --serial-number \
    "$SN"

if [ $? -ne 0 ]; then
    # reset RoT
    >&2 echo "failed to set SN to: \"${SN}\""
    exit 1
fi

# should be a temp file
CSR_FILE=${SN}.csr.pem

echo "getting CSR ..."
# get CSR for platform w/ provided serial number
cargo run --bin dicemfg-get-csr -- \
    --serial-dev /dev/ttyUSB0 \
    --baud 9600 \
    --csr-path $CSR_FILE

if [ $? -ne 0 ]; then
    # reset RoT / humility reset
    >&2 echo "failed to get CSR"
    exit 1
fi

CA_ROOT=./ca-script/
CA_SECTION=ca_intermediate
# should be a temp file
CERT_FILE=${SN}.cert.pem
V3_SECTION=v3_deviceid_eca
OPENSSL_CNF=$CA_ROOT/openssl.cnf

echo "generating X.509 ..."
cargo run --bin dicemfg-sign-csr -- \
    --ca-dir $CA_ROOT \
    --ca-section $CA_SECTION \
    --cert-out $CERT_FILE \
    --csr-in $CSR_FILE \
    --openssl-cnf $OPENSSL_CNF \
    --v3-section $V3_SECTION

if [ $? -ne 0 ]; then
    # reset RoT / humility reset
    >&2 echo "failed to generate cert"
    exit 1
fi

cargo run --bin dicemfg-set-deviceid -- \
    --serial-dev /dev/ttyUSB0 \
    --baud 9600 \
    --cert-path $CERT_FILE

if [ $? -ne 0 ]; then
    # reset RoT / humility reset
    >&2 echo "failed to set DeviceId cert"
    exit 1
fi

cargo run --bin dicemfg-set-intermediate -- \
    --serial-dev /dev/ttyUSB0 \
    --baud 9600 \
    --cert-path $INTERMEDIATE_CERT

if [ $? -ne 0 ]; then
    # reset RoT / humility reset
    >&2 echo "failed to set intermediate cert"
    exit 1
fi

cargo run --bin dicemfg-break -- \
    --serial-dev /dev/ttyUSB0 \
    --baud 9600

if [ $? -ne 0 ]; then
    # reset RoT / humility reset
    >&2 echo "failed to finalize mfg"
    exit 1
fi
