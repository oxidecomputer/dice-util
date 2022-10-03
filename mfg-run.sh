#!/bin/bash

# this should be 11
SN_LEN=12
SN="$(cat /dev/urandom | tr -dc '[:alnum:]' | fold -w $SN_LEN | head -n 1)"
INTERMEDIATE_CERT=./ca-script/intermediate-ca/certs/ca.cert.pem

if [ ! -f $INTERMEDIATE_CERT ]; then
    >&2 echo "intermediate cert doesn't exist"
    exit 1
fi

echo -n "setting SN to: $SN ... "
# set random serial number
cargo run --bin dice-mfg --  \
    --serial-dev /dev/ttyUSB0 \
    --baud 9600 \
    set-serial-number "$SN"
if [ $? -ne 0 ]; then
    >&2 echo "failed to set SN to: \"${SN}\""
    exit 1
fi
echo "success"

# should be a temp file
CSR_FILE=${SN}.csr.pem

echo -n "getting CSR ... "
# get CSR for platform w/ provided serial number
cargo run --bin dice-mfg -- \
    --serial-dev /dev/ttyUSB0 \
    --baud 9600 \
    get-csr $CSR_FILE
if [ $? -ne 0 ]; then
    >&2 echo "failed to get CSR"
    exit 1
fi
echo "success"

CA_ROOT=./ca-script/
CA_SECTION=ca_intermediate
# should be a temp file
CERT_FILE=${SN}.cert.pem
V3_SECTION=v3_deviceid_eca
OPENSSL_CNF=$CA_ROOT/openssl.cnf

echo -n "generating X.509 Cert ... "
cargo run --bin dicemfg-sign-csr -- \
    --ca-dir $CA_ROOT \
    --ca-section $CA_SECTION \
    --cert-out $CERT_FILE \
    --csr-in $CSR_FILE \
    --openssl-cnf $OPENSSL_CNF \
    --v3-section $V3_SECTION
if [ $? -ne 0 ]; then
    >&2 echo "failed to generate cert"
    exit 1
fi
echo "success"

echo -n "sending DeviceId Cert to RoT ... "
cargo run --bin dice-mfg -- \
    --serial-dev /dev/ttyUSB0 \
    --baud 9600 \
    set-device-id $CERT_FILE
if [ $? -ne 0 ]; then
    >&2 echo "failed to set DeviceId cert"
    exit 1
fi
echo "success"

echo -n "sending intermediate Cert to RoT ... "
cargo run --bin dice-mfg -- \
    --serial-dev /dev/ttyUSB0 \
    --baud 9600 \
    set-intermediate $INTERMEDIATE_CERT
if [ $? -ne 0 ]; then
    >&2 echo "failed to set intermediate cert"
    exit 1
fi
echo "success"

echo -n "Manufacturing complete, sending break ... "
cargo run --bin dice-mfg -- \
    --serial-dev /dev/ttyUSB0 \
    --baud 9600 \
    "break"
if [ $? -ne 0 ]; then
    >&2 echo "failed to finalize mfg"
    exit 1
fi
echo "success"
