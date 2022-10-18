#!/bin/bash

set -e

# defaults from init-dice-intermediate-ca.sh
DEFAULT_CFG=dice-intermediate-ca_openssl.cnf
DEFAULT_SERIAL_DEV=/dev/ttyACM0

print_usage ()
{
    cat <<END
Usage: $0
    [ -c | --cfg - path to openssl cfg (DEFAULT: $DEFAULT_CFG) ]
    [ -p | --ca-dir - path where CSR is written (optional) ]
    [ -a | --ca-section - openssl config ca section (optional, uses default from config) ]
    [ -i | --ca-cert - cert sent to manufactured systems ]
    [ -d | --serial-dev - serial device (DEFAULT: $DEFAULT_SERIAL_DEV) ]
    [ -s | --v3-section - x509 v3 extension section (optional, uses default from config) ]
    [ -h | --help  ]
END

    exit 2
}

while test $# -gt 0; do
    case $1 in
    --help) print_usage; exit $?;;
    -a|--ca-section) CA_SECTION=$2; shift;;
    -a=*|--ca-section=*) CA_SECTION="${1#*=}";;
    -c|--cfg) CFG=$2; shift;;
    -c=*|--cfg=*) CFG="${1#*=}";;
    -i|--cert) CA_CERT=$2; shift;;
    -i=*|--cert=*) CA_CERT="${1#*=}";;
    -d|--serial-dev) SERIAL_DEV=$2; shift;;
    -d=*|--serial-dev=*) SERIAL_DEV="${1#*=}";;
    -s|--v3-section) V3_SECTION=$2; shift;;
    -s=*|--v3-section=*) V3_SECTION="${1#*=}";;
     --) shift; break;;
    -*) usage_error "invalid option: '$1'";;
     *) break;;
    esac
    shift
done

# defaults if not set via options or env
if [ -z ${CFG+x} ]; then
    CFG=$DEFAULT_CFG
fi
if [ -z ${SERIAL_DEV+x} ]; then
    SERIAL_DEV=$DEFAULT_SERIAL_DEV
fi

if [ ! -z ${CA_SECTION+x} ]; then
    CA_SECTION="--ca-section $CA_SECTION"
fi
if [ ! -z ${V3_SECTION+x} ]; then
    V3_SECTION="--v3-section $V3_SECTION"
fi

if [ -z ${CA_CERT+x} ]; then
    >&2 "missing required parameter: --ca-cert"
    exit 1
fi

# export for dice-mfg commands
export SERIAL_DEV=$SERIAL_DEV

# get serial number and validate
# if SN is set on command line (positional) use it
if [ ! -z ${1+x} ]; then
    SERIAL_NUMBER=$1
elif [ -z ${SERIAL_NUMBER+x} ]; then
    # if not set through env, error
    >&2 echo "missing serial number, try --help"
    exit 1
fi

# validate SN
SN_LEN=11
if echo "$SERIAL_NUMBER" | grep "[[:alnum:]]\{$SN_LEN\}"; then
    echo "good sn"
else
    echo "malformed serial number"
    exit 1
fi
# generate random SN
#SERIAL_NUMBER="$(cat /dev/urandom | tr -dc '[:alnum:]' | fold -w $SN_LEN | head -n 1)"

# send platform being manufactured its serial number
cargo run --bin dice-mfg -- set-serial-number "$SERIAL_NUMBER"
if [ $? -ne 0 ]; then
    >&2 echo "failed to set SN to: \"${SERIAL_NUMBER}\""
    exit 1
fi

# Both the CSR from the platform being manufactured and the cert we send back
# to it are temp files. `openssl ca` will store a copy of the cert internally.
TMP_DIR=$(mktemp -d -t ${0##*/}-XXXXXXXXXX)
CSR_FILE=$TMP_DIR/${SERIAL_NUMBER}.csr.pem
CERT_FILE=$TMP_DIR/${SERIAL_NUMBER}.cert.pem

# get CSR for platform w/ provided serial number
cargo run --bin dice-mfg -- get-csr $CSR_FILE
if [ $? -ne 0 ]; then
    >&2 echo "failed to get CSR"
    exit 1
fi

# sign CSR, create Cert
./dice-ca-sign.sh \
    $CA_SECTION \
    --cert-out $CERT_FILE \
    --csr-in $CSR_FILE \
    --openssl-cnf $CFG \
    $V3_SECTION
if [ $? -ne 0 ]; then
    >&2 echo "failed to generate cert"
    exit 1
fi

# send platform it's DeviceId cert
cargo run --bin dice-mfg -- set-device-id $CERT_FILE
if [ $? -ne 0 ]; then
    >&2 echo "failed to set DeviceId cert"
    exit 1
fi

# send platform the cert for the CA that signed the DeviceId
# we assume this is an intermediate CA
cargo run --bin dice-mfg -- set-intermediate $CA_CERT
if [ $? -ne 0 ]; then
    >&2 echo "failed to set intermediate CA cert"
    exit 1
fi

# platform has all of the data that makes up its identity
# DeviceId manufacutring is complete, send break command to end mfg 
cargo run --bin dice-mfg -- "break"
if [ $? -ne 0 ]; then
    >&2 echo "failed to finalize mfg"
    exit 1
fi
