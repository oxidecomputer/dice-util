#!/bin/bash

# defaults
OPENSSL_CNF=openssl.cnf
CA_SECTION=ca_intermediate
V3_SECTION=v3_deviceid_eca
CSR_OUT=csr.pem
KEY=key.pem
SERIAL_NUMBER=$(cat /dev/urandom | tr -dc '[:alnum:]' | fold -w 11 | head -n 1)

print_usage ()
{
    cat <<END
Usage: $0
    [ --csr-out - path where CSR is written ]
    [ --key - key described by generated CSR ]
    [ --openssl-cnf - config file passed to openssl ]
    [ --serial-number - platform serial number (default: 11 alpha-numeric) ]
    [ -h | --help  ]
END

    exit 2
}

while test $# -gt 0; do
    case $1 in
    --help) print_usage; exit $?;;
    -c|--openssl-cnf) OPENSSL_CNF=$2; shift;;
    -c=*|--openssl-cnf=*) OPENSSL_CNF="${1#*=}";;
    -o|--csr-out) CSR_OUT=$2; shift;;
    -o=*|--csr-out=*) CSR_OUT="${1#*=}";;
    -k|--key) KEY=$2; shift;;
    -k=*|--key=*) KEY="${1#*=}";;
    # this needs a validator
    -s|--serial-number) SERIAL_NUMBER=$2; shift;;
    -s=*|--serial-number=*) SERIAL_NUMBER="${1#*=}";;
     --) shift; break;;
    -*) usage_error "invalid option: '$1'";;
     *) break;;
    esac
    shift
done

echo $SERIAL_NUMBER | grep -E '^[[:alnum:]]{11}$'
if [ $? -ne 0 ]; then
    >2 echo "invalid serial number, try --help"
    exit 1
fi

DEVICEID_ECA_SUBJ="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=Manufacturing/serialNumber=$SERIAL_NUMBER/CN='device-id"

# Create CSR for DeviceId.
openssl req \
      -config $OPENSSL_CNF \
      -subj "$DEVICEID_ECA_SUBJ" \
      -new \
      -sha3-256 \
      -key $KEY \
      -out $CSR_OUT
