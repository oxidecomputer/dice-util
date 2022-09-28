#!/bin/bash

# defaults
OPENSSL_CNF=openssl.cnf
CA_SECTION=ca_intermediate
V3_SECTION=v3_deviceid_eca
CSR_IN=csr.pem
CERT_OUT=cert.pem

print_usage ()
{
    cat <<END
Usage: $0
    [ --csr-in - file with CSR in PEM form ]
    [ --cert-out - path where cert is written ]
    [ --ca-section - ca config file section ]
    [ --v3-section - v3 extension attribute config file section ]
    [ --openssl-cnf - config file passed to openssl ]
    [ -h | --help  ]
END
    exit 2
}

while test $# -gt 0; do
    case $1 in
    --help) print_usage; exit $?;;
    -c|--openssl-cnf) OPENSSL_CNF=$2; shift;;
    -c=*|--openssl-cnf=*) OPENSSL_CNF="${1#*=}";;
    -s|--ca-section) CA_SECTION=$2; shift;;
    -s=*|--ca-section=*) CA_SECTION="${1#*=}";;
    -v|--v3-section) V3_SECTION=$2; shift;;
    -v=*|--v3-section=*) V3_SECTION="${1#*=}";;
    -i|--csr-in) CSR_IN=$2; shift;;
    -i=*|--csr-in=*) CSR_IN="${1#*=}";;
    -o|--cert-out) CERT_OUT=$2; shift;;
    -o=*|--cert-out=*) CERT_OUT="${1#*=}";;
    --) shift; break;;
    -*) usage_error "invalid option: '$1'";;
     *) break;;
    esac
    shift
done

# Create and sign cert for mock DeviceId ECA.
# Sign DeviceId ECA cert with intermediate CA.
openssl ca \
      -config $OPENSSL_CNF \
      -batch \
      -name $CA_SECTION \
      -extensions $V3_SECTION \
      -enddate '99991231235959Z' \
      -notext \
      -md sha3-256 \
      -in $CSR_IN \
      -out $CERT_OUT
