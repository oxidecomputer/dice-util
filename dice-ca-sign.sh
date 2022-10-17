#!/bin/bash

# defaults
OPENSSL_CNF=openssl.cnf
CSR_IN=csr.pem
CERT_OUT=cert.pem

print_usage ()
{
    cat <<END
Usage: $0
    [ --csr-in - file with CSR in PEM form ]
    [ --cert-out - path where cert is written ]
    [ --ca-section - ca config file section ]
    [ --openssl-cnf - config file passed to openssl ]
    [ --v3-section - v3 extension attribute config file section ]
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

# if these are omitted we want openssl to use the default from the provided config
if [ ! -z ${CA_SECTION+x} ]; then
    CA_SECTION="-name $CA_SECTION"
fi
if [ ! -z ${V3_SECTION+x} ]; then
    V3_SECTION="-extensions $V3_SECTION"
fi

openssl ca \
      -config $OPENSSL_CNF \
      -batch \
      -notext \
      $CA_SECTION \
      $V3_SECTION \
      -in $CSR_IN \
      -out $CERT_OUT
