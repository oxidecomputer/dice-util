#!/bin/bash

DEFAULT_CA_DIR=dice-intermediate-ca
DEFAULT_CSR_OUT=dice-intermediate-ca.csr.pem
DEFAULT_CFG_OUT=dice-intermediate-ca_openssl.cnf
DEFAULT_YUBI="false"
DEFAULT_PIN=123456
DEFAULT_PKCS=/usr/lib/x86_64-linux-gnu/libykcs11.so
# NOTE: We do not support using slot 9c. This slot, per the spec, is supposed
# to require pin entry on each use. Openssl takes this pretty seriously and
# will ignore the pin provided in the config file. There doesn't seem to be
# consensus as to whether this is a bug or a feature.
# https://bugzilla.redhat.com/show_bug.cgi?id=1728016
# https://stackoverflow.com/questions/57729106/how-to-pass-yubikey-pin-to-openssl-command-in-shell-script
DEFAULT_SLOT=9d

print_usage ()
{
    cat <<END
Usage: $0
    [ --cfg-out - path to output openssl cfg (DEFAULT: $DEFAULT_CFG_OUT) ]
    [ --csr-out - path where CSR is written (DEFAULT: $DEFAULT_CSR_OUT) ]
    [ --dir - root directory for CA files / cfg (DEFAULT: $DEFAULT_CA_DIR) ]
    [ --yubi - do key operations on a yubikey (DEFAULT: false) ]
    NOTE: the following options only apply when \'--yubikey\' is provided
    [ --pkcs11 - path to shared library implementing PKCS#11 (DEFAULT: $DEFAULT_PKCS) ]
    [ --slot - PIV slot for key, allowed values: (9a | 9d) (DEFAULT: $DEFAULT_SLOT) ]
    [ --pin - PIN required for key generation (DEFAULT: $DEFAULT_PIN) ]
    [ -h | --help  ]
END

    exit 2
}

print_help ()
{
    print_usage
    exit 0
}

usage_error ()
{
    >&2 echo "$1"
    print_usage
    exit 2
}

while test $# -gt 0; do
    case $1 in
    --help) print_usage; exit $?;;
    -d|--dir) CA_DIR=$2; shift;;
    -d=*|--dir=*) CA_DIR="${1#*=}";;
    -c|--cfg-out) CFG_OUT=$2; shift;;
    -c=*|--cfg-out=*) CFG_OUT="${1#*=}";;
    -o|--csr-out) CSR_OUT=$2; shift;;
    -o=*|--csr-out=*) CSR_OUT="${1#*=}";;
    -y|--yubi) YUBI="true";;
    -p|--pin) PIN=$2; shift;;
    -p=*|--pin=*) PIN="${1#*=}";;
    -l|--slot) SLOT=$2; shift;;
    -l=*|--slot=*) SLOT="${1#*=}";;
    -k|--pkcs11) PKCS=$2; shift;;
    -k=*|--pkcs11=*) PKCS="${1#*=}";;
    --) shift; break;;
    -*) usage_error "invalid option: '$1'";;
     *) break;;
    esac
    shift
done

# defaults if not set via options or env
if [ -z ${CA_DIR+x} ]; then
    CA_DIR=$DEFAULT_CA_DIR
fi
if [ -z ${CFG_OUT+x} ]; then
    CFG_OUT=$DEFAULT_CFG_OUT
fi
if [ -z ${CSR_OUT+x} ]; then
    CSR_OUT=$DEFAULT_CSR_OUT
fi

# don't check too hard
if [ -z ${YUBI+x} ]; then
    YUBI=$DEFAULT_YUBI
fi
if [ -z ${PIN+x} ]; then
    PIN=$DEFAULT_PIN
fi
if [ -z ${PKCS+x} ]; then
    PKCS=$DEFAULT_PKCS
fi
if [ -z ${SLOT+x} ]; then
    SLOT=$DEFAULT_SLOT
fi

OPENSSL_CERT=$CA_DIR/certs/ca.cert.pem
# multiple yubikeys / PIV devices would require identifying the slot too?
if [ $YUBI = "false" ]; then
    # this causes the paths in the config to get weird
    # TODO: make relative in openssl.cnf
    if [ -z ${OPENSSL_KEY+x} ]; then
        OPENSSL_KEY=$CA_DIR/private/ca.key.pem
    fi
else
    case $SLOT in
        9a) OPENSSL_KEY="slot_0-id_1";;
        9d) OPENSSL_KEY="slot_0-id_3";;
        *) usage_error "invalid slot";;
    esac
fi

set -e

mkdir -p $CA_DIR
pushd $CA_DIR > /dev/null
# Using absolute path makes the openssl.cnf flexible / usable from somewhere
# other than $CA_DIR. The down side: if you move CA_DIR you will need to
# update 'dir' in openssl.cnf.
CA_DIR=$(pwd)
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
popd > /dev/null

set +e

echo "# generated by $0" > $CFG_OUT

# config necessary to communicate with the yubikey
# TODO: possible to bind config to yubikey (by serial # etc)?
if [ $YUBI = "true" ]; then
    cat << EOF >> $CFG_OUT
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
MODULE_PATH = $PKCS
PIN = $PIN

EOF
fi

# config necessary to:
# - create CSR for intermediate CA
# - create & sign x509 DeviceId certs
cat << EOF >> $CFG_OUT
openssl_conf = openssl_init

[ openssl_init ]
oid_section = OIDs

[ ca ]
# \`man ca\`
default_ca = ca_default

[ ca_default ]
# Directory and file locations: 'dir' must be updated if moved.
dir               = $CA_DIR
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand
private_key       = $OPENSSL_KEY
certificate       = $OPENSSL_CERT

name_opt          = ca_default
cert_opt          = ca_default
default_enddate   = 99991231235959Z
preserve          = no
policy            = policy_strict
x509_extensions   = v3_deviceid_eca

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
localityName            = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
serialNumber            = optional
emailAddress            = optional

[ req ]
distinguished_name  = req_distinguished_name
string_mask         = utf8only
x509_extensions     = v3_intermediate_ca

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
serialNumber                    = Serial Number
emailAddress                    = Email Address

countryName_default             = US
stateOrProvinceName_default     = California
localityName_default            = Emeryville
0.organizationName_default      = Oxide Computer Company
organizationalUnitName_default  = Manufacturing
emailAddress_default            = security@oxidecomputer.com

[ v3_intermediate_ca ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign

[ v3_deviceid_eca ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign
certificatePolicies = critical, tcg-dice-kp-eca, tcg-dice-kp-attestInit

[ OIDs ]
tcg-dice-kp-attestInit = 2.23.133.5.4.100.8
tcg-dice-kp-eca = 2.23.133.5.4.100.12
EOF

# document in rfd 303
SUBJECT="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=Manufacturing/CN=intermediate-ca"

TMP_DIR=$(mktemp -d -t ${0##*/}-XXXXXXXXXX)
LOG=$TMP_DIR/out.log

# do_keygen_$yubi
do_keygen_false ()
{
    # key for CA signing operations: path is used in openssl.cnf
    echo -n "Generating ed25519 key in file \"$OPENSSL_KEY\" ... "
    openssl genpkey \
        -algorithm ED25519 \
        -out $OPENSSL_KEY > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi
}

do_keygen_true ()
{
    local PUB=$TMP_DIR/pub.pem

    echo -n "Generating ECCP384 key in slot \"$SLOT\" with provided pin ... "
    yubico-piv-tool \
        --action verify-pin \
        --pin $PIN \
        --action generate \
        --slot $SLOT \
        --algorithm ECCP384 \
        --output $PUB > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi
}

do_keygen_$YUBI

do_req_false ()
{
    echo -n "Generating CSR for key \"$OPENSSL_KEY\" w/ subject: \"$SUBJECT\" ... "
    openssl req \
        -config $CFG_OUT \
        -subj "$SUBJECT" \
        -new \
        -sha3-256 \
        -key $OPENSSL_KEY \
        -out $CSR_OUT > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi
}

do_req_true ()
{
    echo -n "Generating CSR w/ subject: \"$SUBJECT\" ... "
    OPENSSL_CONF=$CFG_OUT \
    openssl req \
        -new \
        -engine pkcs11 \
        -keyform engine \
        -key $OPENSSL_KEY \
        -sha384 \
        -subj "$SUBJECT" \
        -out $CSR_OUT > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi
}

do_req_$YUBI
