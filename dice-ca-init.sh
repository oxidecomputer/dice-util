#!/bin/bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

DEFAULT_CA_DIR=$(pwd)/ca
DEFAULT_YUBI="true"
DEFAULT_SELFSIGNED="false"
DEFAULT_PIN=123456
# NOTE: We do not support using slot 9c. This slot, per the spec, is supposed
# to require pin entry on each use. Openssl takes this pretty seriously and
# will ignore the pin provided in the config file. There doesn't seem to be
# consensus as to whether this is a bug or a feature.
# https://bugzilla.redhat.com/show_bug.cgi?id=1728016
# https://stackoverflow.com/questions/57729106/how-to-pass-yubikey-pin-to-openssl-command-in-shell-script
DEFAULT_SLOT=9a
DEFAULT_SUBJECT_SELFSIGNED="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=dvt/CN=root-ca"
DEFAULT_SUBJECT_INTERMEDIATE="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=dvt/CN=intermediate-ca"

# finding the ykcs11 library takes some doing
PKG_CONFIG=$(which pkg-config 2> /dev/null)
if [ $? -ne 0 ]; then
    >&2 echo "Missing required command: pkg-config"
    exit 1
fi
DEFAULT_PKCS=$($PKG_CONFIG --variable=libdir ykcs11)/libykcs11.so
if [ ! -f $DEFAULT_PKCS ]; then
    >&2 echo "Missing ykcs11 library, is it installed?"
    exit 1
fi

print_usage ()
{
    cat <<END
Usage: $0
    [ --dir - root directory for CA files & openssl.cnf (DEFAULT: $DEFAULT_CA_DIR) ]
    [ --self-signed - create self signed cert instead of CSR ]
    [ --subject - an optional subject string for the CSR / cert ]
    [ --no-yubi - don't use a yubikey, keep keys in files on disk (DEFAULT: false) ]
    NOTE: the following options only apply when \'--no-yubi\' is *NOT* provided
    [ --pkcs11 - path to shared library implementing PKCS#11 (DEFAULT: $DEFAULT_PKCS) ]
    [ --slot - PIV slot for key, allowed values: (9a | 9d | 82) (DEFAULT: $DEFAULT_SLOT) ]
    [ --pin - PIN required for key generation (DEFAULT: $DEFAULT_PIN) ]
    [ --archive-prefix - file name prefix for archive of artifacts, \'.tar.xz\' is appended]
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
    -h|--help) print_help; exit $?;;
    -d|--dir) CA_DIR=$2; shift;;
    -d=*|--dir=*) CA_DIR="${1#*=}";;
    -n|--no-yubi) YUBI="false";;
    -p|--pin) PIN=$2; shift;;
    -p=*|--pin=*) PIN="${1#*=}";;
    -l|--slot) SLOT=$2; shift;;
    -l=*|--slot=*) SLOT="${1#*=}";;
    -k|--pkcs11) PKCS=$2; shift;;
    -k=*|--pkcs11=*) PKCS="${1#*=}";;
    -o|--archive-prefix) ARCHIVE_PREFIX=$2; shift;;
    -o=*|--archive-prefix=*) ARCHIVE_PREFIX="${1#*=}";;
    -s|--self-signed) SELFSIGNED=true;;
    -u|--subject) SUBJECT=$2; shift;;
    -u=*|--subject=*) SUBJECT="${1#*=}";;
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

# don't check too hard
if [ -z ${YUBI+x} ]; then
    YUBI=$DEFAULT_YUBI
fi
if [ -z ${SELFSIGNED+x} ]; then
    SELFSIGNED=$DEFAULT_SELFSIGNED
fi
# take subject (or at least CN, maybe OU?) as option
if [ -z ${SUBJECT+x} ]; then
    if [ $SELFSIGNED = "true" ]; then
        SUBJECT=$DEFAULT_SUBJECT_SELFSIGNED
    else
        SUBJECT=$DEFAULT_SUBJECT_INTERMEDIATE
    fi
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

piv_slot_to_pkcs11_id() {
    local slot=$1
    case $slot in
        9a) echo "slot_0-id_1";;
        9d) echo "slot_0-id_3";;
        82) echo "slot_0-id_5";;
        *) return 1;;
    esac
}

# multiple yubikeys / PIV devices would require identifying the slot too?
if [ $YUBI = "true" ]; then
    OPENSSL_KEY=$(piv_slot_to_pkcs11_id $SLOT)
    if [ $? -ne 0 ]; then
        usage_error "invalid slot"
    fi
    KEY=$OPENSSL_KEY
    # assume eccp384
    HASH=sha384
    if [ -z ${ARCHIVE_PREFIX+x} ]; then
        >&2 echo "missing required argument: --archive-prefix"
	exit 1
    else
        ARCHIVE_FILE=${ARCHIVE_PREFIX}.tar.xz
    fi
else
    OPENSSL_KEY="\$dir/private/ca.key.pem"
    KEY=$CA_DIR/private/ca.key.pem
    # assume ed25519
    HASH=sha3-256
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

do_generate_cfg () {
    # first parameter is the output file
    # second parameter is whether or not the CA generated is self signed
    #   "true" or otherwise
    if [ -z ${1+x} -o -z ${2+x} ]; then
        >&2 echo "$0: missing parameter"
    fi
    local OUT=$1
    local SELFSIGNED=$2
    cat << EOF > $OUT
# generated by $0
openssl_conf = openssl_init

[ engine_section ]
pkcs11 = pkcs11_section

[ pkcs11_section ]
engine_id = pkcs11
MODULE_PATH = $PKCS
PIN = $PIN

[ openssl_init ]
engines = engine_section
EOF
    if [ $SELFSIGNED = "true" ]; then
        # root certs default to the config for intermediate certs
        cat << EOF >> $OUT

[ ca ]
default_ca = ca_intermediate
EOF
    else
        # intermediate certs default to the config for issuing DeviceId certs
        # this requires OIDs from the TCG DICE spec
        cat << EOF >> $OUT
oid_section = OIDs

[ ca ]
default_ca = ca_deviceid
EOF
    fi

    # root and intermediate CAs get the config sections for an intermediate ca
    cat << EOF >> $OUT

[ ca_intermediate ]
dir = $CA_DIR
certs = \$dir/certs
crl_dir = \$dir/crl
new_certs_dir = \$dir/newcerts
database = \$dir/index.txt
serial = \$dir/serial
RANDFILE = \$dir/private/.rand
private_key = $OPENSSL_KEY
certificate = \$dir/certs/ca.cert.pem
name_opt = ca_default
cert_opt = ca_default
default_days = 3650
default_md = $HASH
preserve = no
policy = policy_strict
x509_extensions = v3_intermediate_ca

[ v3_intermediate_ca ]
authorityKeyIdentifier = none
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign
subjectKeyIdentifier = none
EOF

    # intermediate CAs get the config section for the DeviceId CA
    if [ $SELFSIGNED != "true" ]; then
        cat << EOF >> $OUT

[ ca_deviceid ]
dir = $CA_DIR
certs = \$dir/certs
crl_dir = \$dir/crl
new_certs_dir = \$dir/newcerts
database = \$dir/index.txt
serial = \$dir/serial
RANDFILE = \$dir/private/.rand
private_key = $OPENSSL_KEY
certificate = \$dir/certs/ca.cert.pem
name_opt = ca_default
cert_opt = ca_default
default_enddate = 99991231235959Z
default_md = $HASH
preserve = no
policy = policy_strict
x509_extensions = v3_deviceid_eca

[ v3_deviceid_eca ]
authorityKeyIdentifier = none
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign
certificatePolicies = critical, tcg-dice-kp-eca, tcg-dice-kp-attestInit
subjectKeyIdentifier = none

[ OIDs ]
tcg-dice-kp-identityInit = 2.23.133.5.4.100.6
tcg-dice-kp-attestInit = 2.23.133.5.4.100.8
tcg-dice-kp-eca = 2.23.133.5.4.100.12
EOF
    fi

    # req
    cat << EOF >> $OUT

[ policy_strict ]
countryName = match
organizationName = match
commonName = supplied

[ req ]
distinguished_name = req_distinguished_name
string_mask = utf8only
x509_extensions = v3_intermediate_ca
default_md = sha384

[ req_distinguished_name ]
countryName = Country Name (2 letter code)
countryName_default = US
0.organizationName = Organization Name
0.organizationName_default = Oxide Computer Company
commonName = Common Name
EOF
}

CFG_OUT=$CA_DIR/openssl.cnf
do_generate_cfg "$CFG_OUT" "$SELFSIGNED"

TMP_DIR=$(mktemp -d -t ${0##*/}-XXXXXXXXXX)
LOG=$TMP_DIR/out.log

# everything in this directory will be rolled up into $ARCHIVE_FILE
ARCHIVE_DIR=$TMP_DIR/$ARCHIVE_PREFIX
mkdir -p $ARCHIVE_DIR

# do_keygen, YUBI = false
do_keygen_false ()
{
    # key for CA signing operations: path is used in openssl.cnf
    echo -n "Generating ed25519 key in file \"$KEY\" ... "
    openssl genpkey \
        -algorithm ED25519 \
        -out $KEY > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi
}

# do_keygen, YUBI = true
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

# do_cred, SELFSIGNED = false, YUBI = false
do_cred_false_false ()
{
    local CSR=$CA_DIR/csr/ca.csr.pem

    echo -n "Generating CSR for key \"$KEY\" w/ subject: \"$SUBJECT\" ... "
    openssl req \
        -config $CFG_OUT \
        -subj "$SUBJECT" \
        -new \
        -sha3-256 \
        -key $KEY \
        -out $CSR > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi
}

# do_cred, selfsigned = false, yubikey = true
do_cred_false_true ()
{
    local CSR=$ARCHIVE_DIR/ca.csr.pem

    echo -n "Generating CSR w/ subject: '$SUBJECT' ... "
    OPENSSL_CONF=$CFG_OUT \
    openssl req \
        -new \
        -engine pkcs11 \
        -keyform engine \
        -key $KEY \
        -sha384 \
        -subj "$SUBJECT" \
        -out $CSR > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi

    local ATTEST_INT_CERT=$ARCHIVE_DIR/attest-intermediate.cert.pem
    echo -n "Getting attestation intermediate cert from slot 'f9' ... "
    yubico-piv-tool \
        --action read-certificate \
        --slot f9 \
        --output $ATTEST_INT_CERT > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi

    local ATTEST_CERT=$ARCHIVE_DIR/attest-leaf.cert.pem
    echo -n "Generating attestation for key in slot '$SLOT' ... "
    yubico-piv-tool \
        --action attest \
        --slot $SLOT \
        --output $ATTEST_CERT > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi

    local VERIFY_SH=$ARCHIVE_DIR/verify-attestation.sh
    cat << EOF > $VERIFY_SH
#!/bin/sh
# script generated by $0

NAME=\${0##*/}
TMP_DIR=\$(mktemp -d -t \${0##*/}-XXXXXXXX)
LOG=\$TMP_DIR/\$NAME
ATTEST_ROOT_CERT=\$TMP_DIR/attest-root.cert.pem
ATTEST_ROOT_URL="https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem"

echo -n "Getting attestation root cert from yuboco.com ... "
wget --output-document \$ATTEST_ROOT_CERT \$ATTEST_ROOT_URL > \$LOG 2>&1
if [ $? -eq 0 ]; then
    echo "success"
else
    echo "failure"
    cat \$LOG
    exit 1
fi

ATTEST_CERT=$(basename $ATTEST_CERT)
ATTEST_INT_CERT=$(basename $ATTEST_INT_CERT)
AWK_CMD="BEGIN { out=0 } /ASN1 OID:/ { out=0 } // { if (out == 1) print \\\$0 } /pub:/ { out=1 }"

echo -n "Verifying attestation signature ... "
openssl verify -CAfile \$ATTEST_ROOT_CERT -untrusted \$ATTEST_INT_CERT \$ATTEST_CERT > \$LOG 2>&1
if [ \$? -eq 0 ]; then
    echo "success"
else
    echo "failure"
    cat \$LOG
    exit 1
fi

CSR=$(basename $CSR)

echo -n "Ensuring public key in attestation matches the CA cert ... "
PUB_CSR=\$(openssl req \
    -in \$CSR \
    -noout \
    -text 2> /dev/null \
| awk "\$AWK_CMD" \
| tr -d " \t\n\r:")
PUB_ATTEST=\$(openssl x509 \
    -in \$ATTEST_CERT \
    -noout \
    -text 2> /dev/null \
| awk "\$AWK_CMD" \
| tr -d " \t\n\r:")
if [ "\$PUB_CSR" = "\$PUB_ATTEST" ]; then
    echo "success"
else
    echo "failure"
    exit 1
fi
EOF
    chmod 755 $VERIFY_SH

    local ATTEST_README=$ARCHIVE_DIR/README.md
    cat << EOF > $ATTEST_README
# yubikey attestation data

This archive contains data sufficient to verify the Yubikey attestation for
the key associated with $CA_CERT. Each file is discussed below. The relevant
yubico docs can be found here:
https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
https://developers.yubico.com/yubico-piv-tool/Attestation.html

## $(basename $VERIFY_SH)
This script is an example of how a PIV attestation from a yubikey may be
verified. It obtains the root CA cert from yubico and then verifies the
signature on the leaf attestation cert through the intermediate CA (the CA
on the yubikey). Additionally this script extracts the public key from the
leaf attestation cert and checks to be sure the cert for our key is the same.

Additional checks and data may be useful or necessary depending on use-case.
For additional fields and data that may be used see:
https://developers.yubico.com/PIV/Introduction/PIV_attestation.html

## $(basename $CSR)
This file is the CSR for the encryption key generated on our yubikey. Before
issuing a cert based on a CSR the CA must be convinced of a number of things
but typically they're concerned with verifying the identity of the requester.
The attestaion data in this archive can be used to convince the CA that the
private key associated with the CSR was created on and held within a yubikey.

## $(basename $ATTEST_CERT)
This file holds the attestation (a leaf cert) for the key generated on our
yubikey. This cert is created by the yubikey and signed by the yubikey's
intermediate attestation cert.

## $(basename $ATTEST_INT_CERT)
This is the certificate for the intermediate attestation key on the yubikey.
This key is provisioned by yubico and it's cert is signed by the yubico
attestation root.

EOF

    tar --directory $TMP_DIR \
        --auto-compress \
        --create \
        --file $ARCHIVE_FILE \
        $ARCHIVE_PREFIX

    # extract archive we've created and run the verification script
    tar --directory $TMP_DIR \
        --auto-compress \
        --extract \
        --file $ARCHIVE_FILE
    pushd $TMP_DIR/$ARCHIVE_PREFIX > /dev/null
    ./$(basename $VERIFY_SH)
    let ret=$?
    if [ $ret -ne 0 ]; then
        exit $ret
    fi
    popd > /dev/null

    # we've done some verification of the yubikey attestation, now copy CSR
    # generated here to CA csr directory
    cp $CSR $CA_DIR/csr
}

# do_cred, selfsigned = true, yubikey = false
do_cred_true_false ()
{
    local CERT=$CA_DIR/ca.cert.pem

    echo -n "Generating self signed cert using $HASH & subject: \"$SUBJECT\" ... "
    openssl req \
        -config $CFG_OUT \
        -subj "$SUBJECT" \
        -key $KEY \
        -new \
        -x509 \
        -extensions v3_ca \
	-sha3-256 \
        -out $CERT > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi
}

# do_cred, selfsigned = true, yubikey = true 
do_cred_true_true ()
{
    local ARCHIVE_DIR=$TMP_DIR/$ARCHIVE_PREFIX
    mkdir -p $ARCHIVE_DIR
    local CSR=$CA_DIR/csr/ca.csr.pem
    local CERT=$ARCHIVE_DIR/ca.cert.pem

    # ROOT
    echo -n "Generating CSR w/ subject: \"$SUBJECT\" ... "
    openssl req \
        -config $CFG_OUT \
        -new \
        -engine pkcs11 \
        -keyform engine \
        -key $KEY \
        -out $CSR \
        -subj "$SUBJECT" > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi

    echo -n "Generating self-signed cert from CSR ... "
    openssl ca \
        -selfsign \
        -batch \
        -config $CFG_OUT \
        -engine pkcs11 \
        -keyform engine \
        -key $KEY \
        -enddate 99991231235959Z \
        -in $CSR \
        -out $CERT > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi

    # ROOT
    echo -n "Importing cert from \"$CERT\" to slot \"$SLOT\" ... "
    yubico-piv-tool \
        --action import-certificate \
        --slot $SLOT \
        --input $CERT > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi
    
    local CERT_TMP=$ARCHIVE_DIR/ca.cert.pem

    # ROOT
    echo -n "Reading cert back from slot \"$SLOT\" ... "
    yubico-piv-tool \
        --action read-certificate \
        --slot $SLOT \
        --output $CERT_TMP > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi

    # ROOT
    echo -n "Checking cert consistency ... "
    if cmp $CERT_TMP $CERT; then
        echo "success"
    else
        echo "failure"
        exit 1
    fi

    local ATTEST_INT_CERT=$ARCHIVE_DIR/attest-intermediate.cert.pem
    echo -n "Getting attestation intermediate cert from slot \"f9\" ... "
    yubico-piv-tool \
        --action read-certificate \
	--slot f9 \
	--output $ATTEST_INT_CERT > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi

    local ATTEST_CERT=$ARCHIVE_DIR/attest-leaf.cert.pem
    echo -n "Generating attestation for key in slot \"$SLOT\" ... "
    yubico-piv-tool \
        --action attest \
        --slot $SLOT \
	--output $ATTEST_CERT > $LOG 2>&1
    if [ $? -eq 0 ]; then
        echo "success"
    else
        echo "failure"
        cat $LOG
        exit 1
    fi

    # ROOT - can make this generic to either selfsigned cert or CSR?
    # generate script to evaluate attestation
    local VERIFY_SH=$ARCHIVE_DIR/verify-attestation.sh
    cat << EOF > $VERIFY_SH
#!/bin/sh

NAME=\${0##*/}
TMP_DIR=\$(mktemp -d -t \${0##*/}-XXXXXXXX)
LOG=\$TMP_DIR/\$NAME
ATTEST_ROOT_CERT=\$TMP_DIR/attest-root.cert.pem
ATTEST_ROOT_URL="https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem"

echo -n "Getting attestation root cert from yuboco.com ... "
wget --output-document \$ATTEST_ROOT_CERT \$ATTEST_ROOT_URL > \$LOG 2>&1
if [ \$? -eq 0 ]; then
    echo "success"
else
    echo "failure"
    cat \$LOG
    exit 1
fi

ATTEST_CERT=$(basename $ATTEST_CERT)
ATTEST_INT_CERT=$(basename $ATTEST_INT_CERT)
AWK_CMD="BEGIN { out=0 } /ASN1 OID:/ { out=0 } // { if (out == 1) print \\\$0 } /pub:/ { out=1 }"

echo -n "Verifying attestation signature ... "
openssl verify -CAfile \$ATTEST_ROOT_CERT -untrusted \$ATTEST_INT_CERT \$ATTEST_CERT > \$LOG 2>&1
if [ \$? -eq 0 ]; then
    echo "success"
else
    echo "failure"
    cat \$LOG
    exit 1
fi

CA_CERT=$(basename $CERT)

echo -n "Ensuring public key in attestation matches the CA cert ... "
PUB_CERT=\$(openssl x509 \
    -in \$CA_CERT \
    -noout \
    -text 2> /dev/null \
| awk "\$AWK_CMD" \
| tr -d " \t\n\r:")
PUB_ATTEST=\$(openssl x509 \
    -in \$ATTEST_CERT \
    -noout \
    -text 2> /dev/null \
| awk "\$AWK_CMD" \
| tr -d " \t\n\r:")
if [ "\$PUB_CERT" = "\$PUB_ATTEST" ]; then
    echo "success"
else
    echo "failure"
    cat \$LOG
    exit 1
fi

EOF
    chmod 755 $VERIFY_SH

    # ROOT - only CERT section is specific to ROOT
    local ATTEST_README=$ARCHIVE_DIR/README.md
    cat << EOF > $ATTEST_README
# yubikey attestation data

This archive contains data sufficient to verify the Yubikey attestation for
the key associated with $CA_CERT. Each file is discussed below. The relevant
yubico docs can be found here:
https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
https://developers.yubico.com/yubico-piv-tool/Attestation.html

## $(basename $VERIFY_SH)
This script is an example of how a PIV attestation from a yubikey may be
verified. It obtains the root CA cert from yubico and then verifies the
signature on the leaf attestation cert through the intermediate CA (the CA
on the yubikey). Additionally this script extracts the public key from the
leaf attestation cert and checks to be sure the cert for our key is the same.

Additional checks and data may be useful or necessary depending on use-case.
For additional fields and data that may be used see:
https://developers.yubico.com/PIV/Introduction/PIV_attestation.html

## $(basename $CERT)
This file is the self-signed certificate for the encryption key generated on
our yubikey. Whether or not you trust this root CA cert depends on the results
of the attestation verification.

## $(basename $ATTEST_CERT)
This file holds the attestation (a leaf cert) for the key generated on our
yubikey. This cert is created by the yubikey and signed by the yubikey's
intermediate attestation cert.

## $(basename $ATTEST_INT_CERT)
This is the certificate for the intermediate attestation key on the yubikey.
This key is provisioned by yubico and it's cert is signed by the yubico
attestation root.

EOF

    tar --directory $TMP_DIR \
        --auto-compress \
        --create \
        --file $ARCHIVE_FILE \
        $ARCHIVE_PREFIX

    # extract archive we've created and run the verification script
    # local VERIFICATION_DIR=$TMP_DIR/verify
    # mkdir $VERIFICATION_DIR
    tar --directory $TMP_DIR \
        --auto-compress \
        --extract \
        --file $ARCHIVE_FILE
    pushd $TMP_DIR/$ARCHIVE_PREFIX > /dev/null
    ./$(basename $VERIFY_SH)
    if [ $? -ne 0 ]; then
        echo "failure"
        cat $LOG
        exit 1
    fi
    popd > /dev/null

    # we've done some verification of the yubikey attestation, now copy CSR
    # generated here to CA csr directory
    cp $CERT $CA_DIR/certs
}

do_cred_${SELFSIGNED}_${YUBI}

rm -rf $TMP_DIR
