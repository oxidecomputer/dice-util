#!/bin/bash

set -e

DEFAULT_CA_DIR=dice-intermediate-ca
DEFAULT_CSR_OUT=dice-intermediate-ca.csr.pem
DEFAULT_CFG_OUT=dice-intermediate-ca_openssl.cnf

print_usage ()
{
    cat <<END
Usage: $0
    [ --cfg-out - path to output openssl cfg (DEFAULT: $DEFAULT_CFG_OUT) ]
    [ --csr-out - path where CSR is written (DEFAULT: $DEFAULT_CSR_OUT) ]
    [ --dir - root directory for CA files / cfg (DEFAULT: $DEFAULT_CA_DIR) ]
    [ -h | --help  ]
END

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

KEY=$CA_DIR/private/ca.key.pem

mkdir $CA_DIR
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

# config necessary to:
# - create CSR for intermediate CA
# - create & sign x509 DeviceId certs
# TODO: slim this down / wtf is all this?
cat << EOF > $CFG_OUT
# config file generated by: $0
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
private_key       = \$dir/private/ca.key.pem
certificate       = \$dir/certs/ca.cert.pem

# For certificate revocation lists.
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30
default_md        = sha3-256

name_opt          = ca_default
cert_opt          = ca_default
default_enddate   = 99991231235959Z
preserve          = no
policy            = policy_strict
x509_extensions   = v3_deviceid_eca

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of \`man ca\`.
countryName             = match
stateOrProvinceName     = match
localityName            = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
serialNumber            = optional
emailAddress            = optional

[ req ]
# Options for the \`req\` tool (\`man req\`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha3-256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_intermediate_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
serialNumber                    = Serial Number
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = US
stateOrProvinceName_default     = California
localityName_default            = Emeryville
0.organizationName_default      = Oxide Computer Company
organizationalUnitName_default  = Manufacturing
emailAddress_default            = security@oxidecomputer.com

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (\`man x509v3_config\`).
basicConstraints = critical, CA:true, pathlen:1
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_deviceid_eca ]
# Extensions for the DeviceId embedded CA
# NOTE: pathlen:0 prevents us from signing any additional intermediates.
# This will prevent us from creating any intermediate embedded CAs.
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
certificatePolicies = critical, tcg-dice-kp-eca, tcg-dice-kp-attestInit

[dice_tcb_info]
field1=IMPLICIT:6,SEQUENCE:fwids

[fwids]
field1=SEQUENCE:sha3_256_null

[sha3_256_null]
field1=OID:2.16.840.1.101.3.4.2.8
field2=FORMAT:HEX,OCTETSTRING:0000000000000000000000000000000000000000000000000000000000000000

[ crl_ext ]
# Extension for CRLs (\`man x509v3_config\`).
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates (\`man ocsp\`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning

[OIDs]
tcg-dice-kp-attestInit = 2.23.133.5.4.100.8
tcg-dice-kp-eca = 2.23.133.5.4.100.12
dice-tcb-info = 2.23.133.5.4.1
EOF

# key for CA signing operations: path is used in openssl.cnf
openssl genpkey \
    -algorithm ED25519 \
    -out $KEY

# document in rfd 303
SUBJ="/C=US/ST=California/L=Emeryville/O=Oxide Computer Company/OU=Manufacturing/CN=intermediate-ca"
openssl req \
      -config $CFG_OUT \
      -subj "$SUBJ" \
      -new \
      -sha3-256 \
      -key $KEY \
      -out $CSR_OUT