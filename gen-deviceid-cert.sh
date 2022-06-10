HASH=sha3-256
KEY_ALG_RSA=RSA
KEY_OPTS_RSA4K="-pkeyopt rsa_keygen_bits:4096"

KEY_ALG_EC=EC
KEY_OPTS_ECP384="-pkeyopt ec_paramgen_curve:P-384 \
    -pkeyopt ec_param_enc:named_curve"

KEY_ALG_ED25519=ED25519
KEY_OPTS_ED25519=

KEY_ALG=$KEY_ALG_ED25519
KEY_OPTS=$KEY_OPTS_ED25519

CA_DIR=./deviceid-ca

openssl genpkey \
    -algorithm $KEY_ALG $KEY_OPTS \
    -out deviceid.key.pem
openssl req \
    -config openssl.cnf \
    -new \
    -$HASH \
    -key deviceid.key.pem \
    -out deviceid.csr.pem
openssl ca \
    -config openssl.cnf \
    -batch \
    -name ca_deviceid \
    -extensions v3_deviceid \
    -days 3650 \
    -notext \
    -md $HASH \
    -in deviceid.csr.pem \
    -out deviceid.cert.pem
