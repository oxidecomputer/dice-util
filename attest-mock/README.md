Testing often requires that we generate various artifacts used in the
attestation API. It's possible to use a live system to generate these artifacts
and then use them in testing but this doesn't give us much control: We can use
them unmodified but that limits what we can test, or we can modify them by hand
which is error prone and annoying.

The alternative is to generate these artifacts from a specification. For
complex structures like the cert chain this can be a lot of work (see
[pki-playground](https://github.com/oxidecomputer/pki-playground)). The other
structures are pretty simple though. This tool is intended to generate
`attest_data::Log` and `rats_corim::Corim` instances from KDL documents.

## example attest_data::Log KDL
```kdl
measurement {
    algorithm "sha3-256"
    digest "be4df4e085175f3de0c8ac4837e1c2c9a34e8983209dac6b549e94154f7cdd9c"
}
measurement {
    algorithm "sha3-256"
    digest "38e136aa11b0246211f36d8426702d90313f2a7dc50fa8a73d4e5007e70af3e3"
}
```

## example rats_corim::Corim KDL
```kdl
vendor "example.com"
tag-id "example-tag-id"
id "example-id"

measurement {
    mkey "fwid-from-cert-chain"
    algorithm 10
    digest "be4df4e085175f3de0c8ac4837e1c2c9a34e8983209dac6b549e94154f7cdd9c"
}

measurement {
    mkey "measurement-from-log"
    algorithm 10
    digest "38e136aa11b0246211f36d8426702d90313f2a7dc50fa8a73d4e5007e70af3e3"
}
```
