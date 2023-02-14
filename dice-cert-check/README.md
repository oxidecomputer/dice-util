This is a crate hosting a prototype validation mechanism for the certificate
hierarchies created by Hubris on boot for DICE keys. We're doing this
validation manually / with new code instead of an existing implementation
like webpki because DICE certs contain at least one component (policy OID or v3
extension) that, if marked as 'critical', cause webpki to balk as it should.
Similarly webpki requires fields like 'subjectAltName' that we don't need
(yet?) and havne't included for size reasons.
