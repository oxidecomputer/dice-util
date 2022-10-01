# ca-scripts

Like pretty much every security architecture, trust in the DICE credentials
derived at boot relies on PKI. A mature deployment will use best practices to
tightly control certificate issuance and management. Our initial implementation
however requires something more agile. This directory hosts scripts and
configuration used to create mock CAs to model the certificate hierarchies
created for / by DICE.
