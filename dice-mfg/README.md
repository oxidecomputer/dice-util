# dice-mfg

This crate hosts tools used by the manufacturing side of the DeviceId certification process.
It uses the serial-rs crate to exchange messages from the dice-mfg-msgs crate with RoTs.
These messages are used to get a CSR for the DeviceId from the RoT.
These tools then used an OpenSSL CA to generate a Cert with all of the required DICE extensions.
This cert is then provided to the RoT where it acts ad the device identity.
