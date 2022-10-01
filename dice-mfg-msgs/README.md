# dice-mfg-msgs

A particular strength of the DICE architecture is that it can be realized
without requiring risky operations like exposing secret keys outside of the
platforms RoT. This minimizes the trust that we must place in the manufacturing
infrastructure. Certifying the DeviceId key without exporting it from the RoT
requires the RoT participate in a certification protocol. This crate hosts a
small `no_std` rust library that defines the messages / types exchanged between
an RoT and the manufacturing system responsible for certifying DeviceId certs.
