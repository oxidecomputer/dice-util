sequenceDiagram
    Note over HW: HMAC(UDS, TCI_L0) -> CDI_L0
    HW->>stage_0: DICE_REG[0-7]
    Note over stage_0: Hkdf-extract(CDI_L0) & extend("identity") -> <br> DeviceID_pub / priv
    Note over stage_0: Get Serial Number -> commonName
    Note over stage_0: CSR_Gen(DeviceID_pub, SerialNumber) -> DeviceID_csr <br>NOTE: define attrs template
    Note over stage_0: CSR_Sign(DeviceID_priv, DeviceID_csr)
    ServiceDev->>stage_0: CsrPlz
    stage_0->>ServiceDev: DeviceID_csr
    ServiceDev->>CA: DeviceID_csr
    Note Over CA: certify(IntermediageCA_priv, DeviceID_csr) -> <br> DeviceID_cert
    CA->>ServiceDev: DeviceID_cert
    Note over ServiceDev: Record SN / Cert<br>Association
    ServiceDev->>stage_0: DeviceID_cert
    Note over stage_0: Persist<br>DeviceID_cert
    Note over stage_0: HMAC(CDI_L0, TCI_L1) -> CDI_L1
    Note over stage_0: keygen(CDI_L1, "Alias") -> <br> Alias_priv / pub
    Note over stage_0: CSR(Alias_pub, ATTRs) -> Alias_csr
    Note over stage_0: certify(DeviceID_priv, Alias_csr) -> <br>Alias_cert
    Note over stage_0: keygen(CDI_L1, "KeyHierarchyRoot") -> <br> KHR_priv / pub
    Note over stage_0: CSR(KHR_pub, ATTRS) ->KHR_csr
    Note over stage_0: certify(DeviceID_priv, KHR_csr) -><br> KHR_cert
    stage_0->>KeyStore: DeviceID_cert, Alias_priv, Alias_cert<br>KHR_priv, KHR_cert
    stage_0->>Hubris: CDI_L1
    NOTE over Hubris: CDI_L1 only necessary<br>if deriving more keys
