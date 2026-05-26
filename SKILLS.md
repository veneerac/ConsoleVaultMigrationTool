# WSO2 EI Secure Vault — Technical Skills & Knowledge

---

## 1. WSO2 Admin Services

WSO2 EI exposes admin functionality via SOAP web services at `https://<host>:9443/services/`.

### Key Services Used

| Service | Purpose |
|---|---|
| `ResourceAdminService` | Read/write WSO2 registry resources and properties |
| `MediationSecurityAdminService` | Encrypt/decrypt vault values |
| `SecurityAdminService` | Manage WS-Security policies on services |
| `PropertiesAdminService` | Read JVM system properties |

### SOAP Call Pattern
```bash
curl -sk -u admin:admin \
  -H "Content-Type: text/xml" \
  -H "SOAPAction: \"urn:operationName\"" \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
       xmlns:ser="NAMESPACE_FROM_WSDL">
    <soapenv:Header/>
    <soapenv:Body>
      <ser:operationName>
        <ser:param>value</ser:param>
      </ser:operationName>
    </soapenv:Body>
  </soapenv:Envelope>' \
  "https://host:9443/services/ServiceName"
```

### Get Correct Namespace
Always check the WSDL first:
```bash
curl -sk -u admin:admin "https://host:9443/services/ServiceName?wsdl" | grep targetNamespace
```

---

## 2. Secure Vault Storage in WSO2 EI 6.x

### How Vault Entries Are Stored
- **NOT** plain files on disk
- Stored as **properties** on a registry collection in the H2 database
- Registry path: `/_system/config/repository/components/secure-vault`
- Key = alias name, Value = Base64 RSA encrypted cipher text

### Read a Vault Entry via SOAP
```bash
curl -sk -u admin:admin \
  -H "Content-Type: text/xml" \
  -H "SOAPAction: \"urn:getProperty\"" \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
       xmlns:ser="http://services.resource.registry.carbon.wso2.org">
    <soapenv:Header/>
    <soapenv:Body>
      <ser:getProperty>
        <ser:resourcePath>/_system/config/repository/components/secure-vault</ser:resourcePath>
        <ser:key>YOUR_ALIAS</ser:key>
      </ser:getProperty>
    </soapenv:Body>
  </soapenv:Envelope>' \
  "https://host:9443/services/ResourceAdminService"
```

### MediationSecurityAdminService Operations
- `doEncrypt(plaintext)` → returns encrypted cipher text
- `doDecrypt(cipherText)` → returns plaintext (admin only)
- Namespace: `http://vault.security.mediation.carbon.wso2.org`
- Port: 8243 (passthrough) or 9443

---

## 3. WSO2 Registry Structure

### Registry Spaces
| Path | Space | Use |
|---|---|---|
| `/_system/config` | Config Registry | Server configuration, vault |
| `/_system/governance` | Governance Registry | Shared artifacts |
| `/_system/local` | Local Registry | Node-specific data |

### EI 6.x vs MI 4.x Registry
| | EI 6.x | MI 4.x |
|---|---|---|
| Storage | H2 Database | File-based |
| Vault config | Registry properties | `deployment.toml [secrets]` |
| Vault file | `cipher-text.properties` | `deployment.toml` |

---

## 4. Integration Studio Project Structure

A Registry Resources project that deploys vault entries to EI:

```
ProjectName/
├── .project                              ← Eclipse/IS project descriptor
├── pom.xml                               ← Maven multi-module root
├── ProjectNameRegistryResources/
│   ├── .classpath
│   ├── .project
│   ├── pom.xml                           ← uses wso2-general-project-plugin
│   ├── artifact.xml                      ← VAULT ENTRIES STORED HERE
│   └── _system/config/repository/
│       └── components/secure-vault/
│           └── .meta/~.xml
└── ProjectNameCompositeExporter/
    ├── .project
    └── pom.xml                           ← uses maven-car-plugin
```

### artifact.xml Format (Vault Entries)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<artifacts>
   <artifact name="__system_config_repository_components_secure-vault"
             groupId="com.example.resource"
             version="1.0.0"
             type="registry/resource"
             serverRole="EnterpriseIntegrator">
      <collection>
         <directory>/_system/config/repository/components/secure-vault</directory>
         <path>/_system/config/repository/components/secure-vault</path>
         <properties>
            <property key="aliasName" value="encryptedCipherText"/>
         </properties>
      </collection>
   </artifact>
</artifacts>
```

---

## 5. CAR File Structure

A `.car` file is a ZIP archive:

```
artifacts.xml           ← root manifest listing all artifacts
ProjectRegistryResources_1.0.0/
  artifact.xml          ← registry resource definitions with vault properties
  _system/config/repository/components/secure-vault/.meta/~.xml
```

### Deployment Flow
```
artifact.xml (project)
     ↓  mvn package / java.util.zip
CAR file (.car = ZIP)
     ↓  copied to carbonapps/ OR HTTP upload
EI CApp Deployer reads artifact.xml
     ↓
Registry Resource Deployer
     ↓
Sets property in H2 database:
  REG_PROPERTY: key=aliasName, value=encryptedValue
     ↓
Synapse Runtime
  wso2:vault-lookup('aliasName') → decrypts with JKS → plaintext
```

---

## 6. Vault in Synapse Configs

Reference a vault alias in any synapse artifact:
```xml
<!-- In proxy/API/sequence -->
<property name="pwd" expression="wso2:vault-lookup('myAlias')"/>

<!-- In endpoint password -->
<parameter name="password" value="{wso2:vault-lookup('dbPassword')}"/>
```

---

## 7. WSO2 MI 4.x — deployment.toml Secrets

```toml
[secrets]
aliasName = "Base64EncryptedCipherText"
dbPassword = "AnotherEncryptedValue"
```

Reference in configs:
```toml
[datasource.WSO2_CARBON_DB]
password = "$secret{dbPassword}"
```

---

## 8. Migration Checklist: EI 6.x → MI 4.x

- [ ] Extract vault aliases + encrypted values (`VaultExtractor.jar`)
- [ ] Copy `wso2carbon.jks` keystore to target (same keystore = same encrypted values work)
- [ ] Add encrypted values to `deployment.toml [secrets]` OR deploy via CAR
- [ ] Update synapse configs to use correct vault-lookup expressions
- [ ] Verify `secret-conf.properties` points to correct vault provider
