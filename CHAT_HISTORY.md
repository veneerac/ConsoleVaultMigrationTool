# Chat History — WSO2 EI Secure Vault Migration

**Date:** 2026-05-19  
**Topic:** Extracting WSO2 EI Secure Vault entries and migrating to WSO2 MI

---

## Summary

Built a Java tool (`VaultExtractor.jar`) to extract Secure Vault entries from a WSO2 EI 6.x instance via admin SOAP services, and generate a deployable Integration Studio project + CAR file for migration.

---

## Journey

### 1. Initial Exploration — Admin Services
- Started with `SecurityAdminService` — manages WS-Security policies, does NOT expose passwords
- Explored `PropertiesAdminService` — exposes JVM system properties only
- Found `MediationSecurityAdminService` WSDL — has `doEncrypt` and `doDecrypt` operations

### 2. Finding the Right Service
- Tried `ResourceAdminService.getResourceTree` → failed (wrong operation name)
- Fixed namespace: `http://service...` → `http://services...` (plural)
- Tried `getCollectionContent` on `/_system/config/repository/components/secure-vault` → returned `childCount=0`
- Discovered vault entries are stored as **properties** on the collection, not child resources

### 3. Successfully Reading Vault Entries
- Used `ResourceAdminService.getProperty` with alias name as key
- Retrieved encrypted value for `veneeratest`:
  ```
  Bnt/iJO9dSCcF+mJkSbWLoLTHK5cKOVWcTQ7um2dmtutP/ivK+mmQJWQWU/...
  ```
- Confirmed: vault entries = registry collection properties in H2 database

### 4. Understanding the Storage Mechanism
- EI 6.x stores vault entries in H2 database (`WSO2CARBON_DB.h2.db`)
- Table: `REG_PROPERTY` — key=alias, value=encrypted cipher text
- No XML files on disk for individual entries
- Managed via Integration Studio → `artifact.xml` → CAR → CApp Deployer → Registry DB

### 5. Discovered the Project Structure
- Found existing project at `/Users/chandimaveneerarathnayake/Documents/SUPPORT_CASE/Migration/venemg`
- `artifact.xml` stores vault entries as `<property key="alias" value="encrypted"/>`
- When CAR is deployed → EI registry deployer writes properties to H2 DB

### 6. Built VaultExtractor.java
Iterative development:
- v1: Basic SOAP calls, registry REST API (returned 501 Not Implemented)
- v2: Added session-based login + JSP scraping for alias list + `getProperty` for values
- v3: Added output folder prompt, `deployment.toml` output alongside `cipher-text.properties`
- v4: Added full Integration Studio project generation (all XML/pom files)
- v5: Added CAR file build using `java.util.zip` (no Maven needed)
- v6: Added deploy-to-target option via multipart HTTP POST
- v7: Added smart URL builder for DNS-mapped hostnames/ports
- v8: Packaged as `VaultExtractor.jar` (self-contained, runs anywhere with Java)

### 7. Key Technical Discoveries

| Discovery | Detail |
|---|---|
| Vault storage | Registry collection properties, not files |
| Admin port | 9443 for admin services, 8243 for passthrough |
| Namespace | `http://services.resource.registry.carbon.wso2.org` (services, plural) |
| EI 6.x vault | Registry DB (H2) via CAR deployment |
| MI 4.x vault | `deployment.toml [secrets]` or `cipher-text.properties` |
| CAR format | ZIP with `artifacts.xml` + artifact folders |
| `secret-conf.properties` | All commented out in MI 4.5 → uses `deployment.toml` |

---

## Files Created

| File | Location | Purpose |
|---|---|---|
| `VaultExtractor.java` | `VaultMigrationTool/` | Source code |
| `VaultExtractor.jar` | `VaultMigrationTool/` | Runnable JAR |
| `README.md` | `VaultMigrationTool/` | Usage guide |
| `SKILLS.md` | `VaultMigrationTool/` | Technical reference |
| `CHAT_HISTORY.md` | `VaultMigrationTool/` | This file |

---

## Servers Referenced

| Server | Purpose |
|---|---|
| `chandimav-2.local:8243` | Local WSO2 EI test instance |
| `10.100.5.122:9443` | Test EI server (admin/admin) — source of vault entries |
| `~/.wso2-mi/micro-integrator/wso2mi-4.5.0` | Local WSO2 MI 4.5.0 installation |

---

## Useful SOAP Calls Reference

### List vault collection metadata
```bash
curl -sk -u admin:admin --insecure \
  -H "Content-Type: text/xml" -H "SOAPAction: \"urn:getCollectionContent\"" \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
       xmlns:ser="http://services.resource.registry.carbon.wso2.org">
    <soapenv:Header/><soapenv:Body>
      <ser:getCollectionContent>
        <ser:path>/_system/config/repository/components/secure-vault</ser:path>
      </ser:getCollectionContent>
    </soapenv:Body></soapenv:Envelope>' \
  "https://10.100.5.122:9443/services/ResourceAdminService"
```

### Get encrypted value for an alias
```bash
curl -sk -u admin:admin --insecure \
  -H "Content-Type: text/xml" -H "SOAPAction: \"urn:getProperty\"" \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
       xmlns:ser="http://services.resource.registry.carbon.wso2.org">
    <soapenv:Header/><soapenv:Body>
      <ser:getProperty>
        <ser:resourcePath>/_system/config/repository/components/secure-vault</ser:resourcePath>
        <ser:key>veneeratest</ser:key>
      </ser:getProperty>
    </soapenv:Body></soapenv:Envelope>' \
  "https://10.100.5.122:9443/services/ResourceAdminService"
```

### Encrypt a plaintext value
```bash
curl -sk -u admin:admin --insecure \
  -H "Content-Type: text/xml" -H "SOAPAction: \"urn:doEncrypt\"" \
  -d '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
       xmlns:ns="http://org.apache.synapse/xsd">
    <soapenv:Header/><soapenv:Body>
      <ns:doEncrypt>
        <ns:plainTextPass>mypassword</ns:plainTextPass>
      </ns:doEncrypt>
    </soapenv:Body></soapenv:Envelope>' \
  "https://host:8243/services/MediationSecurityAdminService"
```
