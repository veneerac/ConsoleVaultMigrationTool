# WSO2 EI Secure Vault Extractor

A lightweight Java tool that connects to a WSO2 EI 6.x instance, reads all Secure Vault entries from the registry, and saves them to files ready for migration to WSO2 MI 4.x.

---

## Requirements

- Java 11 or later
- Network access to the source WSO2 EI admin port (default `9443`)
- Admin credentials for the source EI

---

## How to Run

```bash
java -jar VaultExtractor.jar
```

---

## Steps

1. **Run the tool**
   ```bash
   java -jar VaultExtractor.jar
   ```

2. **Enter connection details when prompted**
   ```
   Source EI Host/IP (e.g. 10.100.5.122): 10.100.5.122
   Port [9443]:                             9443
   Username [admin]:                        admin
   Password:                                ••••••
   Output folder:                           /Users/yourname/vault-output
   ```

3. **Tool connects to EI and extracts all vault entries**
   - Logs into the EI management console
   - Reads all alias names from the Secure Vault UI page
   - Fetches the encrypted value for each alias via `ResourceAdminService` SOAP

4. **Two output files are saved to your output folder**

   | File | Description |
   |---|---|
   | `cipher-text.properties` | `alias=encryptedValue` — standard WSO2 cipher-text format |
   | `vault-export-mi.toml` | `[secrets]` block to paste into WSO2 MI `deployment.toml` |

---

## Output File Examples

**cipher-text.properties**
```properties
# WSO2 EI Secure Vault export
dbPassword=Bnt/iJO9dSCcF+mJkSbWLoLTHK5cKOVWcTQ7um2dmtutP/iv...
apiKey=Xk2pQr7mNvBsT9wCdYeLfUgHjIoKlMnOpQrStUvWxYz...
```

**vault-export-mi.toml**
```toml
# WSO2 MI 4.x deployment.toml [secrets] snippet
[secrets]
dbPassword = "Bnt/iJO9dSCcF+mJkSbWLoLTHK5cKOVWcTQ7um2dmtutP/iv..."
apiKey = "Xk2pQr7mNvBsT9wCdYeLfUgHjIoKlMnOpQrStUvWxYz..."
```

---

## Using the Output in WSO2 MI 4.x

Copy the contents of `vault-export-mi.toml` into your MI server's:
```
<MI_HOME>/conf/deployment.toml
```

Reference a secret in your configs:
```toml
[datasource.WSO2_CARBON_DB]
password = "$secret{dbPassword}"
```

---

## Supported Host/Port Formats

| Input | Resolves To |
|---|---|
| `10.100.5.122` + port `9443` | `https://10.100.5.122:9443` |
| `myserver.wso2.com` + port empty | `https://myserver.wso2.com` |
| `myserver.wso2.com:9443` + port any | `https://myserver.wso2.com:9443` |
| `https://myserver.wso2.com` | `https://myserver.wso2.com` |

---

## Windows

Copy `VaultExtractor.jar` to the Windows machine and run in Command Prompt or PowerShell:

```cmd
java -jar VaultExtractor.jar
```

Java 11+ must be installed. Download from [adoptium.net](https://adoptium.net) if needed.
