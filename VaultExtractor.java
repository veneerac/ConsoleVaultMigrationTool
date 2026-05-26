import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.*;
import javax.net.ssl.*;

public class VaultExtractor {

    static final String VAULT_REG_PATH = "/_system/config/repository/components/secure-vault";
    static final String SOAP_NS        = "http://services.resource.registry.carbon.wso2.org";

    public static void main(String[] args) throws Exception {
        disableSSLVerification();

        Console console = System.console();
        Scanner sc = new Scanner(System.in);

        System.out.println("=== WSO2 EI Secure Vault Extractor ===\n");

        System.out.print("Source EI Host/IP (e.g. 10.100.5.122): ");
        String host = sc.nextLine().trim();

        System.out.print("Port [9443, leave empty if DNS/hostname already maps port]: ");
        String port = sc.nextLine().trim();

        System.out.print("Username [admin]: ");
        String ui = sc.nextLine().trim();
        String username = ui.isEmpty() ? "admin" : ui;

        String password;
        if (console != null) {
            char[] pw = console.readPassword("Password: ");
            password = new String(pw);
        } else {
            System.out.print("Password: ");
            password = sc.nextLine().trim();
        }

        System.out.print("Output folder [" + System.getProperty("user.home") + "]: ");
        String fi = sc.nextLine().trim();
        String outputFolder = fi.isEmpty() ? System.getProperty("user.home") : fi;

        String baseUrl = buildBaseUrl(host, port);
        String creds   = Base64.getEncoder().encodeToString(
                            (username + ":" + password).getBytes(StandardCharsets.UTF_8));

        System.out.println("\nConnecting to: " + baseUrl);

        // Step 1 — get alias list from management console UI
        List<String> aliases = fetchAliasesFromUI(baseUrl, creds);
        if (aliases.isEmpty()) {
            System.out.println("No aliases found. Check host/credentials.");
            return;
        }
        System.out.println("Found " + aliases.size() + " alias(es):\n");

        // Step 2 — fetch encrypted value for each alias
        Map<String, String> vault = new LinkedHashMap<>();
        for (String alias : aliases) {
            String enc = fetchEncryptedValue(baseUrl, creds, alias);
            vault.put(alias, enc.replaceAll("\\s+", ""));
            System.out.printf("  %-40s = %s...%n", alias,
                enc.length() > 40 ? enc.substring(0, 40) : enc);
        }

        // Step 3 — save to vault-export.properties
        Path outDir = Paths.get(outputFolder);
        Files.createDirectories(outDir);

        Path propsFile = outDir.resolve("cipher-text.properties");
        StringBuilder sb = new StringBuilder();
        sb.append("# WSO2 EI Secure Vault export — ").append(new java.util.Date()).append("\n");
        sb.append("# Format: alias=encryptedCipherText\n\n");
        for (Map.Entry<String, String> e : vault.entrySet()) {
            sb.append(e.getKey()).append("=").append(e.getValue()).append("\n");
        }
        Files.writeString(propsFile, sb.toString());

        // Also write a deployment.toml [secrets] snippet for WSO2 MI 4.x
        Path tomlFile = outDir.resolve("vault-export-mi.toml");
        StringBuilder toml = new StringBuilder();
        toml.append("# WSO2 MI 4.x deployment.toml [secrets] snippet\n");
        toml.append("# Copy this block into your deployment.toml\n\n");
        toml.append("[secrets]\n");
        for (Map.Entry<String, String> e : vault.entrySet()) {
            toml.append(e.getKey()).append(" = \"").append(e.getValue()).append("\"\n");
        }
        Files.writeString(tomlFile, toml.toString());

        System.out.println("\nExported " + vault.size() + " entries to:");
        System.out.println("  " + propsFile.toAbsolutePath() + "  (EI cipher-text format)");
        System.out.println("  " + tomlFile.toAbsolutePath() + "  (MI deployment.toml snippet)");
    }

    // ── URL builder ───────────────────────────────────────────────────────
    // Handles all forms:
    //   host=myserver.com       port=9443  → https://myserver.com:9443
    //   host=myserver.com       port=""    → https://myserver.com        (DNS maps port)
    //   host=myserver.com:9443  port=any   → https://myserver.com:9443   (port in host)
    //   host=https://myserver.com          → https://myserver.com        (protocol in host)

    static String buildBaseUrl(String host, String port) {
        // Already has protocol — use as-is (strip trailing slash)
        if (host.startsWith("http://") || host.startsWith("https://")) {
            return host.replaceAll("/+$", "");
        }
        // Port already embedded in host (host:port)
        if (host.contains(":")) {
            return "https://" + host;
        }
        // Port explicitly provided
        if (port != null && !port.isEmpty()) {
            return "https://" + host + ":" + port;
        }
        // No port — DNS handles routing
        return "https://" + host;
    }

    // ── Fetch aliases from UI ──────────────────────────────────────────────

    static List<String> fetchAliasesFromUI(String baseUrl, String creds) throws Exception {
        List<String> aliases = new ArrayList<>();
        String[] parts = new String(Base64.getDecoder().decode(creds), StandardCharsets.UTF_8).split(":", 2);

        CookieManager cm = new CookieManager();
        CookieHandler.setDefault(cm);

        String loginBody = "username=" + URLEncoder.encode(parts[0], StandardCharsets.UTF_8)
                         + "&password=" + URLEncoder.encode(parts[1], StandardCharsets.UTF_8)
                         + "&loginStatus=true";
        int loginStatus = httpPost(baseUrl + "/carbon/admin/login_action.jsp", loginBody, creds);
        System.out.println("[debug] Login POST status: " + loginStatus);

        String vaultUrl = baseUrl + "/carbon/mediation_secure_vault/manageSecureVault.jsp"
                        + "?region=region1&item=secure_vault_list_view";
        System.out.println("[debug] Fetching: " + vaultUrl);
        String html = httpGet(vaultUrl, creds);
        if (html == null) {
            System.out.println("[debug] Got null response from vault page");
            return aliases;
        }
        System.out.println("[debug] Page response length: " + html.length() + " chars");
        System.out.println("[debug] First 600 chars:\n" + html.substring(0, Math.min(600, html.length())));
        System.out.println("...");

        // Aliases are in hidden inputs: id="oldPropName_N" type="hidden" value="aliasName"
        Pattern p = Pattern.compile("id=\"oldPropName_\\d+\"[^>]*value=\"([^\"]+)\"",
                                    Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(html);
        Set<String> seen = new LinkedHashSet<>();
        while (m.find()) seen.add(m.group(1).trim());

        // Fallback: value="alias" id="propName_N"
        if (seen.isEmpty()) {
            Pattern p2 = Pattern.compile("value=\"([^\"]+)\"[^>]*id=\"propName_\\d+\"",
                                         Pattern.CASE_INSENSITIVE);
            Matcher m2 = p2.matcher(html);
            while (m2.find()) seen.add(m2.group(1).trim());
        }

        // Fallback: span class="__propName"
        if (seen.isEmpty()) {
            Pattern p3 = Pattern.compile("class=\"__propName\">([^<]+)</span>",
                                         Pattern.CASE_INSENSITIVE);
            Matcher m3 = p3.matcher(html);
            while (m3.find()) seen.add(m3.group(1).trim());
        }
        aliases.addAll(seen);
        return aliases;
    }

    // ── Fetch encrypted value via SOAP getProperty ─────────────────────────

    static String fetchEncryptedValue(String baseUrl, String creds, String alias) throws Exception {
        String soap = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                    + "xmlns:ser=\"" + SOAP_NS + "\">"
                    + "<soapenv:Header/><soapenv:Body>"
                    + "<ser:getProperty>"
                    + "<ser:resourcePath>" + VAULT_REG_PATH + "</ser:resourcePath>"
                    + "<ser:key>" + alias + "</ser:key>"
                    + "</ser:getProperty>"
                    + "</soapenv:Body></soapenv:Envelope>";

        String response = httpSoap(baseUrl + "/services/ResourceAdminService",
                                   "urn:getProperty", soap, creds);
        if (response == null) return "(error)";

        Matcher m = Pattern.compile("<ns:return>(.*?)</ns:return>", Pattern.DOTALL).matcher(response);
        return m.find() ? m.group(1).trim() : "(not found)";
    }

    // ── HTTP helpers ───────────────────────────────────────────────────────

    static int httpPost(String urlStr, String body, String creds) throws Exception {
        HttpURLConnection c = open(urlStr);
        c.setRequestMethod("POST");
        c.setRequestProperty("Authorization", "Basic " + creds);
        c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        c.setDoOutput(true);
        c.setInstanceFollowRedirects(true);
        c.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
        return c.getResponseCode();
    }

    static String httpGet(String urlStr, String creds) throws Exception {
        HttpURLConnection c = open(urlStr);
        c.setRequestMethod("GET");
        c.setRequestProperty("Authorization", "Basic " + creds);
        c.setConnectTimeout(8000);
        c.setReadTimeout(8000);
        int status = c.getResponseCode();
        InputStream is = (status >= 400) ? c.getErrorStream() : c.getInputStream();
        if (is == null) return null;
        return new String(is.readAllBytes(), StandardCharsets.UTF_8);
    }

    static String httpSoap(String urlStr, String action, String body, String creds) throws Exception {
        HttpURLConnection c = open(urlStr);
        c.setRequestMethod("POST");
        c.setRequestProperty("Authorization", "Basic " + creds);
        c.setRequestProperty("Content-Type", "text/xml; charset=UTF-8");
        c.setRequestProperty("SOAPAction", "\"" + action + "\"");
        c.setDoOutput(true);
        c.setConnectTimeout(8000);
        c.setReadTimeout(8000);
        c.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
        int status = c.getResponseCode();
        InputStream is = (status >= 400) ? c.getErrorStream() : c.getInputStream();
        if (is == null) return null;
        return new String(is.readAllBytes(), StandardCharsets.UTF_8);
    }

    static HttpURLConnection open(String urlStr) throws Exception {
        return (HttpURLConnection) URI.create(urlStr).toURL().openConnection();
    }

    // ── SSL ────────────────────────────────────────────────────────────────

    static void disableSSLVerification() throws Exception {
        TrustManager[] trust = new TrustManager[]{
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
                public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
            }
        };
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trust, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
    }
}
