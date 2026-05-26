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

        // Step 1 — fetch all vault entries (alias + encrypted value) from the UI page in one pass
        Map<String, String> vault = fetchVaultFromUI(baseUrl, creds);
        if (vault.isEmpty()) {
            System.out.println("No vault entries found. Check host/credentials.");
            return;
        }
        System.out.println("Found " + vault.size() + " vault entry/entries:\n");
        for (Map.Entry<String, String> e : vault.entrySet()) {
            String enc = e.getValue();
            System.out.printf("  %-50s = %s...%n", e.getKey(),
                enc.length() > 40 ? enc.substring(0, 40) : enc);
        }

        // Step 2 — save to files
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

    // ── Fetch all vault entries from the UI page in one HTTP call ─────────

    static Map<String, String> fetchVaultFromUI(String baseUrl, String creds) throws Exception {
        String[] parts = new String(Base64.getDecoder().decode(creds), StandardCharsets.UTF_8).split(":", 2);

        CookieManager cm = new CookieManager();
        CookieHandler.setDefault(cm);

        // Login to get session cookie
        String loginBody = "username=" + URLEncoder.encode(parts[0], StandardCharsets.UTF_8)
                         + "&password=" + URLEncoder.encode(parts[1], StandardCharsets.UTF_8)
                         + "&loginStatus=true";
        httpPost(baseUrl + "/carbon/admin/login_action.jsp", loginBody, creds);

        // WSO2 renders ALL entries in the HTML at once (pagination is client-side JS only)
        String vaultUrl = baseUrl + "/carbon/mediation_secure_vault/manageSecureVault.jsp"
                        + "?region=region1&item=secure_vault_list_view";
        String html = httpGet(vaultUrl, creds);
        if (html == null) return new LinkedHashMap<>();

        return extractVaultFromHtml(html);
    }

    // ── Extract alias+value pairs from vault HTML ─────────────────────────
    // HTML structure (attributes span multiple lines):
    //   <span class="__propName">ALIAS</span>
    //   <span class="__propValue">MULTILINE_BASE64==</span>
    // DOTALL is required because the base64 value wraps across lines.

    static Map<String, String> extractVaultFromHtml(String html) {
        Map<String, String> vault = new LinkedHashMap<>();

        List<String> aliases = new ArrayList<>();
        Matcher am = Pattern.compile("class=\"__propName\">([^<]+)</span>",
                                     Pattern.CASE_INSENSITIVE).matcher(html);
        while (am.find()) aliases.add(am.group(1).trim());

        List<String> values = new ArrayList<>();
        Matcher vm = Pattern.compile("class=\"__propValue\">(.*?)</span>",
                                     Pattern.DOTALL | Pattern.CASE_INSENSITIVE).matcher(html);
        while (vm.find()) {
            // Strip all whitespace (newlines inside multiline base64 values)
            values.add(vm.group(1).trim().replaceAll("\\s+", ""));
        }

        if (aliases.isEmpty()) {
            System.out.println("  No entries found in page HTML — check login or page structure.");
            return vault;
        }
        if (aliases.size() != values.size()) {
            System.out.printf("  WARNING: %d aliases vs %d values — results may be incomplete%n",
                aliases.size(), values.size());
        }

        int count = Math.min(aliases.size(), values.size());
        for (int i = 0; i < count; i++) {
            vault.put(aliases.get(i), values.get(i));
        }
        return vault;
    }

    // ── URL builder ───────────────────────────────────────────────────────

    static String buildBaseUrl(String host, String port) {
        if (host.startsWith("http://") || host.startsWith("https://")) {
            return host.replaceAll("/+$", "");
        }
        if (host.contains(":")) {
            return "https://" + host;
        }
        if (port != null && !port.isEmpty()) {
            return "https://" + host + ":" + port;
        }
        return "https://" + host;
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
        c.setConnectTimeout(10000);
        c.setReadTimeout(30000);
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
