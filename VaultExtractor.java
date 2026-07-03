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

        String defaultOut = System.getProperty("user.home");
        String outputFolder;
        while (true) {
            System.out.print("Output folder [" + defaultOut + "]: ");
            String fi = sc.nextLine().trim();
            if (fi.isEmpty()) { outputFolder = defaultOut; break; }
            // Reject Windows-style paths when running on Linux/Mac
            if (!System.getProperty("os.name").toLowerCase().contains("win")
                    && fi.matches("^[A-Za-z]:\\\\.*")) {
                System.out.println("  Windows path detected but running on Linux — enter a Linux path (e.g. /home/user/output)");
                continue;
            }
            outputFolder = fi;
            break;
        }

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

    // ── Fetch all vault entries — registry browser first (all entries, one page),
    //    then paginate vault manager as fallback ────────────────────────────────

    static Map<String, String> fetchVaultFromUI(String baseUrl, String creds) throws Exception {
        String[] parts = new String(Base64.getDecoder().decode(creds), StandardCharsets.UTF_8).split(":", 2);

        CookieManager cm = new CookieManager();
        CookieHandler.setDefault(cm);

        String loginBody = "username=" + URLEncoder.encode(parts[0], StandardCharsets.UTF_8)
                         + "&password=" + URLEncoder.encode(parts[1], StandardCharsets.UTF_8)
                         + "&loginStatus=true";
        httpPost(baseUrl + "/carbon/admin/login_action.jsp", loginBody, creds);

        // URL 1: Registry browser — always returns ALL entries in a single page
        String registryUrl = baseUrl + "/carbon/resources/resource.jsp"
                           + "?region=region3&item=resource_browser_menu"
                           + "&path=/_system/config/repository/components/secure-vault&viewType=std";
        String html = httpGet(registryUrl, creds);
        if (html != null) {
            Map<String, String> result = extractVaultFromHtml(html);
            if (!result.isEmpty()) {
                System.out.println("  (fetched via registry browser — " + result.size() + " entries)");
                return result;
            }
        }

        // URL 2: Vault manager — paginate through all pages (15 entries per page)
        System.out.println("  Registry browser returned 0 — paginating vault manager...");
        Map<String, String> vault = new LinkedHashMap<>();
        for (int page = 1; page <= 200; page++) {
            String vaultUrl = baseUrl + "/carbon/mediation_secure_vault/manageSecureVault.jsp"
                            + "?region=region1&item=secure_vault_list_view&dynamicPageNumber=" + page;
            html = httpGet(vaultUrl, creds);
            if (html == null) break;
            Map<String, String> pageResult = extractVaultFromHtml(html);
            if (pageResult.isEmpty()) break;
            vault.putAll(pageResult);
            System.out.println("  Page " + page + ": " + pageResult.size() + " entries (running total: " + vault.size() + ")");
        }
        if (!vault.isEmpty()) {
            System.out.println("  (fetched via vault manager pagination — " + vault.size() + " entries)");
        } else {
            System.out.println("  No entries found. Check host/port, credentials, server accessibility.");
        }
        return vault;
    }

    // ── Extract alias+value pairs from vault HTML ─────────────────────────
    // Tries two patterns — both with DOTALL because attributes span multiple lines:
    //
    // Pattern A (manageSecureVault.jsp):
    //   <span class="__propName">ALIAS</span>
    //   <span class="__propValue">MULTILINE_BASE64</span>
    //
    // Pattern B (registry browser / fallback):
    //   id="oldPropName_N" type="hidden" value="ALIAS"
    //   <input value="MULTILINE_BASE64" id="propValue_N"

    static Map<String, String> extractVaultFromHtml(String html) {
        // Pattern A: __propName / __propValue spans
        List<String> aliases = new ArrayList<>();
        Matcher am = Pattern.compile("class=\"__propName\">([^<]+)</span>",
                                     Pattern.CASE_INSENSITIVE).matcher(html);
        while (am.find()) aliases.add(am.group(1).trim());

        List<String> values = new ArrayList<>();
        Matcher vm = Pattern.compile("class=\"__propValue\">(.*?)</span>",
                                     Pattern.DOTALL | Pattern.CASE_INSENSITIVE).matcher(html);
        while (vm.find()) values.add(vm.group(1).trim().replaceAll("\\s+", ""));

        if (!aliases.isEmpty() && aliases.size() == values.size()) {
            Map<String, String> vault = new LinkedHashMap<>();
            for (int i = 0; i < aliases.size(); i++) vault.put(aliases.get(i), values.get(i));
            return vault;
        }

        // Pattern B: oldPropName_N input + propValue_N input (DOTALL — attributes on separate lines)
        Map<Integer, String> aliasMap = new TreeMap<>();
        Matcher am2 = Pattern.compile(
            "id=\"oldPropName_(\\d+)\"\\s+type=\"hidden\"\\s+value=\"([^\"]+)\"",
            Pattern.DOTALL | Pattern.CASE_INSENSITIVE).matcher(html);
        while (am2.find()) aliasMap.put(Integer.parseInt(am2.group(1)), am2.group(2).trim());

        Map<Integer, String> valueMap = new TreeMap<>();
        Matcher vm2 = Pattern.compile(
            "<input\\s+value=\"([^\"]*)\"\\s+id=\"propValue_(\\d+)\"",
            Pattern.CASE_INSENSITIVE).matcher(html);
        while (vm2.find()) {
            int idx = Integer.parseInt(vm2.group(2));
            valueMap.put(idx, vm2.group(1).trim().replaceAll("\\s+", ""));
        }

        Map<String, String> vault = new LinkedHashMap<>();
        for (Map.Entry<Integer, String> e : aliasMap.entrySet()) {
            String val = valueMap.get(e.getKey());
            if (val != null) vault.put(e.getValue(), val);
        }

        if (vault.isEmpty()) {
            System.out.println("  No entries found in page HTML.");
            System.out.println("  Check: correct host/port, valid credentials, server accessible.");
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
