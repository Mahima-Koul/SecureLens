package sample.pathssrf;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * Report file resolver and webhook URL builder demonstrating Path Traversal (CWE-22),
 * SSRF (CWE-918), and a benign getSearchUrl false-positive trap (CWE-200).
 */
public class App {

    public File resolveReportFile(String fileName) {
        // Intentional vulnerability (CWE-22): unvalidated fileName passed directly to new File()
        File reportFile = new File("/var/app/reports", fileName);
        return reportFile;
    }

    public URL buildWebhookUrl(String endpointUrl) throws MalformedURLException {
        // Intentional vulnerability (CWE-918): unvalidated user string passed directly to new URL()
        URL url = new URL(endpointUrl);
        return url;
    }

    public String getSearchUrl() {
        // False-positive trap (CWE-200): returns a public static documentation route with no sensitive data
        return "/docs/public/search";
    }
}
