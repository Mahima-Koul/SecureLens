package sample.xxe;

import java.io.InputStream;
import javax.ws.rs.Path;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

/**
 * XML invoice parser demonstrating an XXE vulnerability (CWE-611)
 * and a read-only JAX-RS health endpoint false-positive trap (CWE-352).
 */
public class App {

    public Document parseInvoiceXml(InputStream xmlStream) throws Exception {
        // Intentional vulnerability (CWE-611): DocumentBuilderFactory created without disabling DTDs/external entities
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = dbf.newDocumentBuilder();
        return builder.parse(xmlStream);
    }

    @Path("/health")
    public String healthStatus() {
        // False-positive trap (CWE-352): Read-only health check endpoint performs no state change
        return "READY";
    }
}
