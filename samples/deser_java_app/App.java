package sample.deser;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * Profile deserialization service containing an unsafe SnakeYAML constructor (CWE-502)
 * and a safe constant regex false-positive trap (CWE-1333).
 */
public class App {

    public Map<String, Object> loadProfileYaml(String untrustedYaml) {
        // Intentional vulnerability (CWE-502): default Yaml() constructor allows arbitrary Java gadget instantiation
        org.yaml.snakeyaml.Yaml yaml = new org.yaml.snakeyaml.Yaml();
        return yaml.load(untrustedYaml);
    }

    public boolean isValidUsername(String username) {
        // False-positive trap (CWE-1333): fixed, bounded alphanumeric regex literal with no user-controlled pattern
        Pattern safePattern = Pattern.compile("^[a-zA-Z0-9_]{3,16}$");
        return username != null && safePattern.matcher(username).matches();
    }
}
