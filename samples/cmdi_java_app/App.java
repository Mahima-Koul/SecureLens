package sample.cmdi;

import java.io.IOException;
import java.util.Random;

/**
 * System diagnostics demo containing an OS command injection vulnerability
 * and a non-security Random false-positive trap for Semgrep*.
 */
public class App {

    public Process pingHostUnsafe(String host) throws IOException {
        // Intentional vulnerability (CWE-78): untrusted host is concatenated into Runtime.getRuntime().exec
        return Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    public Process pingLocalhostSafe() throws IOException {
        // Safe constant command with no user input
        return new ProcessBuilder("ping", "-c", "1", "127.0.0.1").start();
    }

    public int nextDisplayBannerIndex(int totalBanners) {
        // False-positive trap (CWE-330): java.util.Random is used only for UI banner rotation,
        // never for cryptographic keys, tokens, or authentication.
        Random rng = new Random(42L);
        return rng.nextInt(Math.max(1, totalBanners));
    }
}
