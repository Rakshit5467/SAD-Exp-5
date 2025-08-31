import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class VulnerableCode {

    // Security: Hardcoded credentials (should never be in code)
    private static final String PASSWORD = "P@ssw0rd123";
    private static final String API_KEY = "12345-ABCDE"; // Security issue: hardcoded API key

    public static void main(String[] args) {
        VulnerableCode vc = new VulnerableCode();

        // Reliability: Redundant authentication check
        if (vc.authenticate("user", PASSWORD)) {
            System.out.println("Authentication successful!");
        } else {
            System.out.println("Authentication failed.");
        }

        // Security: Weak hashing algorithm (MD5)
        String hashedPassword = vc.hashPassword("myPassword");
        System.out.println("Hashed password (MD5): " + hashedPassword);

        // Security & Maintainability: Information leak via exception
        try {
            vc.doRiskyOperation();
        } catch (Exception e) {
            // Reliability: Stack trace leak exposes internal structure
            e.printStackTrace();
        }

        // Security: Insecure encoding of sensitive data
        String encodedKey = Base64.getEncoder().encodeToString(API_KEY.getBytes());
        System.out.println("Encoded API Key: " + encodedKey);

        // Maintainability: Unused method
        vc.unusedMethod();
    }

    // Security: Method uses hardcoded password
    public boolean authenticate(String username, String password) {
        return PASSWORD.equals(password);
    }

    // Security: Method uses insecure hash algorithm
    public String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // Security: Exception handling reveals stack trace and sensitive details
            throw new RuntimeException(e);
        }
    }

    // Security: Exception exposes implementation and leaks info
    public void doRiskyOperation() throws Exception {
        throw new Exception("Detailed error message with sensitive data.");
    }

    // Maintainability: Dead code - unused method
    public void unusedMethod() {
        // Unused
    }
}
