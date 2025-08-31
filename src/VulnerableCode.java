import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class VulnerableCode {

    // Hardcoded password vulnerability
    private static final String PASSWORD = "P@ssw0rd123";

    public static void main(String[] args) {
        VulnerableCode vc = new VulnerableCode();

        // Hardcoded password usage
        if (vc.authenticate("user", PASSWORD)) {
            System.out.println("Authentication successful!");
        } else {
            System.out.println("Authentication failed.");
        }

        // Weak hashing algorithm usage (MD5)
        String hashedPassword = vc.hashPassword("myPassword");
        System.out.println("Hashed password: " + hashedPassword);

        // Detailed exception information leakage
        try {
            vc.doRiskyOperation();
        } catch (Exception e) {
            // Printing stack trace could leak sensitive info
            e.printStackTrace();
        }
    }

    public boolean authenticate(String username, String password) {
        // Simulate authentication logic. Using hardcoded password is insecure.
        return PASSWORD.equals(password);
    }

    public String hashPassword(String password) {
        try {
            // Using insecure MD5 hash algorithm
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // Exception handling revealing stack trace (info leak)
            throw new RuntimeException(e);
        }
    }

    public void doRiskyOperation() throws Exception {
        // Example method that throws exception with detailed info
        throw new Exception("Detailed error message with sensitive data.");
    }
}
