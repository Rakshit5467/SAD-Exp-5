
import java.sql.*;
import java.util.Random;
import javax.servlet.http.*;
import java.io.*;
import java.util.logging.*;

public class VulnerableApp extends HttpServlet {
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "password123"; // Hardcoded credentials
    private static final Logger logger = Logger.getLogger("VulnerableApp");

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // Logging sensitive information (violation)
        logger.info("Login attempt: " + username + " / " + password);

        // SQL Injection vulnerability
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", DB_USER, DB_PASSWORD)) {
            Statement stmt = conn.createStatement();
            String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            ResultSet rs = stmt.executeQuery(sql);

            if (rs.next()) {
                response.getWriter().println("Welcome, " + username);
            } else {
                response.getWriter().println("Invalid credentials");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

        // Insecure randomness
        Random rand = new Random();
        int resetToken = rand.nextInt(); // Insecure for security tokens
        response.getWriter().println("Reset Token: " + resetToken);

        // Path Traversal
        String filename = request.getParameter("file");
        File file = new File("/var/data/files/" + filename);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        while ((line = reader.readLine()) != null) {
            response.getWriter().println(line);
        }
        reader.close();
    }
}
