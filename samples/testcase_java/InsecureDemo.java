import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Statement;
import java.util.Random;
import javax.servlet.http.HttpServletRequest;

public class InsecureDemo {
    private static final String API_TOKEN = "demo-token-123456";

    public void handle(HttpServletRequest request, Statement stmt) throws Exception {
        String user = request.getParameter("user");
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec("sh -c " + cmd);

        String sql = "SELECT * FROM users WHERE name = '" + user + "'";
        stmt.executeQuery(sql);

        String file = request.getParameter("file");
        new FileInputStream(file);

        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        Object obj = ois.readObject();

        MessageDigest md = MessageDigest.getInstance("MD5");
        int resetCode = new Random().nextInt();
    }
}
