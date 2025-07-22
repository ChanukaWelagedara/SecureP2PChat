import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

/**
 * Main launcher for the Secure P2P Chat Application GUI
 * This replaces the command-line interface with a modern GUI
 */
public class ChatAppLauncher {
    public static void main(String[] args) {
        // Launch the login frame
        SwingUtilities.invokeLater(() -> {
            try {
                new LoginFrame().setVisible(true);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(null,
                        "Error starting application: " + e.getMessage(),
                        "Startup Error",
                        JOptionPane.ERROR_MESSAGE);
                e.printStackTrace();
            }
        });
    }
}
