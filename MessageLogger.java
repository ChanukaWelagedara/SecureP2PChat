import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;

public class MessageLogger {
    private static final String LOG_FILE = "encrypted_messages.txt";
    private static boolean logStarted = false;

    public static synchronized void logMessage(String from, String to, String encrypted, String signature) {
        try (FileWriter writer = new FileWriter(LOG_FILE, true)) {
            if (!logStarted && !new java.io.File(LOG_FILE).exists()) {
                writer.write("=== Encrypted Message Log - Started at " + LocalDateTime.now() + " ===\n");
                logStarted = true;
            }

            writer.write("[" + LocalDateTime.now() + "] FROM: " + from + " TO: " + to + "\n");
            writer.write("ENCRYPTED: " + encrypted + "\n");
            writer.write("SIGNATURE: " + signature + "\n");
            writer.write("----------------------------------------\n");
        } catch (IOException e) {
            System.err.println("Failed to write to log: " + e.getMessage());
        }
    }
}
