import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class LogViewer {
  private static final String MESSAGE_LOG_FILE = "encrypted_messages.txt";

  public static void main(String[] args) {
    System.out.println("\n\t\tEncrypted Message Log Viewer");
    System.out.println("\t\t============================\n");

    try {
      if (!Files.exists(Paths.get(MESSAGE_LOG_FILE))) {
        System.out.println("No log file found. Start the server and send some messages first.");
        return;
      }

      Scanner scanner = new Scanner(System.in);

      while (true) {
        System.out.println("Options:");
        System.out.println("1. View all logs");
        System.out.println("2. View logs by sender");
        System.out.println("3. View logs by receiver");
        System.out.println("4. View recent logs (last 10)");
        System.out.println("5. Search logs");
        System.out.println("6. View encryption type statistics");
        System.out.println("7. Exit");
        System.out.print("Choose option: ");

        String choice = scanner.nextLine();
        switch (choice) {
          case "1":
            viewAllLogs();
            break;
          case "2":
            System.out.print("Enter sender username: ");
            String sender = scanner.nextLine();
            viewLogsBySender(sender);
            break;
          case "3":
            System.out.print("Enter receiver username: ");
            String receiver = scanner.nextLine();
            viewLogsByReceiver(receiver);
            break;
          case "4":
            viewRecentLogs(10);
            break;
          case "5":
            System.out.print("Enter search term: ");
            String searchTerm = scanner.nextLine();
            searchLogs(searchTerm);
            break;
          case "6":
            viewEncryptionStats();
            break;
          case "7":
            System.out.println("Goodbye!");
            return;
          default:
            System.out.println("Invalid option. Please try again.\n");
        }
        System.out.println("\nPress Enter to continue...");
        scanner.nextLine();
        System.out.println();
      }
    } catch (Exception e) {
      System.err.println("Error reading log file: " + e.getMessage());
    }
  }

  private static void viewAllLogs() throws IOException {
    List<String> lines = Files.readAllLines(Paths.get(MESSAGE_LOG_FILE));
    System.out.println("\n=== All Encrypted Message Logs ===");
    for (String line : lines) {
      System.out.println(line);
    }
  }

  private static void viewLogsBySender(String sender) throws IOException {
    List<String> lines = Files.readAllLines(Paths.get(MESSAGE_LOG_FILE));
    System.out.println("\n=== Messages from " + sender + " ===");
    boolean inRelevantEntry = false;

    for (String line : lines) {
      if (line.contains("FROM: " + sender)) {
        inRelevantEntry = true;
      }
      if (inRelevantEntry) {
        System.out.println(line);
        if (line.contains("----------------------------------------")) {
          inRelevantEntry = false;
        }
      }
    }
  }

  private static void viewLogsByReceiver(String receiver) throws IOException {
    List<String> lines = Files.readAllLines(Paths.get(MESSAGE_LOG_FILE));
    System.out.println("\n=== Messages to " + receiver + " ===");

    boolean inRelevantEntry = false;
    for (String line : lines) {
      if (line.contains("TO: " + receiver)) {
        inRelevantEntry = true;
      }

      if (inRelevantEntry) {
        System.out.println(line);
        if (line.contains("----------------------------------------")) {
          inRelevantEntry = false;
        }
      }
    }
  }

  private static void viewRecentLogs(int count) throws IOException {
    List<String> lines = Files.readAllLines(Paths.get(MESSAGE_LOG_FILE));
    System.out.println("\n=== Recent " + count + " Messages ===");

    // Find message entries (look for timestamp lines)
    List<String> messageEntries = new ArrayList<>();
    List<String> currentEntry = new ArrayList<>();

    for (String line : lines) {
      if (line.matches("\\[.*\\] FROM:.*")) {
        // Start of new message entry
        if (!currentEntry.isEmpty()) {
          messageEntries.add(String.join("\n", currentEntry));
        }
        currentEntry.clear();
      }
      currentEntry.add(line);
    }

    // Add the last entry
    if (!currentEntry.isEmpty()) {
      messageEntries.add(String.join("\n", currentEntry));
    }

    // Show last 'count' entries
    int start = Math.max(0, messageEntries.size() - count);
    for (int i = start; i < messageEntries.size(); i++) {
      System.out.println(messageEntries.get(i));
      System.out.println();
    }
  }

  private static void searchLogs(String searchTerm) throws IOException {
    List<String> lines = Files.readAllLines(Paths.get(MESSAGE_LOG_FILE));
    System.out.println("\n=== Search Results for '" + searchTerm + "' ===");
    boolean inRelevantEntry = false;
    List<String> currentEntry = new ArrayList<>();

    for (String line : lines) {
      if (line.matches("\\[.*\\] FROM:.*")) {
        // Check if previous entry contained search term
        if (inRelevantEntry) {
          for (String entryLine : currentEntry) {
            System.out.println(entryLine);
          }
          System.out.println();
        }
        // Start new entry
        currentEntry.clear();
        inRelevantEntry = false;
      }
      currentEntry.add(line);
      if (line.toLowerCase().contains(searchTerm.toLowerCase())) {
        inRelevantEntry = true;
      }
    }

    // Check last entry
    if (inRelevantEntry) {
      for (String entryLine : currentEntry) {
        System.out.println(entryLine);
      }
    }
  }

  private static void viewEncryptionStats() throws IOException {
    List<String> lines = Files.readAllLines(Paths.get(MESSAGE_LOG_FILE));
    int rsaCount = 0;
    int aesCount = 0;

    for (String line : lines) {
      if (line.contains("SIGNATURE:")) {
        rsaCount++;
      } else if (line.contains("AES-ENCRYPTED")) {
        aesCount++;
      }
    }

    System.out.println("\n=== Encryption Statistics ===");
    System.out.println("RSA encrypted messages: " + rsaCount);
    System.out.println("AES encrypted messages (PFS): " + aesCount);
    System.out.println("Total messages: " + (rsaCount + aesCount));
  }
}