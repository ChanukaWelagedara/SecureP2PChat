import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

public class UserManager {
 private static final String USERS_FILE = "users.txt";
 private static final String LOG_FILE = "auth_log.txt";

 // Register a new user
 public static boolean register(String username, String password) throws Exception {
  if (userExists(username))
   return false;

  String salt = generateSalt();
  String hashed = hashPassword(password, salt);
  String entry = username + ":" + salt + ":" + hashed;

  Files.write(Paths.get(USERS_FILE), (entry + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
  log(username, "REGISTER_SUCCESS");

  // Generate RSA keys
  CryptoUtils.generateRSAKeyPair(username);
  return true;
 }

 // Authenticate user
 public static boolean authenticate(String username, String password) throws Exception {
  List<String> lines = Files.readAllLines(Paths.get(USERS_FILE));

  for (String line : lines) {
   String[] parts = line.split(":");
   if (parts.length != 3)
    continue;

   String storedUser = parts[0];
   String salt = parts[1];
   String storedHash = parts[2];

   if (storedUser.equals(username)) {
    String hashedInput = hashPassword(password, salt);
    boolean match = storedHash.equals(hashedInput);
    log(username, match ? "LOGIN_SUCCESS" : "LOGIN_FAIL");
    return match;
   }
  }
  log(username, "LOGIN_FAIL");
  return false;
 }

 // Check if user already exists
 private static boolean userExists(String username) throws IOException {
  File file = new File(USERS_FILE);
  if (!file.exists())
   return false;

  List<String> lines = Files.readAllLines(file.toPath());
  for (String line : lines) {
   if (line.startsWith(username + ":"))
    return true;
  }
  return false;
 }

 // Password hashing with salt (SHA-256)
 private static String hashPassword(String password, String salt) throws Exception {
  MessageDigest md = MessageDigest.getInstance("SHA-256");
  md.update((password + salt).getBytes());
  byte[] hash = md.digest();
  return Base64.getEncoder().encodeToString(hash);
 }

 // Generate random salt
 private static String generateSalt() {
  byte[] salt = new byte[8];
  new SecureRandom().nextBytes(salt);
  return Base64.getEncoder().encodeToString(salt);
 }

 // Logging authentication attempts
 private static void log(String username, String status) throws IOException {
  String log = username + ":" + System.currentTimeMillis() + ":" + status;
  Files.write(Paths.get(LOG_FILE), (log + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
 }
}
