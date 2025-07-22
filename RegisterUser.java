import java.util.Scanner;

public class RegisterUser {
 public static void main(String[] args) {
  System.out.println("\n\t\tUser Registration");
  System.out.println("\t\t=================\n");

  Scanner scanner = new Scanner(System.in);

  try {
   System.out.print("Enter new username: ");
   String username = scanner.nextLine();

   System.out.print("Enter password: ");
   String password = scanner.nextLine();

   boolean success = UserManager.register(username, password);

   if (success) {
    System.out.println("User registered successfully. Keys generated.");
   } else {
    System.out.println("Username already exists. Try another one.");
   }

  } catch (Exception e) {
   System.err.println("Error during registration: " + e.getMessage());
  }
 }
}
