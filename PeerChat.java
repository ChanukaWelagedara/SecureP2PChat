import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

public class PeerChat {
    private static final Scanner scanner = new Scanner(System.in);
    private static final String PEER_REGISTRY_FILE = "peers.txt";

    // A class to hold incoming chat requests
    private static class IncomingRequest {
        final Socket socket;
        final BufferedReader in;
        final PrintWriter out;
        final String senderUsername;
        final PublicKey senderPublicKey;

        IncomingRequest(Socket socket, BufferedReader in, PrintWriter out, String senderUsername,
                PublicKey senderPublicKey) {
            this.socket = socket;
            this.in = in;
            this.out = out;
            this.senderUsername = senderUsername;
            this.senderPublicKey = senderPublicKey;
        }
    }

    // Thread-safe queue of incoming requests
    private static final BlockingQueue<IncomingRequest> incomingRequests = new LinkedBlockingQueue<>();

    public static void main(String[] args) {
        System.out.println("\n\t\tSecure P2P Chat");
        System.out.println("\t\t================\n");

        try {
            System.out.print("Enter username: ");
            String username = scanner.nextLine();

            System.out.print("Enter password: ");
            String password = scanner.nextLine();

            if (!UserManager.authenticate(username, password)) {
                System.out.println("Authentication failed.");
                return;
            }
            System.out.println("Authentication successful!");

            PrivateKey privateKey = CryptoUtils.loadPrivateKey(username);

            System.out.print("Enter your listening port: ");
            int listenPort = Integer.parseInt(scanner.nextLine());
            String localIP = InetAddress.getLocalHost().getHostAddress();

            registerToPeerFile(username, localIP, listenPort);

            final ServerSocket serverSocket = new ServerSocket(listenPort);
            System.out.println("Listening for incoming connections on port " + listenPort + "...");

            Thread listenerThread = new Thread(() -> {
                while (true) {
                    try {
                        Socket incomingSocket = serverSocket.accept();
                        new Thread(() -> handleIncomingConnection(incomingSocket, privateKey)).start();
                    } catch (Exception e) {
                        System.out.println("Error: " + e.getMessage());
                    }
                }
            });
            listenerThread.setDaemon(true);
            listenerThread.start();

            // Main input loop now also processes incoming chat requests
            while (true) {
                // Check if there are any incoming chat requests pending
                while (!incomingRequests.isEmpty()) {
                    IncomingRequest req = incomingRequests.poll();
                    if (req != null) {
                        handleChatRequestFromQueue(req, privateKey, username);
                    }
                }

                System.out.print(
                        "\nEnter 'list' to view online users or is there any request pending or username to chat (or 'exit'): ");
                String input = scanner.nextLine().trim();

                if (input.equalsIgnoreCase("exit"))
                    break;

                if (input.equalsIgnoreCase("list")) {
                    listPeers(username);
                    continue;
                }

                String[] peerInfo = getPeerByUsername(input);
                if (peerInfo == null) {
                    System.out.println("User not found or offline.");
                    continue;
                }

                String peerUsername = input;
                String peerIP = peerInfo[0];
                int peerPort = Integer.parseInt(peerInfo[1]);

                try (Socket socket = new Socket(peerIP, peerPort)) {
                    PublicKey peerPublicKey = CryptoUtils.loadPublicKey(peerUsername);
                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

                    // Send REQUEST
                    String request = CryptoUtils.buildSecureMessage("REQUEST:" + username);
                    String signature = CryptoUtils.sign(request, privateKey);
                    String encrypted = CryptoUtils.encrypt(request, peerPublicKey);
                    out.println("MSG:" + encrypted);
                    out.println("SIG:" + signature);

                    // Wait for ACCEPT or REJECT
                    String responseLine, encResp = null, sigResp = null;
                    while ((responseLine = in.readLine()) != null) {
                        if (responseLine.startsWith("MSG:"))
                            encResp = responseLine.substring(4);
                        else if (responseLine.startsWith("SIG:"))
                            sigResp = responseLine.substring(4);

                        if (encResp != null && sigResp != null) {
                            String decrypted = CryptoUtils.decrypt(encResp, privateKey);
                            boolean valid = CryptoUtils.verify(decrypted, sigResp, peerPublicKey);
                            if (!valid) {
                                System.out.println("Invalid response signature.");
                                break;
                            }

                            String body = CryptoUtils.extractMessageBody(decrypted);
                            if (body.startsWith("ACCEPT:")) {
                                System.out.println(
                                        "\nStart chatting with " + peerUsername + ". Type 'quit' to end chat.");
                                startChat(socket, username, peerUsername, privateKey, peerPublicKey, in, out);
                            } else if (body.startsWith("REJECT:")) {
                                System.out.println(peerUsername + " rejected your chat request.");
                            }
                            break;
                        }
                    }
                } catch (Exception e) {
                    System.out.println("Error: " + e.getMessage());
                }
            }

            serverSocket.close();
            System.out.println("Exiting application...");

        } catch (Exception e) {
            System.out.println("Fatal error: " + e.getMessage());
        }
    }

    // Modified handleIncomingConnection now only reads and queues requests
    private static void handleIncomingConnection(Socket socket, PrivateKey privateKey) {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            String encMsg = null, sig = null, line;
            while ((line = in.readLine()) != null) {
                if (line.startsWith("MSG:"))
                    encMsg = line.substring(4);
                else if (line.startsWith("SIG:"))
                    sig = line.substring(4);

                if (encMsg != null && sig != null) {
                    String decrypted = CryptoUtils.decrypt(encMsg, privateKey);
                    String msg = CryptoUtils.extractMessageBody(decrypted);
                    String sender = msg.split(":", 2)[1];
                    PublicKey senderKey = CryptoUtils.loadPublicKey(sender);
                    boolean fresh = CryptoUtils.isFresh(decrypted, 60000);
                    boolean validSig = CryptoUtils.verify(decrypted, sig, senderKey);

                    if (!fresh || !validSig) {
                        System.out.println("Invalid chat request (expired or tampered).");
                        socket.close();
                        return;
                    }

                    if (msg.startsWith("REQUEST:")) {
                        // Instead of prompting here, enqueue request for main thread
                        incomingRequests.offer(new IncomingRequest(socket, in, out, sender, senderKey));
                        // Do NOT break here to wait for main thread to process
                        return;
                    } else {
                        socket.close();
                    }
                    break;
                }
            }
        } catch (Exception e) {
            // Don't print stack trace here to avoid confusing user with "end" errors
            System.out.println("Error handling incoming connection: " + e.getMessage());
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    // Handle chat request on main thread to safely read user input
    private static void handleChatRequestFromQueue(IncomingRequest req, PrivateKey privateKey, String selfUsername) {
        try {
            System.out.print("\n" + req.senderUsername + " wants to chat with you. Accept? (yes/no): ");
            String answer = scanner.nextLine().trim().toLowerCase();

            String response = CryptoUtils
                    .buildSecureMessage((answer.equals("yes") ? "ACCEPT:" : "REJECT:") + selfUsername);
            String responseSig = CryptoUtils.sign(response, privateKey);
            String encryptedResp = CryptoUtils.encrypt(response, req.senderPublicKey);
            req.out.println("MSG:" + encryptedResp);
            req.out.println("SIG:" + responseSig);

            if (answer.equals("yes")) {
                System.out.println("\nStart chatting with " + req.senderUsername + ". Type 'quit' to end chat.");
                startChat(req.socket, selfUsername, req.senderUsername, privateKey, req.senderPublicKey, req.in,
                        req.out);
            } else {
                req.socket.close();
            }
        } catch (Exception e) {
            System.out.println("Error during chat request handling: " + e.getMessage());
            try {
                req.socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static void startChat(Socket socket, String fromUser, String toUser, PrivateKey privKey, PublicKey pubKey,
            BufferedReader in, PrintWriter out) {
        try {
            DHParameterSpec dhSpec = CryptoUtils.getDHParameterSpec();

            out.println("P:" + dhSpec.getP().toString(16));
            out.println("G:" + dhSpec.getG().toString(16));

            KeyPair dhKeyPair = CryptoUtils.generateEphemeralDHKeyPair(dhSpec);
            String myDHPub = CryptoUtils.encodeKey(dhKeyPair.getPublic());
            out.println("DH:" + myDHPub);

            String line, peerPubLine = null;
            while ((line = in.readLine()) != null) {
                if (line.startsWith("DH:")) {
                    peerPubLine = line.substring(3);
                    break;
                }
            }

            if (peerPubLine == null) {
                System.out.println("Failed to receive peer DH key.");
                return;
            }

            PublicKey peerDHPublicKey = CryptoUtils.decodeDHPublicKey(peerPubLine);
            SecretKey sharedAESKey = CryptoUtils.deriveSharedSecret(dhKeyPair.getPrivate(), peerDHPublicKey);

            Thread receiveThread = new Thread(() -> {
                try {
                    String enc = null, sig = null, rline;
                    while ((rline = in.readLine()) != null) {
                        if (rline.startsWith("ENC:"))
                            enc = rline.substring(4);
                        else if (rline.startsWith("SIG:"))
                            sig = rline.substring(4);

                        if (enc != null && sig != null) {
                            String decrypted = CryptoUtils.decryptWithAES(enc, sharedAESKey);
                            boolean valid = CryptoUtils.verify(decrypted, sig, pubKey);

                            if (!valid) {
                                System.out.println("\n[WARNING] Invalid signature!");
                            }

                            if (decrypted.equalsIgnoreCase("quit")) {
                                System.out.println("\nChat closed.");
                                break;
                            }

                            System.out.println("\n[" + toUser + "] > " + decrypted);
                            MessageLogger.logMessage(toUser, fromUser, enc, sig);

                            enc = sig = null;
                            System.out.print("[You] > ");
                        }
                    }
                } catch (Exception e) {
                    System.out.println("\nChat error.");
                }
            });
            receiveThread.setDaemon(true);
            receiveThread.start();

            while (true) {
                System.out.print("[You] > ");
                String message = scanner.nextLine();

                String encryptedMessage = CryptoUtils.encryptWithAES(message, sharedAESKey);
                String signature = CryptoUtils.sign(message, privKey);

                out.println("ENC:" + encryptedMessage);
                out.println("SIG:" + signature);

                MessageLogger.logMessage(fromUser, toUser, encryptedMessage, signature);

                if (message.equalsIgnoreCase("quit")) {
                    socket.close();
                    break;
                }
            }

        } catch (Exception e) {
            System.out.println("Chat error: " + e.getMessage());
        }
    }

    public static void registerToPeerFile(String username, String ip, int port) throws IOException {
        synchronized (PeerChat.class) {
            List<String> peers = Files.exists(Paths.get(PEER_REGISTRY_FILE))
                    ? Files.readAllLines(Paths.get(PEER_REGISTRY_FILE))
                    : new ArrayList<>();

            List<String> updated = new ArrayList<>();
            for (String peer : peers) {
                if (!peer.startsWith(username + ":")) {
                    updated.add(peer);
                }
            }
            updated.add(username + ":" + ip + ":" + port);
            Files.write(Paths.get(PEER_REGISTRY_FILE), updated);
        }
    }

    private static void listPeers(String selfUsername) throws IOException {
        if (!Files.exists(Paths.get(PEER_REGISTRY_FILE))) {
            System.out.println("No peers online.");
            return;
        }
        System.out.println("\n=== Online Peers ===");
        List<String> peers = Files.readAllLines(Paths.get(PEER_REGISTRY_FILE));
        for (String line : peers) {
            String[] parts = line.split(":");
            if (parts.length == 3 && !parts[0].equals(selfUsername)) {
                System.out.println(" - " + parts[0]);
            }
        }
    }

    private static String[] getPeerByUsername(String username) throws IOException {
        if (!Files.exists(Paths.get(PEER_REGISTRY_FILE)))
            return null;
        List<String> peers = Files.readAllLines(Paths.get(PEER_REGISTRY_FILE));
        for (String line : peers) {
            String[] parts = line.split(":");
            if (parts.length == 3 && parts[0].equals(username)) {
                return new String[] { parts[1], parts[2] };
            }
        }
        return null;
    }
}
