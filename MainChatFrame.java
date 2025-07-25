import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import javax.crypto.SecretKey;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import javax.swing.border.TitledBorder;

public class MainChatFrame extends JFrame {
    private String currentUsername;
    private PrivateKey privateKey;
    private ServerSocket serverSocket;
    private int listenPort;

    // UI Components
    private JTextArea chatArea;
    private JTextField messageField;
    private JButton sendButton;
    private JTextField peerUsernameField;
    private JButton connectButton;
    private JButton disconnectButton;
    private JButton listPeersButton;
    private JLabel statusLabel;
    private JLabel connectionStatusLabel;

    // Chat connection
    private Socket chatSocket;
    private BufferedReader chatIn;
    private PrintWriter chatOut;
    private String connectedPeerUsername;
    private PublicKey connectedPeerPublicKey;
    private SecretKey sharedAESKey;
    private boolean isConnected = false;

    // Incoming requests queue
    private final BlockingQueue<IncomingChatRequest> incomingRequests = new LinkedBlockingQueue<>();

    private static class IncomingChatRequest {
        final Socket socket;
        final BufferedReader in;
        final PrintWriter out;
        final String senderUsername;
        final PublicKey senderPublicKey;

        IncomingChatRequest(Socket socket, BufferedReader in, PrintWriter out, String senderUsername,
                PublicKey senderPublicKey) {
            this.socket = socket;
            this.in = in;
            this.out = out;
            this.senderUsername = senderUsername;
            this.senderPublicKey = senderPublicKey;
        }
    }

    public MainChatFrame(String username) throws Exception {
        this.currentUsername = username;
        this.privateKey = CryptoUtils.loadPrivateKey(username);

        // Ask for listening port first
        String portInput = JOptionPane.showInputDialog(
                null,
                "Enter your listening port (e.g., 5000):",
                "Port Configuration",
                JOptionPane.QUESTION_MESSAGE);

        if (portInput == null) {
            System.exit(0); // User cancelled
            return;
        }

        try {
            listenPort = Integer.parseInt(portInput.trim());
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(null, "Invalid port number. Using default port assignment.");
            listenPort = 5000; // fallback to auto-assignment
        }

        initializeComponents();
        setupLayout();
        setupEventHandlers();
        startListeningServer();

        setTitle("Secure P2P Chat - " + username);
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        setSize(800, 600);
        setLocationRelativeTo(null);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                closeApplication();
            }
        });
    }

    private void initializeComponents() {
        // Chat area
        chatArea = new JTextArea();
        chatArea.setEditable(false);
        chatArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        chatArea.setBackground(new Color(248, 248, 248));

        // Message input
        messageField = new JTextField();
        sendButton = new JButton("Send");
        sendButton.setBackground(new Color(34, 139, 34));
        sendButton.setForeground(Color.WHITE);
        sendButton.setFocusPainted(false);

        // Connection fields
        peerUsernameField = new JTextField("", 15);
        connectButton = new JButton("Connect to User");
        disconnectButton = new JButton("Disconnect");
        listPeersButton = new JButton("List Online Users");

        connectButton.setBackground(new Color(70, 130, 180));
        connectButton.setForeground(Color.WHITE);
        connectButton.setFocusPainted(false);

        disconnectButton.setBackground(new Color(220, 20, 60));
        disconnectButton.setForeground(Color.WHITE);
        disconnectButton.setFocusPainted(false);
        disconnectButton.setEnabled(false);

        listPeersButton.setBackground(new Color(128, 0, 128));
        listPeersButton.setForeground(Color.WHITE);
        listPeersButton.setFocusPainted(false);

        // Status labels
        statusLabel = new JLabel("Ready");
        connectionStatusLabel = new JLabel("Not connected");
        connectionStatusLabel.setForeground(Color.RED);

        // Initially disable chat components
        messageField.setEnabled(false);
        sendButton.setEnabled(false);
    }

    private void setupLayout() {
        setLayout(new BorderLayout());

        // Header panel
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(new Color(64, 64, 64));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel titleLabel = new JLabel("🔐 Secure P2P Chat - " + currentUsername);
        titleLabel.setForeground(Color.WHITE);
        titleLabel.setFont(new Font("Arial", Font.BOLD, 16));

        JLabel portLabel = new JLabel("Listening on port: " + listenPort);
        portLabel.setForeground(Color.LIGHT_GRAY);

        headerPanel.add(titleLabel, BorderLayout.WEST);
        headerPanel.add(portLabel, BorderLayout.EAST);

        // Connection panel
        JPanel connectionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        connectionPanel.setBorder(new TitledBorder("Peer Connection"));
        connectionPanel.add(new JLabel("Username to connect:"));
        connectionPanel.add(peerUsernameField);
        connectionPanel.add(connectButton);
        connectionPanel.add(disconnectButton);
        connectionPanel.add(listPeersButton);
        connectionPanel.add(new JLabel(" | Status:"));
        connectionPanel.add(connectionStatusLabel);

        // Chat panel
        JPanel chatPanel = new JPanel(new BorderLayout());
        chatPanel.setBorder(new TitledBorder("Chat Messages"));

        JScrollPane scrollPane = new JScrollPane(chatArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        chatPanel.add(scrollPane, BorderLayout.CENTER);

        // Message input panel
        JPanel messagePanel = new JPanel(new BorderLayout());
        messagePanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        messagePanel.add(new JLabel("Message: "), BorderLayout.WEST);
        messagePanel.add(messageField, BorderLayout.CENTER);
        messagePanel.add(sendButton, BorderLayout.EAST);

        chatPanel.add(messagePanel, BorderLayout.SOUTH);

        // Status bar
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusPanel.setBorder(BorderFactory.createLoweredBevelBorder());
        statusPanel.add(new JLabel("Status: "));
        statusPanel.add(statusLabel);

        // Combine panels
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(headerPanel, BorderLayout.NORTH);
        topPanel.add(connectionPanel, BorderLayout.SOUTH);

        add(topPanel, BorderLayout.NORTH);
        add(chatPanel, BorderLayout.CENTER);
        add(statusPanel, BorderLayout.SOUTH);
    }

    private void setupEventHandlers() {
        connectButton.addActionListener(e -> connectToPeer());
        disconnectButton.addActionListener(e -> disconnectFromPeer());
        sendButton.addActionListener(e -> sendMessage());
        messageField.addActionListener(e -> sendMessage());
        listPeersButton.addActionListener(e -> listOnlinePeers());

        // Timer to check for incoming requests
        Timer requestChecker = new Timer(1000, e -> checkIncomingRequests());
        requestChecker.start();
    }

    private void startListeningServer() {
        try {
            // Use the specified port, with fallback to auto-assignment if it fails
            try {
                serverSocket = new ServerSocket(listenPort);
            } catch (Exception e) {
                // If specified port fails, try auto-assignment
                listenPort = 5000;
                while (listenPort < 6000) {
                    try {
                        serverSocket = new ServerSocket(listenPort);
                        break;
                    } catch (Exception ex) {
                        listenPort++;
                    }
                }
            }

            String localIP = InetAddress.getLocalHost().getHostAddress();
            PeerChat.registerToPeerFile(currentUsername, localIP, listenPort);

            // Start listener thread
            Thread listenerThread = new Thread(this::listenForConnections);
            listenerThread.setDaemon(true);
            listenerThread.start();

            updateStatus("Listening for connections on port " + listenPort);

        } catch (Exception e) {
            updateStatus("Error starting server: " + e.getMessage());
        }
    }

    private void listenForConnections() {
        while (!serverSocket.isClosed()) {
            try {
                Socket incomingSocket = serverSocket.accept();
                new Thread(() -> handleIncomingConnection(incomingSocket)).start();
            } catch (Exception e) {
                if (!serverSocket.isClosed()) {
                    updateStatus("Error accepting connection: " + e.getMessage());
                }
            }
        }
    }

    private void handleIncomingConnection(Socket socket) {
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
                        appendToChat("⚠️ Invalid chat request received (expired or tampered)");
                        socket.close();
                        return;
                    }

                    if (msg.startsWith("REQUEST:")) {
                        incomingRequests.offer(new IncomingChatRequest(socket, in, out, sender, senderKey));
                        SwingUtilities.invokeLater(() -> {
                            appendToChat("📞 Incoming chat request from " + sender);
                            updateStatus("Chat request from " + sender + " - check messages");
                        });
                        return;
                    }
                    break;
                }
            }
        } catch (Exception e) {
            updateStatus("Error handling incoming connection: " + e.getMessage());
        }
    }

    private void checkIncomingRequests() {
        while (!incomingRequests.isEmpty()) {
            IncomingChatRequest request = incomingRequests.poll();
            if (request != null) {
                handleIncomingChatRequest(request);
            }
        }
    }

    private void handleIncomingChatRequest(IncomingChatRequest request) {
        if (isConnected) {
            // Already connected, reject
            try {
                String rejectMsg = CryptoUtils.buildSecureMessage("REJECT:Already connected");
                String encrypted = CryptoUtils.encrypt(rejectMsg, request.senderPublicKey);
                String signature = CryptoUtils.sign(rejectMsg, privateKey);
                request.out.println("MSG:" + encrypted);
                request.out.println("SIG:" + signature);
                request.socket.close();
            } catch (Exception e) {
                // Ignore
            }
            return;
        }

        int result = JOptionPane.showConfirmDialog(
                this,
                "Accept chat request from " + request.senderUsername + "?",
                "Incoming Chat Request",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);

        try {
            if (result == JOptionPane.YES_OPTION) {
                // Accept and start chat
                String acceptMsg = CryptoUtils.buildSecureMessage("ACCEPT:" + currentUsername);
                String encrypted = CryptoUtils.encrypt(acceptMsg, request.senderPublicKey);
                String signature = CryptoUtils.sign(acceptMsg, privateKey);
                request.out.println("MSG:" + encrypted);
                request.out.println("SIG:" + signature);

                // Set up chat connection
                chatSocket = request.socket;
                chatIn = request.in;
                chatOut = request.out;
                connectedPeerUsername = request.senderUsername;
                connectedPeerPublicKey = request.senderPublicKey;

                // Set up DH key exchange and start chat
                setupDHKeyExchange(false);

            } else {
                // Reject
                String rejectMsg = CryptoUtils.buildSecureMessage("REJECT:Request declined");
                String encrypted = CryptoUtils.encrypt(rejectMsg, request.senderPublicKey);
                String signature = CryptoUtils.sign(rejectMsg, privateKey);
                request.out.println("MSG:" + encrypted);
                request.out.println("SIG:" + signature);
                request.socket.close();
            }
        } catch (Exception e) {
            updateStatus("Error handling chat request: " + e.getMessage());
        }
    }

    private void connectToPeer() {
        String peerUsername = peerUsernameField.getText().trim();

        if (peerUsername.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a username to connect to");
            return;
        }

        try {
            // Look up peer info from peers.txt file
            String[] peerInfo = getPeerByUsername(peerUsername);
            if (peerInfo == null) {
                JOptionPane.showMessageDialog(this, "User '" + peerUsername
                        + "' not found or offline.\nClick 'List Online Users' to see available users.");
                return;
            }

            String peerIP = peerInfo[0];
            int peerPort = Integer.parseInt(peerInfo[1]);

            connectButton.setEnabled(false);
            updateStatus("Connecting to " + peerUsername + " at " + peerIP + ":" + peerPort + "...");

            SwingWorker<Boolean, Void> worker = new SwingWorker<Boolean, Void>() {
                @Override
                protected Boolean doInBackground() throws Exception {
                    return performPeerConnection(peerIP, peerPort, peerUsername);
                }

                @Override
                protected void done() {
                    try {
                        boolean success = get();
                        if (success) {
                            setupDHKeyExchange(true);
                        } else {
                            connectButton.setEnabled(true);
                        }
                    } catch (Exception e) {
                        updateStatus("Connection failed: " + e.getMessage());
                        connectButton.setEnabled(true);
                    }
                }
            };
            worker.execute();

        } catch (Exception e) {
            updateStatus("Error connecting: " + e.getMessage());
            connectButton.setEnabled(true);
        }
    }

    private boolean performPeerConnection(String peerIP, int peerPort, String peerUsername) throws Exception {
        chatSocket = new Socket(peerIP, peerPort);
        chatIn = new BufferedReader(new InputStreamReader(chatSocket.getInputStream()));
        chatOut = new PrintWriter(chatSocket.getOutputStream(), true);

        connectedPeerPublicKey = CryptoUtils.loadPublicKey(peerUsername);
        String requestMsg = CryptoUtils.buildSecureMessage("REQUEST:" + currentUsername);
        String encrypted = CryptoUtils.encrypt(requestMsg, connectedPeerPublicKey);
        String signature = CryptoUtils.sign(requestMsg, privateKey);

        chatOut.println("MSG:" + encrypted);
        chatOut.println("SIG:" + signature);

        String encResponse = null, sigResponse = null, line;
        while ((line = chatIn.readLine()) != null) {
            if (line.startsWith("MSG:"))
                encResponse = line.substring(4);
            else if (line.startsWith("SIG:"))
                sigResponse = line.substring(4);

            if (encResponse != null && sigResponse != null) {
                String decrypted = CryptoUtils.decrypt(encResponse, privateKey);
                String response = CryptoUtils.extractMessageBody(decrypted);
                boolean validSig = CryptoUtils.verify(decrypted, sigResponse, connectedPeerPublicKey);

                if (!validSig) {
                    updateStatus("Invalid response signature");
                    return false;
                }

                if (response.startsWith("ACCEPT:")) {
                    connectedPeerUsername = peerUsername;
                    appendToChat("✅ Connected to " + peerUsername);
                    return true;
                } else if (response.startsWith("REJECT:")) {
                    updateStatus(peerUsername + " rejected your request");
                    return false;
                }
            }
        }
        return false;
    }

    private void setupDHKeyExchange(boolean isInitiator) {
        try {
            updateStatus("Setting up secure channel...");

           
            isConnected = true;

            SwingUtilities.invokeLater(() -> {
                messageField.setEnabled(true);
                sendButton.setEnabled(true);
                connectButton.setEnabled(false);
                disconnectButton.setEnabled(true);
                connectionStatusLabel.setText("Connected to " + connectedPeerUsername);
                connectionStatusLabel.setForeground(new Color(34, 139, 34));
                updateStatus("Secure chat established with " + connectedPeerUsername);
                appendToChat("🔒 Secure chat session started with " + connectedPeerUsername);

                // Start message receiving thread
                Thread receiveThread = new Thread(this::receiveMessages);
                receiveThread.setDaemon(true);
                receiveThread.start();
            });

        } catch (Exception e) {
            updateStatus("Error setting up secure channel: " + e.getMessage());
            disconnectFromPeer();
        }
    }

    private void receiveMessages() {
        try {
            String enc = null, sig = null, line;
            while ((line = chatIn.readLine()) != null && isConnected) {
                if (line.startsWith("ENC:"))
                    enc = line.substring(4);
                else if (line.startsWith("SIG:"))
                    sig = line.substring(4);

                if (enc != null && sig != null) {

                    String decrypted = CryptoUtils.decrypt(enc, privateKey);
                    boolean validSig = CryptoUtils.verify(decrypted, sig, connectedPeerPublicKey);

                    if (!validSig) {
                        appendToChat("⚠️ Message with invalid signature received!");
                    }

                    String actualMessage = CryptoUtils.extractMessageBody(decrypted);
                    if (actualMessage.equalsIgnoreCase("quit")) {
                        appendToChat("👋 " + connectedPeerUsername + " has left the chat");
                        SwingUtilities.invokeLater(this::disconnectFromPeer);
                        break;
                    }

                    SwingUtilities.invokeLater(() -> {
                        appendToChat("[" + connectedPeerUsername + "] " + actualMessage);
                    });

                    MessageLogger.logMessage(connectedPeerUsername, currentUsername, enc, sig);
                    enc = null;
                    sig = null;
                }
            }
        } catch (Exception e) {
            if (isConnected) {
                SwingUtilities.invokeLater(() -> {
                    updateStatus("Connection lost: " + e.getMessage());
                    disconnectFromPeer();
                });
            }
        }
    }

    private void sendMessage() {
        if (!isConnected) {
            return;
        }

        String message = messageField.getText().trim();
        if (message.isEmpty()) {
            return;
        }

        try {
            String secureMessage = CryptoUtils.buildSecureMessage(message);
            // In a full implementation, you would encrypt with AES here
            String encrypted = CryptoUtils.encrypt(secureMessage, connectedPeerPublicKey);
            String signature = CryptoUtils.sign(secureMessage, privateKey);

            chatOut.println("ENC:" + encrypted);
            chatOut.println("SIG:" + signature);

            appendToChat("[You] " + message);
            MessageLogger.logMessage(currentUsername, connectedPeerUsername, encrypted, signature);

            messageField.setText("");

        } catch (Exception e) {
            updateStatus("Error sending message: " + e.getMessage());
        }
    }

    private void disconnectFromPeer() {
        if (isConnected) {
            try {
                // Send quit message
                String quitMessage = CryptoUtils.buildSecureMessage("quit");
                String encrypted = CryptoUtils.encrypt(quitMessage, connectedPeerPublicKey);
                String signature = CryptoUtils.sign(quitMessage, privateKey);

                chatOut.println("ENC:" + encrypted);
                chatOut.println("SIG:" + signature);

                appendToChat("👋 You left the chat");
            } catch (Exception e) {
                // Ignore errors when disconnecting
            }
        }

        // Close connection
        try {
            if (chatSocket != null)
                chatSocket.close();
        } catch (Exception e) {
            // Ignore
        }

        // Reset UI state
        isConnected = false;
        chatSocket = null;
        chatIn = null;
        chatOut = null;
        connectedPeerUsername = null;
        connectedPeerPublicKey = null;
        sharedAESKey = null;

        messageField.setEnabled(false);
        sendButton.setEnabled(false);
        connectButton.setEnabled(true);
        disconnectButton.setEnabled(false);
        connectionStatusLabel.setText("Not connected");
        connectionStatusLabel.setForeground(Color.RED);
        updateStatus("Disconnected");
    }

    private void appendToChat(String message) {
        SwingUtilities.invokeLater(() -> {
            chatArea.append(
                    "[" + java.time.LocalTime.now().format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss"))
                            + "] " + message + "\n");
            chatArea.setCaretPosition(chatArea.getDocument().getLength());
        });
    }

    private void updateStatus(String status) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(status);
        });
    }

    private void closeApplication() {
        try {
            disconnectFromPeer();
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (Exception e) {
            // Ignore
        }
        System.exit(0);
    }

    // Method to list online peers
    private void listOnlinePeers() {
        try {
            if (!java.nio.file.Files.exists(java.nio.file.Paths.get("peers.txt"))) {
                appendToChat("📋 No peers online.");
                return;
            }

            appendToChat("📋 === Online Peers ===");
            java.util.List<String> peers = java.nio.file.Files.readAllLines(java.nio.file.Paths.get("peers.txt"));
            boolean foundPeers = false;

            for (String line : peers) {
                String[] parts = line.split(":");
                if (parts.length == 3 && !parts[0].equals(currentUsername)) {
                    appendToChat("👤 " + parts[0] + " (IP: " + parts[1] + ", Port: " + parts[2] + ")");
                    foundPeers = true;
                }
            }

            if (!foundPeers) {
                appendToChat("📋 No other peers online.");
            }
            appendToChat("📋 ==================");

        } catch (Exception e) {
            appendToChat("❌ Error listing peers: " + e.getMessage());
        }
    }

    // Method to get peer info by username
    private String[] getPeerByUsername(String username) {
        try {
            if (!java.nio.file.Files.exists(java.nio.file.Paths.get("peers.txt"))) {
                return null;
            }

            java.util.List<String> peers = java.nio.file.Files.readAllLines(java.nio.file.Paths.get("peers.txt"));
            for (String line : peers) {
                String[] parts = line.split(":");
                if (parts.length == 3 && parts[0].equals(username)) {
                    return new String[] { parts[1], parts[2] }; // IP, Port
                }
            }
        } catch (Exception e) {
            updateStatus("Error looking up peer: " + e.getMessage());
        }
        return null;
    }
}
