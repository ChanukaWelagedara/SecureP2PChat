import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {
    private static final String KEY_DIR = "keys";
    private static final int KEY_SIZE = 2048;

    // Fixed, standard DH parameters (2048-bit MODP Group)
    private static final BigInteger DH_P = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
                    "FFFFFFFFFFFFFFFF",
            16);
    private static final BigInteger DH_G = BigInteger.valueOf(2);
    private static final DHParameterSpec DH_PARAMS = new DHParameterSpec(DH_P, DH_G);

    public static void generateRSAKeyPair(String username) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(KEY_SIZE);
        KeyPair pair = generator.generateKeyPair();
        Files.createDirectories(Paths.get(KEY_DIR));
        try (FileOutputStream out = new FileOutputStream(KEY_DIR + "/" + username + ".pri")) {
            out.write(pair.getPrivate().getEncoded());
        }
        try (FileOutputStream out = new FileOutputStream(KEY_DIR + "/" + username + ".pub")) {
            out.write(pair.getPublic().getEncoded());
        }
    }

    public static PrivateKey loadPrivateKey(String username) throws Exception {
        byte[] bytes = Files.readAllBytes(Paths.get(KEY_DIR + "/" + username + ".pri"));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    public static PublicKey loadPublicKey(String username) throws Exception {
        byte[] bytes = Files.readAllBytes(Paths.get(KEY_DIR + "/" + username + ".pub"));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public static String encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
    }

    public static String decrypt(String encrypted, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encrypted)));
    }

    public static String sign(String message, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(message.getBytes());
        return Base64.getEncoder().encodeToString(sig.sign());
    }

    public static boolean verify(String message, String signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(message.getBytes());
        return sig.verify(Base64.getDecoder().decode(signature));
    }

    public static String buildSecureMessage(String plainText) {
        long timestamp = System.currentTimeMillis();
        String nonce = generateNonce();
        return timestamp + "::" + nonce + "::" + plainText;
    }

    public static boolean isFresh(String message, long maxAgeMillis) {
        try {
            long timestamp = Long.parseLong(message.split("::")[0]);
            return System.currentTimeMillis() - timestamp <= maxAgeMillis;
        } catch (Exception e) {
            return false;
        }
    }

    private static String generateNonce() {
        byte[] nonce = new byte[8];
        new SecureRandom().nextBytes(nonce);
        return Base64.getEncoder().encodeToString(nonce);
    }

    public static String extractMessageBody(String fullMessage) {
        String[] parts = fullMessage.split("::", 3);
        return (parts.length == 3) ? parts[2] : null;
    }

    // ======== Ephemeral DH & AES for PFS ========

    public static KeyPair generateEphemeralDHKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(DH_PARAMS);
        return keyGen.generateKeyPair();
    }

    public static SecretKey deriveSharedSecret(PrivateKey priv, PublicKey pub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(priv);
        ka.doPhase(pub, true);
        byte[] secret = ka.generateSecret();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha256.digest(secret);
        return new SecretKeySpec(keyBytes, 0, 16, "AES");
    }

    public static DHParameterSpec getDHParameterSpec() {
        return DH_PARAMS;
    }

    public static KeyPair generateEphemeralDHKeyPair(DHParameterSpec dhSpec) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhSpec);
        return keyGen.generateKeyPair();
    }

    // public static String encryptWithAES(String message, SecretKey key) throws
    // Exception {
    // Cipher c = Cipher.getInstance("AES");
    // c.init(Cipher.ENCRYPT_MODE, key);
    // return Base64.getEncoder().encodeToString(c.doFinal(message.getBytes()));
    // }

    public static String encryptWithAES(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] ciphertext = cipher.doFinal(message.getBytes());

        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    // public static String decryptWithAES(String cipherText, SecretKey key) throws
    // Exception {
    // Cipher c = Cipher.getInstance("AES");
    // c.init(Cipher.DECRYPT_MODE, key);
    // return new String(c.doFinal(Base64.getDecoder().decode(cipherText)));
    // }

    public static String decryptWithAES(String cipherText, SecretKey key) throws Exception {
        byte[] combined = Base64.getDecoder().decode(cipherText);

        byte[] iv = new byte[16];
        byte[] ciphertext = new byte[combined.length - 16];

        System.arraycopy(combined, 0, iv, 0, 16);
        System.arraycopy(combined, 16, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainBytes = cipher.doFinal(ciphertext);

        return new String(plainBytes);
    }

    public static String encodeKey(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PublicKey decodeDHPublicKey(String base64Key) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(base64Key);
        KeyFactory kf = KeyFactory.getInstance("DH");
        X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
        return kf.generatePublic(spec);
    }
}
