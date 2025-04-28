import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client {
    private String serverIp;
    private int serverPort;
    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private PublicKey serverPublicKey;

    // DH parameters
    private BigInteger p; // Large prime
    private BigInteger g; // Generator
    private BigInteger privateY; // Client's private key
    private BigInteger publicY; // Client's public key (g^y mod p)
    private BigInteger publicX; // Server's public key (g^x mod p)
    private BigInteger sharedKey; // Shared secret key

    // Session keys
    private SecretKey encryptionKey; // K_AB1 for AES
    private SecretKey integrityKey;  // K_AB2 for HMAC
    private IvParameterSpec iv;      // IV for AES

    // Performance metrics
    private long startTime;
    private long authTime;
    private long dhTime;
    private long encryptTime;

    private Map<String, String> services; // Service ID -> Service Name

    public Client(String serverIp, int serverPort) {
        this.serverIp = serverIp;
        this.serverPort = serverPort;
        this.services = new HashMap<>();
        loadServerPublicKey();
    }

    private void loadServerPublicKey() {
        try {
            // In a real implementation, you would load from a file
            // For this example, we'll generate a key pair and use the public key
            // This would normally be the server's public key loaded from a file

            // Check if server_public.key exists
            File keyFile = new File("server_public.key");
            if (keyFile.exists()) {
                // Load the key from file
                byte[] keyBytes = new byte[(int) keyFile.length()];
                try (FileInputStream fis = new FileInputStream(keyFile)) {
                    fis.read(keyBytes);
                }

                X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                serverPublicKey = kf.generatePublic(spec);
                System.out.println("Loaded server public key from file");
            } else {
                System.out.println("Server public key file not found. Please run the server first.");
                System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("Error loading server public key: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    public void connect() throws IOException {
        try {
            startTime = System.currentTimeMillis();

            socket = new Socket(serverIp, serverPort);
            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());

            System.out.println("Connected to server at " + serverIp + ":" + serverPort);

            // Step 1: HELLO + Challenge Authentication
            if (!performAuthentication()) {
                System.err.println("Authentication failed");
                return;
            }
            authTime = System.currentTimeMillis();

            // Step 2: DH Parameter Exchange
            if (!performDHExchange()) {
                System.err.println("DH exchange failed");
                return;
            }
            dhTime = System.currentTimeMillis();

            // Step 3: Session Key Calculation
            calculateSessionKeys();

            // Step 4: Receive IV
            receiveIV();

            // Step 5: Receive encrypted service table
            receiveServiceTable();

            // Step 6: Request a service
            requestService();

            encryptTime = System.currentTimeMillis();

            // Print performance metrics
            System.out.println("\nPerformance Metrics:");
            System.out.println("Authentication time: " + (authTime - startTime) + "ms");
            System.out.println("DH exchange time: " + (dhTime - authTime) + "ms");
            System.out.println("Encryption operations time: " + (encryptTime - dhTime) + "ms");
            System.out.println("Total time: " + (encryptTime - startTime) + "ms");

        } catch (Exception e) {
            System.err.println("Error connecting to server: " + e.getMessage());
            e.printStackTrace();
            throw new IOException("Connection failed", e);
        }
    }

    private boolean performAuthentication() throws IOException {
        try {
            // Send HELLO message
            out.writeUTF("HELLO");
            System.out.println("Sent: HELLO");

            // Generate random challenge
            SecureRandom random = new SecureRandom();
            byte[] challenge = new byte[32];
            random.nextBytes(challenge);

            // Send challenge to server
            out.write(challenge);
            System.out.println("Sent challenge: " + bytesToHex(challenge));

            // Receive signed challenge
            int signatureLength = in.readInt();
            byte[] signature = new byte[signatureLength];
            in.readFully(signature);
            System.out.println("Received signature: " + bytesToHex(signature).substring(0, 32) + "...");

            // Verify signature using server's public key
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(serverPublicKey);
            sig.update(challenge);
            boolean verified = sig.verify(signature);

            if (verified) {
                System.out.println("Server authentication successful");
                out.writeUTF("OK");
                return true;
            } else {
                System.err.println("Server authentication failed");
                out.writeUTF("ERROR");
                return false;
            }

        } catch (Exception e) {
            System.err.println("Error during authentication: " + e.getMessage());
            e.printStackTrace();
            out.writeUTF("ERROR");
            return false;
        }
    }

    private boolean performDHExchange() throws IOException {
        try {
            // Receive DH parameters from server
            String dhParams = in.readUTF();

            // Receive signature
            int signatureLength = in.readInt();
            byte[] signature = new byte[signatureLength];
            in.readFully(signature);

            // Verify signature
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(serverPublicKey);
            sig.update(dhParams.getBytes(StandardCharsets.UTF_8));
            boolean verified = sig.verify(signature);

            if (!verified) {
                System.err.println("DH parameters signature verification failed");
                out.writeUTF("ERROR");
                return false;
            }

            // Parse DH parameters
            String[] params = dhParams.split(",");
            g = new BigInteger(params[0]);
            p = new BigInteger(params[1]);
            publicX = new BigInteger(params[2]);

            System.out.println("Received DH parameters:");
            System.out.println("g: " + g);
            System.out.println("p: " + p.toString().substring(0, 32) + "...");
            System.out.println("g^x: " + publicX.toString().substring(0, 32) + "...");

            // Send OK
            out.writeUTF("OK");

            // Generate client's private key y
            SecureRandom random = new SecureRandom();
            privateY = new BigInteger(1024, random);

            // Calculate client's public key g^y mod p
            publicY = g.modPow(privateY, p);

            // Send client's public key to server
            out.writeUTF(publicY.toString());
            System.out.println("Sent client's public key g^y: " + publicY.toString().substring(0, 32) + "...");

            return true;

        } catch (Exception e) {
            System.err.println("Error in DH exchange: " + e.getMessage());
            e.printStackTrace();
            out.writeUTF("ERROR");
            return false;
        }
    }

    private void calculateSessionKeys() {
        try {
            // Calcular llave secreta compartida (g^x)^y mod p
            sharedKey = publicX.modPow(privateY, p);
            System.out.println("Llave compartida calculada: " + sharedKey.toString().substring(0, 32) + "...");

            // Derivar dos llaves a partir de la llave compartida usando SHA-512
            MessageDigest sha = MessageDigest.getInstance("SHA-512");
            byte[] sharedKeyBytes = sharedKey.toString().getBytes(StandardCharsets.UTF_8);
            byte[] hashedKey = sha.digest(sharedKeyBytes);

            // Primera mitad (32 bytes) para cifrado (K_AB1)
            byte[] encKeyBytes = Arrays.copyOfRange(hashedKey, 0, 32);
            encryptionKey = new SecretKeySpec(encKeyBytes, "AES");

            // Segunda mitad (32 bytes) para integridad (K_AB2)
            byte[] intKeyBytes = Arrays.copyOfRange(hashedKey, 32, 64);
            integrityKey = new SecretKeySpec(intKeyBytes, "HmacSHA256");

            System.out.println("Llave de cifrado derivada: " + bytesToHex(encKeyBytes).substring(0, 32) + "...");
            System.out.println("Llave de integridad derivada: " + bytesToHex(intKeyBytes).substring(0, 32) + "...");

        } catch (Exception e) {
            System.err.println("Error calculando llaves de sesión: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void receiveIV() throws IOException {
        try {
            // Receive IV from server
            int ivLength = in.readInt();
            byte[] ivBytes = new byte[ivLength];
            in.readFully(ivBytes);
            iv = new IvParameterSpec(ivBytes);

            System.out.println("Received IV: " + bytesToHex(ivBytes));

        } catch (Exception e) {
            System.err.println("Error receiving IV: " + e.getMessage());
            throw new IOException("IV reception failed", e);
        }
    }

    private void receiveServiceTable() throws IOException {
        try {
            // Receive encrypted service table
            int encryptedTableLength = in.readInt();
            byte[] encryptedTable = new byte[encryptedTableLength];
            in.readFully(encryptedTable);

            // Receive HMAC
            int hmacLength = in.readInt();
            byte[] receivedHmac = new byte[hmacLength];
            in.readFully(receivedHmac);

            System.out.println("Received encrypted service table (" + encryptedTableLength + " bytes)");
            System.out.println("Received HMAC: " + bytesToHex(receivedHmac).substring(0, 32) + "...");

            // Verify HMAC
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(integrityKey);
            byte[] calculatedHmac = hmac.doFinal(encryptedTable);

            if (!Arrays.equals(receivedHmac, calculatedHmac)) {
                System.err.println("HMAC verification failed");
                return;
            }

            // Decrypt the service table
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, iv);
            byte[] decryptedTable = cipher.doFinal(encryptedTable);

            String tableStr = new String(decryptedTable, StandardCharsets.UTF_8);
            System.out.println("Decrypted service table: " + tableStr);

            // Parse the service table (simple JSON-like parsing)
            parseServiceTable(tableStr);

        } catch (Exception e) {
            System.err.println("Error receiving service table: " + e.getMessage());
            e.printStackTrace();
            throw new IOException("Service table reception failed", e);
        }
    }

    private void parseServiceTable(String tableStr) {
        // Very simple JSON-like parsing (in a real implementation, use a proper JSON parser)
        services.clear();

        // Remove outer braces
        tableStr = tableStr.substring(1, tableStr.length() - 1);

        // Split by service entries
        String[] serviceEntries = tableStr.split("},");

        for (String entry : serviceEntries) {
            // Clean up the entry
            if (!entry.endsWith("}")) {
                entry += "}";
            }

            // Extract service ID
            int idStart = entry.indexOf("\"") + 1;
            int idEnd = entry.indexOf("\"", idStart);
            String serviceId = entry.substring(idStart, idEnd);

            // Extract service name
            int nameStart = entry.indexOf("\"name\":\"") + 8;
            int nameEnd = entry.indexOf("\"", nameStart);
            String serviceName = entry.substring(nameStart, nameEnd);

            services.put(serviceId, serviceName);
        }

        System.out.println("Available services:");
        for (Map.Entry<String, String> entry : services.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }
    }

    private void requestService() throws IOException {
        try {
            // Select a service (in a real client, this would be user input)
            String selectedServiceId = selectService();
            if (selectedServiceId == null) {
                System.err.println("No service selected");
                return;
            }

            // Prepare request (serviceId,clientIp)
            String request = selectedServiceId + "," + InetAddress.getLocalHost().getHostAddress();
            System.out.println("Requesting service: " + selectedServiceId);

            // Encrypt the request
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, iv);
            byte[] encryptedRequest = cipher.doFinal(request.getBytes(StandardCharsets.UTF_8));

            // Calculate HMAC
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(integrityKey);
            byte[] requestHmac = hmac.doFinal(encryptedRequest);

            // Send encrypted request and HMAC
            out.writeInt(encryptedRequest.length);
            out.write(encryptedRequest);
            out.writeInt(requestHmac.length);
            out.write(requestHmac);

            System.out.println("Sent encrypted request (" + encryptedRequest.length + " bytes)");

            // Receive encrypted response
            int encryptedResponseLength = in.readInt();
            byte[] encryptedResponse = new byte[encryptedResponseLength];
            in.readFully(encryptedResponse);

            // Receive HMAC
            int responseHmacLength = in.readInt();
            byte[] receivedResponseHmac = new byte[responseHmacLength];
            in.readFully(receivedResponseHmac);

            System.out.println("Received encrypted response (" + encryptedResponseLength + " bytes)");

            // Verify HMAC
            hmac.reset();
            byte[] calculatedResponseHmac = hmac.doFinal(encryptedResponse);

            if (!Arrays.equals(receivedResponseHmac, calculatedResponseHmac)) {
                System.err.println("Response HMAC verification failed");
                out.writeUTF("ERROR");
                return;
            }

            // Decrypt the response
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, iv);
            byte[] decryptedResponse = cipher.doFinal(encryptedResponse);

            String response = new String(decryptedResponse, StandardCharsets.UTF_8);
            System.out.println("Decrypted response: " + response);

            // Parse the response (format: "serviceIp,servicePort")
            String[] parts = response.split(",");
            String serviceIp = parts[0];
            int servicePort = Integer.parseInt(parts[1]);

            System.out.println("Service available at " + serviceIp + ":" + servicePort);

            // Send confirmation
            out.writeUTF("OK");

        } catch (Exception e) {
            System.err.println("Error requesting service: " + e.getMessage());
            e.printStackTrace();
            out.writeUTF("ERROR");
        }
    }

    private String selectService() {
        if (services.isEmpty()) {
            return null;
        }

        // Mostrar servicios disponibles
        System.out.println("\nServicios disponibles:");
        for (Map.Entry<String, String> entry : services.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }

        // Para esta implementación, seleccionamos automáticamente el primer servicio
        // En una implementación real, se podría solicitar entrada del usuario
        String selectedId = services.keySet().iterator().next();
        System.out.println("Seleccionado automáticamente el servicio: " + selectedId + " - " + services.get(selectedId));

        return selectedId;

        /* Implementación alternativa con selección manual:
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Ingrese el ID del servicio que desea solicitar: ");
            String selectedId = reader.readLine().trim();

            if (services.containsKey(selectedId)) {
                return selectedId;
            } else {
                System.out.println("ID de servicio inválido. Seleccionando el primero disponible.");
                return services.keySet().iterator().next();
            }
        } catch (IOException e) {
            System.err.println("Error leyendo entrada: " + e.getMessage());
            return services.keySet().iterator().next();
        }
        */
    }

    public void disconnect() {
        try {
            if (in != null) in.close();
            if (out != null) out.close();
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
            System.out.println("Disconnected from server");
        } catch (IOException e) {
            System.err.println("Error disconnecting: " + e.getMessage());
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }

    public static void main(String[] args) {
        String serverIp = "127.0.0.1";
        int serverPort = 8080;

        if (args.length >= 1) {
            serverIp = args[0];
        }

        if (args.length >= 2) {
            try {
                serverPort = Integer.parseInt(args[1]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port number. Using default port 8080.");
            }
        }

        Client client = new Client(serverIp, serverPort);

        try {
            client.connect();
        } catch (IOException e) {
            System.err.println("Connection failed: " + e.getMessage());
        } finally {
            client.disconnect();
        }
    }
}