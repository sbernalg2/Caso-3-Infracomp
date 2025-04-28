import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private Server server;
    private DataInputStream in;
    private DataOutputStream out;
    private boolean running;

    // DH parameters
    private BigInteger p; // Large prime
    private BigInteger g; // Generator
    private BigInteger privateX; // Server's private key
    private BigInteger publicX; // Server's public key (g^x mod p)
    private BigInteger publicY; // Client's public key (g^y mod p)
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

    public ClientHandler(Socket clientSocket, Server server) {
        this.clientSocket = clientSocket;
        this.server = server;
        this.running = true;

        try {
            this.in = new DataInputStream(clientSocket.getInputStream());
            this.out = new DataOutputStream(clientSocket.getOutputStream());
        } catch (IOException e) {
            System.err.println("Error creating streams: " + e.getMessage());
            close();
        }
    }

    @Override
    public void run() {
        try {
            startTime = System.currentTimeMillis();

            // Step 1: HELLO + Challenge Authentication
            if (!handleHelloAndAuthentication()) {
                System.err.println("Authentication failed");
                return;
            }
            authTime = System.currentTimeMillis();

            // Step 2: DH Parameter Exchange
            if (!handleDHExchange()) {
                System.err.println("DH exchange failed");
                return;
            }
            dhTime = System.currentTimeMillis();

            // Step 3: Session Key Calculation
            calculateSessionKeys();

            // Step 4: IV Generation
            generateAndSendIV();

            // Step 5: Send encrypted service table
            sendEncryptedServiceTable();

            // Step 6: Handle service request
            handleServiceRequest();

            encryptTime = System.currentTimeMillis();

            // Print performance metrics
            System.out.println("\nPerformance Metrics:");
            System.out.println("Authentication time: " + (authTime - startTime) + "ms");
            System.out.println("DH exchange time: " + (dhTime - authTime) + "ms");
            System.out.println("Encryption operations time: " + (encryptTime - dhTime) + "ms");
            System.out.println("Total time: " + (encryptTime - startTime) + "ms");

        } catch (IOException e) {
            System.err.println("Error handling client: " + e.getMessage());
        } finally {
            close();
        }
    }

    private boolean handleHelloAndAuthentication() throws IOException {
        // Esperar mensaje HELLO
        String hello = in.readUTF();
        System.out.println("Recibido: " + hello);

        if (!hello.equals("HELLO")) {
            System.err.println("Se esperaba HELLO, se recibió: " + hello);
            close(); // Cerrar conexión inmediatamente
            return false;
        }

        // Recibir reto del cliente
        byte[] challenge = new byte[32];
        in.readFully(challenge);
        System.out.println("Reto recibido: " + bytesToHex(challenge));

        // Firmar el reto con la llave privada del servidor
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(server.getPrivateKey());
            signature.update(challenge);
            byte[] signedChallenge = signature.sign();

            // Enviar reto firmado al cliente
            out.writeInt(signedChallenge.length);
            out.write(signedChallenge);
            System.out.println("Reto firmado enviado: " + bytesToHex(signedChallenge).substring(0, 32) + "...");

            // Esperar respuesta del cliente
            String response = in.readUTF();
            System.out.println("Respuesta del cliente: " + response);

            if (!response.equals("OK")) {
                close(); // Cerrar conexión inmediatamente
            }

            return response.equals("OK");

        } catch (Exception e) {
            System.err.println("Error firmando reto: " + e.getMessage());
            close(); // Cerrar conexión inmediatamente
            return false;
        }
    }

    private boolean handleDHExchange() throws IOException {
        try {
            // Generar parámetros DH
            SecureRandom random = new SecureRandom();

            // Usar un primo estándar de 2048 bits para DH
            String hexP = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
                    + "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
                    + "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                    + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
                    + "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
                    + "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                    + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE";

            p = new BigInteger(hexP, 16);
            g = BigInteger.valueOf(2); // Generador común

            // Generar llave privada x del servidor
            privateX = new BigInteger(1024, random);

            // Calcular llave pública del servidor g^x mod p
            publicX = g.modPow(privateX, p);

            // Preparar parámetros DH para enviar
            String dhParams = g.toString() + "," + p.toString() + "," + publicX.toString();

            // Firmar los parámetros DH
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(server.getPrivateKey());
            signature.update(dhParams.getBytes(StandardCharsets.UTF_8));
            byte[] signedParams = signature.sign();

            // Enviar parámetros DH y firma
            out.writeUTF(dhParams);
            out.writeInt(signedParams.length);
            out.write(signedParams);

            System.out.println("Parámetros DH enviados:");
            System.out.println("g: " + g);
            System.out.println("p: " + p.toString().substring(0, 32) + "...");
            System.out.println("g^x: " + publicX.toString().substring(0, 32) + "...");

            // Esperar respuesta del cliente
            String response = in.readUTF();
            if (!response.equals("OK")) {
                System.err.println("Cliente rechazó parámetros DH: " + response);
                close(); // Cerrar conexión inmediatamente
                return false;
            }

            // Recibir llave pública g^y del cliente
            String clientPublicKey = in.readUTF();
            publicY = new BigInteger(clientPublicKey);
            System.out.println("Llave pública g^y del cliente recibida: " + publicY.toString().substring(0, 32) + "...");

            return true;

        } catch (Exception e) {
            System.err.println("Error en intercambio DH: " + e.getMessage());
            e.printStackTrace();
            close(); // Cerrar conexión inmediatamente
            return false;
        }
    }

    private void calculateSessionKeys() {
        try {
            // Calcular llave secreta compartida (g^y)^x mod p
            sharedKey = publicY.modPow(privateX, p);
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

    private void generateAndSendIV() throws IOException {
        try {
            // Generate random IV for AES
            SecureRandom random = new SecureRandom();
            byte[] ivBytes = new byte[16];
            random.nextBytes(ivBytes);
            iv = new IvParameterSpec(ivBytes);

            // Send IV to client
            out.writeInt(ivBytes.length);
            out.write(ivBytes);

            System.out.println("Generated and sent IV: " + bytesToHex(ivBytes));

        } catch (Exception e) {
            System.err.println("Error generating IV: " + e.getMessage());
            throw new IOException("IV generation failed", e);
        }
    }

    private void sendEncryptedServiceTable() throws IOException {
        try {
            // Convert service table to JSON-like string
            StringBuilder serviceTable = new StringBuilder("{");
            for (Map.Entry<String, Server.ServiceInfo> entry : server.getServices().entrySet()) {
                Server.ServiceInfo info = entry.getValue();
                serviceTable.append("\"").append(entry.getKey()).append("\":{")
                        .append("\"name\":\"").append(info.getName()).append("\",")
                        .append("\"ip\":\"").append(info.getIp()).append("\",")
                        .append("\"port\":").append(info.getPort())
                        .append("},");
            }
            if (serviceTable.charAt(serviceTable.length() - 1) == ',') {
                serviceTable.deleteCharAt(serviceTable.length() - 1);
            }
            serviceTable.append("}");

            String tableStr = serviceTable.toString();
            System.out.println("Service table to encrypt: " + tableStr);

            // Encrypt the service table
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, iv);
            byte[] encryptedTable = cipher.doFinal(tableStr.getBytes(StandardCharsets.UTF_8));

            // Calculate HMAC
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(integrityKey);
            byte[] tableHmac = hmac.doFinal(encryptedTable);

            // Send encrypted table and HMAC
            out.writeInt(encryptedTable.length);
            out.write(encryptedTable);
            out.writeInt(tableHmac.length);
            out.write(tableHmac);

            System.out.println("Sent encrypted service table (" + encryptedTable.length + " bytes)");
            System.out.println("Sent HMAC: " + bytesToHex(tableHmac).substring(0, 32) + "...");

        } catch (Exception e) {
            System.err.println("Error encrypting service table: " + e.getMessage());
            e.printStackTrace();
            throw new IOException("Service table encryption failed", e);
        }
    }

    private void handleServiceRequest() throws IOException {
        try {
            // Recibir solicitud cifrada de servicio
            int encryptedRequestLength = in.readInt();
            byte[] encryptedRequest = new byte[encryptedRequestLength];
            in.readFully(encryptedRequest);

            // Recibir HMAC
            int hmacLength = in.readInt();
            byte[] receivedHmac = new byte[hmacLength];
            in.readFully(receivedHmac);

            System.out.println("Solicitud cifrada recibida (" + encryptedRequestLength + " bytes)");
            System.out.println("HMAC recibido: " + bytesToHex(receivedHmac).substring(0, 32) + "...");

            // Verificar HMAC
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(integrityKey);
            byte[] calculatedHmac = hmac.doFinal(encryptedRequest);

            if (!Arrays.equals(receivedHmac, calculatedHmac)) {
                System.err.println("Verificación de HMAC fallida");
                out.writeUTF("ERROR");
                close(); // Cerrar conexión inmediatamente
                return;
            }

            // Descifrar la solicitud
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, iv);
            byte[] decryptedRequest = cipher.doFinal(encryptedRequest);

            String request = new String(decryptedRequest, StandardCharsets.UTF_8);
            System.out.println("Solicitud descifrada: " + request);

            // Analizar la solicitud (formato: "serviceId,clientIp")
            String[] parts = request.split(",");
            String serviceId = parts[0];
            String clientIp = parts[1];

            // Buscar el servicio
            Server.ServiceInfo serviceInfo = server.getServices().get(serviceId);
            if (serviceInfo == null) {
                System.err.println("Servicio no encontrado: " + serviceId);
                out.writeUTF("ERROR");
                close(); // Cerrar conexión inmediatamente
                return;
            }

            // Preparar respuesta con información del servicio
            String response = serviceInfo.getIp() + "," + serviceInfo.getPort();
            System.out.println("Servicio encontrado: " + serviceInfo);

            // Cifrar la respuesta
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, iv);
            byte[] encryptedResponse = cipher.doFinal(response.getBytes(StandardCharsets.UTF_8));

            // Calcular HMAC para la respuesta
            hmac.reset();
            byte[] responseHmac = hmac.doFinal(encryptedResponse);

            // Enviar respuesta cifrada y HMAC
            out.writeInt(encryptedResponse.length);
            out.write(encryptedResponse);
            out.writeInt(responseHmac.length);
            out.write(responseHmac);

            System.out.println("Respuesta cifrada enviada (" + encryptedResponse.length + " bytes)");

            // Esperar confirmación final
            String confirmation = in.readUTF();
            System.out.println("Confirmación recibida: " + confirmation);

            if (!confirmation.equals("OK")) {
                close(); // Cerrar conexión inmediatamente
            }

        } catch (Exception e) {
            System.err.println("Error manejando solicitud de servicio: " + e.getMessage());
            e.printStackTrace();
            out.writeUTF("ERROR");
            close(); // Cerrar conexión inmediatamente
        }
    }

    public void close() {
        running = false;
        try {
            if (in != null) in.close();
            if (out != null) out.close();
            if (clientSocket != null && !clientSocket.isClosed()) {
                clientSocket.close();
            }
        } catch (IOException e) {
            System.err.println("Error closing client handler: " + e.getMessage());
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
}