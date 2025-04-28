import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Server {
    private int port;
    private ServerSocket serverSocket;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private Map<String, ServiceInfo> services;
    private boolean running;
    private List<ClientHandler> clients;

    public Server(int port) {
        this.port = port;
        this.services = new ConcurrentHashMap<>();
        this.clients = new ArrayList<>();
        loadKeys();
        initializeServices();
    }

    private void loadKeys() {
        try {
            File publicKeyFile = new File("server_public.key");
            File privateKeyFile = new File("server_private.key");

            if (publicKeyFile.exists() && privateKeyFile.exists()) {
                // Cargar llaves desde archivos existentes
                System.out.println("Cargando llaves RSA desde archivos...");

                // Leer llave pública
                byte[] publicKeyBytes = new byte[(int) publicKeyFile.length()];
                try (FileInputStream fis = new FileInputStream(publicKeyFile)) {
                    fis.read(publicKeyBytes);
                }
                X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes);

                // Leer llave privada
                byte[] privateKeyBytes = new byte[(int) privateKeyFile.length()];
                try (FileInputStream fis = new FileInputStream(privateKeyFile)) {
                    fis.read(privateKeyBytes);
                }
                PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);

                // Generar objetos de llave
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                this.publicKey = keyFactory.generatePublic(publicSpec);
                this.privateKey = keyFactory.generatePrivate(privateSpec);

                System.out.println("Llaves RSA cargadas exitosamente desde archivos");
            } else {
                // Generar nuevas llaves si los archivos no existen
                System.out.println("Archivos de llaves no encontrados. Generando nuevas llaves RSA...");

                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair keyPair = keyGen.generateKeyPair();

                this.publicKey = keyPair.getPublic();
                this.privateKey = keyPair.getPrivate();

                System.out.println("Nuevas llaves RSA generadas");

                // Guardar llaves en archivos para uso futuro
                saveKeyToFile("server_public.key", publicKey.getEncoded());
                saveKeyToFile("server_private.key", privateKey.getEncoded());
            }
        } catch (Exception e) {
            System.err.println("Error cargando llaves: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void saveKeyToFile(String filename, byte[] key) {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(key);
            System.out.println("Saved key to " + filename);
        } catch (IOException e) {
            System.err.println("Error saving key to file: " + e.getMessage());
        }
    }

    private void initializeServices() {
        // Initialize service table
        services.put("1", new ServiceInfo("Authentication Service", "192.168.1.10", 8081));
        services.put("2", new ServiceInfo("Database Service", "192.168.1.11", 8082));
        services.put("3", new ServiceInfo("File Service", "192.168.1.12", 8083));

        System.out.println("Services initialized:");
        for (Map.Entry<String, ServiceInfo> entry : services.entrySet()) {
            System.out.println("ID: " + entry.getKey() + ", " + entry.getValue());
        }
    }

    public void start() {
        try {
            serverSocket = new ServerSocket(port);
            running = true;
            System.out.println("Server started on port " + port);
            System.out.println("Waiting for client connections...");

            while (running) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("New client connected: " + clientSocket.getInetAddress().getHostAddress());

                ClientHandler clientHandler = new ClientHandler(clientSocket, this);
                clients.add(clientHandler);
                new Thread(clientHandler).start();
            }
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            stop();
        }
    }

    public void stop() {
        running = false;
        for (ClientHandler client : clients) {
            client.close();
        }

        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
            System.out.println("Server stopped");
        } catch (IOException e) {
            System.err.println("Error stopping server: " + e.getMessage());
        }
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public Map<String, ServiceInfo> getServices() {
        return services;
    }

    public static void main(String[] args) {
        int port = 8080;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port number. Using default port 8080.");
            }
        }

        Server server = new Server(port);
        server.start();
    }

    // Inner class to represent service information
    public static class ServiceInfo {
        private String name;
        private String ip;
        private int port;

        public ServiceInfo(String name, String ip, int port) {
            this.name = name;
            this.ip = ip;
            this.port = port;
        }

        public String getName() {
            return name;
        }

        public String getIp() {
            return ip;
        }

        public int getPort() {
            return port;
        }

        @Override
        public String toString() {
            return "Name: " + name + ", IP: " + ip + ", Port: " + port;
        }
    }
}