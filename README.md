# Secure client-server protocol

Course project for Infraestructura Computacional (Universidad de los Andes). A Java server answers queries about a table of services over a channel protected with standard cryptography, and a test client measures how much each step costs.

## How the protocol works

1. **Server authentication.** The client sends a challenge and the server signs it with its RSA private key. The client checks the signature with the server's public key.
2. **Key exchange.** The server sends Diffie-Hellman parameters (2048-bit prime) signed with RSA. Both sides compute a shared secret.
3. **Key derivation.** The shared secret goes through SHA-512 and is split into two keys: one for AES encryption and one for HMAC-SHA256.
4. **Encrypted session.** The server sends the service table encrypted with AES-CBC and tagged with an HMAC. The client picks a service, and the server rejects any request whose HMAC doesn't match.

Each client is handled in its own thread. The server logs how long each stage takes (authentication, key exchange, encryption and verification).

## Files

- `src/Server.java`: loads or generates the RSA keys and accepts connections.
- `src/ClientHandler.java`: runs the protocol for one client.
- `src/Client.java`: client side of the protocol.
- `src/TestClient.java`: load tests, 32 sequential requests, then 4, 16, 32 and 64 concurrent clients.

## Running it

```bash
cd src
javac *.java
java Server 8080            # terminal 1
java TestClient 127.0.0.1 8080   # terminal 2
```

The first time the server starts it generates `server_public.key` and `server_private.key`.
