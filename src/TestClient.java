import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

public class TestClient {
    private String serverIp;
    private int serverPort;

    public TestClient(String serverIp, int serverPort) {
        this.serverIp = serverIp;
        this.serverPort = serverPort;
    }

    public void runIterativeTest(int iterations) {
        System.out.println("\n=== Running Iterative Test with " + iterations + " iterations ===");

        long totalTime = 0;
        long minTime = Long.MAX_VALUE;
        long maxTime = 0;

        for (int i = 0; i < iterations; i++) {
            System.out.println("\nIteration " + (i + 1) + "/" + iterations);

            long startTime = System.currentTimeMillis();

            Client client = new Client(serverIp, serverPort);
            try {
                client.connect();
            } catch (IOException e) {
                System.err.println("Connection failed: " + e.getMessage());
            } finally {
                client.disconnect();
            }

            long endTime = System.currentTimeMillis();
            long iterationTime = endTime - startTime;

            totalTime += iterationTime;
            minTime = Math.min(minTime, iterationTime);
            maxTime = Math.max(maxTime, iterationTime);

            System.out.println("Iteration time: " + iterationTime + "ms");
        }

        double avgTime = (double) totalTime / iterations;

        System.out.println("\n=== Iterative Test Results ===");
        System.out.println("Total time: " + totalTime + "ms");
        System.out.println("Average time per iteration: " + avgTime + "ms");
        System.out.println("Min time: " + minTime + "ms");
        System.out.println("Max time: " + maxTime + "ms");
    }

    public void runConcurrentTest(int numClients) {
        System.out.println("\n=== Running Concurrent Test with " + numClients + " clients ===");

        ExecutorService executor = Executors.newFixedThreadPool(numClients);
        CountDownLatch latch = new CountDownLatch(numClients);
        AtomicLong totalTime = new AtomicLong(0);
        List<Long> clientTimes = new ArrayList<>();

        long startTime = System.currentTimeMillis();

        for (int i = 0; i < numClients; i++) {
            final int clientId = i + 1;
            executor.submit(() -> {
                try {
                    System.out.println("Client " + clientId + " starting");
                    long clientStartTime = System.currentTimeMillis();

                    Client client = new Client(serverIp, serverPort);
                    try {
                        client.connect();
                    } catch (IOException e) {
                        System.err.println("Client " + clientId + " connection failed: " + e.getMessage());
                    } finally {
                        client.disconnect();
                    }

                    long clientEndTime = System.currentTimeMillis();
                    long clientTime = clientEndTime - clientStartTime;

                    synchronized (clientTimes) {
                        clientTimes.add(clientTime);
                    }

                    totalTime.addAndGet(clientTime);
                    System.out.println("Client " + clientId + " finished in " + clientTime + "ms");
                } finally {
                    latch.countDown();
                }
            });
        }

        try {
            latch.await();
        } catch (InterruptedException e) {
            System.err.println("Test interrupted: " + e.getMessage());
        }

        long endTime = System.currentTimeMillis();
        long totalTestTime = endTime - startTime;

        executor.shutdown();

        // Calculate statistics
        double avgClientTime = (double) totalTime.get() / numClients;

        long minTime = Long.MAX_VALUE;
        long maxTime = 0;

        for (long time : clientTimes) {
            minTime = Math.min(minTime, time);
            maxTime = Math.max(maxTime, time);
        }

        System.out.println("\n=== Concurrent Test Results ===");
        System.out.println("Total wall clock time: " + totalTestTime + "ms");
        System.out.println("Average client time: " + avgClientTime + "ms");
        System.out.println("Min client time: " + minTime + "ms");
        System.out.println("Max client time: " + maxTime + "ms");
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

        TestClient testClient = new TestClient(serverIp, serverPort);

        // Run iterative test with 32 iterations
        testClient.runIterativeTest(32);

        // Run concurrent tests with different numbers of clients
        testClient.runConcurrentTest(4);
        testClient.runConcurrentTest(16);
        testClient.runConcurrentTest(32);
        testClient.runConcurrentTest(64);
    }
}
