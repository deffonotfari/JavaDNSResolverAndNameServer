import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.Random;

/**
 * HelperClass provides utility methods for DNS message handling and UDP queries.
 */
public class HelperClass {
    /**
     * Generates a random 16-bit transaction ID for DNS queries.
     *
     * @return an integer between 0 and 65535 representing the transaction ID
     */
    public static int generateTransactionID() {
        return new Random().nextInt(65536);
    }

    /**
     * Reads a 16-bit unsigned short from a byte array at the given offset.
     *
     * @param data   the byte array containing the data
     * @param offset the starting position to read from
     * @return the unsigned short as an int
     */
    public static int readShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    /**
     * Sends a DNS query via UDP and waits for a response.
     *
     * @param server the target DNS server's IP address
     * @param port   the UDP port of the server
     * @param query  the DNS query as a byte array
     * @return the response bytes from the server
     */
    public static byte[] sendQuery(InetAddress server, int port, byte[] query) throws IOException {
        DatagramSocket socket = new DatagramSocket();
        socket.setSoTimeout(3000);

        DatagramPacket request = new DatagramPacket(query, query.length, server, port);
        DatagramPacket response = new DatagramPacket(new byte[1232], 1232);

        socket.send(request);

        try {
            socket.receive(response);
        } catch (SocketTimeoutException e) {
            socket.close();
            throw new IOException("DNS query timed out for " + server);
        }

        socket.close();

        // return only the received portion
        return Arrays.copyOf(response.getData(), response.getLength());
    }

    /**
     * Finds the end index of the question section in a DNS message.
     *
     * @param data the DNS message as a byte array
     * @return the index immediately after the question section (QNAME + QTYPE + QCLASS)
     */
    public static int findAnswerSectionEnd(byte[] data) {
        int index = 12;
        while (data[index] != 0) {
            if ((data[index] & 0xC0) == 0xC0) {
                index += 2;
                break;
            }
            index += (data[index] & 0xFF) + 1;
        }
        return index + 5; // null byte + QTYPE + QCLASS
    }
}