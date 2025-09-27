import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;

// DO NOT EDIT starts
interface StubResolverInterface {
    public void setNameServer(InetAddress ipAddress, int port) throws Exception;
    public InetAddress recursiveResolveAddress(String domainName) throws Exception;
    public String recursiveResolveText(String domainName) throws Exception;
    public String recursiveResolveName(String domainName, int type) throws Exception;
}
// DO NOT EDIT ends

public class StubResolver implements StubResolverInterface {
    private InetAddress nameServerIPAddress;
    private int nameServerPort;

    /**
     *  This method must be called first.
     *
     * @param ipAddress     Assume that it is working, along with the port, so that it leads to a
     *                      working domain name server that supports recursive queries
     * @param port          Assume that it is working, along with the IP ADDRESS, so that it leads to a
     *                      working domain name server that supports recursive queries
     */
    public void setNameServer(InetAddress ipAddress, int port) throws Exception {
        this.nameServerIPAddress = ipAddress;
        this.nameServerPort = port;
    }

    /**
     * Performs a recursive resolution for domainName's A resource
     * record using the name server given by setNameServer.
     *
     * @param domainName    Assume that it is a valid domain name
     */
    public InetAddress recursiveResolveAddress(String domainName) throws Exception {
        byte[] addressQuery = DNSQueryBuilder.buildDNSQuery(domainName, DNSQueryBuilder.TYPE_A, HelperClass.generateTransactionID());
        byte[] addressResponse = sendStubResolverQuery(addressQuery);
        List<DNSResponseReader.DnsRecord> records = DNSResponseReader.parseResponse(addressResponse);

        for (DNSResponseReader.DnsRecord r: records) {
            // If the domainName has A records, it returns the IP address from one of them.
            if (r.type == DNSQueryBuilder.TYPE_A) {
                return r.getAddress();
            }
        }

        // If there is no record then it returns null
        return null;
    }

    /**
     * Performs a recursive resolution for domainName's TXT resource
     * record using the name server given by setNameServer.
     *
     * @param domainName    Assume that domain name is a valid domain name
     * */
    public String recursiveResolveText(String domainName) throws Exception {
        byte[] textQuery = DNSQueryBuilder.buildDNSQuery(domainName, DNSQueryBuilder.TYPE_TXT, HelperClass.generateTransactionID());
        byte[] textResponse = sendStubResolverQuery(textQuery);
        List<DNSResponseReader.DnsRecord> records = DNSResponseReader.parseResponse(textResponse);

        for (DNSResponseReader.DnsRecord r: records) {
            // If the domainName has TXT records, it returns the string contained one of the records
            if (r.type == DNSQueryBuilder.TYPE_TXT) {
                String text = r.getText();

                return text;
            }
        }

        // If there is no record then it returns null.
        return null;
    }


    /**
     * Performs a recursive resolution for domainName's resource
     * record using the name server given by setNameServer
     *
     * @param domainName    Assume that domainName is a valid domain name
     * @param type          Assume that the type is one of NS, MX or CNAME
     */
    public String recursiveResolveName(String domainName, int type) throws Exception {
        byte[] nameQuery = DNSQueryBuilder.buildDNSQuery(domainName, type, HelperClass.generateTransactionID());
        byte[] nameResponse = sendStubResolverQuery(nameQuery);
        List<DNSResponseReader.DnsRecord> records = DNSResponseReader.parseResponse(nameResponse);

        for (DNSResponseReader.DnsRecord r: records) {
            //If the domainName has appropriate records, it returns the
            // domain name contained in one of the records
            if(r.type == type){
                return r.getDomainName();
            }
        }

        // If there is no record then it returns null.
        return null;
    }

    /**
     * Sends a DNS query to the name server using UDP first, and
     * automatically retries over TCP if the UDP response is truncated
     *
     * Referred to RFC 1035, Section 4.2.2
     * If the Truncated bit is set in the UDP response header,
     * the query must be resent over TCP to obtain the complete
     * answer
     *
     * @param query     The raw DNS query packet that we have to send
     * @return          The full DNS response as a byte array
     */
    private byte[] sendStubResolverQuery(byte[] query) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000); // 5 seconds

            DatagramPacket request = new DatagramPacket(query, query.length, nameServerIPAddress, nameServerPort);
            socket.send(request);

            byte[] buffer = new byte[512];
            DatagramPacket reply = new DatagramPacket(buffer, buffer.length);
            socket.receive(reply);

            byte[] udpResponse = Arrays.copyOfRange(reply.getData(), 0, reply.getLength());

            // Check the TC (truncated) flag in the DNS response
            if (DNSResponseReader.isTruncated(udpResponse)) {
                // Retry over TCP
                try (Socket tcpSocket = new Socket(nameServerIPAddress, nameServerPort)) {
                    OutputStream out = tcpSocket.getOutputStream();
                    InputStream in = tcpSocket.getInputStream();

                    // TCP DNS requests start with 2-byte length prefix
                    byte[] lengthPrefix = new byte[2];
                    lengthPrefix[0] = (byte) ((query.length >> 8) & 0xFF);
                    lengthPrefix[1] = (byte) (query.length & 0xFF);
                    out.write(lengthPrefix);
                    out.write(query);
                    out.flush();

                    // Read 2-byte length prefix
                    in.read(lengthPrefix);
                    int tcpLength = ((lengthPrefix[0] & 0xFF) << 8) | (lengthPrefix[1] & 0xFF);

                    byte[] tcpResponse = new byte[tcpLength];
                    int read = 0;
                    while (read < tcpLength) {
                        int n = in.read(tcpResponse, read, tcpLength - read);
                        if (n < 0) throw new Exception("TCP stream ended prematurely");
                        read += n;
                    }

                    return tcpResponse;
                }
            } else {
                return udpResponse;
            }
        } catch (Exception e) {
            throw new Exception("Error: Failed to Send/Receive any DNS packet: " + e.getMessage());
        }
    }
}