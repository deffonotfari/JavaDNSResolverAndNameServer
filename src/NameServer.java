import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

// DO NOT EDIT starts
interface NameServerInterface {
    public void setNameServer(InetAddress ipAddress, int port) throws Exception;
    public void handleIncomingQueries(int port) throws Exception;
}
// DO NOT EDIT ends

public class NameServer implements NameServerInterface {
    private InetAddress rootServer;
    private int rootPort;
    private Resolver resolver;
    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    /**Inner class for cache entries, storing records and expiry time*/
    private static class CacheEntry{
        public List<DNSResponseReader.DnsRecord> records;
        public long expiryTime;

        /**Checks if cache entry has expired or not*/
        public boolean isExpired(){
            return System.currentTimeMillis() > expiryTime;
        }
    }

    /**
     * This method must be called first.
     *
     * @param ipAddress     assume that the IP address and port number lead to
     *                      a working domain name server which supports iterative
     *                      queries.
     * @param port          assume that the IP address and port number lead to
     *                      a working domain name server which supports iterative
     *                      queries.
     */
    public void setNameServer(InetAddress ipAddress, int port) throws Exception {
        this.rootServer = ipAddress;
        this.rootPort = port;

        resolver = new Resolver();
        resolver.setNameServer(ipAddress, port);
    }

    /**
     * Listens for incoming DNS queries on the given UDP port
     *
     * @param port                 Assume that port is a valid UDP port number.
     * */
    public void handleIncomingQueries(int port) throws Exception {
        // Listens for incoming DNS queries on the given port number
        DatagramSocket socket = new DatagramSocket(port);
        ExecutorService executor = Executors.newFixedThreadPool(10);
        byte[] buffer = new byte[1232];

        while (true) {
            //Receive incoming packet
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            socket.receive(packet);

            //Extract client info
            byte[] requestData = Arrays.copyOf(packet.getData(), packet.getLength());
            InetAddress clientAddress = packet.getAddress();
            int clientPort = packet.getPort();

            System.out.println("[DEBUG] Received DNS query from " + clientAddress.getHostAddress() + ":" + clientPort);

            //Responds to them by using cached values and performing iterative resolution.
            executor.submit(() -> {
                try{
                    byte[] response = handleQuery(requestData);
                    DatagramPacket reply = new DatagramPacket(response, response.length, clientAddress, clientPort);
                    socket.send(reply);

                    System.out.println("[DEBUG] Sent response to " + clientAddress.getHostAddress() + ":" + clientPort);
                } catch(Exception e){
                    System.err.println("Failed to handle query: "+e.getMessage());
                }
            });
        }
    }

    /**
     * Handles single DNS query. It checks cache and performs resolution if needed
     *
     * @param query     query Raw DNS query bytes
     * @return Response packet bytes
     * */
    private byte[] handleQuery(byte[] query) throws Exception {
        int transactionID = 0;
        String domainName = null;
        int qType = 0;

        try {
            // Basic query length validation (minimum header + question)
            if (query.length < 12) {
                return buildErrorResponse(0, 1); // Format error (RCODE=1), txID=0 unknown
            }

            // Extract transaction ID from query header
            transactionID = ((query[0] & 0xFF) << 8) | (query[1] & 0xFF);

            // Extract query type safely
            int index = 12;
            while (index < query.length && query[index] != 0) {
                int len = query[index] & 0xFF;
                index += len + 1;
                if (index >= query.length) {
                    return buildErrorResponse(transactionID, 1); // Format error
                }
            }
            index += 1; // skip the 0 label byte
            if (index + 3 > query.length) {
                return buildErrorResponse(transactionID, 1); // Format error
            }

            qType = ((query[index] & 0xFF) << 8) | (query[index + 1] & 0xFF);

            domainName = extractDomainNameFromQuery(query);
        } catch (Exception e) {
            // Malformed query, return format error
            return buildErrorResponse(transactionID, 1);
        }

        System.out.println("[DEBUG] Handling query for domain: " + domainName + ", type: " + qType + ", txID: " + transactionID);

        // Validate supported qType
        if (qType != DNSQueryBuilder.TYPE_A &&
                qType != DNSQueryBuilder.TYPE_TXT &&
                qType != DNSQueryBuilder.TYPE_NS &&
                qType != DNSQueryBuilder.TYPE_MX &&
                qType != DNSQueryBuilder.TYPE_CNAME) {
            // Not implemented query type
            return buildErrorResponse(transactionID, 4);
        }

        // Prepare cache key based on domain name and query type
        String cacheKey = domainName + ":" + qType;
        List<DNSResponseReader.DnsRecord> answerRecords;

        // Check cache for existing, unexpired result
        CacheEntry entry = cache.get(cacheKey);
        if (entry != null && !entry.isExpired()) {
            System.out.println("[DEBUG] Cache hit for " + cacheKey);
            answerRecords = entry.records;
        } else {
            System.out.println("[DEBUG] Cache miss or expired for " + cacheKey + " — performing resolution");

            answerRecords = resolveUsingResolver(domainName, qType);
            if (answerRecords != null && !answerRecords.isEmpty()) {
                int ttl = answerRecords.get(0).ttl;
                CacheEntry newEntry = new CacheEntry();
                newEntry.records = answerRecords;
                newEntry.expiryTime = System.currentTimeMillis() + (ttl * 1000L);
                cache.put(cacheKey, newEntry);

                System.out.println("[DEBUG] Cached new result for " + cacheKey + " with TTL: " + ttl);
            } else {
                System.out.println("[DEBUG] No answer records found for " + cacheKey);
            }
        }

        // Build normal response packet
        return buildResponsePacket(query, transactionID, domainName, qType, answerRecords);
    }

    /**
     * Builds a standard DNS response packet for the given answers.
     * */
    private byte[] buildResponsePacket(byte[] query, int transactionID, String domainName, int qType,
                                       List<DNSResponseReader.DnsRecord> answers) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        System.out.println("[DEBUG] Building response packet for " + domainName + " with " + answers.size() + " answers");

        // --- DNS Header (RFC 1035 Section 4.1.1) ---
        out.write(DNSQueryBuilder.shortToBytes(transactionID));         // ID
        out.write(new byte[]{(byte) 0x81, (byte) 0x80});                // Flags: standard response, recursion available
        out.write(DNSQueryBuilder.shortToBytes(1));                     // QDCOUNT = 1
        out.write(DNSQueryBuilder.shortToBytes(answers.size()));        // ANCOUNT
        out.write(DNSQueryBuilder.shortToBytes(0));                     // NSCOUNT
        out.write(DNSQueryBuilder.shortToBytes(0));                     // ARCOUNT

        // --- Question Section (copy directly from query) ---
        int questionStart = 12; // immediately after header
        int questionEnd = questionStart;

        // Skip QNAME in query (RFC 1035 §3.1, label encoding & compression)
        while (query[questionEnd] != 0) {
            if ((query[questionEnd] & 0xC0) == 0xC0) { // compression pointer
                questionEnd += 2;
                break;
            }
            questionEnd += (query[questionEnd] & 0xFF) + 1;
        }
        questionEnd += 1 + 2 + 2; // null byte + QTYPE (2 bytes) + QCLASS (2 bytes)

        // Copy question section exactly as sent by client
        out.write(query, questionStart, questionEnd - questionStart);

        // --- Answer Section ---
        for (DNSResponseReader.DnsRecord r : answers) {
            // Write NAME as pointer to question section (offset 12 → 0xC00C)
            out.write(new byte[]{(byte) 0xC0, 0x0C});

            out.write(DNSQueryBuilder.shortToBytes(r.type));               // TYPE
            out.write(DNSQueryBuilder.shortToBytes(DNSQueryBuilder.CLASS_IN)); // CLASS
            out.write(ByteBuffer.allocate(4).putInt(r.ttl).array());       // TTL
            out.write(DNSQueryBuilder.shortToBytes(r.rdata.length));       // RDLENGTH
            out.write(r.rdata);                                            // RDATA
        }

        return out.toByteArray();
    }

    /**
     * Resolves a domain name using the Resolver iteratively.
     */
    private List<DNSResponseReader.DnsRecord> resolveUsingResolver(String domainName, int qType) throws Exception {
        List<DNSResponseReader.DnsRecord> records = new ArrayList<>();

        switch (qType) {
            case DNSQueryBuilder.TYPE_A:
                // Iteratively resolve A record (IPv4 address)
                InetAddress ip = resolver.iterativeResolveAddress(domainName);
                if (ip != null) {
                    byte[] rdata = ip.getAddress();
                    DNSResponseReader.DnsRecord record = new DNSResponseReader.DnsRecord();
                    record.type = DNSQueryBuilder.TYPE_A;
                    record.rdata = rdata;
                    record.ttl = 120;
                    records.add(record);
                }
                break;

            case DNSQueryBuilder.TYPE_TXT:
                // Iteratively resolve TXT record
                String txt = resolver.iterativeResolveText(domainName);
                if (txt != null) {
                    byte[] rdata = txt.getBytes();
                    DNSResponseReader.DnsRecord record = new DNSResponseReader.DnsRecord();
                    record.type = DNSQueryBuilder.TYPE_TXT;
                    record.rdata = new byte[rdata.length + 1];
                    record.rdata[0] = (byte) rdata.length;
                    System.arraycopy(rdata, 0, record.rdata, 1, rdata.length);
                    record.ttl = 120;
                    records.add(record);
                }
                break;

            case DNSQueryBuilder.TYPE_NS:
            case DNSQueryBuilder.TYPE_MX:
            case DNSQueryBuilder.TYPE_CNAME:
                // Iteratively resolve NS, MX, or CNAME record
                String target = resolver.iterativeResolveName(domainName, qType);
                if (target != null) {
                    byte[] encodedName = DNSQueryBuilder.encodeDomainName(target);
                    DNSResponseReader.DnsRecord record = new DNSResponseReader.DnsRecord();
                    record.type = qType;
                    record.rdata = encodedName;
                    record.ttl = 120;
                    records.add(record);
                }
                break;

            default:
                throw new Exception("Unsupported query type: " + qType);
        }

        return records;
    }

    /**
     * Builds a DNS error response with the specified RCODE.
     */
    private byte[] buildErrorResponse(int transactionID, int rcode) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // ID
        out.write(DNSQueryBuilder.shortToBytes(transactionID));

        // Flags: QR=1 (response), Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=rcode
        // 0x8000 sets QR bit, 0x0100 RD bit, 0x0080 RA bit
        int flags = 0x8000 | 0x0100 | 0x0080 | (rcode & 0xF);
        out.write(DNSQueryBuilder.shortToBytes(flags));

        // QDCOUNT = 0 (no questions echoed)
        out.write(DNSQueryBuilder.shortToBytes(0));

        // ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
        out.write(DNSQueryBuilder.shortToBytes(0));
        out.write(DNSQueryBuilder.shortToBytes(0));
        out.write(DNSQueryBuilder.shortToBytes(0));

        return out.toByteArray();
    }

    /**
     * Extracts the domain name from the DNS query question section.
     */
    private String extractDomainNameFromQuery(byte[] query) throws Exception {
        String name = DNSResponseReader.readDomainName(query, 12);
        System.out.println("[DEBUG] Extracted domain from query: " + name);
        return name;
    }
}