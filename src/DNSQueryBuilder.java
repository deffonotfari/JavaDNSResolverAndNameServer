import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * We will be constructing questions for A, NS, MX, CNAME, and TXT records
 * We are handling DNS queries according to RFC 1035
 * */
public class DNSQueryBuilder {
    //DNS Resource Records - Referred to RFC 1035 Section 3.2.2
    public static final int TYPE_A = 1; //Meaning: host address
    public static final int TYPE_NS = 2; //Meaning: name server
    public static final int TYPE_CNAME = 5; //Meaning: canonical name for an alias
    public static final int TYPE_MX = 15; //Meaning: mall exchange
    public static final int TYPE_TXT = 16; //Meaning: text strings

    //DNS Class Values - Referred to RFC 1035 Section 3.2.4
    public static final int CLASS_IN = 1; //Meaning: the Internet

    /**
     * Builds a standard DNS query packet as a byte array
     *
     * @param domainName        domain name
     * @param qType             query type
     * @param transactionID     transaction ID - has to be unique and 16-bit
     * @return Byte array representing the DNS query packet
     * */
    public static byte[] buildDNSQuery(String domainName, int qType, int transactionID) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // --- Header (12 bytes) ---
        // Transaction ID
        baos.write(shortToBytes(transactionID));

        // Flags: 0x0100 = Standard Query with recursion desired
        baos.write(new byte[]{0x01, 0x00});

        // QDCount = 1 (number of questions)
        baos.write(shortToBytes(1));

        // ANCOUNT, NSCOUNT, ARCOUNT = 0
        baos.write(shortToBytes(0));
        baos.write(shortToBytes(0));
        baos.write(shortToBytes(0));

        // --- Question Section ---
        baos.write(encodeDomainName(domainName)); // QNAME
        baos.write(shortToBytes(qType));          // QTYPE
        baos.write(shortToBytes(CLASS_IN));       // QCLASS

        return baos.toByteArray();
    }

    /**
     * Encodes a domain name into the DNS QNAME format:
     * e.g., "example.com." becomes [7]example[3]com[0]
     *
     * Referenced to RFC 1035 Section 3.1
     *
     * @param domainName    Domain name to encode (must be fully qualified)
     * @return              Byte array for query name section
     */
    public static byte[] encodeDomainName(String domainName) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        String[] labels = domainName.split("\\.");

        for (String label : labels) {
            if(!label.isEmpty()) {
                baos.write(label.length());
                baos.write(label.getBytes());
            }
        }

        baos.write(0);
        return baos.toByteArray();
    }

    /** Converts 16-bit short value into a 2-byte array
     *
     * Referenced to RFC 1035 Section 2.3.2
     *
     * @param value     the value we will be converting
     * @return          a 2-byte array
     * */
    public static byte[] shortToBytes(int value) {
        return ByteBuffer.allocate(2).putShort((short) value).array();
    }
}