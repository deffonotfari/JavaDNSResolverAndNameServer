import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Utility class to parse DNS response packets received via UDP.
 * Extracts records from the Answer section based on query type.
 */
public class DNSResponseReader {

    /**
     * Represents a resource record parsed from the DNS response.
     *
     * To build this, I referenced to RFC 1035 Section 3.2.1, which provided the formatting
     * of how a DNS record should look like
     */
    public static class DnsRecord {
        public int type;        // A, NS, CNAME, etc.
        public int clazz;       // Always 1 (IN)
        public int ttl;         // Time-to-live in seconds
        public byte[] rdata;    // Raw resource data
        public int rdlength;    // Length of rdata
        public int rDataOffset;
        public byte[] fullPacket;

        /**
         * Get an IPv4 address if the type is A.
         */
        public InetAddress getAddress() throws UnknownHostException {
            if (type == DNSQueryBuilder.TYPE_A && rdata.length == 4) {
                return InetAddress.getByAddress(rdata);
            }
            return null;
        }

        /**
         * Get a human-readable domain name if the type is NS, MX, or CNAME.
         */
        public String getDomainName() throws Exception {
            if (type == DNSQueryBuilder.TYPE_NS ||
                    type == DNSQueryBuilder.TYPE_CNAME) {
                return DNSResponseReader.readDomainName(fullPacket, rDataOffset);
            } else if (type == DNSQueryBuilder.TYPE_MX) {
                return DNSResponseReader.readDomainName(fullPacket, rDataOffset + 2);
            }
            return null;
        }

        /**
         * Get the string from a TXT record.
         */
        public String getText() {
            if (type == DNSQueryBuilder.TYPE_TXT && rdata.length > 1) {
                StringBuilder result = new StringBuilder();
                int i = 0;

                while (i < rdata.length) {
                    int len = rdata[i] & 0xFF;

                    if (i + len > rdata.length) {
                        break;
                    }

                    result.append(new String(Arrays.copyOfRange(rdata, i + 1, i + len + 1)));
                    i += len + 1;
                }

                return result.toString();
            }
            return null;
        }
    }

    /**
     * Parses the DNS response packet and extracts all answer records.
     *
     * @param data Raw DNS response byte array (from DatagramPacket)
     * @return List of DnsRecord objects
     */
    public static List<DnsRecord> parseResponse(byte[] data) throws Exception {
        int answerCount = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);
        List<DnsRecord> records = new ArrayList<>();

        // Skip header (12 bytes) - RFC 1035 Section 4.1.1
        int index = 12;

        //Reference to RFC 1035 Section 4.1.2
        // Skip QNAME (label-based domain name)
        while (data[index] != 0) {
            if ((data[index] & 0xC0) == 0xC0) {
                index += 2; // compression pointer
                break;
            }
            index += (data[index] & 0xFF) + 1;
        }
        index += 5; // null byte + QTYPE (2 bytes) + QCLASS (2 bytes)

        //Reference to RFC 1035 Section 4.1.3
        // --- Parse Answer Section ---
        for (int i = 0; i < answerCount; i++) {
            // Skip NAME (can be compression pointer)
            index = skipDomainName(data, index);

            // TYPE
            int type = ((data[index++] & 0xFF) << 8) | (data[index++] & 0xFF);

            // CLASS
            int clazz = ((data[index++] & 0xFF) << 8) | (data[index++] & 0xFF);

            // TTL
            int ttl = ((data[index++] & 0xFF) << 24)
                    | ((data[index++] & 0xFF) << 16)
                    | ((data[index++] & 0xFF) << 8)
                    | (data[index++] & 0xFF); //32 bits TTL

            // RDLENGTH
            int rdlength = ((data[index++] & 0xFF) << 8) | (data[index++] & 0xFF);

            // RDATA offset
            int rDataOffset = index;

            byte[] rdata = Arrays.copyOfRange(data, index, index + rdlength);

            DnsRecord record = new DnsRecord();
            record.type = type;
            record.clazz = clazz;
            record.ttl = ttl;
            record.rdlength = rdlength;
            record.rdata = rdata;
            record.rDataOffset = rDataOffset;
            record.fullPacket = data;

            records.add(record);
            index += rdlength;
        }

        return records;
    }

    /**
     * Skip a compressed or uncompressed domain name in the packet.
     * This is used to move the pointer forward past NAME fields.
     *
     * Referenced to RFC 1035 Section 4.1.4
     *
     * @param data  Full DNS packet
     * @param index Current position
     * @return New index just after the domain name
     */
    public static int skipDomainName(byte[] data, int index) {
        while (data[index] != 0) {
            if ((data[index] & 0xC0) == 0xC0) {
                return index + 2; // compression pointer (2 bytes)
            }
            index += (data[index] & 0xFF) + 1;
        }
        return index + 1; // null byte terminator
    }

    /**
     * Decode a domain name from a DNS packet, handling compression.
     *
     * Referenced to 1035 Section 4.1.4
     *
     * @param data  Full DNS packet
     * @param index Offset to start decoding
     * @return The full domain name (e.g., "example.com.")
     */
    public static String readDomainName(byte[] data, int index) throws Exception {
        StringBuilder name = new StringBuilder();
        int originalIndex = index;
        boolean jumped = false;

        while (true) {
            int len = data[index] & 0xFF;

            // Compression pointer (two-byte jump)
            if ((len & 0xC0) == 0xC0) {
                if (!jumped) originalIndex = index + 2;
                int pointer = ((len & 0x3F) << 8) | (data[index + 1] & 0xFF);
                index = pointer;
                jumped = true;
                continue;
            }

            if (len == 0) break;

            index++;
            for (int i = 0; i < len; i++) {
                name.append((char) data[index++]);
            }
            name.append('.');
        }

        return name.toString();
    }

    /**
     * Checks whether the DNS response message has been truncated.
     *
     * Referred to RFC 1035 Section 4.1.1 to complete this
     *
     * @param udpResponse       the full byte array of the DNS response
     * @return  whether the truncated bit is set or not
     */
    public static boolean isTruncated(byte[] udpResponse) {
        if (udpResponse == null || udpResponse.length < 3) {
            return false;
        }

        //Using Byte 2 because it is the first bute of the flags (QR, Opcode, AA, TC, RD)
        return (udpResponse[2] & 0x02) != 0;
    }
}