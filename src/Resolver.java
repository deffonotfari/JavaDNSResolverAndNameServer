import java.io.IOException;
import java.net.InetAddress;
import java.util.*;

// DO NOT EDIT starts
interface ResolverInterface {
    public void setNameServer(InetAddress ipAddress, int port) throws Exception;
    public InetAddress iterativeResolveAddress(String domainName) throws Exception;
    public String iterativeResolveText(String domainName) throws Exception;
    public String iterativeResolveName(String domainName, int type) throws Exception;
}
// DO NOT EDIT ends

public class Resolver implements ResolverInterface {
    private InetAddress nameServerIP;
    private int nameServerPort;

    /**
     * This method must be called first.
     *
     * @param ipAddress     Assume that IP address leads to a working domain
     *                      name server which supports iterative queries (along with
     *                      the port - both need to be valid)
     * @param port          Assume that the port number leads to a working domain
     *                      name server which supports iterative queries. (along with
     *                      the ipAddress - both need to be valid)
     */
    public void setNameServer(InetAddress ipAddress, int port) throws Exception {
        this.nameServerIP = ipAddress;
        this.nameServerPort = port;
    }


    /**
     * Performs a iterative resolution for domainName's A resource
     * record using the name server given by setNameServer.
     *
     * @param domainName    Assume that it is a valid domain name.
     */
    public InetAddress iterativeResolveAddress(String domainName) throws Exception {
        // If the domainName has A records, it returns the IP address from one of them.
        // If there is no record then it returns null.
        DNSResponseReader.DnsRecord result = iterativeResolve(domainName, DNSQueryBuilder.TYPE_A);
        return result != null ? result.getAddress() : null;
    }


    /**
     * Performs a iterative resolution for domainName's TXT resource
     * record using the name server given by setNameServer.
     *
     * @param domainName    Assume that it is a valid domain name.
     */
    public String iterativeResolveText(String domainName) throws Exception {
        // If the domainName has TXT records, it returns the string contained one of the records.
        // If there is no record then it returns null.
        DNSResponseReader.DnsRecord result = iterativeResolve(domainName, DNSQueryBuilder.TYPE_TXT);
        return result != null ? result.getText() : null;
    }


    /**
     * Performs a iterative resolution for domainName's resource
     * record using the name server given by setNameServer.
     *
     * @param domainName    Assume that it is a valid domain name.
     * @param type          Assume that the type is one of NS, MX or CNAME.
     */
    public String iterativeResolveName(String domainName, int type) throws Exception {
        //if it is not one of the types, then return error message
        if (type != DNSQueryBuilder.TYPE_NS &&
                type != DNSQueryBuilder.TYPE_CNAME &&
                type != DNSQueryBuilder.TYPE_MX) {
            throw new Exception("Error: Unsupported Record Type - " + type);
        }

        // If the domainName has appropriate records, it returns the domain name contained in one of the records.
        // If there is no record then it returns null.
        DNSResponseReader.DnsRecord result = iterativeResolve(domainName, type);
        return result != null ? result.getDomainName() : null;
    }


    /**
     * Performs the main iterative resolution algorithm
     *
     * Follows CNAME chains
     * Retries unresponsive reserve
     * Uses glue records and authority referrals to resolve the requested record type.
     */
    private DNSResponseReader.DnsRecord iterativeResolve(String domainName, int type) throws Exception {
        String currentDomain = domainName;
        InetAddress currentServer = nameServerIP;
        int currentPort = nameServerPort;
        Set<String> seenCNAMEs = new HashSet<>();
        int countLoopNo = 0;

        while (true) {
            //Setted a maximum amount of loops that CNAME can do - 10
            if (countLoopNo >= 10) {
                throw new Exception("CNAME chain too long or loop detected for: " + currentDomain);
            }
            countLoopNo++;

            byte[] query = DNSQueryBuilder.buildDNSQuery(currentDomain, type, HelperClass.generateTransactionID());
            byte[] response = retrySendingQueries(currentServer, currentPort, query, 3);

            List<DNSResponseReader.DnsRecord> records = DNSResponseReader.parseResponse(response);

            // Check answers first
            for (DNSResponseReader.DnsRecord r : records) {
                if (r.type == type) {
                    return r; // Final answer
                } else if (r.type == DNSQueryBuilder.TYPE_CNAME) {
                    if (seenCNAMEs.contains(r.getDomainName())) {
                        throw new Exception("CNAME loop detected: " + r.getDomainName());
                    }
                    seenCNAMEs.add(r.getDomainName());
                    currentDomain = r.getDomainName(); // Follow CNAME
                    break;
                }
            }

            // If no answer yet, use authority + glue
            List<String> nsNames = extractNSNames(response);
            List<InetAddress> glueIPs = extractGlueIPs(response);

            if (!glueIPs.isEmpty()) {
                currentServer = glueIPs.get(0);
            } else if (!nsNames.isEmpty()) {
                InetAddress resolved = iterativeResolveAddress(nsNames.get(0));
                if (resolved == null) {
                    throw new Exception("Unable to resolve name server: " + nsNames.get(0));
                }
                currentServer = resolved;
            } else {
                return null;
            }
        }
    }


    /**
     * Extracts NS domain names from the Authority section.
     */
    private List<String> extractNSNames(byte[] response) throws Exception {
        List<String> nsNames = new ArrayList<>();
        int index = HelperClass.findAnswerSectionEnd(response);
        int authorityCount = HelperClass.readShort(response, 8);

        for (int i = 0; i < authorityCount; i++) {
            index = DNSResponseReader.skipDomainName(response, index);
            int type = HelperClass.readShort(response, index); index += 2;
            index += 2 + 4; // class + TTL
            int rdLength = HelperClass.readShort(response, index); index += 2;
            if (type == DNSQueryBuilder.TYPE_NS) {
                String nsName = DNSResponseReader.readDomainName(response, index);
                nsNames.add(nsName);
            }
            index += rdLength;
        }

        return nsNames;
    }


    /**
     * Extracts A records (glue IPs) from the Additional section.
     */
    private List<InetAddress> extractGlueIPs(byte[] response) throws Exception {
        List<InetAddress> glue = new ArrayList<>();
        int index = HelperClass.findAnswerSectionEnd(response);
        int authorityCount = HelperClass.readShort(response, 8);
        int additionalCount = HelperClass.readShort(response, 10);

        //Skip authority section
        for (int i = 0; i < authorityCount; i++) {
            index = DNSResponseReader.skipDomainName(response, index);
            index += 2 + 2 + 4; // type + class + TTL
            int rdLength = HelperClass.readShort(response, index); index += 2 + rdLength;
        }

        //Parse Additional section for A records
        for (int i = 0; i < additionalCount; i++) {
            index = DNSResponseReader.skipDomainName(response, index);
            int type = HelperClass.readShort(response, index); index += 2;
            index += 2 + 4; // class + TTL
            int rdLength = HelperClass.readShort(response, index); index += 2;
            if (type == DNSQueryBuilder.TYPE_A && rdLength == 4) {
                glue.add(InetAddress.getByAddress(Arrays.copyOfRange(response, index, index + 4)));
            }
            index += rdLength;
        }

        return glue;
    }


    /**
     * Retry mechanism for Iterative Resolve
     *
     * @param server        Server to send the query to again
     * @param port          Port to send the query to again
     * @param query         The query that has to be sent
     * @param maxRetries    Amount of times allowed to retry sending the query
     * */
    private byte[] retrySendingQueries(InetAddress server, int port, byte[] query, int maxRetries) throws Exception {
        int retryAttemptNo = 0;
        while (retryAttemptNo < maxRetries) {
            try {
                return HelperClass.sendQuery(server, port, query); // Success
            } catch (IOException e) {
                retryAttemptNo++;
                if (retryAttemptNo >= maxRetries) {
                    throw new Exception("Name server unresponsive after " + maxRetries + " attempts: " + server);
                }
            }
        }
        return null;
    }
}