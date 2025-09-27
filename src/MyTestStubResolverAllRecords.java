import java.net.InetAddress;

public class MyTestStubResolverAllRecords {
    public static void testWorkingDomain(String domainName, StubResolver resolver) throws Exception {
        System.out.println("\nDomain Name: " + domainName+"\n");

        // Test A record
        InetAddress aRecord = resolver.recursiveResolveAddress(domainName);
        if (aRecord == null) {
            System.out.println("Failed to resolve A record for "+domainName);
        } else {
            System.out.println(domainName+"\tA\t" + aRecord.getHostAddress());
        }

        // Test TXT record
        String txtRecord = resolver.recursiveResolveText(domainName);
        if (txtRecord == null) {
            System.out.println("Failed to resolve TXT record for "+domainName);
        } else {
            System.out.println(domainName+"\tTXT\t" + txtRecord);
        }

        // Test NS record
        String nsRecord = resolver.recursiveResolveName(domainName, DNSQueryBuilder.TYPE_NS);
        if (nsRecord == null) {
            System.out.println("Failed to resolve NS record for "+domainName);
        } else {
            System.out.println(domainName+"\tNS\t" + nsRecord);
        }

        // Test MX record
        String mxRecord = resolver.recursiveResolveName(domainName, DNSQueryBuilder.TYPE_MX);
        if (mxRecord == null) {
            System.out.println("Failed to resolve MX record for "+domainName);
        } else {
            System.out.println(domainName+"\tMX\t" + mxRecord);
        }
    }


    public static void main(String[] args) {
        try {
            StubResolver resolver = new StubResolver();

            // Set the Cloudflare public DNS name server
            byte[] cloudflarePublic = new byte[] {1, 1, 1, 1};
            resolver.setNameServer(InetAddress.getByAddress(cloudflarePublic), 53);
            String domainName = "instagram.com.";

            testWorkingDomain("instagram.com.", resolver);
            testWorkingDomain("google.com.", resolver);
            testWorkingDomain("facebook.com.", resolver);


            // Test unsuccessful query (non-existent domain)
            String badDomain = "nonexistentdomainforsure12345.com.";
            System.out.println("\nTesting unsuccessful query for: " + badDomain);

            // Attempt A record resolution
            InetAddress badA = resolver.recursiveResolveAddress(badDomain);
            if (badA == null) {
                System.out.println(badDomain + "\tA\tResolution failed as expected.");
            } else {
                System.out.println(badDomain + "\tA\tUnexpectedly resolved: " + badA.getHostAddress());
            }

            // Attempt TXT record resolution
            String badTXT = resolver.recursiveResolveText(badDomain);
            if (badTXT == null) {
                System.out.println(badDomain + "\tTXT\tResolution failed as expected.");
            } else {
                System.out.println(badDomain + "\tTXT\tUnexpectedly resolved: " + badTXT);
            }

            // Attempt NS record resolution
            String badNS = resolver.recursiveResolveName(badDomain, DNSQueryBuilder.TYPE_NS);
            if (badNS == null) {
                System.out.println(badDomain + "\tNS\tResolution failed as expected.");
            } else {
                System.out.println(badDomain + "\tNS\tUnexpectedly resolved: " + badNS);
            }

            // Attempt MX record resolution
            String badMX = resolver.recursiveResolveName(badDomain, DNSQueryBuilder.TYPE_MX);
            if (badMX == null) {
                System.out.println(badDomain + "\tMX\tResolution failed as expected.");
            } else {
                System.out.println(badDomain + "\tMX\tUnexpectedly resolved: " + badMX);
            }


        } catch (Exception e) {
            System.out.println("Exception caught during testing:");
            e.printStackTrace();
        }

        System.out.println("All tests complete.");
    }
}