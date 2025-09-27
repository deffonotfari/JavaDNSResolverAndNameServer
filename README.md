Components
==========

1. StubResolver.java
- Sends DNS queries over UDP.
- Receives responses and extracts answers.
- Supports A, NS, MX, TXT, and CNAME record types.
- Handles successful and unsuccessful queries.

2. Resolver.java
- Implements iterative DNS resolution.
- Follows referrals using NS and glue records.
- Handles CNAMEs, including loop detection.
- Manages unresponsive name servers with timeout handling.

3. NameServer.java
- Caching authoritative server handling multiple clients concurrently.
- Caches positive and negative responses with TTL.
- Responds to queries using cache or forwards via Resolver if needed.

4. DNSQueryBuilder.java
- Constructs DNS query messages in wire format.
- Supports multiple query types.

5. DNSResponseReader.java
- Parses DNS responses from byte arrays.
- Handles pointer compression and all required record types.

6. HelperClass.java
- Utility functions for byte/array and domain conversions.




Build Instructions
==================
- The project can be run in any Java-compatible environment (e.g., IntelliJ, Visual Studio Code) or via the terminal.
- To build via terminal, navigate to the src directory and compile all files:
  cd /path/to/src
  javac *.java
- Running the compiled classes can then be done according to the testing instructions below.




Working Functionality
=====================
- Supports query types: A, NS, MX, TXT, CNAME
- Iterative resolution via Resolver.java
- Caching of both positive and negative responses with TTL management
- Handles multiple simultaneous clients
- Detects and handles CNAME loops
- Basic error handling for timeouts, malformed responses, and unresponsive servers




Testing Approach
================
- Tested using terminal on MacBook Pro by navigating to the src folder.
- Compiled and ran:
  javac *.java && java TestStubResolver
- Developed **MyTestStubResolver.java** to perform extended testing:
  - Sent queries for all supported record types (A, MX, NS, TXT, CNAME).
  - Tested resolution of both existing and non-existing domains.
  - Tested malformed or malfunctioning records by sending intentionally corrupted or unsupported queries to verify error handling.
  - Checked correct parsing of responses and proper handling of negative responses.

- Tested Resolver.java using:
  java TestResolver
  - Verified iterative resolution across multiple domains.
  - Confirmed proper use of glue records.
  - Confirmed handling of unresponsive or incorrect NS responses.

- Tested NameServer.java using:
  java TestNameServer
  - Verified caching of positive and negative responses.
  - Verified TTL expiry handling.
  - Tested multiple simultaneous clients by sending parallel dig commands.

- Example dig commands used for testing:

To test different record types:
dig @127.0.0.1 -p 7364 example.com A
dig @127.0.0.1 -p 7364 example.com MX
dig @127.0.0.1 -p 7364 example.com NS
dig @127.0.0.1 -p 7364 www.wikipedia.org A
dig @127.0.0.1 -p 7364 example.com TXT
dig @127.0.0.1 -p 7364 nonexistdomain12345.com A

For multiple simultaneous queries:
dig @127.0.0.1 -p 7364 example.com A
dig @127.0.0.1 -p 7364 example.com A &
dig @127.0.0.1 -p 7364 example.org A &
dig @127.0.0.1 -p 7364 example.net A &
wait

For erroneous or malfunctioning queries:
dig @127.0.0.1 -p 7364 example.com A +dnssec
dig @127.0.0.1 -p 7364 malformed.domain A

- Verified correct handling of positive and negative responses, caching, and TTL expiry.
- Captured Wireshark PCAPs to confirm UDP packet structure and resolution process.
