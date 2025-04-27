# Multi-Tool

A comprehensive, modular CLI-based tool for network reconnaissance, website analysis, and security insights.

## Features

1. IP Information - Details about an IP address
2. SSL Chain Analysis - Analyze SSL certificate chain
3. DNS Records - Retrieve DNS records for a domain
4. Cookies Analysis - Analyze cookies from a website
5. Crawl Rules Analysis - Analyze robots.txt and crawl directives
6. HTTP Headers Analysis - Analyze HTTP headers
7. Quality Metrics Assessment - Website quality and best practices
8. Server Location Information - Geographic location of servers
9. Associated Hosts - Find hosts associated with a domain
10. Redirect Chain Inspection - Inspect redirect chain for a URL
11. TXT Records Analysis - Analyze TXT records (SPF, DMARC, etc.)
12. Server Status - Check server availability and performance
13. Open Ports Scanning - Check for open ports on a host
14. Traceroute Execution - Execute traceroute to a host
15. Carbon Footprint - Estimate website's environmental impact
16. Server Information - Detailed server information
17. WHOIS Lookup - Domain registration information
18. Domain Information - Comprehensive domain analysis
19. DNS Security Extensions - Check DNSSEC implementation
20. Site Features Detection - Detect website features and technologies
21. HTTP Security Analysis - Analyze HTTP security headers including HSTS
22. DNS Server Analysis - Analyze DNS server configuration
23. Tech Stack Analysis - Identify technology stack of a website
24. Listed Pages Analysis - Extract and analyze pages listed on a website
25. Security.txt Check - Check for security.txt file compliance
26. Linked Pages Analysis - Analyze linked pages from a website
27. Social Tags Analysis - Analyze social media tags and integration
28. Email Configuration Analysis - Analyze email security (SPF, DKIM, DMARC)
29. Firewall Detection - Detect web application firewalls
30. Certificate Transparency - Check certificate transparency logs
31. Archive History - Check website archive history
32. Global Ranking - Check website's global traffic ranking
33. Block Detection - Check if domain is on blocklists
34. Malware & Phishing Detection - Check for malicious content
35. TLS Cipher Suites - Analyze supported TLS cipher suites
36. TLS Security Configuration - Analyze TLS security configuration
37. TLS Handshake Simulation - Simulate TLS handshake process
38. Screenshot Capture - Capture screenshot of a website

## Installation on Kali Linux

1. Clone or download this repository
2. Navigate to the directory containing the `init.sh` script
3. Make the script executable: `chmod +x init.sh`
4. Run the installation script as root: `sudo ./init.sh`

This will install the tool and make it available system-wide.

## Usage

### Interactive Mode (Recommended)

Simply run the tool without any arguments to enter the interactive mode:

```bash
multi-tool
```

You'll be presented with a menu of tools to choose from. Select the desired tool by entering the corresponding number.

### Command Line Mode

Run the tool with specific arguments to use a particular feature:

```bash
multi-tool ipinfo --ip 8.8.8.8
multi-tool sslchain --domain example.com
multi-tool dnsrecords --domain example.com --type A
multi-tool cookies --url https://example.com
multi-tool crawlrules --url https://example.com
multi-tool headers --url https://example.com
multi-tool qualitymetrics --url https://example.com
multi-tool serverlocation --domain example.com
multi-tool associatedhosts --domain example.com
multi-tool redirectchain --url https://example.com
multi-tool txtrecords --domain example.com
multi-tool serverstatus --url https://example.com
multi-tool openports --host example.com --ports 1-1000
multi-tool traceroute --host example.com
multi-tool carbonfootprint --url https://example.com
multi-tool serverinfo --url https://example.com
multi-tool whois --domain example.com
multi-tool domaininfo --domain example.com
multi-tool dnssecurity --domain example.com
multi-tool sitefeatures --url https://example.com
multi-tool httpsecurity --url https://example.com
multi-tool dnsserver --domain example.com
multi-tool techstack --url https://example.com
multi-tool listedpages --url https://example.com
multi-tool securitytxt --url https://example.com
multi-tool linkedpages --url https://example.com
multi-tool socialtags --url https://example.com
multi-tool emailconfig --domain example.com
multi-tool firewall --url https://example.com
```

### Output Formats

All tools support multiple output formats:

```bash
multi-tool dnsrecords --domain example.com --format json
multi-tool dnsrecords --domain example.com --format table
multi-tool dnsrecords --domain example.com --format text
```

### Saving Output

To save the results to a file:

```bash
multi-tool dnsrecords --domain example.com --format json --output results.json
```

### Debug Mode

For verbose output, use the debug flag:

```bash
multi-tool dnsrecords --domain example.com --debug
```

## Requirements

- Python 3.6+
- Required Python packages (automatically installed):
  - requests
  - beautifulsoup4
  - dnspython
  - python-whois
  - tabulate
  - pyOpenSSL
  - cryptography
  - validators
  - selenium
  - pillow
  - pyppeteer
  - websocket-client
  - tldextract
  - trafilatura
  - email-validator
  - pymisp
  - zxcvbn
  - psycopg2-binary

## License

[MIT License](LICENSE)