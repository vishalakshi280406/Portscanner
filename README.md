#PYTHON PORT SCANNER

📖 About the Project
This is a beginner cybersecurity project that demonstrates how TCP port scanning works at a fundamental level. Instead of using existing tools, the entire scanner is written from scratch using Python's built-in socket and threading modules.
The scanner works by attempting a TCP connection to each port on a target IP address. If the connection succeeds, the port is open — meaning an active service is listening on it. Multithreading allows scanning 100 ports simultaneously, reducing scan time from ~8 minutes (sequential) to under 1 second

Where it is used?
. Penetration Testing : Identify open ports = identify attack surface before an en engagement
. Network Administration : Audit servers to detect unexpected or unauthorized open ports

TECH STACK
python - language ; socket - TCP connection ; threading - port scanning

📚 What I Learned

How TCP/IP ports work and what open vs closed means at the socket level
Python socket module — creating connections, handling timeouts, reading error codes
Multithreading with threading.Thread, Semaphore, and Lock
Why thread safety matters and how Lock prevents race conditions
CLI tool design with argparse
How professional tools like Nmap work under the hood
Ethical and legal boundaries around network scanning

Domain: Cybersecurity | Python | Networking
