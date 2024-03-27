Port scanning portal
    https://nmap.org/book/port-scanning-options.html

============================
Namp scanning techniques.
============================
-sS	nmap 192.168.1.1 -sS	TCP SYN port scan (Default)
-sT	nmap 192.168.1.1 -sT	TCP connect port scan (Default without root privilege)
-sU	nmap 192.168.1.1 -sU	UDP port scan
-sA	nmap 192.168.1.1 -sA	TCP ACK port scan
-sW	nmap 192.168.1.1 -sW	TCP Window port scan
-sM	nmap 192.168.1.1 -sM	TCP Maimon port scan


==================================================
By default how many and which ports Nmap will scan.
===================================================
    By default, Nmap scans the most common 1,000 ports for each protocol.
    This catches roughly 93% of the TCP ports and 49% of the UDP ports. With the -F (fast) option
    http
    ssh
    telnet
    smtp
    ftp

====================================================
What is diffrence between Stealth scan and connect scan.
=====================================================
    TCP SYN scan is a most popular and default scan in Nmap because it perform quickly compare to other scan types and it is also less likely to block from firewalls.  TCP SYN scan required raw-packet privileges that needs root access. -sS
    In the Nmap TCP connection scan, Nmap asks its underlying Operating network to establish a connection with the target server by issuing the “connect” system call. -sT

=============================================
Nmap command -sS -Pn -sC and its meaning.
============================================
-sS : Stealth scan
-Pn : Disable host discovery. Port scan only.

=======================
How SSL works.
=======================
The client creates a session key, encrypts it with the server's public key and sends it to the server.

=========================
Port Number
=================

20      File Transfer Protocol (FTP) Data Transfer
21      File Transfer Protocol (FTP) Command Control
22      Secure Shell (SSH)
23      Telnet - Remote login service, unencrypted text messages
25      Simple Mail Transfer Protocol (SMTP) E-mail Routing
53      Domain Name System (DNS) service
80      Hypertext Transfer Protocol (HTTP) used in World Wide Web
110     Post Office Protocol (POP3) used by e-mail clients to retrieve e-mail from a server
119     etwork News Transfer Protocol (NNTP)
123     Network Time Protocol (NTP)
143     Internet Message Access Protocol (IMAP) Management of Digital Mail
161     Simple Network Management Protocol (SNMP)
194     Internet Relay Chat (IRC)
443     HTTP Secure (HTTPS) HTTP over TLS/SSL


=============================================
Digital Signeture and how it works.
=============================================
Digital signatures work by proving that a digital message or document was not modified—intentionally or unintentionally—from the time it was signed. 

Digital signatures do this by generating a unique hash of the message or document and encrypting it using the sender's private key.



nmap -Pn -sU -p53 --script dns* -v
nmap -Pn -sS -p22 --script ssh* -v
nmap -Pn -sS -p25 --script smtp* -v


How does Network Address Translation (NAT) work with firewalls?

Why is logging and monitoring firewall activity important?

What are some best practices for configuring and managing network firewalls?

What role do Access Control Lists (ACLs) play in network firewalls?

What is an Intrusion Detection System (IDS), and how does it complement network firewalls?

