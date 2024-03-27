A1 : Injection
A2 : Broken Authentication
A3 : Sensitive Data Expose
A4 : XML External Entities
A5 : Broken Access Control
A6 : Security Misconfiguration.
A7 : Cross Site Scripting.
A8 : Insecure Deserialization.
A9 : Using Components with Known Vulnerabilities.
A10 : Insufficient Logging and Monitoring

Test approch
    https://infosecwriteups.com/thick-client-pentest-modern-approaches-and-techniques-part-1-7bb0f5f28e8e

Thick Client Check List
    https://hariprasaanth.notion.site/hariprasaanth/THICK-CLIENT-PENTESTING-CHECKLIST-35c6803f26eb4c9d89ba7f5fdc901fb0

============================
Two-tier architecture
==============================
    In the two-tier architecture, all the components required for the functionality of the application such as the database, code logic, etc sit on the local system/network of the user and generally, there is no external API communication.

===========================
Three-tier architecture
===========================
    In the three-tier architecture, the application makes an outbound call to the external-facing components like an application server or an external-facing entity to process certain application logic. 
One example of a three-tier architecture is Slack, where the communication involves APIs and other protocols to interact with other users.


====================================
Methodology 
=========================
1.  Enumeration: Identify language & framework, architecture, intercept traffic, and common functionality probing
2.  Client-Side Checks: Memory analysis, file analysis, binary analysis, etc. 
3.  Server-side Attacks: OWASP Top 10 Checks if the application interacts with Web/API server
4.  Network Attacks: Intercept Traffic, Examine Vulnerabilities on External Server Interactions

__________________________
Proxy-aware thick client:  Natively includes proxy settings, so outgoing and incoming traffic is sent to the proxy server and then to the main server
___________________________
Proxy unaware thick client: Do not natively include proxy settings so the user is required to make some changes in the system’s host file

=========================================================
1. Sensitive data leakage
Mitigation: It is recommended to remove hardcoded sensitive data.
Mitigation: Avoid sensitive data leakage.


2. DLL Hijacking

3. Improper Error Handling
Mitigation:
    A specific policy for how to handle errors should be documented, including the types of errors to be handled and for each, what information is going to be reported back to the user, and what information is going to be logged. All developers need to understand the policy and ensure that their code follows it.


4. Injection

5. Reverse Engineering

6. Session Management

7. Insecure Storage

8. SSL/TLS

9. Business Logic

10. Weak encryption checks

11. Lack of code obfuscation:
It is recommended to use a set of software for code obfuscation. Like: ProGuard, JObfuscator, Javaguard, and many others.



==========================================================
-------------------
Echo Mirage.
--------------------
    Echo Mirage enables intercepting non-HTTP traffic between the tested thick client and the local or remote server.

----------------
2. Procmon -
----------------
    dnSpy is a portable debugger and .NET assembly editor for use when editing and debugging assemblies even if the source code isn’t available

3. Strings.exe

4. Sysinternals Suite

5. Nmap

6. Testssl

7. Process Hacker

8. Dnspy/ Dot Peek/ VB decompiler

9. Metasploit (To create Mal. DLL file)

10. Fiddler/Burpsuite

11. Wireshark

12. Ollydbg

13. .Net Reflector

14. Winhex


https://www.cobalt.io/blog/cobalt-core-academy-thick-client-pentesting