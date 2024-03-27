Owasp top 10 vulnerabilities, impact and their mitigations.

=========================================
Diffrence beween get and POST method.
========================================= 
GET carries request parameter appended in URL string while POST carries request parameter in message body 

========================================
Is it safe to send data in get method.
========================================
No

======================================================
Diffrence beween encoding, hashing and encryption.
======================================================
Encoding: Reversible transformation of data format, used to preserve the usability of data. Hashing: A one-way summary of data that cannot be reversed and is used to validate the integrity of data. Encryption: Secure encoding of data used to protect the confidentiality of data.


How you can confirm that string either encoded hashed or encrypted by looking at it.


How hashes can be cracked.

===============================
What is rainbow table.
==============================
A rainbow table is a precomputed table for caching the outputs of a cryptographic hash function, usually for cracking password hashes. 


SQL injection types, mitigation, exploit scenarios, what most you can do with sql injection, is it possible to perform rce using sql injection, simple manual payloads for sql injection ex - payload to enumerate columns




===========================================
How will you test for blind sql injection.
=============================================
' or sleep(5)#,		' or 1=1 and sleep(5)#

===============================
If there is no diffrence between the responce for diffrent payloads for SQL injection, what will be your approach to test it further. 
=================================
Bliend SQL injection


Xss and its types, mitigation, what most you can do by XSS.

What will be severity of XSS on login page and why.

Explain DOM based XSS and how will you exploit it.

SSRF and its mitigation and impact,

Payload for SSRF and if input validation implemented what payload will you use.


===========================================
how port scanning can be performed by SSRF.
===========================================
using HTTP, HTTPS, GOPHER, or DICT protocols. If there is a Blind SSRF to find out whether the port is open or closed, you can pay attention to Content-length, Response Time, or HTTP Status Code.

=========================================================
XXE its mutilation and impact, what is the way to exploit XXE.

Is it possible to perform XXE on Json request.


===========================================
CSRF and it's mitigation.



===========================================
Java deserialization impqct and mitigation.




CORS vulnerability.



========================
What is CLRF injection.

What is diffrence between Privilege escalation and IDOR.

what all things you will test on file upload fuctionality.

How will you bypass file extension validation.

What is CSV injection it's impact and mitigation.
Any 5 ports and services running on them.

=======================
How SSL works.
=======================
The client creates a session key, encrypts it with the server's public key and sends it to the server.

=============================================
What is Digital Signeture and how it works.
=============================================
Digital signatures work by proving that a digital message or document was not modified—intentionally or unintentionally—from the time it was signed. 

Digital signatures do this by generating a unique hash of the message or document and encrypting it using the sender's private key.



==========================================
Oauth token and its vulnerabilities.
==========================================
when the configuration of the OAuth service itself enables attackers to steal authorization codes or access tokens associated with other users' accounts. 

==================================
JWT token and its vulnerabilities.
==================================
involve a user sending modified JWTs to the server in order to achieve a malicious goal

