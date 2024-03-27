API

What is an API?
An application programming interface is a way for two or more computer programs to communicate with each other.

SOAP vs REST

1)	SOAP is a protocol.	REST is an architectural style.
2)	SOAP stands for Simple Object Access Protocol.	REST stands for REpresentational State Transfer.
3)	SOAP can't use REST because it is a protocol.	REST can use SOAP web services because it is a concept and can use any protocol like HTTP, SOAP.
4)	SOAP uses services interfaces to expose the business logic.	REST uses URI to expose business logic.
5)	SOAP permits XML data format only.	REST permits different data format such as Plain text, HTML, XML, JSON etc.
6)	SOAP is less preferred than REST.	REST more preferred than SOAP.


API1:2019 — Broken object level authorization
API2:2019 — Broken authentication
API3:2019 — Excessive data exposure .
API4:2019 — Lack of resources and rate limiting .
API5:2019 — Broken function level authorization
API6:2019 — Mass assignment .
API7:2019 — Security misconfiguration
API8:2019 — Injection .
API9:2019 — Improper assets management
API10:2019 — Insufficient logging and monitoring .

API 01:2023 — Broken object level authorization .
API 02:2023 — Broken authentication .
API 03:2023 — Broken Object Property Level Authorisation
API 04:2023 — Unrestricted resources consumption
API 05:2023 — Broken function level authorization .
API 06:2023 — Unrestricted access to sensitive business flows
API 07:2023 — Server side request forgery
API 08:2023 — Security misconfiguration .
API 09:2023 — Improper inventory management .
API 10:2023 — Unsafe consumption of APIs


==================================
API1 — Broken object level authorization
==================================
    Attackers substitute the ID of their own resource in the API call with an ID of a resource belonging to another user. The lack of proper authorization checks allows attackers to access the specified resource. This attack is also known as IDOR (Insecure Direct Object Reference).
Impact 
    Attackers can exploit API endpoints that are vulnerable to broken object-level authorization by manipulating the ID of an object that is sent within the request
How to prevent
    Implement authorization checks with user policies and hierarchy.
    Do not rely on IDs that the client sends. Use IDs stored in the session object instead.
    Check authorization for each client request to access database.
    Use random IDs that cannot be guessed (UUIDs).


===============================
API2 — Broken User Authentication
===============================
Poorly implemented API authentication allows attackers to assume other users’ identities.

Kind of OTP Bypass
Password reset token expose

Impact
    exploit vulnerabilities in authentication mechanisms can take over user accounts, gain unauthorized access to another user's data, or make unauthorized transactions as another user.

How to prevent
    Check all possible ways to authenticate to all APIs.
    APIs for password reset and one-time links also allow users to authenticate, and should be protected just as rigorously.
    Use standard authentication, token generation, password storage, and multi-factor authentication (MFA).
    Use short-lived access tokens.
    Authenticate your apps (so you know who is talking to you).
    Use stricter rate-limiting for authentication, and implement lockout policies and weak password checks.

=============================
API3 — Broken Object Property Level Authorisation
============================
API endpoints can be vulnerable to attacks based on their data: either they may expose more data than is required for their business purposes (excessive information exposure), or they may inadvertently accept and process more data than they should (mass assignment). 

Impact
    1) The API endpoint exposes properties of an object that are considered sensitive and should not be read by the user. 
    2) The API endpoint allows a user to change, add/or delete the value of a sensitive object's property which the user should not be able to acces.

How to prevent
    Never rely on the client to filter data!
    Review all API responses and adapt them to match what the API consumers really need.
    Carefully define schemas for all the API responses.
    Do not forget about error responses, define proper schemas as well.
    Identify all the sensitive data or Personally Identifiable Information (PII), and justify its use using a robust data governance process.


=================================
Unlimited Resource Consumption
=================================
The API is not protected against an excessive amount of calls or payload sizes. Attackers can use this for Denial of Service (DoS) and authentication flaws like brute force attacks.

Impact
    Satisfying API requests requires resources such as network bandwidth, CPU, memory, and storage. Sometimes required resources are made available by service providers via API integrations, and paid for per request, such as sending emails/SMS/phone calls, biometrics validation, etc

How to Prevent
    Apply rate limiting policies to all endpoints.
    Pay special attention to endpoints related to authentication which are a prime target for hackers.
    Tailor rate limiting to match what API methods, clients, or addresses need or should be allowed to retrieve.
    IPs can easily be forged, whenever possible, configure rate limiting on different keys, such as fingerprints, or tokens. 
    Limit payload sizes, and query complexity.
    Leverage DDoS protections from your cloud provider.


=============================
API3 — Excessive Data Exposure
==============================
The API may expose a lot more data than what the client legitimately needs, relying on the client to do the filtering. If attackers go directly to the API, they have it all.

Password token link has been shown in response

Impact
     data leaks, man-in-the-middle attacks, and other cyber threats.

prevent
    Never rely on the client to filter data!
    Review all API responses and adapt them to match what the API consumers really need.
    Carefully define schemas for all the API responses.
    Do not forget about error responses, define proper schemas as well.
    Identify all the sensitive data or Personally Identifiable Information (PII), and justify its use.
    Enforce response checks to prevent accidental leaks of data or exceptions.

==============================
API4 — Lack of resources and rate limiting
==============================
The API is not protected against an excessive amount of calls or payload sizes. Attackers can use this for Denial of Service (DoS) and authentication flaws like brute force attacks.

Bruteforse to create Multiple account

How to prevent
    Define proper rate limiting.
    Limit payload sizes.
    Tailor the rate limiting to be match what API methods, clients, or addresses need or should be allowed to get.
    Add checks on compression ratios.
    Define limits for container resources.

==============================
API5 — Broken function level authorization
==============================
The API relies on the client to use user level or admin level APIs as appropriate. Attackers figure out the “hidden” admin API methods and invoke them directly.

Access control(Vertical & Horizontal)
also kind of IDOR

Impact
    Exposed endpoints will be easily
    
How to prevent
    Do not rely on the client to enforce admin access.
    Deny all access by default.
    Only allow operations to users belonging to the appropriate group or role.
    Properly design and test authorization.


==============================
Unrestricted access to sensitive business flows
==============================
A set of APIs exposes a business flow and an attacker abuses these APIs using automated methods to achieve a malicious intent, such as exfiltrating data or manipulating market or price data.

Impact
    When creating an API Endpoint, it is important to understand which business flow it exposes. Some business flows are more sensitive than others, in the sense that excessive access to them may harm the business.

How to prevent
    Understand business flows that could be sensitive to abuse and add extra layers of protection to these and ensure authentication is required, using recommended OAuth flows, like authorization_code.
    Ensure that APIs are fully protected with robust rate-limiting in front of the API.
    Monitor API access and restrict clients using either suspicious devices or originating from risky IP addresses.

==============================
Server side request forgery
==============================
Server-Side Request Forgery (SSRF) can occur when an API fetches a remote resource without validating the user-supplied URL. This enables an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall or a VPN.

Impact
    Server-Side Request Forgery (SSRF) flaws occur when an API is fetching a remote resource without validating the user-supplied URL. It enables an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall or a VPN.

How to prevent
    Precisely define the schemas, types, and patterns you will accept in requests at design time and enforce them at runtime.
    Prevent your API server from following HTTP redirections.
    Use an allow list of permitted redirects or accesses. 
    Restrict the range of allowed URL schemes and ports allowed.

==============================
API6 — Mass assignment
=============================
The API takes data that client provides and stores it without proper filtering for whitelisted properties. Attackers can try to guess object properties or provide additional object properties in their requests, read the documentation, or check out API endpoints for clues where to find the openings to modify properties they are not supposed to on the data objects stored in the backend.

IsAdmin - false/true
Role - 0/1

How to prevent 
    Do not automatically bind incoming data and internal objects.
    Explicitly define all the parameters and payloads you are expecting.
    Use the readOnly property set to true in object schemas for all properties that can be retrieved through APIs but should never be modified.
    Precisely define the schemas, types, and patterns you will accept in requests at design time and enforce them at runtime.


==================================
API7 — Security Misconfiguration
====================================
Poor configuration of the API servers allows attackers to exploit them.

Clickjacking
CSP
Security header
    CSP
    Strict-Transport-Security Header (HSTS)
    3. X-Content-Type-Options
    4. X-Frame-Options
    5. Referrer-Policy



Incomplete or ad-hoc configurations
Insecure default configurations
Open cloud storage
Unnecessary HTTP methods
Misconfigured HTTP headers
Verbose error messages that contain sensitive information
Permissive cross-origin resource sharing (CORS)

====================================
API8 — Injection
====================================
Attackers construct API calls that include SQL, NoSQL, LDAP, OS, or other commands that the API or the backend behind it blindly executes.

Impact
    data loss, data manipulation, unauthorized access to sensitive data, and additional compromises in the API.

How to prevent
    Never trust your API consumers, even if they are internal.
    Strictly define all input data, such as schemas, types, and string patterns, and enforce them at runtime.
    Validate, filter, and sanitize all incoming data.
    Define, limit, and enforce API outputs to prevent data leaks

====================================
API9 — Improper Assets Management
================================
Attackers find non-production versions of the API (for example, staging, testing, beta, or earlier versions) that are not as well protected as the production API, and use those to launch their attacks.

Change previous version
V1 to V2

Impact 
    vulnerability also allows malicious actors to access non-production versions of the API

prevent
    Keep an up-to-date inventory all API hosts.
    Limit access to anything that should not be public.
    Limit access to production data, and segregate access to production and non-production data.
    Implement additional external controls, such as API firewalls.
    Properly retire old versions of APIs or backport security fixes to them.
    Implement strict authentication, redirects, CORS, and so forth.


====================================
Unsafe consumption of APIs
====================================
Modern API-based systems tend to be highly interconnected, frequently consuming upstream APIs. Unfortunately, these upstream APIs may themselves be vulnerable and put their consumers at risk.

Impact
    
====================================
API10 — Insufficient logging and monitoring
====================================
Lack of proper logging, monitoring, and alerting allows attacks and attackers go unnoticed.

Log file monitor

Impact
    Without logging and monitoring, or with insufficient logging and monitoring, it is almost impossible to track suspicious activities and respond to them in a timely fashion.

How to prevent
    Log failed attempts, denied access, input validation failures, or any failures in security policy checks.
    Ensure that logs are formatted so that other tools can consume them as well.
    Protect logs like highly sensitive information.
    Include enough detail to identify attackers.
    Avoid having sensitive data in logs — if you need the information for debugging purposes, redact it partially.
    Integrate with SIEMs and other dashboards, monitoring, and alerting tools.

-------------------------------


How to approch the API Security Testing?

    Understand the API architecture and functionality
    Identify the attack surface
    API Fuzzing
    Authentication and Authorization Testing
    Input Validation Testing
    Access Control Testing
    Error Handling and Information Disclosure Testing
    API Security Headers
    Data Integrity and Encryption
    Rate Limiting and Anti-DoS Mechanisms
    Logging and Monitoring
    Secure Configuration and Deployment Testing
    Third-Party Integration and API Abuse
    Reporting and Remediation


---------------------------------
What kind of initial check to do on simple API link?



-------------------------------------

What to test in API

    Functional Testing
    Integration Testing
    Regrassion TEsting
    Security Testing
    Load Testing
    Penetration Testing
    Fuzz testing -Discover Coding Error

    API Monitering
    



