Android 


M1: Platform Misuse
M2: Lack of Data Storage Security
M3: Unsafe Communications
M4: Authentication Issues
M5: Lack of Cryptography
M6: Insufficient Authorization
M7: Poor-Quality Client Code
M8: Manipulated Code
M9: Reverse Engineering Attacks
M10: Redundant Functionality



============================
M1: Platform Misuse 
==================================
The improper usage of Android and iOS platforms is a leading threat, with many applications unintentionally violating the relevant security guidelines and best practices. Misuse extends to any feature of the platform or failure to implement security controls. 

    Injection (SQL, XSS, Command) on both web services and mobile-enabled websites
    Authentication flaws
    Session Management flaws
    Access control vulnerabilities
    Local and Remote File Includes

Prevent:
    Adhere to the platform development best practices and guidelines. 
    Use secure configuration and coding to the server-side. 
    Restrict applications from transmitting user data.
    Restrict file access permissions.
    Encrypt and store data securely.

=======================================
M2: Lack of Data Storage Security
=======================================
attackers can easily exploit stolen devices and  sensitive data. Sometimes an application must store data, but this data must remain in a secure location that other applications cannot access. 

    Keep data encrypted.
    Use an access authorization mechanism in the mobile application.
    Restrict the application’s access to stored data. 
    Use secure coding practices to prevent buffer overflow and data logging.

========================================
M3: Unsafe Communications
========================================
    Transmitting data to or from mobile applications usually involves the Internet or a telecommunications carrier. Attackers can intercept data in transit via compromised networks. 

    Use SSL/TLS certificates for secure transmission.
    Use signed and trusted CA certificates.
    Use encryption protocols.
    Send sensitive data to a back end API.
    Avoid sending user IDs with SSL session tokens.
    Implement encryption before SSL channel transmission.

=================================
M4: Authentication Issues
=================================
Mobile devices sometimes fail to identify users, allowing malicious scripts to log in using default credentials. Attackers can often bypass authentication protocols due to poor implementation. 

    Use the right authentication method (i.e., server-side mechanism). 
    Avoid storing passwords on local and user devices.
    Avoid persistent authentication functionalities and display caution signals if users opt for them.
    Use device-based authentication to prevent users from accessing data from other devices.
    Implement binary attack protection.

=====================================
M5: Lack of Cryptography
=====================================
Without sufficient cryptography, attackers can get sensitive data to the original state and enable unauthorized access. This vulnerability is usually easy to exploit. 

    Avoid storing data on mobile devices.
    Use robust cryptography algorithms.

========================================
M6: Insufficient Authorization
========================================
Without sufficient authorization measures, intruders can access sensitive data and escalate privileges to expand their attacks. Insecure direct object reference (IDOR) allows attackers to access files, accounts, and databases. The app is insecure if the authorization mechanism fails to verify users and grant permissions. 

    Avoid granting access permissions and roles via mobile devices.
    Verify identities independently via back end code.

==================================
M7: Poor-Quality Client Code 
==================================
Poor coding practices can result in vulnerable code. The risk is especially high when team members use different coding techniques and fail to collaborate or provide sufficient documentation. Detecting this vulnerability is challenging because hackers must be aware of the poor coding practices.

Enforce good coding practices with consistent patterns across the organization.
Perform static code analysis.
Use complex logic code.
Securely integrate external libraries.
Use automated tools to test memory leaks, buffer overflow, and code execution.

=========================================
M8: Manipulated Code 
=========================================
App stores often contain manipulated versions of mobile applications, such as apps with modified binaries, including malicious content or backdoors. Attackers can deliver these counterfeit applications directly to the victim via phishing or publish them on app stores. 

To prevent attackers from tampering with code:

Inspect the code for test keys, OTA certificates, rooted APKs, and SU binaries.
Look for the ro.build.tags=test-keys in the build.prop to see if it’s an unofficial ROM or developer build.
Attempt commands directly (i.e., SU commands).
Set up alerts for code integration and respond accordingly to incidents.
Implement anti-tampering measures like validation, code hardening, and digital signatures.

=========================================
M9: Reverse Engineering Attacks
==========================================
Attackers can reverse engineer applications and perform code analysis—this is especially dangerous because attackers can inspect and modify the code to inject malicious functionalities. Reverse engineering allows attackers to understand how an application operates, allowing them to recompile it. 

To protect mobile applications from reverse engineering:

Check if it’s possible to decompile the application.
Use debugging tools to run the application from an attacker’s perspective.
Ensure robust obfuscation (including for metadata).
Develop the application using C or C++ to protect the code.
Use binary packaging to prevent attackers from decompiling code.
Block debugging tools.

==========================================
M10: Redundant Functionality
=======================================
Attackers can examine mobile applications via log and configuration files, identifying and exploiting redundant functionalities to access the back end. For example, an attacker might anonymously execute privileged actions. Manual code reviews before release help mitigate this risk.

To identify and eliminate redundant functionality:

Inspect the application’s configurations for hidden switches.
Check that the log statement and API endpoints are not publicly exposed. 
Check if the app’s accessible API endpoint is properly documented.
Check if the log contains content exposing privileged accounts or back end server processes.


=====================================================
What is SSL pining and how this can be bypassed.
===================================================
    SSL certificate pinning is a technique designed to prevent dangerous and complex security attacks. This security measure pins the identity of trustworthy certificates on mobile apps and blocks unknown documents from the suspicious servers.

    frida --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -f YOUR_BINARY

    Xpose toll > SSL Pinning


    Mitigate:
        Regularly update the SSL pinning logic
        Certificate pinning and key validation
        Use hardware-backed security
        anti-tampering techniques
        Runtime Integrity Checks
        Certificate transparency monitoring
        Continuous monitoring and threat intelligence
        Secure software development practices
        User education and awareness


=========================================
What are vulnerable permissions and why.
========================================
READ_CALENDAR, WRITE_CALENDAR, CAMERA, READ_CONTACTS, WRITE_CONTACTS, RECORD_AUDIO, READ_PHONE_NUMBERS, CALL_PHONE, ANSWER_PHONE_CALLS, SEND_SMS, RECEIVE_SMS, READ_SMS

==================================
What all thing you will check in manifest file for mobile appsec.
================================
All permissions
Components and Activities
Intent Filters
Exported Services
App Sandbox and Permissions
Security Configurations (enforcing HTTPS)
App Signatures  -   digital signatures
Android-specific Checks
Third-Party Libraries and Providers
Additional Manifest Metadata


==================
Shared Preferences.
==================

    Shared Preferences is a data storage mechanism in Android that allows applications to store and retrieve small amounts of data in key-value pairs. It provides a simple and lightweight way to persist data in the form of primitive data types, such as strings, booleans, integers, floats, and long values.

    Purpose, File Storage, Key-Value Structure, Accessibility


Root detection:
    frida -U -r packagename -l hooking.js --no-pause

    My fav 7 methods for Bypassing Android Root detection
    https://kishorbalan.medium.com/my-fav-7-methods-for-bypassing-android-root-detection-f8afb0ddfaf3

    Mitigation
        Check for System Properties:
            properties such as "ro.secure" or "ro.debuggable" to identify rooted devices.

        Check for Superuser Binary:
            The presence of superuser binaries (like su binary) is a clear indicator of a rooted device. You can check for the existence of these binaries in common root locations.

        Check for Rooted Files and Directories:
            Some root-related files and directories may exist on rooted devices. For example, you can check for the presence of "/system/bin/su" or "/system/xbin/su" as indicators of root access.

        SafetyNet API:
            Google provides the SafetyNet API, which can be used to assess the integrity of a device. It checks for signs of root access, tampering, and other security issues. Note that this requires a network connection, and the device must have Google Play services installed.

        Use Native Code Obfuscation:
            Implement native code obfuscation to make it more difficult for attackers to analyze and modify your app's code.


What is Smalli

    Smali is a type of assembly language for the Dalvik virtual machine, which is used by Android devices. It is used to modify and reverse engineer Android apps, and allows developers to make changes to the bytecode of an app.

