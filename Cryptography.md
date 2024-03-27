
===================================================
Diffrence beween encoding, hashing and encryption.
===================================================
Encoding:
        Data Copatibility. Encoding is a process of converting data from one format to another format. It is primarily used for data representation, compatibility, and readability. Common encoding schemes include Base64, URL encoding, and ASCII.
Hashing:
        VArify Data Integrity, Varify Data Integrity. Hashing is a one-way transformation that takes an input of any size and produces a fixed-length string of characters called a hash value. Common hash algorithms include MD5, SHA-1, SHA-256, and bcrypt.

Salting:
        is a concept that typically pertains to password hashing. Essentially, it's a unique value that can be added to the end of the password to create a different hash value. This adds a layer of security to the hashing process, specifically against brute force attacks.

hashing VS Salting:
        Hashing is a one-way function where data is mapped to a fixed-length value. Hashing is primarily used for authentication. Salting is an additional step during hashing, typically seen in association to hashed passwords, that adds an additional value to the end of the password that changes the hash value produced.


Encryption:
        Data confidentiality, Encryption is the process of converting data into an unreadable form (ciphertext) using an encryption algorithm and a secret key. The purpose of encryption is to protect data confidentiality and prevent unauthorized access. Encryption algorithms can be symmetric (using the same key for both encryption and decryption) or asymmetric (using different keys for encryption and decryption), with popular examples including AES (Advanced Encryption Standard) and RSA (Rivest-Shamir-Adleman).

==============================================================
How you can confirm that string either ENCODED, HASHED or ENCRYPTED by looking at it.
=============================================================

Encoded strings:
        Encoded strings are typically used to represent data in a different format, such as Base64 encoding.
        They often contain a limited set of characters, such as alphanumeric characters and specific symbols.

Hashed strings:
        Hashing is a one-way process that generates a fixed-length string from any input data.
        Hashed strings are usually of fixed length, regardless of the length of the input.
        Even a small change in the input data will produce a significantly different hashed string.

Encrypted strings:
        Encryption involves transforming data into a cipher text using an encryption algorithm and a key.
        Encrypted strings are typically longer than the original data.
        Encryption can be reversible with the correct decryption key.



============================
How hashes can be cracked.
============================
        Brute force attacks
        Rainbow table attacks
        Dictionary attacks

==========================
What is rainbow table.
=========================
        Rainbow tables are precomputed tables that contain a large number of possible inputs and their corresponding hash values. Attackers compare the target hash with the entries posibilitis in the rainbow table to find a actual match.

=============================================
What is Digital Signeture and how it works.
=============================================
Digital signatures work by proving that a digital message or document was not modified—intentionally or unintentionally—from the time it was signed. Digital signatures do this by generating a unique hash of the message or document and encrypting it using the sender's private key.