This program uses PGP Key pair generated locally and copied to the src/main/resources folder.
Upon running the Main method it will ask to provide an input string through the Console.

This string will be written to a signed and encrypted file encrypted_msg.pgp in the src/main/resources folder.
Then the above mentioned file will be read back and decrypted and verified and the plain text message will be written back as decrypted_msg.txt in src/main/resources folder.

Signing Alg Used: SHA384
Compression Alg: ZIP
Encryption Alg: AES256
