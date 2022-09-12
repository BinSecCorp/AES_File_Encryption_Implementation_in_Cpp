# AES_implementation_in_C-

# USAGE #

Encryption:
```
./executable_file -e <unencrypted_file> <encrypted_file> <key in hex>
```
Decryption:
```
./executable_file -d <encrypted_file> <output_file> <key in hex>
```

Note: The 128-bit encryption key must be in hexidecimal (32 hex digits).

Note: If the encrypted file is to be transfered to another system by any means, it is recommended to use an unknown .e file extension to avoid formatting or auto compression issues, which may prevent the decryption of said file.

Note: The current main branch includes progress report. If you would rather do without it because of performance issues, build V2-patch.

# Build #
The single source file can be simply compiled using g++.
```
g++ -o executable_file AES_encryption.cpp
```
