# scryptbc

`scryptbc` is a reimplementation of https://github.com/Tarsnap/scrypt
using Java and Bouncy Castle. As such, it is a working example of how
to use the SCRYPT key derivation function in Bouncy Castle. 

# License

MIT License - see LICENSE.txt for details

Copyright (c) 2022-2024 Jonathan W. Cranford

The scrypt-FORMAT.txt file is copied from the scrypt project at
https://raw.githubusercontent.com/Tarsnap/scrypt/master/FORMAT and is
governed by the copyright statement at the top of that file (also copied
from the scrypt project).

Includes example code from "Java Cryptography: Tools and Techniques",
by David Hook and Jon Eaves.
* https://leanpub.com/javacryptotoolsandtech
* https://downloads.bouncycastle.org/examples/java-crypto-tools-src.zip

# Usage

```
Usage: scryptbc [-hV] COMMAND
Encrypt and decrypt files with a Bouncycastle-based version of the scrypt
utility
  -h, --help      Show this help message and exit.
  -V, --version   Print version information and exit.
Commands:
  help  Display help information about the specified command.
  dec   Decrypts infile and writes the result to outfile if specified, or the
          standard output otherwise. The user will be prompted to enter the
          passphrase used at encryption time to generate the derived encryption
          key.
  info  Provides information about the encryption parameters used for infile.
```

# Implementation Notes

TODO - add some details about memory limits taken from JVM args, not from command-line