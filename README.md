# scryptbc

`scryptbc` is a reimplementation of https://github.com/Tarsnap/scrypt
using Java and Bouncy Castle (https://www.bouncycastle.org/). As such, it is a working example of how
to use the SCRYPT key derivation function in Bouncy Castle. 

You can use `scryptbc` to encrypt and decrypt files with a password. `scryptbc` derives a secure symmetric key
from the password, and uses it to encrypt or decrypt the given file. The SCRYPT key derivation function 
is designed to be far more secure against hardware brute-force attacks than alternative functions 
such as PBKDF2 or bcrypt.

`scryptbc` has a similar command-line interface to `scrypt`, to simplify interoperability testing.

# Usage

```
scryptbc [-hV] COMMAND
  -h, --help      Show this help message and exit.
  -V, --version   Print version information and exit.
```

## Commands

### Help
Display help information about the specified command.

```
scryptbc help info
scryptbc help dec
scryptbc help enc
```

### Info
Provide information about the encryption parameters used for the given file.

```
scryptbc info infile
```

### Decryption
Decrypt infile and write the result to outfile. The user will be prompted to enter the passphrase used at
encryption time to derive the encryption key.

```
scryptbc dec [-v] infile outfile
  -v, --verbose   Print encryption parameters (N, r, p) and memory/cpu limits 
                    to standard error
```

### Encryption
Encrypt infile and write the result to outfile.  The user will be prompted to enter a passphrase (twice) to
be used to derive the encryption key.

```
scryptbc enc [-v] [--logN=<arg1>] [-p=<arg3>] [-r=<arg2>] infile outfile
  --logN=<arg1>       Set the work parameter N to 2^value.  If --logN is set,
                        -r and -p must also be set for the logN value to be
                        used; otherwise, a default value is calculated based on
                        half of the maximum heap size of the JVM.
  -p=<arg3>           Set the work parameter p to value.  If -p is set, --logN
                        and -r must also be set for the p value to be used;
                        otherwise, a default value of 1 is used.
  -r=<arg2>           Set the work parameter r to value.  If -r is set, --logN
                        and -p must also be set for the r value to be used;
                        otherwise, a default value of 8 is used.
  -v, --verbose       Print encryption parameters (N, r, p) and memory/cpu
                        limits to standard error
```

# Implementation Notes

The decryption sub-command (`scryptbc dec`) exits with an error message if 
the max heap memory is too small to generate the decryption key for the input file,
based on the `N` and `r` parameters in the file header. See
https://blog.filippo.io/the-scrypt-parameters/ for a great discussion on how the 
N, r, and p parameters affect memory and CPU usage.

To specify the max heap size from the command line, set the `JAVA_OPTS` environment variable, 
as in the following:

```
JAVA_OPTS=-Xmx1200M scryptbc dec infile outfile
```

# Building

This project uses gradle as the build tool. 

```
./gradlew build installDist 
cd build/install/scryptbc/bin
./scryptbc -h 
```

## Releases

The releases available in github were built using the following commands, using the 0.2.0 
release as an example. 

```
git tag v0.2.0
./gradlew clean build 
cd build/distributions
mv scryptbc.tar scryptbc-0.2.0.tar
mv scryptbc.zip scryptbc-0.2.0.zip
git push --tags
```

`scryptbc-0.2.0.tar` and `scryptbc-0.2.0.zip` were then uploaded as a release in github.

# Interoperability Testing with scrypt

The following commands assume that scrypt is installed on the PATH.

```
cd build/install/scryptbc/bin

scrypt enc scryptbc scryptbc.enc
./scryptbc dec -v scryptbc.enc scryptbc.dec
diff scryptbc scryptbc.dec

./scryptbc enc scryptbc scryptbc.enc2
scrypt dec -v scryptbc.enc2 scryptbc.dec2
diff scryptbc scryptbc.dec2
```

# License

MIT License - see LICENSE.txt for details

Copyright (c) 2022-2025 Jonathan W. Cranford

The scrypt-FORMAT.txt file is copied from the scrypt project at
https://raw.githubusercontent.com/Tarsnap/scrypt/master/FORMAT and is
governed by the copyright statement at the top of that file.

Includes example code from "Java Cryptography: Tools and Techniques",
by David Hook and Jon Eaves.
* https://leanpub.com/javacryptotoolsandtech
* https://downloads.bouncycastle.org/examples/java-crypto-tools-src.zip
