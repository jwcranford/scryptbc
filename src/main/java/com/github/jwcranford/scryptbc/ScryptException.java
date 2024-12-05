package com.github.jwcranford.scryptbc;

import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;

public class ScryptException extends Exception {
    public ScryptException(String message) {
        super(message);
    }

    public ScryptException(Throwable cause) {
        super(cause);
    }

    public static class WrongPassword extends Decryption {
        public WrongPassword() {
            super("Wrong password");
        }
    }

    public static class CorruptFile extends Decryption {
        public CorruptFile(byte[] expected, byte[] actual) {
            super(String.format("File integrity check failed. Expected HMAC: %s, Actual HMAC: %s",
                    Hex.toHexString(expected), Hex.toHexString(actual)));
        }
    }

    public static class Decryption extends ScryptException {
        public Decryption(Exception cause) {
            super(cause);
        }

        public Decryption(String message) {
            super(message);
        }
    }

    public static class InvalidField extends ScryptException {
        public InvalidField(String fieldName, byte[] expected, byte[] actual) {
            super(String.format("Invalid %s. Expected '%s' (0x%s), read '%s' (0x%s) instead",
                    fieldName,
                    new String(expected, StandardCharsets.US_ASCII),
                    Hex.toHexString(expected),
                    new String(actual, StandardCharsets.US_ASCII),
                    Hex.toHexString(actual))
            );
        }

        public InvalidField(String fieldName, byte expected, byte actual) {
            super(String.format("Invalid %s. Expected %d, read %d instead", fieldName, expected, actual));
        }
    }

    public static class InvalidLog2n extends ScryptException {
        public InvalidLog2n(byte log2n) {
            super(String.format("Invalid log2N: %d", log2n));
        }
    }

    public static class InvalidRP extends ScryptException {
        public InvalidRP(int r, int p) {
            super(String.format("Invalid R or P value: R=%d, P=%d", r, p));
        }
    }
}
