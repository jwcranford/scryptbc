package com.github.jwcranford.scryptbc;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import java.io.*;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * Represents a file following the scrypt file format.
 *
 * <h3>Usage</h3>
 * <pre>
 *    try {
 *         ScryptFile file = ScryptFile.decrypt(inputFile, password, outputFile);
 *         Header header = file.getHeader();
 *    } catch (IOException e) {
 *        // handle I/O error
 *    } catch (ScryptException e) {
 *        // handle error decrypting the input stream
 *    }
 * </pre>
 *
 * <p>
 *     Note that in the case of error, partially decrypted data can be sent to the outputFile. The caller
 *     is responsible for discarding the data if an exception is thrown.
 * </p>
 */
public final class ScryptFile {

    private static final int GENERATED_KEY_BITS = 64 * 8;
    private static final int HMAC_KEY_OFFSET = 32;
    private static final int GENERATED_KEY_LEN = 32;
    private static final int HMAC_LEN = 32;
    private static final int IV_SIZE = 16;

    private final Header header;

    public ScryptFile(Header header) {
        this.header = header;
    }

    /**
     * Decrypt the given input stream of the given length, with the given password. The decrypted data is sent
     * to the given output stream.
     *
     * <p>
     *     Note that the caller is responsible to discard the output data if an exception is thrown and the decryption
     *     doesn't successfully complete.
     * </p>
     *
     * @param inputStream input stream. This stream is always closed before the method returns
     * @param len length of the input stream
     * @param password password used to generate the symmetric encryption key.
     *                 Note that this method clears the password array immediately after use, as a security precaution.
     * @param outputStream decrypted data gets sent here. This stream is always closed before the method returns.
     * @return an ScryptFile object that holds the scrypt header read from the input stream
     * @throws IOException on I/O error
     * @throws ScryptException on an error decrypting the data
     */
    public static ScryptFile decrypt(InputStream inputStream, long len, char[] password, OutputStream outputStream)
            throws IOException, ScryptException {
        // first off, verify that the length of the input is at least the length
        // of the header and the two HMACs
        int minLength = Header.HEADER_LEN + HMAC_LEN + HMAC_LEN;
        if (len < minLength) {
            throw new ScryptException("Not a valid scrypt file: expected at least " + minLength + " bytes; actual = " + len);
        }

        try (inputStream) {
            Header header = Header.decode(inputStream);
            if (header.calcMemRequired() > Runtime.getRuntime().maxMemory()) {
                var msg = String.format("Not enough memory to derive the decryption key. Run again with a heap size larger than %,d MB.",
                        header.calcMbRequired());
                throw new ScryptException(msg);
            }
            byte[] generatedKeys = null;
            try {
                generatedKeys = BcUtil.jceScrypt(
                            password,
                            header.getSalt(),
                            1 << header.getLog2N(),
                            header.getR(),
                            header.getP(),
                            GENERATED_KEY_BITS);
            } catch (OutOfMemoryError e) {
                System.err.printf("Not enough memory to generate the symmetric encryption key. Run again with a heap size larger than %,d bytes.%n",
                        Runtime.getRuntime().maxMemory());
                throw e;
            }

            // clear password, since we don't need it anymore
            Arrays.fill(password, (char) 0);

            try {
                Mac mac = BcUtil.newHmacSha256Mac(generatedKeys, HMAC_KEY_OFFSET);
                mac.update(header.getEncodedBytes(), 0, Header.HEADER_LEN);
                byte[] firstHMac = mac.doFinal();

                byte[] actualHMac = Header.readNBytesFully(inputStream, "HMAC", HMAC_LEN);
                if (!Arrays.equals(firstHMac, actualHMac)) {
                    throw new ScryptException.WrongPassword();
                }

                byte[] iv = new byte[IV_SIZE];
                Cipher aesCipher = BcUtil.initAESCTRDecryptCipher(generatedKeys, 0, GENERATED_KEY_LEN, iv);
                final int blockSize = aesCipher.getBlockSize();
                byte[] buf = new byte[blockSize];
                long remaining = len - (HMAC_LEN + HMAC_LEN + Header.HEADER_LEN);
                mac.update(header.getEncodedBytes());
                mac.update(actualHMac);
                try (outputStream) {
                    while (remaining > 0) {
                        int read = inputStream.read(buf, 0, min(remaining, blockSize));
                        var dec = aesCipher.update(buf, 0, read);
                        if (dec != null) {
                            outputStream.write(dec);
                        }
                        mac.update(buf, 0, read);
                        remaining -= read;
                        Arrays.fill(buf, (byte) 0 ); // zero out array between reads defensively
                    }
                    outputStream.write(aesCipher.doFinal());
                }

                // verify hmac
                byte[] lastHmac = mac.doFinal();
                byte[] actualLastHmac = Header.readNBytesFully(inputStream, "finalHmac", HMAC_LEN);
                if (!Arrays.equals(lastHmac, actualLastHmac)) {
                    throw new ScryptException.CorruptFile(lastHmac, actualLastHmac);
                }

                return new ScryptFile(header);

            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new ScryptException.Decryption(e);
            }
        }
    }

    /**
     * Encrypt the given input stream with the given password. The encrypted data is sent
     * to the given output stream.
     *
     * <p>
     *     Note that the caller is responsible to discard the output data if an exception is thrown and the encryption
     *     doesn't successfully complete.
     * </p>
     *
     * @param inputStream input stream. This stream is always closed before the method returns
     * @param password password used to generate the symmetric encryption key.
     *                 Note that this method clears the password array immediately after use, as a security precaution.
     * @param outputStream encrypted data gets sent here. This stream is always closed before the method returns.
     * @throws IOException on I/O error
     * @throws ScryptException on an error encrypting the data
     */
    public void encrypt(InputStream inputStream, char[] password, OutputStream outputStream) throws IOException, ScryptException {
        if (header.calcMemRequired() > Runtime.getRuntime().maxMemory()) {
            var msg = String.format("Not enough memory to derive the symmetric encryption key with log2N=%d. Run again with a heap size larger than %,d MB, or with a smaller value for log2N",
                    header.getLog2N(), header.calcMbRequired());
            throw new ScryptException(msg);
        }

        byte[] generatedKeys = null;
        try {
            generatedKeys = BcUtil.jceScrypt(
                    password,
                    header.getSalt(),
                    1 << header.getLog2N(),
                    header.getR(),
                    header.getP(),
                    GENERATED_KEY_BITS);
        } catch (OutOfMemoryError e) {
            System.err.printf("Not enough memory to generate the symmetric encryption key with log2N=%d. Run again with a heap size larger than %,d bytes, or with a smaller value for log2N.%n",
                    header.getLog2N(), Runtime.getRuntime().maxMemory());
            throw e;
        }

        // clear password, since we don't need it anymore
        Arrays.fill(password, (char) 0);

        // encrypt
        try (outputStream) {
            outputStream.write(header.encode());
            try {
                Mac mac = BcUtil.newHmacSha256Mac(generatedKeys, HMAC_KEY_OFFSET);
                mac.update(header.getEncodedBytes(), 0, Header.HEADER_LEN);
                byte[] firstHMac = mac.doFinal();
                outputStream.write(firstHMac);

                byte[] iv = new byte[IV_SIZE];
                Cipher aesCipher = BcUtil.initAESCTREncryptCipher(generatedKeys, 0, GENERATED_KEY_LEN, iv);
                final int blockSize = aesCipher.getBlockSize();
                byte[] buf = new byte[blockSize];
                mac.update(header.getEncodedBytes());
                mac.update(firstHMac);
                try (inputStream) {
                    int read = inputStream.read(buf, 0, blockSize);
                    while (read > 0) {
                        var enc = aesCipher.update(buf, 0, read);
                        if (enc != null) {
                            outputStream.write(enc);
                            mac.update(enc);
                        }
                        Arrays.fill(buf, (byte) 0); // zero out array between reads defensively
                        read = inputStream.read(buf, 0, blockSize);
                    }
                }
                byte[] last = aesCipher.doFinal();
                outputStream.write(last);
                mac.update(last);

                byte[] lastHmac = mac.doFinal();
                outputStream.write(lastHmac);

            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new ScryptException.Encryption(e);
            }
        }
    }

    private static int min(long bigNumber, int littleNumber) {
        if (bigNumber > Integer.MAX_VALUE) {
            return littleNumber;
        }
        return Math.min((int)bigNumber, littleNumber);
    }

    /** Convenience method */
    public static ScryptFile decrypt(byte[] bytes, char[] password, OutputStream outputStream) throws IOException, ScryptException {
        return decrypt(new ByteArrayInputStream(bytes), bytes.length, password, outputStream);
    }

    /** Convenience method */
    public void encrypt(byte[] bytes, char[] password, OutputStream outputStream) throws IOException, ScryptException {
        encrypt(new ByteArrayInputStream(bytes), password, outputStream);
    }

    /** Convenience method */
    public static ScryptFile decrypt(File inputFile, char[] password, File outputFile)
            throws IOException, ScryptException {
        return decrypt(new FileInputStream(inputFile), inputFile.length(), password, new FileOutputStream(outputFile));
    }

    /** Convenience method */
    public void encrypt(File inputFile, char[] password, File outputFile)
            throws IOException, ScryptException {
        encrypt(new FileInputStream(inputFile), password, new FileOutputStream(outputFile));
    }

    public Header getHeader() {
        return header;
    }

}
