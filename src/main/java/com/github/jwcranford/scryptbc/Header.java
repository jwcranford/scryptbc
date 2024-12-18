package com.github.jwcranford.scryptbc;

import org.bouncycastle.util.Pack;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class Header {
    private static final int BYTES_IN_MB = 1 << 20;
    private static final long MEM_USAGE_FACTOR = 128L;

    static final int HEADER_LEN = 64;
    static final byte[] MAGIC = "scrypt".getBytes(StandardCharsets.US_ASCII);
    static final byte VERSION = 0;
    static final int VERSION_OFFSET = 6;
    static final int LOG2N_OFFSET = 7;
    static final int R_OFFSET = 8;
    static final int P_OFFSET = 12;
    private static final int SALT_OFFSET = 16;
    private static final int SALT_LEN = 32;
    private static final int FIRST_HASHABLE_LEN = 48;
    static final int FIRST_HASH_OFFSET = 48;
    static final int FIRST_HASH_LEN = 16;
    public static final int MAX_LOG2N = 63;
    public static final int MAX_RP = 1 << 30;

    private final byte log2N;
    private final int r;
    private final int p;
    private final byte[] salt;

    private byte[] encodedBytes;

    public Header(byte log2N, int r, int p, byte[] salt) {
        if (invalidLog2N(log2N)) {
            throw new IllegalArgumentException(String.format("invalid log2N - must be between 1 and %d inclusive", MAX_LOG2N));
        }
        if (invalidRP(r, p)) {
            throw new IllegalArgumentException("Invalid r and p; must satisfy r * p < 2 ^ 30");
        }
        this.log2N = log2N;
        this.r = r;
        this.p = p;
        this.salt = salt;
    }

    /**
     * Parses the given input stream using the scrypt file format. Does not close the input stream.
     *
     * @param in input stream
     * @return a parsed ScryptFile instance
     * @throws IOException                if there's an error reading the input stream
     * @throws ScryptException if there's an error decoding the input stream
     * @throws java.io.EOFException       if EOF is reached prematurely
     */
    public static Header decode(final InputStream in) throws IOException, ScryptException {
        byte[] header = readNBytesFully(in, "header", HEADER_LEN);
        if (!Arrays.equals(MAGIC, 0, MAGIC.length,
                header, 0, MAGIC.length)) {
            throw new ScryptException.InvalidField("header", MAGIC, Arrays.copyOfRange(header, 0, MAGIC.length));
        }
        if (header[VERSION_OFFSET] != VERSION) {
            throw new ScryptException.InvalidField("version", VERSION, header[VERSION_OFFSET]);
        }

        byte log2n = header[LOG2N_OFFSET];
        if (invalidLog2N(log2n)) {
            throw new ScryptException.InvalidLog2n(log2n);
        }

        int r = Pack.bigEndianToInt(header, R_OFFSET);
        int p = Pack.bigEndianToInt(header, P_OFFSET);
        if (invalidRP(r, p)) {
            throw new ScryptException.InvalidRP(r, p);
        }

        byte[] salt = Arrays.copyOfRange(header, SALT_OFFSET, SALT_OFFSET + SALT_LEN);

        byte[] firstHash = BcUtil.computeDigest(header, 0, FIRST_HASHABLE_LEN);
        if (!Arrays.equals(firstHash, 0, FIRST_HASH_LEN,
                header, FIRST_HASH_OFFSET, FIRST_HASH_OFFSET + FIRST_HASH_LEN)) {
            throw new ScryptException.InvalidField("hash", firstHash,
                    Arrays.copyOfRange(header, FIRST_HASH_OFFSET, FIRST_HASH_OFFSET + FIRST_HASH_LEN));
        }

        var hdr = new Header(log2n, r, p, salt);
        hdr.setEncodedBytes(header);
        return hdr;
    }

    /**
     * Encodes the instance into the scrypt file header format, returning the encoded bytes.
     * <p>
     * Note that the return value is memoized, so that subsequent calls to
     * {@link #getEncodedBytes()} will return the same value.
     */
    public byte[] encode() {
        var out = new ByteArrayOutputStream(HEADER_LEN);
        out.writeBytes(MAGIC);
        out.write(VERSION);
        out.write(log2N);
        out.writeBytes(Pack.intToBigEndian(r));
        out.writeBytes(Pack.intToBigEndian(p));
        out.writeBytes(salt);
        var firstBytes = out.toByteArray();
        var firstHash = BcUtil.computeDigest(firstBytes);
        out.write(firstHash, 0, FIRST_HASH_LEN);
        encodedBytes = out.toByteArray();
        return encodedBytes;
    }

    private static boolean invalidRP(int r, int p) {
        return r * p >= MAX_RP;
    }

    private static boolean invalidLog2N(byte log2n) {
        return log2n < 1 || log2n > MAX_LOG2N;
    }


    public static Header decode(byte[] bytes) throws ScryptException {
        try {
            return decode(new ByteArrayInputStream(bytes));
        } catch (IOException e) {
            // ByteArrayInputStream doesn't throw IOException, but we
            // have to catch it anyway according to the type signature
            throw new RuntimeException(e);
        }
    }

    static byte[] readNBytesFully(InputStream in, String fieldName, int len) throws IOException {
        byte[] actual = in.readNBytes(len);
        if (actual.length < len) {
            throw new IOException("Unexpected end of stream while reading " + fieldName);
        }
        return actual;
    }

    public long calcMbRequired() {
        return calcMemRequired() / BYTES_IN_MB;
    }

    public long calcMemRequired() {
        return MEM_USAGE_FACTOR * (1L << log2N) * r;
    }

    public byte getLog2N() {
        return log2N;
    }

    public int getR() {
        return r;
    }

    public int getP() {
        return p;
    }

    /**
     * @return defensive copy of the salt array
     */
    public byte[] getSalt() {
        return Arrays.copyOf(salt, salt.length);
    }

    public byte[] getEncodedBytes() {
        return encodedBytes;
    }

    public void setEncodedBytes(byte[] encodedBytes) {
        this.encodedBytes = encodedBytes;
    }

}
