package com.github.jwcranford.scryptbc;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import static com.github.jwcranford.scryptbc.Header.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class HeaderTest {

    // Heads up - this scrypt file takes 2GB to decrypt
    static final String HELLOWORLD_HEX =
            "736372797074001400000008000000018be0865ea0d0a5897c8c53fc0952355d450487b28ba8e6cbb1c30a85f0112d035be0a9e97db2468659459719b4948446759eb4cab6541dcb921798240c8e4c8949000ef60757598c7e4e14a7cd9bb0d91ca9ce5e3426077ee79bbbc82cc5a146dec44cc793d17a8a520a67e55747a9fa4de3bedd7616c8b9435912e7";
    private static final byte[] HELLOWORLD_ENC_BYTES = Hex.decode(HELLOWORLD_HEX);
    static final byte HELLOWORLD_LOG2N = 0x14;
    static final int HELLOWORLD_R = 0x8;
    static final int HELLOWORLD_P = 1;
    private static final byte[] INVALID_HEADER = "invalid".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] INVALID_HEADER2 = "œ∑ß≈ç√".getBytes(StandardCharsets.UTF_8);
    private static final byte INVALID_VERSION = 1;
    private static final String SALT_HEX = "8be0865ea0d0a5897c8c53fc0952355d450487b28ba8e6cbb1c30a85f0112d03";

    @ParameterizedTest
    @MethodSource("headerSource")
    public void invalid_input_stream_throws_exception(byte[] header) {
        var input = Arrays.concatenate(
                header,
                Arrays.copyOfRange(HeaderTest.HELLOWORLD_ENC_BYTES, MAGIC.length, HeaderTest.HELLOWORLD_ENC_BYTES.length)
        );
        assertThrows(ScryptException.InvalidField.class,
                () ->
                        decode(input)
        );
    }

    @Test
    public void valid_input_is_accepted() throws ScryptException {
        byte[] input = Hex.decode(HeaderTest.HELLOWORLD_HEX);
        Header file = decode(input);
        assertEquals(HeaderTest.HELLOWORLD_LOG2N, file.getLog2N());
        assertEquals(HeaderTest.HELLOWORLD_R, file.getR());
        assertEquals(HeaderTest.HELLOWORLD_P, file.getP());
        assertEquals(HeaderTest.SALT_HEX, Hex.toHexString(file.getSalt()));
    }

    static Stream<byte[]> headerSource() {
        return Stream.of(INVALID_HEADER, INVALID_HEADER2);
    }

    @Test
    public void invalid_version_throws_Exception() {
        byte[] bytes = Arrays.copyOf(HeaderTest.HELLOWORLD_ENC_BYTES, HeaderTest.HELLOWORLD_ENC_BYTES.length);
        bytes[VERSION_OFFSET] = HeaderTest.INVALID_VERSION;
        assertThrows(ScryptException.InvalidField.class,
                () -> decode(bytes));
    }

    @ParameterizedTest
    @ValueSource(bytes = { -1, 0, 64 })
    public void invalid_log2N_throws_Exception(byte log2n) {
        byte[] input = Arrays.copyOf(HeaderTest.HELLOWORLD_ENC_BYTES, HeaderTest.HELLOWORLD_ENC_BYTES.length);
        input[LOG2N_OFFSET] = log2n;
        assertThrows(ScryptException.InvalidLog2n.class,
                () -> decode(input));
    }

    @ParameterizedTest
    @MethodSource("rpSource")
    public void invalid_r_p_throws_Exception(int[] rp) {
        byte[] input = Arrays.copyOf(HeaderTest.HELLOWORLD_ENC_BYTES, HeaderTest.HELLOWORLD_ENC_BYTES.length);
        System.arraycopy(Pack.intToBigEndian(rp[0]), 0, input, R_OFFSET, 4);
        System.arraycopy(Pack.intToBigEndian(rp[1]), 0, input, P_OFFSET, 4);
        assertThrows(ScryptException.InvalidRP.class,
                () -> decode(input));
    }

    static Stream<int[]> rpSource() {
        return Stream.of(
                new int[] {1 << 15, 1 << 15},
                new int[] {1 << 16, 1 << 14},
                new int[] {1 << 17, 1 << 13},
                new int[] {1 << 18, 1 << 12},
                new int[] {1 << 19, 1 << 11},
                new int[] {1 << 20, 1 << 10},
                new int[] {1 << 21, 1 << 9},
                new int[] {1 << 22, 1 << 8},
                new int[] {1 << 23, 1 << 7},
                new int[] {1 << 24, 1 << 6},
                new int[] {1 << 25, 1 << 5},
                new int[] {1 << 26, 1 << 4},
                new int[] {1 << 27, 1 << 3},
                new int[] {1 << 28, 1 << 2},
                new int[] {1 << 29, 1 << 1},
                new int[] {1 << 30, 1 }
        );
    }

    @Test
    public void invalid_hash_throws_Exception() {
        byte[] bytes = BcUtil.computeDigest("not the right data".getBytes(StandardCharsets.US_ASCII));
        byte[] input = Arrays.copyOf(HeaderTest.HELLOWORLD_ENC_BYTES, HeaderTest.HELLOWORLD_ENC_BYTES.length);
        System.arraycopy(bytes, 0, input, FIRST_HASH_OFFSET, FIRST_HASH_LEN);
        assertThrows(ScryptException.InvalidField.class,
                () -> decode(input)
        );
    }

    @Test
    public void encode_works() {
        var header = new Header(HELLOWORLD_LOG2N, HELLOWORLD_R, HELLOWORLD_P, Hex.decode(SALT_HEX));
        assertEquals(HELLOWORLD_HEX.substring(0, 128), Hex.toHexString(header.encode()));
    }

    @Test
    public void test_calcDefaultLog2N() {
        assertEquals(20, calcDefaultLog2N(1<<30, DEFAULT_R));
        assertEquals(19, calcDefaultLog2N(1<<29, DEFAULT_R));
        assertEquals(18, calcDefaultLog2N(1<<28, DEFAULT_R));
    }
}
