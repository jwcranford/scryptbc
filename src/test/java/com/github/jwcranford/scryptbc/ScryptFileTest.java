package com.github.jwcranford.scryptbc;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class ScryptFileTest {

    private static final String PASSPHRASE = "passphrase";

    private static final String HELLOWORLD = "Hello world\n";

    @Test
    public void wrong_password_throws_Exception() {
        byte[] input = Hex.decode(HeaderTest.HELLOWORLD_HEX);
        assertThrows(ScryptException.WrongPassword.class,
                () -> ScryptFile.decrypt(input, "wrong password".toCharArray(), new NullOutputStream()));
    }

    @Test
    public void valid_input_decrypts_successfully() throws IOException, ScryptException {
        byte[] input = Hex.decode(HeaderTest.HELLOWORLD_HEX);
        var out = new ByteArrayOutputStream();
        ScryptFile file = ScryptFile.decrypt(input, PASSPHRASE.toCharArray(), out);
        assertNotNull(file);
        assertArrayEquals(HELLOWORLD.getBytes(StandardCharsets.US_ASCII), out.toByteArray());
    }

    @Test
    public void corrupted_input_is_detected() {
        byte[] input = Hex.decode(HeaderTest.HELLOWORLD_HEX);
        input[96] = 0;
        input[97] = 0;
        input[99] = 0;
        assertThrows(ScryptException.CorruptFile.class,
                () -> ScryptFile.decrypt(input, PASSPHRASE.toCharArray(), new NullOutputStream()));
    }

    @Test
    public void encrypt_and_decrypt_work_symmetrically() throws IOException, ScryptException {
        var file = new ScryptFile(HeaderTest.HELLOWORLD_LOG2N, HeaderTest.HELLOWORLD_R, HeaderTest.HELLOWORLD_P);
        var cipherStream = new ByteArrayOutputStream();
        byte[] plaintext = HELLOWORLD.getBytes(StandardCharsets.US_ASCII);
        file.encrypt(plaintext, PASSPHRASE.toCharArray(), cipherStream);
        var decryptedStream = new ByteArrayOutputStream();
        ScryptFile.decrypt(cipherStream.toByteArray(), PASSPHRASE.toCharArray(), decryptedStream);
        assertArrayEquals(plaintext, decryptedStream.toByteArray());
    }
}

class NullOutputStream extends OutputStream {
    NullOutputStream() {
    }

    @Override
    public void write(int b) {
    }
}