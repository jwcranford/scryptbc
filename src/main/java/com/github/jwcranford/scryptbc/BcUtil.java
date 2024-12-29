package com.github.jwcranford.scryptbc;

import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/*
 * Adapted from the example code for Java Cryptography: Tools and Techniques,
 * by David Hook and Jon Eaves.
 */
public class BcUtil {
    static final Provider BC = new BouncyCastleProvider();
    public static final String SHA_256 = "SHA-256";
    public static final String HMAC_SHA_256 = "HmacSHA256";
    public static final String SCRYPT = "SCRYPT";
    public static final int HMAC_256_KEY_LEN = 32;
    public static final String AES_CTR_NO_PADDING = "AES/CTR/NoPadding";
    public static final String AES = "AES";


    static {
        Security.addProvider(BC);
    }


    /**
     * Return a digest computed over data using SHA-256
     *
     * @param data the input for the digest function.
     * @param offset input starts at offset
     * @param len length of the input from the data array
     * @return the computed message digest.
     */
    public static byte[] computeDigest(byte[] data, int offset, int len)
    {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256, BC);
            digest.update(data, offset, len);
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Return a digest computed over data using SHA-256
     *
     * @param data the input for the digest function.
     * @return the computed message digest.
     */
    public static byte[] computeDigest(byte[] data)
    {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256, BC);
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Calculate a derived key using SCRYPT using the BC JCE provider.
     *
     * @param password the password input.
     * @param salt the salt parameter.
     * @param costParameter the cost parameter.
     * @param blocksize the blocksize parameter.
     * @param parallelizationParam the parallelization parameter.
     * @param keySize number of bits in the generated key
     * @return the derived key.
     */
    public static byte[] jceScrypt(char[] password, byte[] salt,
                                int costParameter, int blocksize,
                                int parallelizationParam, int keySize)
    {
        try {
            SecretKeyFactory fact = SecretKeyFactory.getInstance(SCRYPT, BC);

            return fact.generateSecret(
                    new ScryptKeySpec(password, salt,
                            costParameter, blocksize, parallelizationParam,
                            keySize)).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static Mac newHmacSha256Mac(byte[] generatedKeys, int keyOffset) throws InvalidKeyException {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA_256, BC);
            mac.init(new SecretKeySpec(generatedKeys, keyOffset, HMAC_256_KEY_LEN, HMAC_SHA_256));
            return mac;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static Cipher initAESCTRDecryptCipher(byte[] keyData, int offset, int len, byte[] iv) throws InvalidKeyException {
        return initAESCTRCipher(Cipher.DECRYPT_MODE, keyData, offset, len, iv);
    }

    public static Cipher initAESCTREncryptCipher(byte[] keyData, int offset, int len, byte[] iv) throws InvalidKeyException {
        return initAESCTRCipher(Cipher.ENCRYPT_MODE, keyData, offset, len, iv);
    }

    private static Cipher initAESCTRCipher(int mode, byte[] keyData, int offset, int len, byte[] iv) throws InvalidKeyException {
        try {
            var cipher = Cipher.getInstance(AES_CTR_NO_PADDING, BC);
            cipher.init(mode,
                    new SecretKeySpec(keyData, offset, len, AES),
                    new IvParameterSpec(iv));
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    public static SecureRandom getSecureRandom() {
        try {
            return SecureRandom.getInstance("DEFAULT", BC);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
