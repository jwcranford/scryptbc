package com.github.jwcranford.scryptbc;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
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

    public static byte[] computeHMAC(byte[] key,  int keyOffset,  int keyLen,
                              byte[] data, int dataOffset, int dataLen) {
        try {
            SecretKey macKey = new SecretKeySpec(key, keyOffset, keyLen, HMAC_SHA_256);
            Mac mac = Mac.getInstance(HMAC_SHA_256, BC);
            mac.init(macKey);
            mac.update(data, dataOffset, dataLen);
            return mac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
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

    /**
     * Calculate a derived key using SCRYPT using the BC low-level API.
     *
     * @param password the password input.
     * @param salt the salt parameter.
     * @param costParameter the cost parameter.
     * @param blocksize the blocksize parameter.
     * @param parallelizationParam the parallelization parameter.
     * @param keySize in bytes
     * @return the derived key.
     */
    public static byte[] bcSCRYPT(char[] password, byte[] salt,
                                  int costParameter, int blocksize,
                                  int parallelizationParam,
                                  int keySize)
    {
        return SCrypt.generate(
                PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password),
                salt, costParameter, blocksize, parallelizationParam,
                keySize);
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

    public static Cipher initAESCTRCipher(byte[] keyData, int offset, int len, byte[] iv) throws InvalidKeyException {
        try {
            var cipher = Cipher.getInstance(AES_CTR_NO_PADDING, BC);
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(keyData, offset, len, AES),
                    new IvParameterSpec(iv));
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }
}
