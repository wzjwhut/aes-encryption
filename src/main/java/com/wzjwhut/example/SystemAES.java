package com.wzjwhut.example;

import com.wzjwhut.util.HexUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

public class SystemAES {
    private final static Logger logger = LogManager.getLogger(SystemAES.class);
    private KeyPair keyPair;

    public SystemAES() throws Exception{

    }

    public static byte[] encrypt(byte[] key, byte[] input) throws Exception {
//        KeyGenerator kgen = KeyGenerator.getInstance("AES");
//        kgen.init(128, new SecureRandom());
//        SecretKey secretKey = kgen.generateKey();
//        byte[] enCodeFormat = secretKey.getEncoded();
        key = Arrays.copyOf(key, 16);
        input = Arrays.copyOf(input, 16);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] result = cipher.doFinal(input);
        return result;
    }

    public static byte[] decrypt(byte[] key, byte[] cipherContent) throws Exception {
        key = Arrays.copyOf(key, 16);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher decoder = Cipher.getInstance("AES/ECB/NoPadding");
        decoder.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] out = decoder.doFinal(cipherContent);
        logger.info("[decrypt] input: \r\n{}, out:{}\r\n{}", HexUtils.dumpString(cipherContent),out.length,  HexUtils.dumpString(out));
        return out;
    }

}
