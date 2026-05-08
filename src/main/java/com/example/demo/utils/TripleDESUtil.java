package com.example.demo.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

public class TripleDESUtil {
    public static String KEY = "f589514c39f554a662ab87f85d812644aa3a3c64b1c8f880";
    /**
     * 算法配置
     * 1.CBC模式下加解密 Cipher 初始化必须传入同一个 IvParameterSpec 实例参数
     * 2.IvParameterSpec 构造函数中参数字节数组长度必须是8位
     */
    private static final String ALGORITHM_3DES = "DESEDE";
    private static final String ALGORITHM_MODE = "/CBC/";
    private static final String ALGORITHM_PADDING = "PKCS5Padding";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final IvParameterSpec IV_PARAMETER_SPEC = new IvParameterSpec(RANDOM.generateSeed(8));

    /**
     * 生成168位密钥,共24个字节,48个十六进制数,有24位是校验位
     */
    public static String keyGenerator() {
        SecureRandom sr = new SecureRandom();
        String sKey = new BigInteger(48 * 4, sr).toString(16);
        return "000000000000000000000000000000000000000000000000".substring(0, 48 - sKey.length()) + sKey;
    }

    /**
     * TripleDES加密
     */
    public static String encrypt(String plaintext, String key) {
        // 添加一个安全供应商
        Security.addProvider(new BouncyCastleProvider());
        // 生成密钥
        try {
            Key desKey = keyTransfer(new BigInteger(key, 16).toByteArray());
            // 实例化一个 Cipher 对象用于完成加密操作
            Cipher cipher = Cipher.getInstance(ALGORITHM_3DES + ALGORITHM_MODE + ALGORITHM_PADDING);
            // 初始化 Cipher 对象，设置为加密模式
            cipher.init(Cipher.ENCRYPT_MODE, desKey, IV_PARAMETER_SPEC);
            // TripleDES加密
            byte[] ptext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            // 密文转成字符串输出
            return new BigInteger(1, ptext).toString(16);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * TripleDES解密
     */
    public static String decrypt(String ciphertext, String key) {
        try {
            Key desKey = keyTransfer(new BigInteger(key, 16).toByteArray());
            Cipher cipher = Cipher.getInstance(ALGORITHM_3DES + ALGORITHM_MODE + ALGORITHM_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, desKey, IV_PARAMETER_SPEC);
            byte[] ctext = new BigInteger(ciphertext, 16).toByteArray();
            if (ctext[0] == 0) {
                byte[] atext = new byte[ctext.length - 1];
                System.arraycopy(ctext, 1, atext, 0, atext.length);
                return new String(cipher.doFinal(atext));
            }
            return new String(cipher.doFinal(ctext));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 密钥转换,用于加密和解密时,将字符串密钥转换成可利用的密钥
     */
    private static Key keyTransfer(byte[] key) {
        try {
            DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(key);
            // 创建一个密钥工厂，用于转换DESKeySpec
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(ALGORITHM_3DES);
            // 生成一个密钥并返回
            return secretKeyFactory.generateSecret(deSedeKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}