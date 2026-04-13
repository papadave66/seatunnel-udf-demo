package com.example.demo.utils;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RSAUtils {

    /**
     * RSA的加解密方法包括
     * 1.公钥加密私钥解密
     * 2.私钥加密公钥解密
     */
    /**
     * 指定加密算法
     */
    private static final String ALGORITHM_NAME = "RSA";

    /**
     * 定义密钥对
     */
    public static final String PUBLIC_KEY = "publicKey";

    public static final String PRIVATE_KEY = "privateKey";

    /**
     * 生成密钥对
     */
    public static Map<String, String> keyGenerator() {
        Map<String, String> key = new HashMap<>();
        try {
            // 创建密钥对生成器对象
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM_NAME);
            // 生成RSA密钥对
            KeyPair kp = kpg.generateKeyPair();
            // 获取公钥和私钥
            PublicKey pubKey = kp.getPublic();
            PrivateKey priKey = kp.getPrivate();
            // 获取字符串类型的公钥和私钥
            byte[] pubKeyEncoded = pubKey.getEncoded();
            String pubKeyString = Base64.encodeBase64String(pubKeyEncoded);
            byte[] priKeyEncoded = priKey.getEncoded();
            String priKeyString = Base64.encodeBase64String(priKeyEncoded);
            key.put(PUBLIC_KEY, pubKeyString);
            key.put(PRIVATE_KEY, priKeyString);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return key;
    }

    /**
     * 公钥加密
     */
    public static String encryptPublic(String plaintext, String publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //创建加密对象
        Cipher cipher = Cipher.getInstance(ALGORITHM_NAME);
        //初始化
        cipher.init(Cipher.ENCRYPT_MODE, pubKeyTransfer(publicKey));
        //加密
        byte[] ctext = cipher.doFinal(plaintext.getBytes());
        //转密文类型
        return Base64.encodeBase64String(ctext);
    }

    /**
     * 私钥加密
     */
    public static String encryptPrivate(String plaintext, String privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //创建加密对象
        Cipher cipher = Cipher.getInstance(ALGORITHM_NAME);
        //初始化
        cipher.init(Cipher.ENCRYPT_MODE, priKeyTransfer(privateKey));
        //加密
        byte[] ctext = cipher.doFinal(plaintext.getBytes());
        //转密文类型
        return Base64.encodeBase64String(ctext);
    }

    /**
     * 公钥解密
     */
    public static String decryptPublic(String ciphertext, String publicKey) throws BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {
        //创建解密对象
        Cipher cipher = Cipher.getInstance(ALGORITHM_NAME);
        //初始化
        cipher.init(Cipher.DECRYPT_MODE, pubKeyTransfer(publicKey));
        //解密
        byte[] cText = new byte[0];
        cText = cipher.doFinal(Base64.decodeBase64(ciphertext));
        return new String(cText);
    }

    /**
     * 私钥解密
     */
    public static String decryptPrivate(String ciphertext, String privateKey) throws BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {
        //创建解密对象
        Cipher cipher = Cipher.getInstance(ALGORITHM_NAME);
        //初始化
        cipher.init(Cipher.DECRYPT_MODE, priKeyTransfer(privateKey));
        //解密
        byte[] cText = new byte[0];
        cText = cipher.doFinal(Base64.decodeBase64(ciphertext));
        return new String(cText);
    }

    //内部使用,将字符串转成可使用的公钥
    private static PublicKey pubKeyTransfer(String pubKeyString) {
        try {
            // 构建密钥工厂
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM_NAME);
            // 构建密钥规范,进行密钥编码,返回密钥
            X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.decodeBase64(pubKeyString));
            return kf.generatePublic(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    //内部使用,将字符串转成可使用的私钥
    private static PrivateKey priKeyTransfer(String priKeyString) {
        try {
            // 构建密钥工厂
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM_NAME);
            // 构建密钥规范,进行密钥编码,返回密钥
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.decodeBase64(priKeyString));
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

//    /**
//     * 将Ascii转换成字符串
//     */
//    private static String asciiTransformString(String value) {
//        StringBuilder sbu = new StringBuilder();
//        value = value.replaceAll("\\s*", "");
//        String[] chars = value.split(",");
//        for (String aChar : chars) {
//            sbu.append((char) Integer.parseInt(aChar));
//        }
//        return sbu.toString();
//    }


}