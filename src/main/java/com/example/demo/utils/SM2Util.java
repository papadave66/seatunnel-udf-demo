package com.example.demo.utils;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class SM2Util {
    /**
     * 公钥,分成未压缩公钥和压缩公钥,未压缩公钥以04开头,压缩公钥以02或03开头,本算法是未压缩公钥
     */
    public static final String KEY_PUBLIC_KEY = "04f65ff2b281c21c6e203a0a7fb5fb8574a726a0b39d7df6b8ec6bf0c18ebda2bcade1373a57e904028b98048e983e97c0939b8b7d99bf505f4fe68cb6660eef42";
    /**
     * 私钥
     */
    public static final String KEY_PRIVATE_KEY = "7728cee418379ce52f5a43f6274219237f29aca8169e02f842cb0fcf52a05054";

    /**
     * 生成密钥
     */
    public static Map<String, String> createKey() throws Exception {
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        //获取一个椭圆曲线类型的密钥对生成器
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        //使用SM2参数初始化生成器
        kpg.initialize(sm2Spec);
        //获取密钥对
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        BCECPublicKey p = (BCECPublicKey) publicKey;
        PrivateKey privateKey = keyPair.getPrivate();
        BCECPrivateKey s = (BCECPrivateKey) privateKey;
        Map<String, String> result = new HashMap<>();
        result.put(KEY_PUBLIC_KEY, Hex.toHexString(p.getQ().getEncoded(false)));
        result.put(KEY_PRIVATE_KEY, Hex.toHexString(s.getD().toByteArray()));
        return result;
    }

    /**
     * SM2加密算法
     */
    public static String encrypt(String publicKey, String data) {
        //获取一条SM2曲线参数
        X9ECParameters sm2ECPrameters = GMNamedCurves.getByName("sm2p256v1");
        //构造ECC算法参数,曲线方程,椭圆曲线G点,大整数N
        ECDomainParameters domainParameters = new ECDomainParameters(sm2ECPrameters.getCurve(), sm2ECPrameters.getG(), sm2ECPrameters.getN());
        //提取公钥点
        ECPoint pukPoint = sm2ECPrameters.getCurve().decodePoint(Hex.decode(publicKey));
        //公钥前面的02或者03表示是压缩公钥,04表示未压缩公钥,04的时候,可以去掉前面的04
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(pukPoint, domainParameters);
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        //设置sm2为加密模式
        sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
        byte[] arrayOfBytes = null;
        try {
            byte[] in = data.getBytes();
            arrayOfBytes = sm2Engine.processBlock(in, 0, in.length);
            return Hex.toHexString(arrayOfBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * SM2解密算法
     */
    public static String decrypt(String privateKey, String cipherData) {
        //使用BC库加解密时密文以04开头,传入的密文前面没有04则补上
        if (!cipherData.startsWith("04")) {
            cipherData = "04" + cipherData;
        }
        byte[] cipherDataByte = Hex.decode(cipherData);
        BigInteger privateKeyD = new BigInteger(privateKey, 16);
        //获取一条SM2曲线参数
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
        //构造domain参数
        ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKeyD, domainParameters);
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        //设置sm2为解密模式
        sm2Engine.init(false, privateKeyParameters);
        String result = "";
        try {
            byte[] arrayOfBytes = sm2Engine.processBlock(cipherDataByte, 0, cipherDataByte.length);
            return new String(arrayOfBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

//    public static void main(String[] args) throws Exception {
//        Map<String, String> key = createKey();
//        System.out.println(key);
//    }
}
