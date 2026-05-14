package com.example.demo.utils;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;

public class SM4Util {
    public static String KEY = "f0c5a8b001314979b27e110c205a66e1";

    //SBOX,共16*16=256个,每个1字节,用密钥生成轮密钥时使用
    private static final int[][] SBOX = {
            {0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05},
            {0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},
            {0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62},
            {0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6},
            {0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8},
            {0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35},
            {0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87},
            {0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e},
            {0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1},
            {0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3},
            {0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f},
            {0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51},
            {0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8},
            {0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0},
            {0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84},
            {0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48}
    };
    //FK,共4个,每个4字节,用密钥生成轮密钥时使用
    private static final int[] FK = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};
    //CK,共32个,每个4字节,用密钥生成轮密钥时使用
    private static final int[] CK = {
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    };

    /**
     * 密钥
     */
    //密钥字符串形式,32个16进制数字
    private static String sKey;
    //密钥,共4个,每个4字节,合成1组
    private static final int[] key = new int[4];
    //密钥中间值,共36个,每个4字节
    private static int[] tKey = new int[36];

    /**
     * 轮密钥
     */
    //轮密钥,正序32个,每个4字节,逆序32个,每个4字节
    private static int[] RK = new int[32];
    private static int[] RK_R = new int[32];

    /**
     * 明文
     */
    //明文字符串形式,utf-8编码
    private static String pText = "";
    //单组明文序列,共36个,每个4字节
    private static int[] plainText = new int[36];

    /**
     * 密文
     */
    //密文字符串形式,32个16进制数字
    private static String cText = "";
    //单组密文,共4个,每个4字节,合成1组
    private static final int[] cipherText = new int[4];

    /**
     * 主函数,测试功能：密钥生成、明文加密、密文解密
     * 此3个功能对外开放
     * 密钥生成 generateSM4Key()
     * 明文加密 encryECBSM4()
     * 密文解密 decryECBSM4()
     */
//    public static void main(String[] args) {
//
//        String str = "127.0.0.1.system.userName.database";
//        String[] array = str.split("\\.");
//        if (array.length != 7) {
//            System.out.println("请按照规定格式传入数据源");
//        }
//        StringBuilder sb = new StringBuilder();
//        for (int i = 0; i < 4; i++) {
//            sb.append(array[i]).append(".");
//        }
//        System.out.println(sb.substring(0, sb.length() - 1));
//        System.out.println(array[4]);
//        System.out.println(array[5]);
//        System.out.println(array[6]);
//
//        // 加密部分
//        pText = "加密123/解密mnp@qq.com => " + (Math.random() * 100000);
//        sKey = generateSM4Key();
//        cText = encryECBSM4(pText, sKey);
//        System.out.println("明文:" + pText);
//        System.out.println("密钥:" + sKey);
//        System.out.println("密文:" + cText);
//
//        // 解密部分
//        sKey = "9146cfe9c4be4291b61473118a0eed66";
//        cText = "b95267844b7255a0df1d61753d27711ce2e7d5f54a0f7ef44b1ecd5486621f044317eb1545e03a0a56e20cbee6cf9ce499f9955981a7107c7cd56f1d5c036837";
//        pText = decryECBSM4(cText, sKey);
//        System.out.println("密文:" + cText);
//        System.out.println("密钥:" + sKey);
//        System.out.println("明文:" + pText);
//    }

    /**
     * 以下3个方法对外开放
     * 生成密钥,generateSM4Key
     * 明文加密,encryECBSM4
     * 密文解密,decryECBSM4
     */
    //生成字符串形式密钥,32个16进制数字
    public static String generateSM4Key() {
        UUID uuid = UUID.randomUUID();
        //生成128bit密钥,用十六进制表示成32个十六进制字符
        sKey = Long.toHexString(uuid.getMostSignificantBits()) + Long.toHexString(uuid.getLeastSignificantBits());
        //如果密钥首部有连续若干个0导致位数不够,则进行首部补0,补足32位
        return "00000000000000000000000000000000".substring(0, 32 - sKey.length()) + sKey;
    }

    //SM4加密,明文是任意字符,密文是128位整数倍的16进制数据
    public static String encryECBSM4(String pText, String sKey) {
        /**
         * 处理密钥
         * 128位字符串密钥 sKey-> int[4]密钥字节 key -> int[36]密钥中间值 tKey -> int[32]的轮密钥 RK
         */
        //字符串类型密钥sKey -> int[4] key
        stringToIntKey(sKey, key);
        //获取密钥中间值,tKey
        tKey = getTKey();
        //获取轮密钥,RK
        RK = getRK(tKey);
        /**
         * 处理明文
         * 字符串明文 pText-> 16整数倍的字节数组明文 pbText -> 多组字节数组明文 pmText -> 多组整型数组明文 pnText
         */
        //字符串明文pText -> 字节数组明文pbText
        //明文字节数组形式,汉字占3个字节,补齐16位的整数倍
        byte[] pbText = stringToBytePlain(pText);
        //字节数组明文pbText -> 多组字节数组明文pmText
        //多组明文二维数组字节形式
        byte[][] pmText = groupingPlain(pbText);
        //多组字节数组明文pmText -> 多组int数组明文pnText
        //多维明文二维数组int形式
        int[][] pnText = byteToIntPlain(pmText);

        /**
         * 分组加密
         * 若明文长度大于等于16字节,则需要对明文进行分组,单组明文加密成单组密文后,将单组密文拼接成最终密文
         */
        // 清空密文
        cText = "";
        for (int i = 0; i < pmText.length; i++) {
            //对多组整型数组明文pnText进行循环,每次取出单组整型数组明文plainText进行加密
            plainText = Arrays.copyOfRange(pnText[i], 0, pnText[i].length);
            //获取单组整型数组明文int[36] plainText的中间值
            getPlainText(plainText, RK);
            //将整型数组明文int[36] plainText的后4位倒叙排列,获取整型密文cipherText
            getCipherText(plainText);
            //将整型密文cipherText输出成字符串,当成本组明文生成的本组密文,并连接到最终密文cText的后边
            cText = String.format("%s%s", cText, intToString());
        }
        return cText;
    }

    //SM4解密,密文是32位整数倍的十六进制字符
    public static String decryECBSM4(String cText, String sKey) {
        /**
         * 处理密钥
         * 128位字符串密钥 sKey-> int[4]密钥字节 key -> int[36]密钥中间值 tKey -> int[32]的轮密钥 RK
         */
        //字符串类型密钥sKey -> int[4] key
        stringToIntKey(sKey, key);
        //获取密钥中间值,tKey
        tKey = getTKey();
        //获取逆序轮密钥,RK_R
        RK_R = getRK_R(tKey);
        /**
         * 处理密文
         * 字符串密文 cText-> 16整数倍的字符串密文 cmText -> 多组整型数组密文 cnText -> 多组整型数组明文 pnText
         */
        //密文长度是16字节整数倍,如果前边有0导致位数不够,则手动填0
        //密文字符串形式,32个16进制数字的整数倍
        String cmText = completeCipher(cText);
        //将密文分组,方便单组解密
        //多组密文整型形式,int[][4]的密文
        int[][] cnText = groupingCipher(cmText);
        //多组字节格式密文拼成的一长串字节格式的密文,cbText是cnText的平铺
        //多组字节格式密文拼成的一长串字节格式的密文,cbText是cnText的平铺
        byte[] cbText = new byte[16 * cnText.length];
        /**
         * 分组解密方法
         *
         */
        pText = "";
        for (int i = 0; i < cnText.length; i++) {
            /**
             * 以下代码为了体现加密和解密的具体方法一致，plainText代表密文,cipherText代表明文
             * 仅此处解密时如此
             */
            //对多组整型数组密文cnText进行循环,每次取出单组整型数组密文plainText进行解密
            plainText = Arrays.copyOfRange(cnText[i], 0, cnText[i].length);
            //获取单组整型数组密文int[36] plainText的中间值,此处采用逆序轮密钥RK_R进行,因此是解密不是加密
            getPlainText(plainText, RK_R);
            //将整型数组明文int[36] plainText的后4位倒叙排列,获取整型明文cipherText
            getCipherText(plainText);
            //多组字节格式密文拼成的一长串字节格式的密文,cbText是cnText的平铺
            getCBText(cbText, i);
        }
        //将字节数组cbText生成pText,需要查找最后16位并去除不可显示字符,从而还原成明文
        pText = getPText(cbText);
        return pText;
    }

    /**
     * 以下7个方法是【使用密钥生成轮密钥】和【使用明文生成密文】和【使用密文生成明文】中的主要方法,包括
     * 获取密钥中间值 getTKey
     * S盒运算 getSBOX
     * 循环左移 rotate_left
     * 获取正序轮密钥 getRK
     * 获取逆序轮密钥 getRK_R
     * 获取明文中间值 getPlainText
     * 倒序获取密文 getCipherText
     */
    //使用密钥、FK、CK进行32次迭代，获取密钥中间值
    private static int[] getTKey() {
        int[] tKey = new int[36];
        //将4位整型密钥key和常数FK进行位异或运算得到4位密钥中间值
        for (int i = 0; i < 4; i++) {
            tKey[i] = key[i] ^ FK[i];
        }
        //将4个密钥中间值与CK进行T变换，再进行L变换，得到新的密钥中间值
        for (int i = 0; i < 32; i++) {
            int T = getSBOX(tKey[i + 1] ^ tKey[i + 2] ^ tKey[i + 3] ^ CK[i]);
            int L = T ^ rotateLeft(T, 13) ^ rotateLeft(T, 23);
            tKey[i + 4] = L ^ tKey[i];
        }
        return tKey;
    }

    //获取4个SBOX值,每个值1字节
    private static int getSBOX(int input) {
        int[] temp = new int[4];
        int output = 0;
        for (int i = 3; i >= 0; i--) {
            temp[i] = input >> (8 * i) & 0xff;
            temp[i] = SBOX[(temp[i] >> 4) & 0x0f][temp[i] & 0x0f];
            output = output | temp[i];
            if (i != 0) {
                output = output << 8;
            }
        }
        return output;
    }

    //循环左移i位
    private static int rotateLeft(int input, int i) {
        return input << i | input >>> (32 - i);
    }

    //获取正序轮密钥RK
    private static int[] getRK(int[] tKey) {
        RK = new int[32];
        System.arraycopy(tKey, 4, RK, 0, 32);
        return RK;
    }

    //获取逆序轮密钥RK_R
    private static int[] getRK_R(int[] tKey) {
        RK_R = new int[32];
        for (int i = 0; i < 32; i++) {
            RK_R[i] = tKey[35 - i];
        }
        return RK_R;
    }

    //使用处理后的明文plainText、轮密钥RK进行32次迭代，获取明文序列
    private static void getPlainText(int[] plainText, int[] RK) {
        for (int i = 0; i < 32; i++) {
            int T = getSBOX(plainText[i + 1] ^ plainText[i + 2] ^ plainText[i + 3] ^ RK[i]);
            int L = T ^ rotateLeft(T, 2) ^ rotateLeft(T, 10) ^ rotateLeft(T, 18) ^ rotateLeft(T, 24);
            plainText[i + 4] = plainText[i] ^ L;
        }
    }

    //将明文序列后4位拿出并倒序排列后形成密文cipherText
    private static void getCipherText(int[] plainText) {
        for (int i = 0; i < 4; i++) {
            SM4Util.cipherText[i] = plainText[35 - i];
        }
    }

    /**
     * 以下5个方法在【加密】和【解密】过程中用来对明文和密文进行补位和分组,包括
     * groupingPlain, 单组字节数组明文 pbText -> 多组字节数组明文 pmText
     * completeCipher, 字符串密文 cText -> 字符串密文 cmText
     * groupingCipher, 字符串密文 cmText -> 多组整型密文 cnText
     * getCBText, 循环迭代每组整型明文cipherText -> 平铺成字节数组明文cbText
     * getPText, 平铺的字节数组明文cbText -> 字符串明文 pText,同时去除明文后端补位使用的不可见字符
     */
    //将一长串的字节数组明文pbText转成多组字节数组明文pmText
    private static byte[][] groupingPlain(byte[] pbText) {
        int n = pbText.length / 16;
        byte[][] pmText = new byte[n][16];
        for (int i = 0; i < n; i++) {
            System.arraycopy(pbText, i * 16, pmText[i], 0, 16);
        }
        return pmText;
    }

    //密文长度应该是16字节的整数倍,即32位十六进制数字的整数倍
    //密文前如果有0则会舍弃,需要手动补足32位十六进制数字的整数倍
    private static String completeCipher(String cText) {
        StringBuilder sb = new StringBuilder();
        int t = cText.length() % 32;
        if (t != 0) {
            for (int i = 0; i < 32 - t; i++) {
                sb.append("0");
            }
        }
        return sb.append(cText).toString();
    }

    //将密文分组,以便对单组密文进行解密
    private static int[][] groupingCipher(String cmText) {
        int t = cmText.length() / 32;
        int[][] cnText = new int[t][36];
        for (int i = 0; i < t; i++) {
            cnText[i] = stringToIntKey(cmText.substring(i * 32, i * 32 + 32), cnText[i]);
        }
        return cnText;
    }

    //将多组字节格式的明文拼成一长串字节格式的明文,即cbText是cnText的平铺,方便进行最终的输出
    private static void getCBText(byte[] cbText, int i) {
        ByteBuffer bb = ByteBuffer.allocate(SM4Util.cipherText.length * 4);
        IntBuffer ib = bb.asIntBuffer();
        ib.put(SM4Util.cipherText);
        byte[] tb = bb.array();
        System.arraycopy(tb, 0, cbText, 16 * i, tb.length);
    }

    //将字节数组cbText输出成字符串pText,其中去除最后16位的不可见字符,从而还原成明文,不带乱码
    private static String getPText(byte[] cbText) {
        String pText = new String(cbText, StandardCharsets.UTF_8);
        int t = 0;
        for (int i = 0; i < 16; i++) {
            if (Character.isISOControl(pText.charAt(pText.length() - 1 - i))) {
                t = i;
            } else {
                break;
            }
        }
        return pText.substring(0, pText.length() - 1 - t);
    }

    /**
     * 以下6个方法用来进行格式转换,包括
     * stringToIntKey, 处理密钥时使用,将 string 转成 int[4]
     * stringToCharKey, 是 stringToIntKey 的子方法
     * charToInt, 是 stringToIntKey 的子方法
     * stringToBytePlain, 加密时使用,将 string 转成 byte[16整数倍],根据PKCS7的补位方法进行补位,若不够16个整数倍则补齐,每个字节写入ASCII值为差值的数据,若正好16个整数倍则再补16个,每个字节写入ASCII值为0x10的数据
     * byteToIntPlain, 加密时使用, 将多组字节数组密文 pmText 转成 多组整型数组密文 pnText
     * intToString, 加密时使用,不足8位需要补足8位
     */
    //string_to_int[4]_key,处理密钥时使用,将string转成int[4]
    private static int[] stringToIntKey(String input, int[] outPut) {
        char[] temp = new char[16];
        for (int i = 0; i < input.length(); i = i + 2) {
            temp[i / 2] = (char) (Integer.parseInt(input.substring(i, i + 2), 16));
        }
        for (int i = 0; i < 4; i++) {
            outPut[i] = temp[i * 4];
            for (int j = 1; j < 4; j++) {
                outPut[i] = outPut[i] << 8;
                outPut[i] = temp[i * 4 + j] | outPut[i];
            }
        }
        return outPut;
    }

    //stringToBytePlain,处理明文时使用,将string转成不定长byte[16整数倍]
    //同时根据PKCS7的补位方法对位数不够的明文进行补位
    private static byte[] stringToBytePlain(String pText) {
        byte[] pbt = pText.getBytes(StandardCharsets.UTF_8);
        int n = pbt.length / 16;
        int m = pbt.length % 16;
        byte[] pbText = new byte[(n + 1) * 16];
        System.arraycopy(pbt, 0, pbText, 0, pbt.length);
        if (m == 0) {
            for (int i = 0; i < 16; i++) {
                pbText[n * 16 + m] = (byte) (0x10);
            }
        } else {
            for (int i = 0; i < 16 - m; i++) {
                pbText[n * 16 + m + i] = (byte) (0x10 - m);
            }
        }
        return pbText;
    }

    //byteToIntPlain,处理明文时使用,将多组字节数组明文转成多组整型数组明文
    private static int[][] byteToIntPlain(byte[][] pmText) {
        int m = pmText.length;
        int[][] pnText = new int[m][36];
        for (int i = 0; i < m; i++) {
            for (int j = 0; j < 4; j++) {
                pnText[i][j] = pmText[i][j * 4];
                for (int k = 1; k < 4; k++) {
                    pnText[i][j] = pmText[i][j * 4 + k] & 0x000000ff | pnText[i][j] << 8;
                }
            }
        }
        return pnText;
    }

    //int[4]_to_string_en,不足8位需要补足8位,加密时使用
    private static String intToString() {
        StringBuilder sb = new StringBuilder();
        for (int j : SM4Util.cipherText) {
            String c = Integer.toHexString(j);
            sb.append("00000000", 0, 8 - c.length()).append(c);
        }
        return sb.toString();
    }

}