package Ours;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class Ours {
    // 存储临时密文组件 - 使用普通HashMap而非同步版本
    private static final Map<String, byte[]> tempStorage = new HashMap<>(16);
    // 缓存配对实例，避免重复创建
    private static Pairing cachedPairing;

    //---------------------------系统初始化-----------------------------------
    public static void setup(String pairingFile, String publicFile, String mskFile) {
        Pairing bp = getPairing(pairingFile);

        // 生成主私钥s
        Element s = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("s", Base64.getEncoder().encodeToString(s.toBytes()));
        storePropToFile(mskProp, mskFile);

        // 生成系统参数
        Element P = bp.getG1().newRandomElement().getImmutable();       // G1生成元
        Element P0 = bp.getG1().newRandomElement().getImmutable();      // 额外生成元P0
        Element P_pub = P.powZn(s).getImmutable();                      // 主公钥Ppub = s*P
        Element g = bp.pairing(P_pub, P0).getImmutable();               // g = e(Ppub, P0)

        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("P0", Base64.getEncoder().encodeToString(P0.toBytes()));
        pubProp.setProperty("P_pub", Base64.getEncoder().encodeToString(P_pub.toBytes()));
        pubProp.setProperty("g", Base64.getEncoder().encodeToString(g.toBytes()));
        storePropToFile(pubProp, publicFile);
    }

    //---------------------------密钥提取算法-----------------------------------
    public static void keyExtract(String pairingFile, String publicFile, String mskFile,
                                  String id, String pkFile, String skFile, int index)
            throws NoSuchAlgorithmException, IOException {
        Pairing bp = getPairing(pairingFile);
        Properties pubProp = loadPropFromFile(publicFile);

        // 直接获取P而不创建Element实例（优化点：延迟创建Element）
        String pValue = pubProp.getProperty("P");

        // 计算身份公钥PK_ID = H1(ID)
        byte[] h1Hash = H1(id);
        Element PK_ID = bp.getG1().newElementFromHash(h1Hash, 0, h1Hash.length).getImmutable();

        // 获取主私钥s并计算私钥SK_ID = s * PK_ID
        Properties mskProp = loadPropFromFile(mskFile);
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskProp.getProperty("s"))).getImmutable();
        Element SK_ID = PK_ID.powZn(s).getImmutable();

        // 存储密钥对和Ri
        saveKeyToFile(pkFile, "PK" + index, PK_ID.toBytes());
        saveKeyToFile(skFile, "SK" + index, SK_ID.toBytes());

        // 生成并保存Ri，用于后续验证
        Element R = bp.getZr().newRandomElement().getImmutable();
        saveKeyToFile(pkFile, "R" + index, R.toBytes());
    }

    //---------------------------签密算法-----------------------------------
    public static void signCrypt(String pairingFile, String publicFile, String skFile,
                                 String pkFile, String message, String[] senderSet,
                                 String[] receiverSet, String signCryptFile)
            throws NoSuchAlgorithmException, IOException {
        Pairing bp = getPairing(pairingFile);
        Properties pubProp = loadPropFromFile(publicFile);

        // 加载系统参数（优化点：一次性解码所有参数）
        byte[] pBytes = Base64.getDecoder().decode(pubProp.getProperty("P"));
        byte[] p0Bytes = Base64.getDecoder().decode(pubProp.getProperty("P0"));
        byte[] pPubBytes = Base64.getDecoder().decode(pubProp.getProperty("P_pub"));
        byte[] gBytes = Base64.getDecoder().decode(pubProp.getProperty("g"));

        Element P = bp.getG1().newElementFromBytes(pBytes).getImmutable();
        Element P0 = bp.getG1().newElementFromBytes(p0Bytes).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(pPubBytes).getImmutable();
        Element g = bp.getG2().newElementFromBytes(gBytes).getImmutable();

        // 1. 处理发送者伪装集
        int m = senderSet.length;
        Element sumRH = bp.getZr().newZeroElement().getImmutable();
        Properties pkProp = loadPropFromFile(pkFile);

        // 优化点：减少循环内的Element创建和哈希计算
        for (int i = 0; i < m; i++) {
            String pkValue = pkProp.getProperty("PK" + i);
            if (pkValue == null) {
                throw new IllegalArgumentException("发送者公钥PK" + i + "不存在");
            }

            // 直接使用字节数组进行计算，减少Element转换
            byte[] pkBytes = Base64.getDecoder().decode(pkValue);
            Element PK_Si = bp.getG1().newElementFromBytes(pkBytes).getImmutable();
            Element R_i = bp.getZr().newRandomElement().getImmutable();

            // 优化哈希输入大小
            byte[] hashInput = new byte[pkBytes.length + R_i.getLengthInBytes()];
            System.arraycopy(pkBytes, 0, hashInput, 0, pkBytes.length);
            System.arraycopy(R_i.toBytes(), 0, hashInput, pkBytes.length, R_i.getLengthInBytes());

            Element h_i = bp.getZr().newElementFromHash(MessageDigest.getInstance("SHA-256").digest(hashInput), 0, 32).getImmutable();
            sumRH = sumRH.add(R_i).add(h_i).getImmutable();
        }

        // 2. 生成发送者相关参数（优化点：合并计算步骤）
        int aliceIndex = 0;
        Element r_Alice = bp.getZr().newRandomElement().getImmutable();
        Element R_Alice = r_Alice.sub(sumRH).getImmutable();

        // 直接使用已解码的公钥字节数组
        Element PK_Alice = bp.getG1().newElementFromBytes(
                Base64.getDecoder().decode(pkProp.getProperty("PK" + aliceIndex))).getImmutable();

        Element h_Alice = H2(PK_Alice, R_Alice, pairingFile);
        Element Q_Alice = r_Alice.add(h_Alice).getImmutable();
        Element pi = sumRH.add(R_Alice).getImmutable();

        // 3. 生成随机参数a并计算相关组件（优化点：减少指数运算）
        Element a = bp.getZr().newRandomElement().getImmutable();
        Element U = g.powZn(a).getImmutable();                  // U = g^a
        Element delta = P.powZn(a).getImmutable();              // delta = a*P
        Element beta = bp.pairing(delta, P0).getImmutable();    // beta = e(aP, P0)

        // 4. 生成接收者相关参数（优化点：预计算公钥指数）
        int n = receiverSet.length;
        Element aPpub = P_pub.powZn(a).getImmutable();  // 预计算a*Ppub，避免重复计算

        for (int j = 0; j < n; j++) {
            int receiverPkIndex = m + j;
            String pkValue = pkProp.getProperty("PK" + receiverPkIndex);
            if (pkValue == null) {
                throw new IllegalArgumentException("接收者公钥PK" + receiverPkIndex + "不存在");
            }

            Element PK_Rj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkValue)).getImmutable();
            Element Zj = P_pub.add(PK_Rj).getImmutable();              // Zj = Ppub + PK_Rj
            Element aPK_Rj = PK_Rj.powZn(a).getImmutable();            // 计算a*PK_Rj
            Element Nj = aPpub.add(aPK_Rj).getImmutable();             // 复用预计算的aPpub

            // 存储接收者参数
            tempStorage.put("Z" + j, Zj.toBytes());
            tempStorage.put("N" + j, Nj.toBytes());
        }

        // 5. 计算签名和加密组件（优化点：减少哈希计算次数）
        Element SK_Alice = bp.getZr().newElementFromBytes(
                Base64.getDecoder().decode(loadPropFromFile(skFile).getProperty("SK" + aliceIndex))).getImmutable();

        Element T = H3(SK_Alice, Q_Alice, pairingFile);

        // 优化点：合并哈希输入
        byte[] K = H2(concatenate(U.toBytes(), delta.toBytes(), beta.toBytes()));
        byte[] c = encrypt(message.getBytes(StandardCharsets.UTF_8), K);

        // 6. 生成MAC
        byte[] phi = concatenate(delta.toBytes(), beta.toBytes(), pi.toBytes(),
                Q_Alice.toBytes(), T.toBytes(), intToBytes(m), intToBytes(n));
        byte[] mac = HMac(c, phi);

        // 7. 存储密文
        Properties sigC = new Properties();
        sigC.setProperty("c", Base64.getEncoder().encodeToString(c));
        sigC.setProperty("U", Base64.getEncoder().encodeToString(U.toBytes()));
        sigC.setProperty("delta", Base64.getEncoder().encodeToString(delta.toBytes()));
        sigC.setProperty("beta", Base64.getEncoder().encodeToString(beta.toBytes()));
        sigC.setProperty("T", Base64.getEncoder().encodeToString(T.toBytes()));
        sigC.setProperty("Q_Alice", Base64.getEncoder().encodeToString(Q_Alice.toBytes()));
        sigC.setProperty("pi", Base64.getEncoder().encodeToString(pi.toBytes()));
        sigC.setProperty("mac", Base64.getEncoder().encodeToString(mac));
        sigC.setProperty("senderCount", String.valueOf(m));
        sigC.setProperty("receiverCount", String.valueOf(n));
        storePropToFile(sigC, signCryptFile);
    }

    //---------------------------解签密算法-----------------------------------
    public static String unSignCrypt(String pairingFile, String publicFile, String skFile,
                                     String pkFile, String[] senderSet, String[] receiverSet,
                                     String signCryptFile, int receiverIndex)
            throws NoSuchAlgorithmException, IOException {
        Pairing bp = getPairing(pairingFile);
        Properties pubProp = loadPropFromFile(publicFile);

        // 加载系统参数（优化点：一次性解码所有参数）
        byte[] pBytes = Base64.getDecoder().decode(pubProp.getProperty("P"));
        byte[] p0Bytes = Base64.getDecoder().decode(pubProp.getProperty("P0"));
        byte[] pPubBytes = Base64.getDecoder().decode(pubProp.getProperty("P_pub"));

        Element P = bp.getG1().newElementFromBytes(pBytes).getImmutable();
        Element P0 = bp.getG1().newElementFromBytes(p0Bytes).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(pPubBytes).getImmutable();

        // 1. 加载接收者私钥
        Properties sigC = loadPropFromFile(signCryptFile);
        int senderCount = Integer.parseInt(sigC.getProperty("senderCount"));
        int receiverPkIndex = senderCount + receiverIndex;

        Properties skProp = loadPropFromFile(skFile);
        String skValue = skProp.getProperty("SK" + receiverPkIndex);
        if (skValue == null) {
            return "接收者私钥SK" + receiverPkIndex + "不存在";
        }
        Element SK_Bob = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(skValue)).getImmutable();

        Properties pkProp = loadPropFromFile(pkFile);
        String pkValue = pkProp.getProperty("PK" + receiverPkIndex);
        if (pkValue == null) {
            return "接收者公钥PK" + receiverPkIndex + "不存在";
        }
        Element PK_Bob = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pkValue)).getImmutable();

        // 2. 加载密文（优化点：批量解码）
        byte[] c = Base64.getDecoder().decode(sigC.getProperty("c"));
        Element U = bp.getG2().newElementFromBytes(Base64.getDecoder().decode(sigC.getProperty("U"))).getImmutable();
        Element delta = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(sigC.getProperty("delta"))).getImmutable();
        Element beta = bp.getG2().newElementFromBytes(Base64.getDecoder().decode(sigC.getProperty("beta"))).getImmutable();
        Element T = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sigC.getProperty("T"))).getImmutable();
        Element Q_Alice = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sigC.getProperty("Q_Alice"))).getImmutable();
        Element pi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sigC.getProperty("pi"))).getImmutable();
        byte[] mac = Base64.getDecoder().decode(sigC.getProperty("mac"));
        int m = Integer.parseInt(sigC.getProperty("senderCount"));
        int n = Integer.parseInt(sigC.getProperty("receiverCount"));

        // 3. 验证MAC（优化点：提前验证，失败快速返回）
        byte[] phi = concatenate(delta.toBytes(), beta.toBytes(), pi.toBytes(),
                Q_Alice.toBytes(), T.toBytes(), intToBytes(m), intToBytes(n));
        if (!MessageDigest.isEqual(mac, HMac(c, phi))) {
            return "MAC验证失败，密文被篡改";
        }

        // 4. 验证发送者身份合法性（优化点：减少循环内操作）
        Element sumRH = bp.getZr().newZeroElement().getImmutable();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256"); // 复用MessageDigest实例

        for (int i = 0; i < m; i++) {
            String pkSiValue = pkProp.getProperty("PK" + i);
            String riValue = pkProp.getProperty("R" + i);
            if (pkSiValue == null || riValue == null) {
                return "发送者信息不完整，PK" + i + "或R" + i + "不存在";
            }

            byte[] pkBytes = Base64.getDecoder().decode(pkSiValue);
            Element PK_Si = bp.getG1().newElementFromBytes(pkBytes).getImmutable();
            Element Ri = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(riValue)).getImmutable();

            // 优化哈希计算
            sha256.reset();
            sha256.update(pkBytes);
            sha256.update(Ri.toBytes());
            Element hi = bp.getZr().newElementFromHash(sha256.digest(), 0, 32).getImmutable();

            sumRH = sumRH.add(Ri).add(hi).getImmutable();
        }

        if (!sumRH.isEqual(Q_Alice)) {
            return "发送者身份验证失败";
        }

        // 5. 验证接收者合法性
        Element Z_Bob = P_pub.add(PK_Bob).getImmutable();
        Element storedZ = bp.getG1().newElementFromBytes(tempStorage.get("Z" + receiverIndex)).getImmutable();
        if (storedZ == null || !Z_Bob.isEqual(storedZ)) {
            return "接收者未授权";
        }

        // 6. 解密（优化点：减少配对运算次数）
        Element N_Bob = bp.getG1().newElementFromBytes(tempStorage.get("N" + receiverIndex)).getImmutable();
        if (N_Bob == null) {
            return "接收者密文组件不存在";
        }

        // 优化配对计算顺序，减少临时变量
        Element computedU = bp.pairing(P0, N_Bob).mul(bp.pairing(P, SK_Bob)).getImmutable();
        if (!computedU.isEqual(U)) {
            return "密钥验证失败";
        }

        // 优化密钥生成
        byte[] K = H2(concatenate(U.toBytes(), delta.toBytes(), beta.toBytes()));
        byte[] messageBytes = decrypt(c, K);

        return new String(messageBytes, StandardCharsets.UTF_8);
    }

    //------------------------------------哈希函数实现--------------------------------
    private static byte[] H1(String content) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(content.getBytes(StandardCharsets.UTF_8));
    }

    private static Element H2(Element g1, Element g2, String pairingFile) throws NoSuchAlgorithmException {
        Pairing bp = getPairing(pairingFile);
        byte[] input = concatenate(g1.toBytes(), g2.toBytes());
        return bp.getZr().newElementFromHash(MessageDigest.getInstance("SHA-256").digest(input), 0, 32).getImmutable();
    }

    // 优化点：合并的H2实现，减少方法调用开销
    private static byte[] H2(byte[] input) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(input);
    }

    private static Element H3(Element sk, Element q, String pairingFile) throws NoSuchAlgorithmException {
        Pairing bp = getPairing(pairingFile);
        byte[] input = concatenate(sk.toBytes(), q.toBytes());
        return bp.getZr().newElementFromHash(MessageDigest.getInstance("SHA-256").digest(input), 0, 32).getImmutable();
    }

    private static byte[] HMac(byte[] c, byte[] phi) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(concatenate(c, phi));
    }

    //------------------------------------辅助函数--------------------------------
    private static byte[] encrypt(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];
        int keyLen = key.length;
        // 优化点：减少取模运算
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i < keyLen ? i : i % keyLen]);
        }
        return result;
    }

    private static byte[] decrypt(byte[] data, byte[] key) {
        return encrypt(data, key); // 复用加密函数
    }

    private static void saveKeyToFile(String fileName, String keyName, byte[] value) throws IOException {
        Properties prop = new Properties();
        File file = new File(fileName);
        if (file.exists()) {
            prop.load(new FileInputStream(file));
        }
        prop.setProperty(keyName, Base64.getEncoder().encodeToString(value));
        try (FileOutputStream out = new FileOutputStream(file)) {
            prop.store(out, null);
        }
    }

    public static void storePropToFile(Properties prop, String fileName) {
        try (FileOutputStream out = new FileOutputStream(fileName)) {
            prop.store(out, null);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " 保存失败!");
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)) {
            prop.load(in);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " 加载失败!");
        }
        return prop;
    }

    // 优化点：预分配数组长度，减少内存分配
    private static byte[] concatenate(byte[]... arrays) {
        if (arrays == null || arrays.length == 0) return new byte[0];

        int totalLen = 0;
        for (byte[] arr : arrays) {
            if (arr != null) totalLen += arr.length;
        }

        byte[] result = new byte[totalLen];
        int pos = 0;
        for (byte[] arr : arrays) {
            if (arr != null) {
                System.arraycopy(arr, 0, result, pos, arr.length);
                pos += arr.length;
            }
        }
        return result;
    }

    private static byte[] intToBytes(int value) {
        return new byte[] {
                (byte)(value >>> 24),
                (byte)(value >>> 16),
                (byte)(value >>> 8),
                (byte)value
        };
    }

    // 优化点：缓存配对实例，避免重复初始化开销
    private static Pairing getPairing(String pairingFile) {
        if (cachedPairing == null) {
            cachedPairing = PairingFactory.getPairing(pairingFile);
        }
        return cachedPairing;
    }

    //------------------------------------测试主函数--------------------------------
    public static void main(String[] args) throws Exception {
        String dir = "./storeFile/Ours/";
        new File(dir).mkdirs();

        // 文件路径
        String pairingFile = dir + "a.properties";
        String publicFile = dir + "pub.properties";
        String mskFile = dir + "msk.properties";
        String pkFile = dir + "pk.properties";
        String skFile = dir + "sk.properties";
        String signCryptFile = dir + "signcrypt.properties";

        // 用户身份设置
        String[] senderSet = {"sender1@example.com"};
        String [] receiverSet = new String[] {"1", "2","3","4","5","6","7","8","9","10"};

        String message = "轻量级匿名签密测试消息：敏感数据传输示例";

        // 1. 系统初始化
        long start1 = System.currentTimeMillis();
        long start = System.currentTimeMillis();
        setup(pairingFile, publicFile, mskFile);
        System.out.println("初始化耗时: " + (System.currentTimeMillis() - start) + "ms");

        // 2. 生成密钥对（先发送者，后接收者）
        start = System.currentTimeMillis();
        for (int i = 0; i < senderSet.length; i++) {
            keyExtract(pairingFile, publicFile, mskFile, senderSet[i], pkFile, skFile, i);
        }
        for (int i = 0; i < receiverSet.length; i++) {
            keyExtract(pairingFile, publicFile, mskFile, receiverSet[i], pkFile, skFile, senderSet.length + i);
        }
        System.out.println("密钥生成耗时: " + (System.currentTimeMillis() - start) + "ms");

        // 3. 签密
        start = System.currentTimeMillis();
        signCrypt(pairingFile, publicFile, skFile, pkFile, message, senderSet, receiverSet, signCryptFile);
        System.out.println("签密耗时: " + (System.currentTimeMillis() - start) + "ms");

        // 4. 解签密（接收者2解密，索引从0开始）
        start = System.currentTimeMillis();
        String recovered = unSignCrypt(pairingFile, publicFile, skFile, pkFile, senderSet, receiverSet, signCryptFile, 1);
        System.out.println("解签密耗时: " + (System.currentTimeMillis() - start) + "ms");

        // 输出结果
        System.out.println("\n原始消息: " + message);
        System.out.println("解密结果: " + recovered);
        System.out.println("总耗时: " + (System.currentTimeMillis() - start1) + "ms");
    }
}
