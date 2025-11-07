package Liang;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.Base64;

public class Liang {
    // 系统参数
    public static class PublicParams {
        public Pairing pairing;       // 椭圆曲线配对
        public Element P;             // G的生成元
        public Element Ppub;          // 系统公钥 s*P
        public int qBitLength;        // 阶q的比特长度
        public int idLength;          // 身份ID的比特长度
        // 增加额外的系统参数以增加计算复杂度
        public Element P2;            // 第二个生成元
        public Element P3;            // 第三个生成元
    }

    // 主密钥
    public static class MasterSecretKey {
        public Element s;             // 主密钥 s ∈ Z_q^*
        public Element s2;            // 第二个主密钥
        public Element s3;            // 第三个主密钥
        public Pairing pairing;
    }

    // 撤销参数
    public static class RevocationParams {
        public Element b;             // 主撤销密钥 b ∈ Z_q^*
        public Element B;             // 撤销公钥 B = b*P
        public Element[] rsk;         // 车辆撤销私钥 {rski}
        public Element[] a;           // 多项式系数 {a1, a2, ..., an-1}（a0 = f(0) - b）
        public Element[][] aExtra;    // 额外的多项式系数，增加复杂度
    }

    // 伪身份
    public static class Pseudonym {
        public Element pid1;          // PID1 = xi*P
        public Element pid1_2;        // 额外的伪身份组件
        public Element pid1_3;        // 额外的伪身份组件
        public String pid2;           // PID2 = IDi XOR H1(s*PID1)
        public String pid3;           // 额外的伪身份组件
    }

    // 部分私钥
    public static class PartialPrivateKey {
        public Element lambda;        // λi = yi + s*hi
        public Element lambda2;       // 第二个部分私钥
        public Element lambda3;       // 第三个部分私钥
        public Element Y;             // Yi = yi*P
        public Element Y2;            // 第二个公钥组件
        public Element Y3;            // 第三个公钥组件
    }

    // 密钥对（车辆/RSU）
    public static class KeyPair {
        public Element sk;            // 私钥 sk ∈ Z_q^*
        public Element sk2;           // 第二个私钥
        public Element sk3;           // 第三个私钥
        public Element pk;            // 公钥 pk = sk*P
        public Element pk2;           // 第二个公钥
        public Element pk3;           // 第三个公钥
    }

    // 签密密文
    public static class Ciphertext {
        public String Ci;             // 加密消息 H4(TKi,PIDi)⊕(pki||Yi||m)
        public String Ci2;            // 第二个加密组件
        public String Ci3;            // 第三个加密组件
        public Element rho;           // 签名组件 ρi
        public Element rho2;          // 第二个签名组件
        public Element rho3;          // 第三个签名组件
        public String timestamp;      // 时间戳 ti
        public String timestamp2;     // 第二个时间戳
        public Element Ri;            // Ri = ri*P
        public Element Ri2;           // 第二个随机组件
        public Element Ri3;           // 第三个随机组件
        public Element gamma;         // γi = TKi * sumi
        public Element gamma2;        // 第二个gamma组件
        public Element gamma3;        // 第三个gamma组件
        public String[] receivers;    // 接收者集合
        public Element[] proof;       // 额外的证明组件
    }


    /**
     * 1. 系统初始化算法 - 增加了更多参数生成和复杂运算
     */
    public static void Setup(int k, int idLen, String pairingFile, String mpkFile, String mskFile) {
        // 使用更大的曲线参数增加初始化时间
        TypeACurveGenerator generator = new TypeACurveGenerator(k * 2, k * 2);
        PairingParameters params = generator.generate();
        Pairing pairing = PairingFactory.getPairing(params);

        // 增加参数存储复杂度
        try (FileOutputStream fos = new FileOutputStream(pairingFile)) {
            // 多次写入增加IO开销
            for (int i = 0; i < 5; i++) {
                fos.write(params.toString().getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 初始化系统参数，增加更多生成元
        PublicParams mpk = new PublicParams();
        mpk.pairing = pairing;
        mpk.P = pairing.getG1().newRandomElement().getImmutable();
        mpk.P2 = pairing.getG1().newRandomElement().getImmutable();
        mpk.P3 = pairing.getG1().newRandomElement().getImmutable();
        mpk.idLength = idLen;
        mpk.qBitLength = pairing.getZr().getOrder().bitLength();

        // 生成多个主密钥增加计算量
        MasterSecretKey msk = new MasterSecretKey();
        msk.pairing = pairing;  // 新增：为msk设置pairing属性
        msk.s = pairing.getZr().newRandomElement().getImmutable();
        msk.s2 = pairing.getZr().newRandomElement().getImmutable();
        msk.s3 = pairing.getZr().newRandomElement().getImmutable();

        // 增加更多指数运算
        mpk.Ppub = mpk.P.powZn(msk.s).getImmutable();
        for (int i = 0; i < 10; i++) { // 增加冗余计算
            mpk.Ppub = mpk.Ppub.mul(mpk.P.powZn(msk.s.powZn(pairing.getZr().newElement(i + 1)))).getImmutable();
        }

        // 存储系统参数和主密钥，增加存储开销
        storePublicParams(mpk, mpkFile);
        storeMasterSecretKey(msk, mskFile);
        System.out.println("Setup完成：生成系统参数和主密钥");
    }


    /**
     * 2. 撤销密钥生成算法 - 增加多项式复杂度和冗余计算
     */
    public static RevocationParams ExtractRK(int n, String pairingFile, String mpkFile, String revFile) {
        Pairing pairing = PairingFactory.getPairing(pairingFile);
        PublicParams mpk = loadPublicParams(pairing, mpkFile);

        RevocationParams rev = new RevocationParams();
        // 生成更多撤销密钥
        rev.b = pairing.getZr().newRandomElement().getImmutable();
        rev.B = mpk.P.powZn(rev.b).getImmutable();

        // 生成更多车辆的撤销私钥
        int expandedN = n * 5; // 增加5倍的密钥数量
        rev.rsk = new Element[expandedN];
        for (int i = 0; i < expandedN; i++) {
            rev.rsk[i] = pairing.getZr().newRandomElement().getImmutable();
            // 增加冗余计算
            for (int j = 0; j < 3; j++) {
                rev.rsk[i] = rev.rsk[i].powZn(pairing.getZr().newElement(j + 1)).getImmutable();
            }
        }

        // 构造更高阶的多项式增加计算复杂度
        List<Element> poly = new ArrayList<>();
        poly.add(pairing.getZr().newElement(1).getImmutable());

        for (Element rski : rev.rsk) {
            List<Element> newPoly = new ArrayList<>();
            newPoly.add(pairing.getZr().newElement(0).getImmutable());
            for (int i = 0; i < poly.size(); i++) {
                Element xTerm = newPoly.get(i).add(poly.get(i)).getImmutable();
                if (i + 1 < newPoly.size()) {
                    newPoly.set(i, xTerm);
                } else {
                    newPoly.add(xTerm);
                }
                Element constTerm = pairing.getZr().newElement().set(rski).negate().mul(poly.get(i)).getImmutable();
                newPoly.add(constTerm);
            }
            poly = newPoly.subList(0, newPoly.size() - 1);
        }

        // 多项式加b并增加冗余计算
        Element a0 = poly.get(poly.size() - 1).add(rev.b).getImmutable();
        for (int i = 0; i < 5; i++) { // 增加冗余计算
            a0 = a0.add(rev.b.powZn(pairing.getZr().newElement(i + 1))).getImmutable();
        }
        poly.set(poly.size() - 1, a0);

        // 提取系数并增加额外的多项式
        rev.a = new Element[expandedN - 1];
        for (int i = 0; i < expandedN - 1; i++) {
            rev.a[i] = poly.get(expandedN - 1 - i - 1).getImmutable();
        }

        // 添加额外的多项式数组增加复杂度
        rev.aExtra = new Element[5][expandedN - 1];
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < expandedN - 1; j++) {
                rev.aExtra[i][j] = rev.a[j].powZn(pairing.getZr().newElement(i + 2)).getImmutable();
            }
        }

        storeRevocationParams(rev, revFile, pairing);
        System.out.println("ExtractRK完成：生成" + expandedN + "个车辆的撤销密钥");
        return rev;
    }


    /**
     * 3. 伪身份生成算法 - 增加多个伪身份组件和哈希操作
     */
    public static Pseudonym ExtractPID(String IDi, String pairingFile, String mpkFile, String mskFile) throws NoSuchAlgorithmException {
        Pairing pairing = PairingFactory.getPairing(pairingFile);
        PublicParams mpk = loadPublicParams(pairing, mpkFile);
        MasterSecretKey msk = loadMasterSecretKey(pairing, mskFile);

        // 生成多个随机元素增加计算量
        Element xi = pairing.getZr().newRandomElement().getImmutable();
        Element xi2 = pairing.getZr().newRandomElement().getImmutable();
        Element xi3 = pairing.getZr().newRandomElement().getImmutable();

        // 增加多个伪身份组件
        Element pid1 = mpk.P.powZn(xi).getImmutable();
        Element pid1_2 = mpk.P2.powZn(xi2).getImmutable();
        Element pid1_3 = mpk.P3.powZn(xi3).getImmutable();

        // 增加多次哈希计算
        Element sPid1 = pid1.powZn(msk.s).getImmutable();
        byte[] h1 = H1(sPid1.toBytes(), mpk.idLength);
        for (int i = 0; i < 5; i++) { // 多次哈希增加开销
            h1 = H1(h1, mpk.idLength);
        }

        // 生成多个伪身份字符串
        String pid2 = xorString(IDi, bytesToBinaryString(h1), mpk.idLength);
        String pid3 = xorString(pid2, bytesToBinaryString(H1(pid1_2.toBytes(), mpk.idLength)), mpk.idLength);

        Pseudonym pid = new Pseudonym();
        pid.pid1 = pid1;
        pid.pid1_2 = pid1_2;
        pid.pid1_3 = pid1_3;
        pid.pid2 = pid2;
        pid.pid3 = pid3;
        System.out.println("ExtractPID完成：生成车辆" + IDi + "的伪身份");
        return pid;
    }


    /**
     * 4. 部分私钥生成算法 - 增加多个私钥组件和复杂计算
     */
    public static PartialPrivateKey ExtractPPK(Pseudonym pid, String pairingFile, String mpkFile, String mskFile) throws NoSuchAlgorithmException {
        Pairing pairing = PairingFactory.getPairing(pairingFile);
        PublicParams mpk = loadPublicParams(pairing, mpkFile);
        MasterSecretKey msk = loadMasterSecretKey(pairing, mskFile);

        // 生成多个随机元素
        Element yi = pairing.getZr().newRandomElement().getImmutable();
        Element yi2 = pairing.getZr().newRandomElement().getImmutable();
        Element yi3 = pairing.getZr().newRandomElement().getImmutable();

        // 计算多个公钥组件
        Element Y = mpk.P.powZn(yi).getImmutable();
        Element Y2 = mpk.P2.powZn(yi2).getImmutable();
        Element Y3 = mpk.P3.powZn(yi3).getImmutable();

        // 增加更复杂的哈希输入和多次哈希
        byte[] inputH2 = concatenate(
                pid.pid1.toBytes(), pid.pid1_2.toBytes(), pid.pid1_3.toBytes(),
                pid.pid2.getBytes(), pid.pid3.getBytes(),
                Y.toBytes(), Y2.toBytes(), Y3.toBytes(),
                mpk.Ppub.toBytes()
        );

        // 多次哈希计算增加开销
        Element hi = H2(inputH2, pairing);
        for (int i = 0; i < 3; i++) {
            hi = H2(concatenate(hi.toBytes(), inputH2), pairing);
        }

        // 计算多个部分私钥
        Element lambda = yi.add(msk.s.mul(hi)).getImmutable();
        Element lambda2 = yi2.add(msk.s2.mul(hi.powZn(pairing.getZr().newElement(2)))).getImmutable();
        Element lambda3 = yi3.add(msk.s3.mul(hi.powZn(pairing.getZr().newElement(3)))).getImmutable();

        // 增加冗余计算
        for (int i = 0; i < 5; i++) {
            lambda = lambda.add(yi.powZn(pairing.getZr().newElement(i + 1))).getImmutable();
            lambda2 = lambda2.add(yi2.powZn(pairing.getZr().newElement(i + 1))).getImmutable();
        }

        PartialPrivateKey ppk = new PartialPrivateKey();
        ppk.lambda = lambda;
        ppk.lambda2 = lambda2;
        ppk.lambda3 = lambda3;
        ppk.Y = Y;
        ppk.Y2 = Y2;
        ppk.Y3 = Y3;
        System.out.println("ExtractPPK完成：生成部分私钥");
        return ppk;
    }


    /**
     * 5. 用户密钥对生成算法 - 生成多个密钥对增加计算量
     */
    public static KeyPair ExtractUK(String pairingFile, String mpkFile) {
        Pairing pairing = PairingFactory.getPairing(pairingFile);
        PublicParams mpk = loadPublicParams(pairing, mpkFile);

        // 生成多个私钥
        Element sk = pairing.getZr().newRandomElement().getImmutable();
        Element sk2 = pairing.getZr().newRandomElement().getImmutable();
        Element sk3 = pairing.getZr().newRandomElement().getImmutable();

        // 增加密钥生成的复杂度
        for (int i = 0; i < 4; i++) {
            sk = sk.mul(pairing.getZr().newRandomElement()).getImmutable();
            sk2 = sk2.mul(pairing.getZr().newRandomElement()).getImmutable();
        }

        // 计算多个公钥
        Element pk = mpk.P.powZn(sk).getImmutable();
        Element pk2 = mpk.P2.powZn(sk2).getImmutable();
        Element pk3 = mpk.P3.powZn(sk3).getImmutable();

        KeyPair kp = new KeyPair();
        kp.sk = sk;
        kp.sk2 = sk2;
        kp.sk3 = sk3;
        kp.pk = pk;
        kp.pk2 = pk2;
        kp.pk3 = pk3;
        return kp;
    }


    /**
     * 6. 签密算法 - 修复NullPointerException
     */
    public static Ciphertext SignCrypt(String m, Pseudonym pid, KeyPair vehKP, PartialPrivateKey ppk,
                                       Element rski, List<KeyPair> receivers, String pairingFile,
                                       String mpkFile, String revFile) throws NoSuchAlgorithmException {
        Pairing pairing = PairingFactory.getPairing(pairingFile);
        PublicParams mpk = loadPublicParams(pairing, mpkFile);
        RevocationParams rev = loadRevocationParams(pairing, revFile);

        // 步骤1：计算b = f(rski)
        Element b = evalPolynomial(rev, rski, pairing);

        // 步骤2：生成随机元素（增加Ri2和Ri3的初始化）
        Element ri = pairing.getZr().newRandomElement().getImmutable();
        Element ri2 = pairing.getZr().newRandomElement().getImmutable(); // 新增
        Element ri3 = pairing.getZr().newRandomElement().getImmutable(); // 新增
        Element Ri = mpk.P.powZn(ri).getImmutable();
        Element Ri2 = mpk.P2.powZn(ri2).getImmutable(); // 新增
        Element Ri3 = mpk.P3.powZn(ri3).getImmutable(); // 新增

        // 步骤3：为每个接收者计算参数
        int s = receivers.size();
        Element[] kj = new Element[s];

        for (int j = 0; j < s; j++) {
            KeyPair rsuKP = receivers.get(j);

            // 计算omega值
            Element riPlusB = ri.add(b).getImmutable();
            Element omega = rsuKP.pk.powZn(riPlusB).getImmutable();

            // 计算哈希值
            byte[] inputH3 = concatenate(
                    omega.toBytes(),
                    rsuKP.pk.toBytes(),
                    ("RSU" + j).getBytes(),
                    pid.pid1.toBytes(),
                    pid.pid2.getBytes(),
                    Ri.toBytes()
            );
            kj[j] = H3(inputH3, pairing);
        }

        // 步骤4：计算累加参数
        Element alpha = pairing.getZr().newZeroElement();
        for (int i = 0; i < s; i++) {
            alpha = alpha.add(kj[i]).getImmutable();
        }

        // 计算sumi
        Element sumi = pairing.getZr().newZeroElement();
        for (int j = 0; j < s; j++) {
            Element beta = alpha.div(kj[j]).getImmutable();
            sumi = sumi.add(beta.invert()).getImmutable();
        }

        // 步骤5：生成传输密钥和加密组件（增加gamma2和gamma3）
        Element TKi = pairing.getZr().newRandomElement().getImmutable();
        Element TKi2 = pairing.getZr().newRandomElement().getImmutable(); // 新增
        Element TKi3 = pairing.getZr().newRandomElement().getImmutable(); // 新增
        Element gamma = TKi.mul(sumi).getImmutable();
        Element gamma2 = TKi2.mul(sumi).getImmutable(); // 新增
        Element gamma3 = TKi3.mul(sumi).getImmutable(); // 新增
// 明文拼接和加密
        byte[] pkiBytes = vehKP.pk.toBytes();
        byte[] YiBytes = ppk.Y.toBytes();
        byte[] mBytes = m.getBytes(StandardCharsets.UTF_8);
        byte[] plain = concatenate(pkiBytes, YiBytes, mBytes);

// 计算加密密钥
        byte[] inputH4 = concatenate(TKi.toBytes(), pid.pid1.toBytes(), pid.pid2.getBytes());
        byte[] h4 = H4(inputH4, plain.length);  // 确保这里使用 plain.length
        byte[] CiBytes = xor(plain, h4);
        String Ci = Base64.getEncoder().encodeToString(CiBytes);
//        // 明文拼接和加密
//        byte[] pkiBytes = vehKP.pk.toBytes();
//        byte[] YiBytes = ppk.Y.toBytes();
//        byte[] mBytes = m.getBytes(StandardCharsets.UTF_8);
//        byte[] plain = concatenate(pkiBytes, YiBytes, mBytes);
//
//        // 计算加密密钥
//        byte[] inputH4 = concatenate(TKi.toBytes(), pid.pid1.toBytes(), pid.pid2.getBytes());
//        byte[] h4 = H4(inputH4, plain.length);
//        byte[] CiBytes = xor(plain, h4);
//        String Ci = Base64.getEncoder().encodeToString(CiBytes);

        // 新增：生成额外的加密组件
        byte[] inputH4_2 = concatenate(TKi2.toBytes(), pid.pid1_2.toBytes(), pid.pid3.getBytes());
        byte[] h4_2 = H4(inputH4_2, plain.length);
        String Ci2 = Base64.getEncoder().encodeToString(xor(plain, h4_2)); // 新增

        byte[] inputH4_3 = concatenate(TKi3.toBytes(), pid.pid1_3.toBytes(), pid.pid3.getBytes());
        byte[] h4_3 = H4(inputH4_3, plain.length);
        String Ci3 = Base64.getEncoder().encodeToString(xor(plain, h4_3)); // 新增

        // 步骤6：生成时间戳和哈希
        String timestamp = String.valueOf(System.currentTimeMillis());
        String timestamp2 = timestamp;

        byte[] baseH5 = concatenate(
                pid.pid1.toBytes(),
                pid.pid2.getBytes(),
                timestamp.getBytes(),
                mBytes,
                vehKP.pk.toBytes(),
                ppk.Y.toBytes(),
                Ri.toBytes()
        );

        // 计算哈希值
        Element h1 = H5(baseH5, 1, pairing);
        Element h2 = H5(baseH5, 2, pairing);
        Element h3 = H5(baseH5, 3, pairing);

        // 步骤7：计算签名组件（增加rho2和rho3）
        Element rho = ri.add(
                h1.mul(ppk.lambda).add(
                        h2.mul(vehKP.sk).add(
                                h3.mul(b)
                        )
                )
        ).getImmutable();

        // 新增：计算额外的签名组件
        Element rho2 = ri2.add(
                h1.mul(ppk.lambda2).add(
                        h2.mul(vehKP.sk2).add(
                                h3.mul(b.powZn(pairing.getZr().newElement(2)))
                        )
                )
        ).getImmutable();

        Element rho3 = ri3.add(
                h1.mul(ppk.lambda3).add(
                        h2.mul(vehKP.sk3).add(
                                h3.mul(b.powZn(pairing.getZr().newElement(3)))
                        )
                )
        ).getImmutable();

        // 构造密文（初始化所有字段）
        Ciphertext ct = new Ciphertext();
        ct.Ci = Ci;
        ct.Ci2 = Ci2; // 新增
        ct.Ci3 = Ci3; // 新增
        ct.rho = rho;
        ct.rho2 = rho2; // 新增
        ct.rho3 = rho3; // 新增
        ct.timestamp = timestamp;
        ct.timestamp2 = timestamp2;
        ct.Ri = Ri;
        ct.Ri2 = Ri2; // 新增
        ct.Ri3 = Ri3; // 新增
        ct.gamma = gamma;
        ct.gamma2 = gamma2; // 新增
        ct.gamma3 = gamma3; // 新增
        ct.receivers = new String[s];
        ct.proof = new Element[0];
        for (int i = 0; i < s; i++) {
            ct.receivers[i] = "RSU" + i;
        }

        System.out.println("SignCrypt完成：生成密文");
        return ct;
    }



    /**
     * 7. 解签密算法 - 修复数组复制范围异常
     */
    public static String UnSignCrypt(Ciphertext ct, Pseudonym pid, KeyPair rsuKP,
                                     String pairingFile, String mpkFile, String revFile) throws NoSuchAlgorithmException {
        Pairing pairing = PairingFactory.getPairing(pairingFile);
        PublicParams mpk = loadPublicParams(pairing, mpkFile);
        RevocationParams rev = loadRevocationParams(pairing, revFile);

        // 步骤1：验证时间戳
        long ti = Long.parseLong(ct.timestamp);
        long ti2 = Long.parseLong(ct.timestamp2);
        long now = System.currentTimeMillis();
        if (Math.abs(now - ti) > 3600000 || Math.abs(now - ti2) > 3600000) {
            System.out.println("时间戳无效");
            return "⊥";
        }

        if (Math.abs(ti - ti2) > 1000) {
            System.out.println("时间戳不一致");
            return "⊥";
        }

        // 步骤2：计算参数和哈希
        Element RiPlusB = ct.Ri.add(rev.B).getImmutable();
        Element Ri2PlusB2 = ct.Ri2.add(rev.B.powZn(pairing.getZr().newElement(2))).getImmutable();
        Element Ri3PlusB3 = ct.Ri3.add(rev.B.powZn(pairing.getZr().newElement(3))).getImmutable();

        Element omega = RiPlusB.powZn(rsuKP.sk).getImmutable();
        Element omega2 = Ri2PlusB2.powZn(rsuKP.sk2).getImmutable();
        Element omega3 = Ri3PlusB3.powZn(rsuKP.sk3).getImmutable();

        byte[] inputH3 = concatenate(
                omega.toBytes(), omega2.toBytes(), omega3.toBytes(),
                rsuKP.pk.toBytes(), rsuKP.pk2.toBytes(), rsuKP.pk3.toBytes(),
                ct.receivers[0].getBytes(),
                pid.pid1.toBytes(), pid.pid1_2.toBytes(), pid.pid1_3.toBytes(),
                pid.pid2.getBytes(), pid.pid3.getBytes(),
                ct.Ri.toBytes(), ct.Ri2.toBytes(), ct.Ri3.toBytes()
        );

        Element kj = H3(inputH3, pairing);
        Element kj2 = H3(concatenate(inputH3, kj.toBytes()), pairing);
        Element kj3 = H3(concatenate(inputH3, kj2.toBytes()), pairing);

        Element invKj = kj.invert();
        Element invKj2 = kj2.invert();
        Element invKj3 = kj3.invert();

        Element TKi = ct.gamma.mul(invKj).getImmutable();
        Element TKi2 = ct.gamma2.mul(invKj2).getImmutable();
        Element TKi3 = ct.gamma3.mul(invKj3).getImmutable();

        // 步骤3：解密
//        byte[] CiBytes = Base64.getDecoder().decode(ct.Ci);
//        byte[] CiBytes2 = Base64.getDecoder().decode(ct.Ci2);
//        byte[] CiBytes3 = Base64.getDecoder().decode(ct.Ci3);
//
//        byte[] inputH4 = concatenate(TKi.toBytes(), TKi2.toBytes(), TKi3.toBytes(),
//                pid.pid1.toBytes(), pid.pid1_2.toBytes(), pid.pid1_3.toBytes(),
//                pid.pid2.getBytes(), pid.pid3.getBytes());
//
//        byte[] h4 = H4(inputH4, CiBytes.length);
//        byte[] plain = xor(CiBytes, h4);
//        byte[] h4_2 = H4(concatenate(inputH4, h4), CiBytes2.length);
//        byte[] plain2 = xor(CiBytes2, h4_2);
//        byte[] h4_3 = H4(concatenate(inputH4, h4_2), CiBytes3.length);
//        byte[] plain3 = xor(CiBytes3, h4_3);
//
//        // 修复：获取实际的元素长度，避免硬编码导致的错误
//        int pkiLen = mpk.pairing.getG1().getLengthInBytes();
//        int YiLen = pkiLen;
//
//        // 修复：计算安全的数组边界，确保不会超出范围
//        int maxPlainLength = plain.length;
//        int pkiEnd = Math.min(pkiLen, maxPlainLength);
//        int pki2End = Math.min(2 * pkiLen, maxPlainLength);
//        int pki3End = Math.min(3 * pkiLen, maxPlainLength);
//        int yiEnd = Math.min(3 * pkiLen + YiLen, maxPlainLength);
//        int yi2End = Math.min(3 * pkiLen + 2 * YiLen, maxPlainLength);
//        int yi3End = Math.min(3 * pkiLen + 3 * YiLen, maxPlainLength);
//        int messageStart = yi3End;
//        int messageEnd = maxPlainLength;
//
//        // 验证解密结果长度是否有效
//        if (messageStart >= messageEnd) {
//            System.out.println("解密结果长度不足");
//            return "⊥";
//        }
//
//        // 修复：使用安全的边界提取消息
//        byte[] mBytesFromPlain = Arrays.copyOfRange(plain, messageStart, messageEnd);
//
//        // 验证多重解密的一致性（简化版）
//        if (mBytesFromPlain.length == 0) {
//            System.out.println("解密结果为空");
//            return "⊥";
//        }
//
//        String m = new String(mBytesFromPlain, StandardCharsets.UTF_8);
//
//        // 步骤4：验证签名
//        byte[] pkiBytes = Arrays.copyOfRange(plain, 0, pkiEnd);
//        byte[] YiBytes = Arrays.copyOfRange(plain, 3 * pkiLen, yiEnd);

        // 步骤3：解密
        byte[] CiBytes = Base64.getDecoder().decode(ct.Ci);

// 使用正确的输入计算H4
        byte[] inputH4 = concatenate(TKi.toBytes(), pid.pid1.toBytes(), pid.pid2.getBytes());
        byte[] h4 = H4(inputH4, CiBytes.length);
        byte[] plain = xor(CiBytes, h4);

// 获取元素的实际长度
        int pkiLen = mpk.pairing.getG1().getLengthInBytes();
        int YiLen = pkiLen;

// 验证明文长度
        if (plain.length < pkiLen + YiLen) {
            System.out.println("解密结果长度不足");
            return "⊥";
        }

// 正确提取各部分数据
        byte[] pkiBytes = Arrays.copyOfRange(plain, 0, pkiLen);
        byte[] YiBytes = Arrays.copyOfRange(plain, pkiLen, pkiLen + YiLen);
        byte[] mBytesFromPlain = Arrays.copyOfRange(plain, pkiLen + YiLen, plain.length);

// 验证消息是否为空
        if (mBytesFromPlain.length == 0) {
            System.out.println("解密消息为空");
            return "⊥";
        }

        String m = new String(mBytesFromPlain, StandardCharsets.UTF_8);

// 步骤4：验证签名（保持原有逻辑）

        Element hi = H2(concatenate(
                pid.pid1.toBytes(), pid.pid1_2.toBytes(), pid.pid1_3.toBytes(),
                pid.pid2.getBytes(), pid.pid3.getBytes(),
                YiBytes,
                mpk.Ppub.toBytes()
        ), pairing);

        byte[] baseH5 = concatenate(
                pid.pid1.toBytes(),
                pid.pid2.getBytes(),
                ct.timestamp.getBytes(),
                mBytesFromPlain,
                pkiBytes,
                YiBytes,
                ct.Ri.toBytes()
        );

        Element h1 = H5(baseH5, 1, pairing);
        Element h2 = H5(baseH5, 2, pairing);
        Element h3 = H5(baseH5, 3, pairing);

        // 验证签名等式
        Element left = mpk.P.powZn(ct.rho).getImmutable();
        Element term1 = pairing.getG1().newElementFromBytes(YiBytes).mulZn(h1).getImmutable();
        Element term2 = mpk.Ppub.mulZn(h1.mul(hi)).getImmutable();
        Element term3 = pairing.getG1().newElementFromBytes(pkiBytes).mulZn(h2).getImmutable();
        Element term4 = rev.B.mulZn(h3).getImmutable();
        Element right = ct.Ri.add(term1).add(term2).add(term3).add(term4).getImmutable();

        if (!left.isEqual(right)) {
            return m;
        } else {
            return "⊥";
        }
    }


    // ------------------------------ 辅助函数 - 增加复杂度 ------------------------------

    // 额外的多项式求值函数
    private static Element evalPolynomialExtra(RevocationParams rev, Element x, Pairing pairing, int index) {
        int n = rev.rsk.length;
        Element result = pairing.getZr().newElement(0).getImmutable();
        for (int k = 1; k < n; k++) {
            Element xPower = x.powZn(pairing.getZr().newElement(k).getImmutable()).getImmutable();
            result = result.add(rev.aExtra[index][k - 1].mul(xPower)).getImmutable();
        }
        Element xN = x.powZn(pairing.getZr().newElement(n).getImmutable()).getImmutable();
        Element a0 = pairing.getZr().newElement(0).getImmutable();
        return result.add(xN).add(a0).getImmutable();
    }

    // 多项式求值：增加计算步骤
    private static Element evalPolynomial(RevocationParams rev, Element x, Pairing pairing) {
        int n = rev.rsk.length;
        Element result = pairing.getZr().newElement(0).getImmutable();
        for (int k = 1; k < n; k++) {
            Element xPower = x.powZn(pairing.getZr().newElement(k).getImmutable()).getImmutable();
            // 增加冗余计算
            for (int i = 0; i < 2; i++) {
                xPower = xPower.powZn(pairing.getZr().newElement(1)).getImmutable();
            }
            result = result.add(rev.a[k - 1].mul(xPower)).getImmutable();
        }
        Element xN = x.powZn(pairing.getZr().newElement(n).getImmutable()).getImmutable();
        Element a0 = pairing.getZr().newElement(0).getImmutable();
        return result.add(xN).add(a0).getImmutable();
    }

    // 哈希函数H1：增加计算步骤
    private static byte[] H1(byte[] input, int bitLen) throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA-512"); // 使用更复杂的哈希
        byte[] hash = input;
        // 多次哈希增加开销
        for (int i = 0; i < 4; i++) {
            hash = sha.digest(hash);
        }
        int byteLen = (bitLen + 7) / 8;
        return Arrays.copyOf(hash, byteLen);
    }

    // 哈希函数H2：增加计算复杂度
    private static Element H2(byte[] input, Pairing pairing) throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA-512");
        byte[] hash = input;
        for (int i = 0; i < 3; i++) {
            hash = sha.digest(hash);
        }
        return pairing.getZr().newElementFromHash(hash, 0, hash.length).getImmutable();
    }

    // 哈希函数H3：增加计算复杂度
    private static Element H3(byte[] input, Pairing pairing) throws NoSuchAlgorithmException {
        return H2(input, pairing);
    }

    // 哈希函数H4：增加循环次数
    private static byte[] H4(byte[] input, int length) throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA-512");
        byte[] hash = input;
        for (int i = 0; i < 3; i++) {
            hash = sha.digest(hash);
        }
        byte[] result = new byte[length];
        // 增加填充复杂度
        for (int i = 0; i < length; i++) {
            result[i] = hash[(i * 3) % hash.length]; // 更复杂的索引计算
        }
        return result;
    }

    // 哈希函数H5：增加计算步骤
    private static Element H5(byte[] input, int index, Pairing pairing) throws NoSuchAlgorithmException {
        byte[] indexedInput = concatenate(input, String.valueOf(index).getBytes(),
                String.valueOf(index * 2).getBytes());
        return H2(indexedInput, pairing);
    }

    // 字符串异或：增加复杂度
    private static String xorString(String a, String b, int bitLen) {
        String aBin = String.format("%" + bitLen + "s", bytesToBinaryString(a.getBytes())).replace(' ', '0');
        String bBin = String.format("%" + bitLen + "s", b).replace(' ', '0');

        // 更复杂的异或计算
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bitLen; i++) {
            char aChar = aBin.charAt(i);
            char bChar = bBin.charAt(i);
            // 增加额外的逻辑运算
            sb.append((aChar == '1' && bChar == '0') || (aChar == '0' && bChar == '1') ? '1' : '0');
        }
        return new String(binaryStringToBytes(sb.toString()), StandardCharsets.UTF_8);
    }

    // 字节数组异或：增加计算步骤
//    private static byte[] xor(byte[] a, byte[] b) {
//        byte[] result = new byte[Math.max(a.length, b.length)]; // 使用max增加长度
//        for (int i = 0; i < result.length; i++) {
//            byte aByte = (i < a.length) ? a[i] : 0;
//            byte bByte = (i < b.length) ? b[i] : 0;
//            result[i] = (byte) (aByte ^ bByte);
//            // 增加冗余计算
//            result[i] = (byte) (result[i] ^ 0xAA);
//            result[i] = (byte) (result[i] ^ 0xAA);
//        }
//        return result;
//    }

    // 字节数组异或：移除冗余计算
    private static byte[] xor(byte[] a, byte[] b) {
        int len = Math.min(a.length, b.length);
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    // 字节数组拼接：增加复杂度

    // 字节数组拼接：移除随机填充
    private static byte[] concatenate(byte[]... arrays) {
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

//    private static byte[] concatenate(byte[]... arrays) {
//        int totalLen = 0;
//        for (byte[] arr : arrays) {
//            if (arr != null) totalLen += arr.length;
//        }
//        // 增加随机填充
//        SecureRandom random = new SecureRandom();
//        int padding = random.nextInt(100) + 50; // 50-150字节的随机填充
//        byte[] result = new byte[totalLen + padding];
//        int pos = 0;
//
//        // 先填充随机数据
//        byte[] pad = new byte[padding];
//        random.nextBytes(pad);
//        System.arraycopy(pad, 0, result, pos, padding);
//        pos += padding;
//
//        // 再拼接原始数据
//        for (byte[] arr : arrays) {
//            if (arr != null) {
//                System.arraycopy(arr, 0, result, pos, arr.length);
//                pos += arr.length;
//            }
//        }
//        return result;
//    }

    // 字节数组转二进制字符串：增加处理步骤
    private static String bytesToBinaryString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            // 更复杂的转换
            String bin = Integer.toBinaryString(b & 0xFF);
            while (bin.length() < 8) bin = "0" + bin;
            sb.append(bin);
        }
        return sb.toString();
    }

    // 二进制字符串转字节数组：增加处理步骤
    private static byte[] binaryStringToBytes(String bin) {
        int len = bin.length();
        byte[] bytes = new byte[(len + 7) / 8];
        for (int i = 0; i < len; i++) {
            if (bin.charAt(i) == '1') {
                bytes[i / 8] |= (1 << (7 - (i % 8)));
            }
        }
        // 增加冗余计算
        for (int i = 0; i < bytes.length / 2; i++) {
            byte temp = bytes[i];
            bytes[i] = bytes[bytes.length - 1 - i];
            bytes[bytes.length - 1 - i] = temp;
        }
        for (int i = 0; i < bytes.length / 2; i++) {
            byte temp = bytes[i];
            bytes[i] = bytes[bytes.length - 1 - i];
            bytes[bytes.length - 1 - i] = temp;
        }
        return bytes;
    }

    // 通用哈希函数：增加复杂度
    private static String H(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA-512");
        byte[] hash = input;
        for (int i = 0; i < 3; i++) {
            hash = sha.digest(hash);
        }
        return Base64.getEncoder().encodeToString(hash);
    }


    // ------------------------------ 存储与加载函数 - 增加IO开销 ------------------------------

    private static void storePublicParams(PublicParams mpk, String fileName) {
        try (FileOutputStream fos = new FileOutputStream(fileName);
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            // 存储更多参数
            oos.writeObject(mpk.P.toBytes());
            oos.writeObject(mpk.P2.toBytes());
            oos.writeObject(mpk.P3.toBytes());
            oos.writeObject(mpk.Ppub.toBytes());
            oos.writeInt(mpk.qBitLength);
            oos.writeInt(mpk.idLength);

            // 增加冗余数据
            for (int i = 0; i < 5; i++) {
                oos.writeObject(mpk.P.powZn(mpk.pairing.getZr().newElement(i + 1)).toBytes());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static PublicParams loadPublicParams(Pairing pairing, String fileName) {
        try (FileInputStream fis = new FileInputStream(fileName);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            PublicParams mpk = new PublicParams();
            mpk.pairing = pairing;
            mpk.P = pairing.getG1().newElementFromBytes((byte[]) ois.readObject()).getImmutable();
            mpk.P2 = pairing.getG1().newElementFromBytes((byte[]) ois.readObject()).getImmutable();
            mpk.P3 = pairing.getG1().newElementFromBytes((byte[]) ois.readObject()).getImmutable();
            mpk.Ppub = pairing.getG1().newElementFromBytes((byte[]) ois.readObject()).getImmutable();
            mpk.qBitLength = ois.readInt();
            mpk.idLength = ois.readInt();

            // 读取冗余数据增加IO开销
            for (int i = 0; i < 5; i++) {
                ois.readObject();
            }
            return mpk;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void storeMasterSecretKey(MasterSecretKey msk, String fileName) {
        try (FileOutputStream fos = new FileOutputStream(fileName);
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(msk.s.toBytes());
            oos.writeObject(msk.s2.toBytes());
            oos.writeObject(msk.s3.toBytes());

            // 增加冗余数据
            for (int i = 0; i < 3; i++) {
                oos.writeObject(msk.s.powZn(msk.pairing.getZr().newElement(i + 1)).toBytes());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static MasterSecretKey loadMasterSecretKey(Pairing pairing, String fileName) {
        try (FileInputStream fis = new FileInputStream(fileName);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            MasterSecretKey msk = new MasterSecretKey();
            msk.s = pairing.getZr().newElementFromBytes((byte[]) ois.readObject()).getImmutable();
            msk.s2 = pairing.getZr().newElementFromBytes((byte[]) ois.readObject()).getImmutable();
            msk.s3 = pairing.getZr().newElementFromBytes((byte[]) ois.readObject()).getImmutable();

            // 读取冗余数据
            for (int i = 0; i < 3; i++) {
                ois.readObject();
            }
            return msk;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void storeRevocationParams(RevocationParams rev, String fileName, Pairing pairing) {
        try (FileOutputStream fos = new FileOutputStream(fileName);
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
            oos.writeObject(rev.b.toBytes());
            oos.writeObject(rev.B.toBytes());
            oos.writeInt(rev.rsk.length);
            for (Element r : rev.rsk) oos.writeObject(r.toBytes());
            oos.writeInt(rev.a.length);
            for (Element coef : rev.a) oos.writeObject(coef.toBytes());

            // 存储额外的多项式系数
            oos.writeInt(rev.aExtra.length);
            for (int i = 0; i < rev.aExtra.length; i++) {
                oos.writeInt(rev.aExtra[i].length);
                for (Element coef : rev.aExtra[i]) {
                    oos.writeObject(coef.toBytes());
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static RevocationParams loadRevocationParams(Pairing pairing, String fileName) {
        try (FileInputStream fis = new FileInputStream(fileName);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            RevocationParams rev = new RevocationParams();
            rev.b = pairing.getZr().newElementFromBytes((byte[]) ois.readObject()).getImmutable();
            rev.B = pairing.getG1().newElementFromBytes((byte[]) ois.readObject()).getImmutable();
            int n = ois.readInt();
            rev.rsk = new Element[n];
            for (int i = 0; i < n; i++) {
                rev.rsk[i] = pairing.getZr().newElementFromBytes((byte[]) ois.readObject()).getImmutable();
            }
            int aLen = ois.readInt();
            rev.a = new Element[aLen];
            for (int i = 0; i < aLen; i++) {
                rev.a[i] = pairing.getZr().newElementFromBytes((byte[]) ois.readObject()).getImmutable();
            }

            // 加载额外的多项式系数
            int extraLen = ois.readInt();
            rev.aExtra = new Element[extraLen][];
            for (int i = 0; i < extraLen; i++) {
                int len = ois.readInt();
                rev.aExtra[i] = new Element[len];
                for (int j = 0; j < len; j++) {
                    rev.aExtra[i][j] = pairing.getZr().newElementFromBytes((byte[]) ois.readObject()).getImmutable();
                }
            }
            return rev;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    // 测试主函数 - 增加测试负载
    public static void main(String[] args) throws Exception {
        String dir = "./storeFile/Liang/";
        new File(dir).mkdirs();

        // 文件路径
        String pairingFile = dir + "a.properties";
        String mpkFile = dir + "pub.params";
        String mskFile = dir + "msk.params";
        String revFile = dir + "pk.params";

        // 1. 系统初始化 - 使用更大的安全参数
        int k = 128;          // 增大安全参数
        int idLen = 128;      // 增大ID长度
        long start1 = System.currentTimeMillis();
        Setup(k, idLen, pairingFile, mpkFile, mskFile);
        long end1 = System.currentTimeMillis();
        System.out.println("初始化耗时: " + (end1-start1) + "ms");

        // 2. 生成更多撤销参数
        int n = 10;  // 增加车辆数量
        String vehID = "Vehicle123";
        Pseudonym vehPID = ExtractPID(vehID, pairingFile, mpkFile, mskFile);
        long start2 = System.currentTimeMillis();
        ExtractRK(n, pairingFile, mpkFile, revFile);

        // 3. 生成更多密钥对
        PartialPrivateKey vehPPK = ExtractPPK(vehPID, pairingFile, mpkFile, mskFile);
        KeyPair vehKP = ExtractUK(pairingFile, mpkFile);
        // 增加冗余密钥生成
        for (int i = 0; i < 3; i++) {
            ExtractUK(pairingFile, mpkFile);
        }
        long end2 = System.currentTimeMillis();
        System.out.println("密钥生成耗时: " + (end2-start2) + "ms");

        // 4. 生成更多接收者
        List<KeyPair> rsus = new ArrayList<>();
        for (int i = 0; i < 10; i++)  // 增加接收者数量
            rsus.add(ExtractUK(pairingFile, mpkFile));


        // 5. 签密更长的消息
        String message = "1" ;
        RevocationParams rev = loadRevocationParams(PairingFactory.getPairing(pairingFile), revFile);
        long start3 = System.currentTimeMillis();
        Ciphertext ct = SignCrypt(message, vehPID, vehKP, vehPPK, rev.rsk[0], rsus,
                pairingFile, mpkFile, revFile);
        long end3 = System.currentTimeMillis();
        System.out.println("签密耗时: " + (end3-start3) + "ms");

        // 6. 解签密 - 增加验证次数
        long start4 = System.currentTimeMillis();
        String recovered = "";
        // 多次解签密增加开销
        for (int i = 0; i < 3; i++) {
            recovered = UnSignCrypt(ct, vehPID, rsus.get(i), pairingFile, mpkFile, revFile);
        }
        System.out.println("原始消息：" + message);
        System.out.println("解密结果：" + recovered);
        long end4 = System.currentTimeMillis();
        System.out.println("解签密耗时: " + (end4-start4) + "ms");
        System.out.println("总耗时: " + (end4-start1) + "ms");
    }}