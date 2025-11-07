package Wang;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.Base64;

public class Wang {
    // 系统参数
    public static class PublicParams {
        public Pairing pairing;
        public Element g;        // G1中的生成元
        public Element[] gArray; // g1, g2, ..., gt
        public Element h;        // G2中的元素
        public Element[] hArray; // h1, h2, ..., hn
        public Element T;        // g^γ
        public Element Y;        // T^φ = g^(γφ)
        public Element e_gh;     // e(g, h)
        public int t;            // 属性最大数量
        public int n;            // 专业人员最大数量
        public int l;            // 消息长度参数
    }

    // 主密钥
    public static class MasterSecretKey {
        public Element gamma;    // γ ∈ Z_p
        public Element phi;      // φ ∈ Z_p
    }

    // 工人凭证
    public static class Credential {
        public Element A;        // 属性密钥
        public Element B;        // 辅助密钥
        public Element E;        // 公钥组件
        public Element s;        // 秘密值
    }

    // 专业人员解密密钥
    public static class DecryptionKey {
        public Element D;        // 解密密钥
    }

    // 签密密文
    public static class Ciphertext {
        public String C0;        // (mi||ri)⊕H1(...)
        public Element C1;       // h^ki
        public Element C2;       // A_i^νi
        public Element C3;       // B_i^νi
        public Element C4;       // T^(-ki)
        public Element C5;       // E_i·Y^(-ki)
        public ZKProof pi;       // 零知识证明
        public String cmi;       // 承诺
        public String[] attributes; // 披露的属性
        public String[] receivers;  // 接收者集合
        public String timestamp;    // 时间戳
    }

    // 零知识证明结构
    public static class ZKProof {
        public Element ci;
        public Element uid;
        public Element us;
        public Element uν;
        public Element uk;
        public Element[] uj;
    }

    // 1. 初始化阶段 - Setup算法
    public static void setup(int lambda, int t, int n, int l,
                             String pairingFile, String mpkFile, String mskFile) {
        // 生成配对参数
        Pairing pairing = PairingFactory.getPairing(pairingFile);
        if (pairing == null) {
            TypeACurveGenerator generator = new TypeACurveGenerator(lambda, 512);
            pairing = (Pairing) generator.generate();
            try (FileOutputStream fos = new FileOutputStream(pairingFile)) {
                fos.write(pairing.toString().getBytes(StandardCharsets.UTF_8));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        // 生成系统参数
        PublicParams mpk = new PublicParams();
        mpk.pairing = pairing;
        mpk.t = t;
        mpk.n = n;
        mpk.l = l;

        // 随机选择生成元
        mpk.g = pairing.getG1().newRandomElement().getImmutable();
        mpk.h = pairing.getG2().newRandomElement().getImmutable();
        mpk.e_gh = pairing.pairing(mpk.g, mpk.h).getImmutable();

        // 生成g1, g2, ..., gt
        mpk.gArray = new Element[t];
        for (int i = 0; i < t; i++) {
            mpk.gArray[i] = pairing.getG1().newRandomElement().getImmutable();
        }

        // 生成主密钥
        MasterSecretKey msk = new MasterSecretKey();
        msk.gamma = pairing.getZr().newRandomElement().getImmutable();
        msk.phi = pairing.getZr().newRandomElement().getImmutable();

        // 计算T = g^γ, Y = T^φ = g^(γφ)
        mpk.T = mpk.g.powZn(msk.gamma).getImmutable();
        mpk.Y = mpk.T.powZn(msk.phi).getImmutable();

        // 生成h1, h2, ..., hn，其中hi = h^γ^i
        mpk.hArray = new Element[n];
        Element gammaPower = msk.gamma.duplicate();
        for (int i = 0; i < n; i++) {
            mpk.hArray[i] = mpk.h.powZn(gammaPower).getImmutable();
            gammaPower = gammaPower.mul(msk.gamma).getImmutable();
        }

        // 存储主公钥和主密钥
        storePublicParams(mpk, mpkFile);
        storeMasterSecretKey(msk, mskFile);
    }

    // 2. 注册阶段 - 工人凭证生成
    public static Credential CKeyGen(String idi, String[] attributes,
                                     String pairingFile, String mpkFile, String mskFile,
                                     String regFile) throws Exception {
        Pairing pairing = PairingFactory.getPairing(pairingFile);
        PublicParams mpk = loadPublicParams(pairing, mpkFile);
        MasterSecretKey msk = loadMasterSecretKey(pairing, mskFile);

        // 工人生成si和Ei = g^si
        Element si = pairing.getZr().newRandomElement().getImmutable();
        Element Ei = mpk.g.powZn(si).getImmutable();

        // 生成零知识证明ZKPoK1
        ZKProof1 proof = generateZKPoK1(pairing, mpk, idi, Ei, si, attributes);

        // KGI验证零知识证明
        if (!verifyZKPoK1(pairing, mpk, idi, Ei, proof, attributes)) {
            throw new SecurityException("ZKPoK1验证失败");
        }

        // 计算H0(Idi)
        Element H0Idi = H0(pairing, idi);

        // 计算属性乘积: product(g_i^a_i)
        Element attrProduct = pairing.getG1().newOneElement();
        for (int i = 0; i < attributes.length && i < mpk.t; i++) {
            int a_i = Integer.parseInt(attributes[i]);
            attrProduct = attrProduct.mul(mpk.gArray[i].powZn(pairing.getZr().newElement(a_i))).getImmutable();
        }

        // 计算Ai = (Ei · product(g_i^a_i))^(1/[γ + H0(Idi)])
        Element denominator = msk.gamma.add(H0Idi).getImmutable();
        Element invDenominator = denominator.invert().getImmutable();
        Element base = Ei.mul(attrProduct).getImmutable();
        Element Ai = base.powZn(invDenominator).getImmutable();

        // 将(Idi, Ei, Ai)添加到注册列表
        addToRegistry(regFile, idi, Ei, Ai);

        // 工人验证Ai
        Element h1 = mpk.hArray[0]; // h1 = h^γ
        Element h_H0Idi = mpk.h.powZn(H0Idi).getImmutable();
        Element left = pairing.pairing(Ai, h1.mul(h_H0Idi)).getImmutable();
        Element right = pairing.pairing(base, mpk.h).getImmutable();

        if (!left.isEqual(right)) {
            throw new SecurityException("工人凭证验证失败");
        }

        // 计算Bi = Ai^(-H0(Idi)) · Ei · product(g_i^a_i)
        Element Bi = Ai.powZn(H0Idi.negate()).mul(base).getImmutable();

        // 返回工人凭证
        Credential cred = new Credential();
        cred.A = Ai;
        cred.B = Bi;
        cred.E = Ei;
        cred.s = si;
        return cred;
    }

    // 2. 注册阶段 - 专业人员解密密钥生成
    public static DecryptionKey DKeyGen(String idv,
                                        String pairingFile, String mpkFile, String mskFile) throws Exception {
        Pairing pairing = PairingFactory.getPairing(pairingFile);
        PublicParams mpk = loadPublicParams(pairing, mpkFile);
        MasterSecretKey msk = loadMasterSecretKey(pairing, mskFile);

        // 计算H0(Idv)
        Element H0Idv = H0(pairing, idv);

        // 计算Dv = g^[1/(γ + H0(Idv))]
        Element denominator = msk.gamma.add(H0Idv).getImmutable();
        Element invDenominator = denominator.invert().getImmutable();
        Element Dv = mpk.g.powZn(invDenominator).getImmutable();

        // 验证Dv
        Element h1 = mpk.hArray[0]; // h1 = h^γ
        Element h_H0Idv = mpk.h.powZn(H0Idv).getImmutable();
        Element left = pairing.pairing(Dv, h1.mul(h_H0Idv)).getImmutable();
        Element right = pairing.pairing(mpk.g, mpk.h).getImmutable();

        if (!left.isEqual(right)) {
            throw new SecurityException("解密密钥验证失败");
        }

        DecryptionKey dk = new DecryptionKey();
        dk.D = Dv;
        return dk;
    }

    // 3. 数据签密阶段
    public static Ciphertext signcrypt(String mi, Credential cred, String[] disclosedAttrs,
                                       String[] receivers, String pairingFile, String mpkFile,String workerId,String[] allAttributes) throws Exception {
        Pairing pairing = PairingFactory.getPairing(pairingFile);
        PublicParams mpk = loadPublicParams(pairing, mpkFile);

        // 生成随机数
        Element ki = pairing.getZr().newRandomElement().getImmutable();
        byte[] ri = new byte[mpk.l / 8];
        new SecureRandom().nextBytes(ri);
        String timestamp = String.valueOf(System.currentTimeMillis());

        // 计算Ci,0 = (mi||ri)⊕H1(e(g,h)^ki)
        Element e_gh_ki = mpk.e_gh.powZn(ki).getImmutable();
        byte[] key = H1(e_gh_ki.toBytes(), 2 * mpk.l);
        byte[] miBytes = mi.getBytes(StandardCharsets.UTF_8);
        byte[] miRi = concatenate(miBytes, ri);
        byte[] C0 = xor(miRi, key);

        // 计算承诺cmi = H(ri||Ai||TS)
        String cmi = H(concatenate(ri, cred.A.toBytes(), timestamp.getBytes(StandardCharsets.UTF_8)));

        // 随机选择νi
        Element nui = pairing.getZr().newRandomElement().getImmutable();

        // 计算各个Ci组件
        Ciphertext ct = new Ciphertext();
        ct.C0 = Base64.getEncoder().encodeToString(C0);
        ct.C1 = mpk.h.powZn(ki).getImmutable();
        ct.C2 = cred.A.powZn(nui).getImmutable();
        ct.C3 = cred.B.powZn(nui).getImmutable();
        ct.C4 = mpk.T.powZn(ki.negate()).getImmutable();
        ct.C5 = cred.E.mul(mpk.Y.powZn(ki.negate())).getImmutable();
        ct.cmi = cmi;
        ct.attributes = disclosedAttrs;
        ct.receivers = receivers;
        ct.timestamp = timestamp;

        // 生成零知识证明ZKPoK2
        ct.pi = generateZKPoK2(pairing, mpk, ct, cred, nui, ki, disclosedAttrs,workerId,allAttributes);

        return ct;
    }

    // 4. 数据解签密阶段 - 云服务器外包验证
    public static boolean outsourcedUnsigncrypt(Ciphertext ct, String pairingFile, String mpkFile) throws Exception {
        Pairing pairing = PairingFactory.getPairing(pairingFile);
        PublicParams mpk = loadPublicParams(pairing, mpkFile);

        // 验证时间戳是否有效（简单检查，实际应用需更复杂逻辑）
        long ts = Long.parseLong(ct.timestamp);
        long now = System.currentTimeMillis();
        if (Math.abs(now - ts) > 3600000) { // 1小时有效期
            return false;
        }

        // 验证e(Ci,3, h) == e(Ci,2, h1)
        Element h1 = mpk.hArray[0];
        Element left = pairing.pairing(ct.C3, mpk.h).getImmutable();
        Element right = pairing.pairing(ct.C2, h1).getImmutable();
        if (!left.isEqual(right)) {
            return false;
        }

        // 验证零知识证明ZKPoK2
        if (!verifyZKPoK2(pairing, mpk, ct)) {
            return false;
        }

        return true;
    }

    // 4. 数据解签密阶段 - 专业人员解密
    public static String unsigncrypt(Ciphertext ct, DecryptionKey dk, String idv,
                                     String pairingFile, String mpkFile,String mskFile) throws Exception {
        Pairing pairing = PairingFactory.getPairing(pairingFile);
        PublicParams mpk = loadPublicParams(pairing, mpkFile);

        // 计算hpv,s(γ)
        Element hpv = computeHpv(pairing, mpk, ct.receivers, idv,mskFile);

        // 计算Zv = e(Ci,4, hpv,s(γ))
        Element Zv = pairing.pairing(ct.C4, hpv).getImmutable();

        // 计算Fv = e(Dv, Ci,1)
        Element Fv = pairing.pairing(dk.D, ct.C1).getImmutable();

        // 计算Zv·Fv
        Element ZvFv = Zv.mul(Fv).getImmutable();

        // 计算所有其他接收者的H0(Idj)之和
        Element sumH0 = pairing.getZr().newZeroElement();
        for (String idj : ct.receivers) {
            if (!idj.equals(idv)) {
                sumH0 = sumH0.add(H0(pairing, idj)).getImmutable();
            }
        }

        // 计算Tv = (Zv·Fv)^[1/sumH0]
        Element invSumH0 = sumH0.invert().getImmutable();
        Element Tv = ZvFv.powZn(invSumH0).getImmutable();

        // 恢复mi||ri
        byte[] key = H1(Tv.toBytes(), 2 * mpk.l);
        byte[] C0 = Base64.getDecoder().decode(ct.C0);
        byte[] miRi = xor(C0, key);

        // 分离mi和ri
        byte[] ri = Arrays.copyOfRange(miRi, miRi.length - mpk.l / 8, miRi.length);
        byte[] miBytes = Arrays.copyOfRange(miRi, 0, miRi.length - mpk.l / 8);

        // 验证承诺
        String computedCmi = H(concatenate(ri, ct.C2.toBytes(), ct.timestamp.getBytes(StandardCharsets.UTF_8)));
        if (!computedCmi.equals(ct.cmi)) {
            System.out.println("承诺验证失败");
        }

        return new String(miBytes, StandardCharsets.UTF_8);
    }

    // 生成ZKPoK1
    private static ZKProof1 generateZKPoK1(Pairing pairing, PublicParams mpk,
                                           String idi, Element Ei, Element si, String[] attributes) throws NoSuchAlgorithmException {
        ZKProof1 proof = new ZKProof1();

        // 选择随机数ri
        Element ri = pairing.getZr().newRandomElement().getImmutable();

        // 计算Ri = g^ri
        Element Ri = mpk.g.powZn(ri).getImmutable();

        // 计算ci = H(Idi||Ei||Ri||a1||a2||...||at)
        byte[] hashInput = concatenate(idi.getBytes(StandardCharsets.UTF_8),
                Ei.toBytes(),
                Ri.toBytes(),
                String.join(",", attributes).getBytes(StandardCharsets.UTF_8));
        proof.ci = pairing.getZr().newElementFromHash(H(hashInput).getBytes(), 0, 32).getImmutable();

        // 计算ui = si·ci - ri
        proof.ui = si.mul(proof.ci).sub(ri).getImmutable();

        return proof;
    }

    // 验证ZKPoK1
    private static boolean verifyZKPoK1(Pairing pairing, PublicParams mpk,
                                        String idi, Element Ei, ZKProof1 proof, String[] attributes) throws NoSuchAlgorithmException {
        // 计算Ri = Ei^ci / g^ui
        Element Ri = Ei.powZn(proof.ci).div(mpk.g.powZn(proof.ui)).getImmutable();

        // 计算ci' = H(Idi||Ei||Ri||a1||a2||...||at)
        byte[] hashInput = concatenate(idi.getBytes(StandardCharsets.UTF_8),
                Ei.toBytes(),
                Ri.toBytes(),
                String.join(",", attributes).getBytes(StandardCharsets.UTF_8));
        Element ciPrime = pairing.getZr().newElementFromHash(H(hashInput).getBytes(), 0, 32).getImmutable();

        // 验证ci == ci'
        return proof.ci.isEqual(ciPrime);
    }


    // 生成ZKPoK2 - 修复了数组索引越界异常
    private static ZKProof generateZKPoK2(Pairing pairing, PublicParams mpk, Ciphertext ct,
                                          Credential cred, Element nui, Element ki, String[] disclosedAttrs, String workerId,
                                          String[] allAttributes) throws NoSuchAlgorithmException {  // 添加所有属性参数
        ZKProof proof = new ZKProof();
        int t = mpk.t;
        int disclosedCount = disclosedAttrs.length;
        int hiddenCount = t - disclosedCount;

        // 验证属性数量是否匹配
        if (allAttributes.length != t) {
            throw new IllegalArgumentException("所有属性数量必须等于最大属性数量t");
        }
        if (disclosedCount > t) {
            throw new IllegalArgumentException("披露的属性数量不能超过最大属性数量t");
        }

        // 初始化uj数组
        proof.uj = new Element[hiddenCount];

        // 选择随机数
        Element rid = pairing.getZr().newRandomElement().getImmutable();
        Element rnu = pairing.getZr().newRandomElement().getImmutable();
        Element rs = pairing.getZr().newRandomElement().getImmutable();
        Element rk = pairing.getZr().newRandomElement().getImmutable();
        Element[] rj = new Element[hiddenCount];
        for (int i = 0; i < hiddenCount; i++) {
            rj[i] = pairing.getZr().newRandomElement().getImmutable();
        }

        // 计算临时值用于生成ci
        Element tempRi0 = mpk.g.powZn(rs)
                .mul(mpk.g.powZn(nui.mul(rnu)))
                .getImmutable();
        for (int i = 0; i < hiddenCount; i++) {
            // 使用所有属性而非仅披露的属性
            tempRi0 = tempRi0.mul(mpk.gArray[disclosedCount + i].powZn(rj[i])).getImmutable();
        }

        Element tempRi1 = mpk.T.powZn(rk.negate()).getImmutable();
        Element tempRi2 = mpk.g.powZn(rs).mul(mpk.Y.powZn(rk.negate())).getImmutable();

        // 计算ci
        byte[] hashInput = concatenate(ct.C0.getBytes(), ct.C1.toBytes(), ct.C2.toBytes(),
                ct.C3.toBytes(), ct.C4.toBytes(), ct.C5.toBytes(),
                tempRi0.toBytes(), tempRi1.toBytes(), tempRi2.toBytes(),
                ct.cmi.getBytes(), ct.timestamp.getBytes(),
                String.join(",", allAttributes).getBytes());  // 使用所有属性
        proof.ci = pairing.getZr().newElementFromHash(H(hashInput).getBytes(), 0, 32).getImmutable();

        // 计算H0Idi
        Element H0Idi = H0(pairing, workerId);

        // 计算Ri0
        Element Ri0 = ct.C3.powZn(proof.ci.negate())
                .mul(mpk.g.powZn(rs))
                .mul(mpk.g.powZn(nui.mul(rnu)))
                .getImmutable();

        // 处理隐藏属性（使用allAttributes获取隐藏属性）
        for (int i = 0; i < hiddenCount; i++) {
            // 从所有属性中获取隐藏的属性（索引 = 披露属性数量 + 当前隐藏属性索引）
            int hiddenAttrIndex = disclosedCount + i;
            if (hiddenAttrIndex >= allAttributes.length) {
                throw new ArrayIndexOutOfBoundsException("隐藏属性索引超出所有属性数组范围");
            }
            int aj = Integer.parseInt(allAttributes[hiddenAttrIndex]);
            Element ajElement = pairing.getZr().newElement(aj).getImmutable();
            proof.uj[i] = nui.mul(ajElement).mul(proof.ci).sub(rj[i]).getImmutable();

            // 计算Ri0
            Ri0 = Ri0.mul(mpk.gArray[hiddenAttrIndex].powZn(proof.uj[i])).getImmutable();
        }

        Element Ri1 = mpk.T.powZn(rk.negate()).getImmutable();
        Element Ri2 = mpk.g.powZn(rs).mul(mpk.Y.powZn(rk.negate())).getImmutable();

        // 计算各种u值
        proof.uid = H0Idi.mul(proof.ci).sub(rid).getImmutable();
        proof.us = nui.mul(cred.s).mul(proof.ci).sub(rs).getImmutable();
        proof.uν = nui.mul(proof.ci).sub(rnu).getImmutable();
        proof.uk = ki.mul(proof.ci).sub(rk).getImmutable();

        return proof;
    }

    // 验证ZKPoK2
    private static boolean verifyZKPoK2(Pairing pairing, PublicParams mpk, Ciphertext ct) throws NoSuchAlgorithmException {
        ZKProof proof = ct.pi;
        if (proof == null || proof.ci == null) {
            return false; // 验证proof和ci不为空
        }

        int t = mpk.t;
        int disclosedCount = ct.attributes.length;
        int hiddenCount = t - disclosedCount;

        // 计算Ri,0 - 修复类型转换错误：使用powZn()代替直接乘法
        Element Ri0 = ct.C3.powZn(proof.ci)
                .div(ct.C2.powZn(proof.uid))  // 修复：使用幂运算代替乘法
                .mul(mpk.g.powZn(proof.us))
                .mul(mpk.g.powZn(proof.uν))  // 修复：使用g的幂运算代替直接乘法
                .getImmutable();
        for (int i = 0; i < hiddenCount; i++) {
            Ri0 = Ri0.mul(mpk.gArray[disclosedCount + i].powZn(proof.uj[i])).getImmutable();
        }

        Element Ri1 = ct.C4.powZn(proof.ci).div(mpk.T.powZn(proof.uk.negate())).getImmutable();
        Element Ri2 = ct.C5.powZn(proof.ci)
                .div(mpk.g.powZn(proof.us))
                .div(mpk.Y.powZn(proof.uk.negate()))
                .getImmutable();

        // 计算ci'并验证
        byte[] hashInput = concatenate(ct.C0.getBytes(), ct.C1.toBytes(), ct.C2.toBytes(),
                ct.C3.toBytes(), ct.C4.toBytes(), ct.C5.toBytes(),
                Ri0.toBytes(), Ri1.toBytes(), Ri2.toBytes(),
                ct.cmi.getBytes(), ct.timestamp.getBytes(),
                String.join(",", ct.attributes).getBytes());
        Element ciPrime = pairing.getZr().newElementFromHash(H(hashInput).getBytes(), 0, 32).getImmutable();

        return proof.ci.isEqual(ciPrime);
    }


    // 计算hpv,s(γ)
    private static Element computeHpv(Pairing pairing, PublicParams mpk, String[] receivers, String idv,String mskFile) throws Exception {
        Element hpv = pairing.getG2().newOneElement();
        MasterSecretKey msk = loadMasterSecretKey(pairing, mskFile);
        for (String idj : receivers) {
            if (!idj.equals(idv)) {
                Element H0Idj = H0(pairing, idj);
                Element h1 = mpk.hArray[0];  // h1 = h^γ

                // 修复：使用幂运算替代加法，计算 h^(γ + H0(Idj))
                Element exponent = mpk.pairing.getZr().newElement()
                        .set(mpk.pairing.getZr().newElementFromBytes(msk.gamma.toBytes()))  // γ
                        .add(H0Idj)  // γ + H0(Idj)
                        .getImmutable();
                Element term = mpk.h.powZn(exponent).getImmutable();  // h^(γ + H0(Idj))

                hpv = hpv.mul(term).getImmutable();
            }
        }

        Element sumH0 = pairing.getZr().newZeroElement();
        for (String idj : receivers) {
            if (!idj.equals(idv)) {
                sumH0 = sumH0.add(H0(pairing, idj)).getImmutable();
            }
        }

        Element hSumH0 = mpk.h.powZn(sumH0).getImmutable();
        hpv = hpv.div(hSumH0).getImmutable();

        return hpv;
    }


    // 哈希函数实现
    private static Element H0(Pairing pairing, String id) throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha.digest(id.getBytes(StandardCharsets.UTF_8));
        return pairing.getZr().newElementFromHash(hash, 0, hash.length).getImmutable();
    }

    private static byte[] H1(byte[] input, int length) throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha.digest(input);
        return Arrays.copyOf(hash, length / 8);
    }

    private static String H(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha.digest(input);
        return Base64.getEncoder().encodeToString(hash);
    }

    // 辅助方法：字节数组拼接
    private static byte[] concatenate(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }
        byte[] result = new byte[totalLength];
        int currentIndex = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, currentIndex, array.length);
            currentIndex += array.length;
        }
        return result;
    }

    // 辅助方法：异或操作
    private static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[Math.min(a.length, b.length)];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    // 注册列表操作
    private static void addToRegistry(String regFile, String idi, Element Ei, Element Ai) throws IOException {
        Properties reg = new Properties();
        File file = new File(regFile);
        if (file.exists()) {
            try (FileInputStream fis = new FileInputStream(file)) {
                reg.load(fis);
            }
        }

        reg.setProperty("Ei_" + idi, Base64.getEncoder().encodeToString(Ei.toBytes()));
        reg.setProperty("Ai_" + idi, Base64.getEncoder().encodeToString(Ai.toBytes()));

        try (FileOutputStream fos = new FileOutputStream(file)) {
            reg.store(fos, null);
        }
    }

    // 参数存储与加载方法
    private static void storePublicParams(PublicParams mpk, String fileName) {
        try {
            Properties prop = new Properties();
            prop.setProperty("g", Base64.getEncoder().encodeToString(mpk.g.toBytes()));
            prop.setProperty("h", Base64.getEncoder().encodeToString(mpk.h.toBytes()));
            prop.setProperty("T", Base64.getEncoder().encodeToString(mpk.T.toBytes()));
            prop.setProperty("Y", Base64.getEncoder().encodeToString(mpk.Y.toBytes()));
            prop.setProperty("e_gh", Base64.getEncoder().encodeToString(mpk.e_gh.toBytes()));
            prop.setProperty("t", String.valueOf(mpk.t));
            prop.setProperty("n", String.valueOf(mpk.n));
            prop.setProperty("l", String.valueOf(mpk.l));

            for (int i = 0; i < mpk.t; i++) {
                prop.setProperty("g_" + i, Base64.getEncoder().encodeToString(mpk.gArray[i].toBytes()));
            }

            for (int i = 0; i < mpk.n; i++) {
                prop.setProperty("h_" + i, Base64.getEncoder().encodeToString(mpk.hArray[i].toBytes()));
            }

            try (FileOutputStream fos = new FileOutputStream(fileName)) {
                prop.store(fos, null);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static PublicParams loadPublicParams(Pairing pairing, String fileName) {
        try {
            Properties prop = new Properties();
            try (FileInputStream fis = new FileInputStream(fileName)) {
                prop.load(fis);
            }

            PublicParams mpk = new PublicParams();
            mpk.pairing = pairing;
            mpk.t = Integer.parseInt(prop.getProperty("t"));
            mpk.n = Integer.parseInt(prop.getProperty("n"));
            mpk.l = Integer.parseInt(prop.getProperty("l"));

            mpk.g = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(prop.getProperty("g"))).getImmutable();
            mpk.h = pairing.getG2().newElementFromBytes(Base64.getDecoder().decode(prop.getProperty("h"))).getImmutable();
            mpk.T = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(prop.getProperty("T"))).getImmutable();
            mpk.Y = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(prop.getProperty("Y"))).getImmutable();
            mpk.e_gh = pairing.getGT().newElementFromBytes(Base64.getDecoder().decode(prop.getProperty("e_gh"))).getImmutable();

            mpk.gArray = new Element[mpk.t];
            for (int i = 0; i < mpk.t; i++) {
                mpk.gArray[i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(prop.getProperty("g_" + i))).getImmutable();
            }

            mpk.hArray = new Element[mpk.n];
            for (int i = 0; i < mpk.n; i++) {
                mpk.hArray[i] = pairing.getG2().newElementFromBytes(Base64.getDecoder().decode(prop.getProperty("h_" + i))).getImmutable();
            }

            return mpk;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static void storeMasterSecretKey(MasterSecretKey msk, String fileName) {
        try {
            Properties prop = new Properties();
            prop.setProperty("gamma", Base64.getEncoder().encodeToString(msk.gamma.toBytes()));
            prop.setProperty("phi", Base64.getEncoder().encodeToString(msk.phi.toBytes()));

            try (FileOutputStream fos = new FileOutputStream(fileName)) {
                prop.store(fos, null);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static MasterSecretKey loadMasterSecretKey(Pairing pairing, String fileName) {
        try {
            Properties prop = new Properties();
            try (FileInputStream fis = new FileInputStream(fileName)) {
                prop.load(fis);
            }

            MasterSecretKey msk = new MasterSecretKey();
            msk.gamma = pairing.getZr().newElementFromBytes(Base64.getDecoder().decode(prop.getProperty("gamma"))).getImmutable();
            msk.phi = pairing.getZr().newElementFromBytes(Base64.getDecoder().decode(prop.getProperty("phi"))).getImmutable();

            return msk;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    // ZKPoK1专用结构
    private static class ZKProof1 {
        public Element ci;
        public Element ui;
    }

    // 测试主函数
    public static void main(String[] args) throws Exception {

        String dir = "./storeFile/Wang/";
        new File(dir).mkdirs();

        // 文件路径
        String pairingFile = dir + "a.properties";
        String mpkFile = dir + "pub.properties";
        String mskFile = dir + "msk.properties";
        String regFile = dir + "pk.properties";

        // 1. 初始化系统
        int lambda = 160;  // 安全参数
        int t = 10;         // 最大属性数量
        int n = 10;        // 最大专业人员数量
        int l = 128;       // 消息长度参数（位）
        long start = System.currentTimeMillis();
        long start1 = System.currentTimeMillis();
        setup(lambda, t, n, l, pairingFile, mpkFile, mskFile);
        long end1 = System.currentTimeMillis();
        System.out.println(end1-start1);
        System.out.println("系统初始化完成");

        // 2. 注册工人和专业人员
        String workerId = "worker123";
        String[] attributes = {"1", "0", "3", "2", "1","2","2","2","2","2"};  // 工人属性
        long start2 = System.currentTimeMillis();
        Credential workerCred = CKeyGen(workerId, attributes, pairingFile, mpkFile, mskFile, regFile);
        System.out.println("工人注册完成");

        String professionalId = "doctor456";

        DecryptionKey decKey = DKeyGen(professionalId, pairingFile, mpkFile, mskFile);
        System.out.println("专业人员注册完成");
        long end2 = System.currentTimeMillis();
        System.out.println(end2-start2);
        // 3. 签密数据
        String message = "这是一个秘密的医疗数据";
        String[] receivers = {professionalId, "doctor789"};  // 接收者列表
        String[] disclosedAttrs = {"1", "0"};  // 披露的属性
        long start3 = System.currentTimeMillis();
        Ciphertext ciphertext = signcrypt(message, workerCred, disclosedAttrs, receivers, pairingFile, mpkFile,workerId,attributes);
        long end3 = System.currentTimeMillis();
        System.out.println(end3-start3);
        System.out.println("数据签密完成");

        // 4. 云服务器验证
        long start4 = System.currentTimeMillis();
        boolean valid = outsourcedUnsigncrypt(ciphertext, pairingFile, mpkFile);
        if (!valid) {
            System.out.println("云服务器验证失败");
        }
        else
            System.out.println("云服务器验证通过");

        // 5. 专业人员解密
        String recovered = unsigncrypt(ciphertext, decKey, professionalId, pairingFile, mpkFile,mskFile);
        System.out.println("解密结果: " + recovered);
        System.out.println("原始消息: " + message);
        System.out.println("解密" + (recovered.equals(message) ? "成功" : "失败"));
        long end4 = System.currentTimeMillis();
        System.out.println(end4-start4);

        long end = System.currentTimeMillis();
        System.out.println(end-start);
    }



}
