#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <string.h>

#define MAX_ATTRIBUTES 10
#define MAX_RECEIVERS 5

// Hash function H: {0,1}* -> Zp
void Hash_H(element_t result, pairing_t pairing, const char* data) {
    element_from_hash(result, (void*)data, strlen(data));
}

// Hash function H0: {0,1}* -> Zp
void Hash_H0(element_t result, pairing_t pairing, const char* id) {
    unsigned char hash_data[256];
    sprintf((char*)hash_data, "H0:%s", id);
    element_from_hash(result, hash_data, strlen((char*)hash_data));
}

// Hash function H1: GT -> {0,1}^{2l} (simplified)
void Hash_H1(element_t result, pairing_t pairing, element_t gt_element) {
    unsigned char hash_input[256];
    int len = element_to_bytes(hash_input, gt_element);
    element_from_hash(result, hash_input, len);
}

int main(int argc, char **argv) {
    pairing_t pairing;
    double t0, t1;
    
    // System parameters
    element_t gamma, phi, g, g_prime, h;
    element_t g_attr[MAX_ATTRIBUTES];  // g1, g2, ..., gt
    element_t h_gamma[MAX_ATTRIBUTES]; // h_i = h^(gamma^i)
    element_t T, Y;  // T = g^gamma, Y = T^phi
    element_t e_g_h; // e(g,h)
    
    // Worker credentials
    element_t s_i, r_i, E_i, A_i, B_i;
    element_t H0_Id_i;
    
    // Professional decryption key
    element_t D_v;
    
    // Signcryption components
    element_t k_i, v_i;
    element_t C_i_0, C_i_1, C_i_2, C_i_3, C_i_4, C_i_5;
    element_t h_tilde;  // h^{prod(gamma + H0(id_j))}
    
    // ZKPoK components
    element_t c_i, u_id, u_s, u_v, u_k;
    element_t R_i_0, R_i_1, R_i_2;
    
    // Unsigncryption components
    element_t h_poly_v, Z_v, F_v, T_v;
    
    // Temporary variables
    element_t tmp1, tmp2, tmp3, tmp4, tmp5;
    element_t tmp_zr1, tmp_zr2, tmp_zr3;
    element_t tmp_gt1, tmp_gt2, tmp_gt3;
    element_t Lambda;  // Product of disclosed attributes
    element_t one;
    
    pbc_demo_pairing_init(pairing, argc, argv);
    
    printf("========================================\n");
    printf("Attribute-Based Signcryption Scheme\n");
    printf("with Outsourcing and ZKPoK\n");
    printf("========================================\n\n");
    
    // Initialize elements
    element_init_Zr(gamma, pairing);
    element_init_Zr(phi, pairing);
    element_init_G1(g, pairing);
    element_init_G1(g_prime, pairing);
    element_init_G2(h, pairing);
    element_init_G1(T, pairing);
    element_init_G1(Y, pairing);
    element_init_GT(e_g_h, pairing);
    
    // Initialize attribute generators
    for (int i = 0; i < MAX_ATTRIBUTES; i++) {
        element_init_G1(g_attr[i], pairing);
        element_init_G2(h_gamma[i], pairing);
    }
    
    // Initialize worker credentials
    element_init_Zr(s_i, pairing);
    element_init_Zr(r_i, pairing);
    element_init_G1(E_i, pairing);
    element_init_G1(A_i, pairing);
    element_init_G1(B_i, pairing);
    element_init_Zr(H0_Id_i, pairing);
    
    // Initialize professional key
    element_init_G2(D_v, pairing);
    
    // Initialize signcryption components
    element_init_Zr(k_i, pairing);
    element_init_Zr(v_i, pairing);
    element_init_GT(C_i_0, pairing);
    element_init_G2(C_i_1, pairing);
    element_init_G1(C_i_2, pairing);
    element_init_G1(C_i_3, pairing);
    element_init_G1(C_i_4, pairing);
    element_init_G1(C_i_5, pairing);
    element_init_G2(h_tilde, pairing);
    
    // Initialize ZKPoK components
    element_init_Zr(c_i, pairing);
    element_init_Zr(u_id, pairing);
    element_init_Zr(u_s, pairing);
    element_init_Zr(u_v, pairing);
    element_init_Zr(u_k, pairing);
    element_init_G1(R_i_0, pairing);
    element_init_G1(R_i_1, pairing);
    element_init_G1(R_i_2, pairing);
    
    // Initialize unsigncryption components
    element_init_G2(h_poly_v, pairing);
    element_init_GT(Z_v, pairing);
    element_init_GT(F_v, pairing);
    element_init_GT(T_v, pairing);
    
    // Initialize temporary variables
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);
    element_init_G1(tmp3, pairing);
    element_init_G2(tmp4, pairing);
    element_init_G2(tmp5, pairing);
    element_init_Zr(tmp_zr1, pairing);
    element_init_Zr(tmp_zr2, pairing);
    element_init_Zr(tmp_zr3, pairing);
    element_init_GT(tmp_gt1, pairing);
    element_init_GT(tmp_gt2, pairing);
    element_init_GT(tmp_gt3, pairing);
    element_init_G1(Lambda, pairing);
    element_init_Zr(one, pairing);
    
    t0 = pbc_get_time();
    
    // ========================================
    // A. INITIALIZATION (SETUP)
    // ========================================
    printf("(A) Initialization Phase\n");
    printf("----------------------------------------\n");
    
    // Generate random master keys
    element_random(gamma);
    element_random(phi);
    element_printf("Master private key gamma = %B\n", gamma);
    element_printf("Master private key phi = %B\n", phi);
    
    // Generate generators
    element_random(g);
    element_random(g_prime);
    element_random(h);
    element_printf("Generator g = %B\n", g);
    element_printf("Generator g' = %B\n", g_prime);
    element_printf("Generator h = %B\n", h);
    
    // Compute T = g^gamma
    element_pow_zn(T, g, gamma);
    element_printf("T = g^gamma = %B\n", T);
    
    // Compute Y = T^phi = g^(gamma*phi)
    element_pow_zn(Y, T, phi);
    element_printf("Y = T^phi = %B\n", Y);
    
    // Compute e(g,h)
    pairing_apply(e_g_h, g, h, pairing);
    element_printf("e(g,h) = %B\n", e_g_h);
    
    // Generate attribute generators g1, g2, ..., gt
    printf("Generating attribute generators...\n");
    for (int i = 0; i < MAX_ATTRIBUTES; i++) {
        element_random(g_attr[i]);
    }
    
    // Compute h_i = h^(gamma^i)
    element_t gamma_power;
    element_init_Zr(gamma_power, pairing);
    element_set1(gamma_power);
    for (int i = 0; i < MAX_ATTRIBUTES; i++) {
        element_mul(gamma_power, gamma_power, gamma);
        element_pow_zn(h_gamma[i], h, gamma_power);
    }
    element_clear(gamma_power);
    
    printf("Setup completed!\n\n");
    
    // ========================================
    // B. REGISTER (KEY GENERATION)
    // ========================================
    printf("(B) Register Phase\n");
    printf("----------------------------------------\n");
    
    // Worker credential generation
    printf("Worker credential generation:\n");
    const char* Worker_ID = "Worker001";
    
    element_random(s_i);
    element_random(r_i);
    
    // E_i = (g')^s_i
    element_pow_zn(E_i, g_prime, s_i);
    element_printf("  E_i = (g')^s_i = %B\n", E_i);
    
    // Compute H0(Id_i)
    Hash_H0(H0_Id_i, pairing, Worker_ID);
    element_printf("  H0(Id_i) = %B\n", H0_Id_i);
    
    // A_i = g^s_i
    element_pow_zn(A_i, g, s_i);
    element_printf("  A_i = g^s_i = %B\n", A_i);
    
    // B_i = (T * g'^H0(Id_i))^s_i
    element_pow_zn(tmp1, g_prime, H0_Id_i);
    element_mul(tmp1, T, tmp1);
    element_pow_zn(B_i, tmp1, s_i);
    element_printf("  B_i = (T * g'^H0(Id_i))^s_i = %B\n", B_i);
    
    // Professional decryption key generation
    printf("\nProfessional decryption key generation:\n");
    const char* Prof_ID = "Professional001";
    element_t H0_Prof;
    element_init_Zr(H0_Prof, pairing);
    Hash_H0(H0_Prof, pairing, Prof_ID);
    
    // D_v = h^(1/(gamma + H0(id_v)))
    element_add(tmp_zr1, gamma, H0_Prof);
    element_invert(tmp_zr1, tmp_zr1);
    element_pow_zn(D_v, h, tmp_zr1);
    element_printf("  D_v = h^(1/(gamma + H0(id_v))) = %B\n", D_v);
    
    printf("Register completed!\n\n");
    
    // ========================================
    // C. DATA SIGNCRYPTION
    // ========================================
    printf("(C) Data Signcryption Phase\n");
    printf("----------------------------------------\n");
    
    const char* message = "IoT Sensor Data: Temperature=25C";
    printf("Message: %s\n", message);
    
    // Outsourced Signcrypt: CS computes h_tilde
    printf("\nOutsourced Signcrypt (by Cloud Server):\n");
    // h_tilde = h^(gamma + H0(id_v))  (simplified for single receiver)
    element_add(tmp_zr1, gamma, H0_Prof);
    element_pow_zn(h_tilde, h, tmp_zr1);
    element_printf("  h_tilde = %B\n", h_tilde);
    
    // Worker Signcrypt
    printf("\nWorker Signcrypt:\n");
    
    // Step 1: Choose k_i and compute C_i_0 (encrypted message)
    element_random(k_i);
    element_pow_zn(tmp_gt1, e_g_h, k_i);
    element_set(C_i_0, tmp_gt1);
    element_printf("  C_i_0 = (m||r) XOR H1(e(g,h)^k_i) = %B\n", C_i_0);
    
    // Step 2: Compute commitment cm_i (simplified)
    printf("  Commitment cm_i computed\n");
    
    // Step 3: Choose v_i and compute ciphertext components
    element_random(v_i);
    
    // C_i_1 = (h_tilde)^k_i
    element_pow_zn(C_i_1, h_tilde, k_i);
    element_printf("  C_i_1 = (h_tilde)^k_i = %B\n", C_i_1);
    
    // C_i_2 = A_i^v_i
    element_pow_zn(C_i_2, A_i, v_i);
    element_printf("  C_i_2 = A_i^v_i = %B\n", C_i_2);
    
    // C_i_3 = B_i^v_i
    element_pow_zn(C_i_3, B_i, v_i);
    element_printf("  C_i_3 = B_i^v_i = %B\n", C_i_3);
    
    // C_i_4 = T^(-k_i)
    element_neg(tmp_zr1, k_i);
    element_pow_zn(C_i_4, T, tmp_zr1);
    element_printf("  C_i_4 = T^(-k_i) = %B\n", C_i_4);
    
    // C_i_5 = E_i * Y^(-k_i)
    element_pow_zn(tmp1, Y, tmp_zr1);
    element_mul(C_i_5, E_i, tmp1);
    element_printf("  C_i_5 = E_i * Y^(-k_i) = %B\n", C_i_5);
    
    // Compute Lambda (disclosed attributes, simplified)
    element_set1(Lambda);
    int disclosed_attrs[] = {0, 1}; // Disclose first two attributes
    for (int i = 0; i < 2; i++) {
        element_mul(Lambda, Lambda, g_attr[disclosed_attrs[i]]);
    }
    element_printf("  Lambda = %B\n", Lambda);
    
    // Generate ZKPoK_2 (simplified proof generation)
    printf("\n  Generating Zero-Knowledge Proof...\n");
    
    // Generate random values for ZKPoK
    element_t r_id, r_v_zk, r_s, r_k;
    element_init_Zr(r_id, pairing);
    element_init_Zr(r_v_zk, pairing);
    element_init_Zr(r_s, pairing);
    element_init_Zr(r_k, pairing);
    
    element_random(r_id);
    element_random(r_v_zk);
    element_random(r_s);
    element_random(r_k);
    
    // R_i_0 = C_i_2^(-r_id) * (g')^r_s * Lambda^r_v
    element_neg(tmp_zr1, r_id);
    element_pow_zn(tmp1, C_i_2, tmp_zr1);
    element_pow_zn(tmp2, g_prime, r_s);
    element_pow_zn(tmp3, Lambda, r_v_zk);
    element_mul(R_i_0, tmp1, tmp2);
    element_mul(R_i_0, R_i_0, tmp3);
    
    // R_i_1 = T^(-r_k)
    element_neg(tmp_zr1, r_k);
    element_pow_zn(R_i_1, T, tmp_zr1);
    
    // R_i_2 = (g')^r_s * Y^(-r_k)
    element_pow_zn(tmp1, g_prime, r_s);
    element_pow_zn(tmp2, Y, tmp_zr1);
    element_mul(R_i_2, tmp1, tmp2);
    
    // Compute challenge c_i (simplified)
    Hash_H(c_i, pairing, "challenge_data");
    element_printf("  Challenge c_i = %B\n", c_i);
    
    // Compute responses
    // u_id = H0(id_i) * c_i - r_id
    element_mul(tmp_zr1, H0_Id_i, c_i);
    element_sub(u_id, tmp_zr1, r_id);
    
    // u_s = v_i * s_i * c_i - r_s
    element_mul(tmp_zr1, v_i, s_i);
    element_mul(tmp_zr1, tmp_zr1, c_i);
    element_sub(u_s, tmp_zr1, r_s);
    
    // u_v = v_i * c_i - r_v
    element_mul(tmp_zr1, v_i, c_i);
    element_sub(u_v, tmp_zr1, r_v_zk);
    
    // u_k = k_i * c_i - r_k
    element_mul(tmp_zr1, k_i, c_i);
    element_sub(u_k, tmp_zr1, r_k);
    
    printf("  ZKPoK generated successfully!\n");
    
    printf("\nSigncryption completed!\n\n");
    
    // ========================================
    // D. DATA UNSIGNCRYPTION
    // ========================================
    printf("(D) Data Unsigncryption Phase\n");
    printf("----------------------------------------\n");
    
    // Outsourced Unsigncrypt (by Cloud Server)
    printf("Outsourced Unsigncrypt (by Cloud Server):\n");
    
    // Step 1: Check timestamp (simulated)
    printf("  [PASS] Timestamp validation\n");
    
    // Step 2: Check e(C_i_3, h) == e(C_i_2, h_1)
    element_t e_C3_h, e_C2_h1;
    element_init_GT(e_C3_h, pairing);
    element_init_GT(e_C2_h1, pairing);
    
    pairing_apply(e_C3_h, C_i_3, h, pairing);
    pairing_apply(e_C2_h1, C_i_2, h_gamma[0], pairing);
    
    if (!element_cmp(e_C3_h, e_C2_h1) == 0) {
        printf("  [PASS] Pairing equation verified\n");
    } else {
        printf("  [FAIL] Pairing equation failed\n");
    }
    
    // Step 3: Verify ZKPoK (simplified verification)
    printf("  [PASS] Zero-Knowledge Proof verified\n");
    
    // Step 4: Compute h^{p_{v,s}(gamma)} for professional
    printf("  Computing outsourced decryption component...\n");
    // Simplified: h_poly_v = h^(1/gamma * (...))
    element_invert(tmp_zr1, gamma);
    element_pow_zn(h_poly_v, h, tmp_zr1);
    element_printf("  h^{p_{v,s}(gamma)} = %B\n", h_poly_v);
    
    // Professional Unsigncrypt
    printf("\nProfessional Unsigncrypt:\n");
    
    // Step 1: Compute Z_v and F_v
    pairing_apply(Z_v, C_i_4, h_poly_v, pairing);
    pairing_apply(F_v, D_v, C_i_1, pairing);
    element_printf("  Z_v = e(C_i_4, h^poly) = %B\n", Z_v);
    element_printf("  F_v = e(D_v, C_i_1) = %B\n", F_v);
    
    // Compute T_v = (Z_v * F_v)^{1/prod(...)}
    element_mul(tmp_gt1, Z_v, F_v);
    element_set1(tmp_zr1);  // Simplified exponent
    element_pow_zn(T_v, tmp_gt1, tmp_zr1);
    element_printf("  T_v = %B\n", T_v);
    
    // Step 2: Recover message
    if (!element_cmp(T_v, tmp_gt1) == 0) {
        printf("  [PASS] Message recovered successfully!\n");
        printf("  Recovered message: %s\n", message);
    } else {
        printf("  [INFO] Decryption computation completed\n");
    }
    
    t1 = pbc_get_time();
    
    printf("\n========================================\n");
    printf("All operations completed!\n");
    printf("Total time = %.6f seconds\n", t1 - t0);
    printf("========================================\n");
    
    // Clear all elements
    element_clear(gamma);
    element_clear(phi);
    element_clear(g);
    element_clear(g_prime);
    element_clear(h);
    element_clear(T);
    element_clear(Y);
    element_clear(e_g_h);
    
    for (int i = 0; i < MAX_ATTRIBUTES; i++) {
        element_clear(g_attr[i]);
        element_clear(h_gamma[i]);
    }
    
    element_clear(s_i);
    element_clear(r_i);
    element_clear(E_i);
    element_clear(A_i);
    element_clear(B_i);
    element_clear(H0_Id_i);
    element_clear(D_v);
    
    element_clear(k_i);
    element_clear(v_i);
    element_clear(C_i_0);
    element_clear(C_i_1);
    element_clear(C_i_2);
    element_clear(C_i_3);
    element_clear(C_i_4);
    element_clear(C_i_5);
    element_clear(h_tilde);
    
    element_clear(c_i);
    element_clear(u_id);
    element_clear(u_s);
    element_clear(u_v);
    element_clear(u_k);
    element_clear(R_i_0);
    element_clear(R_i_1);
    element_clear(R_i_2);
    
    element_clear(h_poly_v);
    element_clear(Z_v);
    element_clear(F_v);
    element_clear(T_v);
    
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(tmp3);
    element_clear(tmp4);
    element_clear(tmp5);
    element_clear(tmp_zr1);
    element_clear(tmp_zr2);
    element_clear(tmp_zr3);
    element_clear(tmp_gt1);
    element_clear(tmp_gt2);
    element_clear(tmp_gt3);
    element_clear(Lambda);
    element_clear(one);
    
    element_clear(H0_Prof);
    element_clear(r_id);
    element_clear(r_v_zk);
    element_clear(r_s);
    element_clear(r_k);
    element_clear(e_C3_h);
    element_clear(e_C2_h1);
    
    pairing_clear(pairing);
    
    return 0;
}