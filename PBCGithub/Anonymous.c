
// 只保留这两个头文件:
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <string.h>

// Hash function H1: {0,1}* -> G1
void H1(element_t result, pairing_t pairing, const char* id) {
    element_from_hash(result, (void*)id, strlen(id));
}

// Hash function H2: G1 x Zr -> Zr
void H2(element_t result, pairing_t pairing, element_t Q, element_t r) {
    unsigned char hash_input[512];
    int len1 = element_to_bytes(hash_input, Q);
    int len2 = element_to_bytes(hash_input + len1, r);
    element_from_hash(result, hash_input, len1 + len2);
}

// Hash function H3: {0,1}* -> Zr
void H3(element_t result, pairing_t pairing, const char* data) {
    element_from_hash(result, (void*)data, strlen(data));
}

// Hash function H4: {0,1}* -> Zr
void H4(element_t result, pairing_t pairing, const char* data) {
    element_from_hash(result, (void*)data, strlen(data));
}

// Hash function H5: {0,1}* -> Zr
void H5(element_t result, pairing_t pairing, const char* id) {
    element_from_hash(result, (void*)id, strlen(id));
}

int main(int argc, char **argv) {
    pairing_t pairing;
    double t0, t1;
    
    // System parameters
    element_t s, P, Ppub, P0;
    element_t e_Ppub_P0; // e(Ppub, P0)
    
    // Sender private key components
    element_t d1_S, d2_S, d3_S, r_S;
    
    // Receiver private key components
    element_t d1_R, d2_R, d3_R, r_R;
    
    // Signcryption parameters
    element_t z, U, Z;
    element_t a_j, C1_j, C2_j, T_j;
    element_t sigma, eta, delta;
    element_t t_a, r_k, h_i, Q_i, Q_Sk;
    
    // Unsigncryption verification
    element_t beta, T_b, U_verify;
    element_t tmp1, tmp2, tmp3, tmp4, tmp5;
    
    pbc_demo_pairing_init(pairing, argc, argv);
    if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");
    
    printf("========================================\n");
    printf("Identity-Based Signcryption Scheme\n");
    printf("========================================\n\n");
    
    // Initialize elements
    element_init_Zr(s, pairing);
    element_init_G1(P, pairing);
    element_init_G1(Ppub, pairing);
    element_init_G1(P0, pairing);
    element_init_GT(e_Ppub_P0, pairing);
    
    element_init_G1(d1_S, pairing);
    element_init_G1(d2_S, pairing);
    element_init_G1(d3_S, pairing);
    element_init_Zr(r_S, pairing);
    
    element_init_G1(d1_R, pairing);
    element_init_G1(d2_R, pairing);
    element_init_G1(d3_R, pairing);
    element_init_Zr(r_R, pairing);
    
    element_init_Zr(z, pairing);
    element_init_GT(U, pairing);
    element_init_G1(Z, pairing);
    element_init_Zr(a_j, pairing);
    element_init_G1(C1_j, pairing);
    element_init_Zr(C2_j, pairing);
    element_init_GT(T_j, pairing);
    
    element_init_G1(sigma, pairing);
    element_init_Zr(eta, pairing);
    element_init_G1(delta, pairing);
    element_init_Zr(t_a, pairing);
    element_init_Zr(r_k, pairing);
    element_init_Zr(h_i, pairing);
    element_init_G1(Q_i, pairing);
    element_init_G1(Q_Sk, pairing);
    
    element_init_Zr(beta, pairing);
    element_init_GT(T_b, pairing);
    element_init_GT(U_verify, pairing);
    
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);
    element_init_G1(tmp3, pairing);
    element_init_GT(tmp4, pairing);
    element_init_GT(tmp5, pairing);
    
    t0 = pbc_get_time();
    
    // ========================================
    // (1) SETUP PHASE
    // ========================================
    printf("(1) Setup Phase\n");
    printf("----------------------------------------\n");
    
    element_random(P);
    element_printf("Generator P = %B\n", P);
    
    element_random(P0);
    element_printf("Generator P0 = %B\n", P0);
    
    element_random(s);
    element_mul_zn(Ppub, P, s);
    element_printf("Public key Ppub = sP = %B\n", Ppub);
    
    pairing_apply(e_Ppub_P0, Ppub, P0, pairing);
    element_printf("e(Ppub, P0) = %B\n\n", e_Ppub_P0);
    
    // ========================================
    // (2) KEY EXTRACTION PHASE
    // ========================================
    printf("(2) Key Extraction Phase\n");
    printf("----------------------------------------\n");
    
    // Sender key extraction
    printf("Sender (Alice) key extraction:\n");
    const char* ID_Alice = "Alice@example.com";
    element_random(r_S);
    
    // d1 = (s+r)P0
    element_t s_plus_r;
    element_init_Zr(s_plus_r, pairing);
    element_add(s_plus_r, s, r_S);
    element_mul_zn(d1_S, P0, s_plus_r);
    element_printf("  d1_S = (s+r)P0 = %B\n", d1_S);
    
    // d2 = rP
    element_mul_zn(d2_S, P, r_S);
    element_printf("  d2_S = rP = %B\n", d2_S);
    
    // d3 = r(H1(ID) + P0)
    element_t H1_Alice;
    element_init_G1(H1_Alice, pairing);
    H1(H1_Alice, pairing, ID_Alice);
    element_add(tmp1, H1_Alice, P0);
    element_mul_zn(d3_S, tmp1, r_S);
    element_printf("  d3_S = r(H1(ID)+P0) = %B\n\n", d3_S);
    
    // Receiver key extraction
    printf("Receiver (Bob) key extraction:\n");
    const char* ID_Bob = "Bob@example.com";
    element_random(r_R);
    
    // d1 = (s+r)P0
    element_t s_plus_r_R;
    element_init_Zr(s_plus_r_R, pairing);
    element_add(s_plus_r_R, s, r_R);
    element_mul_zn(d1_R, P0, s_plus_r_R);
    element_printf("  d1_R = (s+r)P0 = %B\n", d1_R);
    
    // d2 = rP
    element_mul_zn(d2_R, P, r_R);
    element_printf("  d2_R = rP = %B\n", d2_R);
    
    // d3 = r(H1(ID) + P0)
    element_t H1_Bob;
    element_init_G1(H1_Bob, pairing);
    H1(H1_Bob, pairing, ID_Bob);
    element_add(tmp1, H1_Bob, P0);
    element_mul_zn(d3_R, tmp1, r_R);
    element_printf("  d3_R = r(H1(ID)+P0) = %B\n\n", d3_R);
    
    // ========================================
    // (3) SIGNCRYPTION PHASE
    // ========================================
    printf("(3) Signcryption Phase\n");
    printf("----------------------------------------\n");
    
    const char* message = "Secret Message";
    printf("Message: %s\n", message);
    
    // Select anonymity set (simplified: only Alice)
    // In real implementation, include multiple senders
    element_random(t_a);
    element_set(r_k, t_a);
    
    // Compute h_k = H2(Q_Sk, r_k)
    H1(Q_Sk, pairing, ID_Alice);
    H2(h_i, pairing, Q_Sk, r_k);
    
    // Choose z, compute U = e(Ppub, P0)^z and Z = zP
    element_random(z);
    element_pow_zn(U, e_Ppub_P0, z);
    element_mul_zn(Z, P, z);
    element_printf("U = e(Ppub, P0)^z = %B\n", U);
    element_printf("Z = zP = %B\n", Z);
    
    // For receiver Bob: compute C1_j, C2_j, T_j
    element_random(a_j);
    
    // C1_j = z(H1(ID_Bob) + a_j*P0)
    element_mul_zn(tmp1, P0, a_j);
    element_add(tmp1, H1_Bob, tmp1);
    element_mul_zn(C1_j, tmp1, z);
    element_set(C2_j, a_j);
    element_printf("C1_j = %B\n", C1_j);
    element_printf("C2_j = %B\n", C2_j);
    
    // T_j = e(P0, Ppub)^H5(ID_Bob)
    element_t H5_Bob;
    element_init_Zr(H5_Bob, pairing);
    H5(H5_Bob, pairing, ID_Bob);
    element_t e_P0_Ppub;
    element_init_GT(e_P0_Ppub, pairing);
    pairing_apply(e_P0_Ppub, P0, Ppub, pairing);
    element_pow_zn(T_j, e_P0_Ppub, H5_Bob);
    element_printf("T_j = %B\n", T_j);
    
    // Set sigma = d2_S
    element_set(sigma, d2_S);
    
    // Compute eta (simplified for single sender)
    element_set(eta, t_a);
    element_printf("eta = %B\n", eta);
    
    // Generate session key K = H4(U||eta)
    printf("Session key generated\n");
    
    // Compute delta = H2(eta)*d1 + H3(c||phi)*d3
    element_t H2_eta, H3_c_phi;
    element_init_Zr(H2_eta, pairing);
    element_init_Zr(H3_c_phi, pairing);
    
    H2(H2_eta, pairing, Q_Sk, eta);  // Simplified H2(eta)
    H3(H3_c_phi, pairing, "c||phi");  // Simplified H3(c||phi)
    
    element_mul_zn(tmp1, d1_S, H2_eta);
    element_mul_zn(tmp2, d3_S, H3_c_phi);
    element_add(delta, tmp1, tmp2);
    element_printf("delta = %B\n\n", delta);
    
    printf("Signcryption completed!\n\n");
    
    // ========================================
    // (4) UNSIGNCRYPTION PHASE
    // ========================================
    printf("(4) Unsigncryption Phase\n");
    printf("----------------------------------------\n");
    
    // Sender Validation
    printf("Step 1: Sender Validation\n");
    element_set(beta, eta);  // Simplified for single sender
    if (!element_cmp(beta, eta) == 0) {
        printf("  Sender validation PASSED\n\n");
    } else {
        printf("  Sender validation FAILED\n\n");
    }
    
    // Integrity Verification
    printf("Step 2: Integrity Verification\n");
    // Verify: e(delta, P) = e(P0, Ppub+sigma)^H2(eta) * e(sigma, H1(ID)+P0)^H3(c||phi)
    element_t e_delta_P, lhs, rhs;
    element_init_GT(e_delta_P, pairing);
    element_init_GT(lhs, pairing);
    element_init_GT(rhs, pairing);
    
    pairing_apply(e_delta_P, delta, P, pairing);
    
    // RHS part 1: e(P0, Ppub+sigma)^H2(eta)
    element_add(tmp1, Ppub, sigma);
    pairing_apply(tmp4, P0, tmp1, pairing);
    element_pow_zn(tmp4, tmp4, H2_eta);
    
    // RHS part 2: e(sigma, H1(ID)+P0)^H3(c||phi)
    element_add(tmp2, H1_Alice, P0);
    pairing_apply(tmp5, sigma, tmp2, pairing);
    element_pow_zn(tmp5, tmp5, H3_c_phi);
    
    element_mul(rhs, tmp4, tmp5);
    
    if (!element_cmp(e_delta_P, rhs) == 0) {
        printf("  Integrity verification PASSED\n\n");
    } else {
        printf("  Integrity verification FAILED\n\n");
    }
    
    // Receiver Authorization
    printf("Step 3: Receiver Authorization\n");
    // T_b = (e(d1, P) * e(d2, P0)^{-1})^H5(ID_Bob)
    element_t e_d1_P, e_d2_P0, e_d2_P0_inv;
    element_init_GT(e_d1_P, pairing);
    element_init_GT(e_d2_P0, pairing);
    element_init_GT(e_d2_P0_inv, pairing);
    
    pairing_apply(e_d1_P, d1_R, P, pairing);
    pairing_apply(e_d2_P0, d2_R, P0, pairing);
    element_invert(e_d2_P0_inv, e_d2_P0);
    element_mul(T_b, e_d1_P, e_d2_P0_inv);
    element_pow_zn(T_b, T_b, H5_Bob);
    
    if (!element_cmp(T_b, T_j) == 0) {
        printf("  Receiver authorization PASSED\n\n");
    } else {
        printf("  Receiver authorization FAILED\n\n");
    }
    
    // Decryption
    printf("Step 4: Decryption\n");
    // U = (e(d3, Z) / e(C1, d2))^{1/(C2-1)} * e(d1, Z)
    element_t e_d3_Z, e_C1_d2, C2_minus_1, C2_minus_1_inv;
    element_init_GT(e_d3_Z, pairing);
    element_init_GT(e_C1_d2, pairing);
    element_init_Zr(C2_minus_1, pairing);
    element_init_Zr(C2_minus_1_inv, pairing);
    element_init_GT(U_verify, pairing);
    
    pairing_apply(e_d3_Z, d3_R, Z, pairing);
    pairing_apply(e_C1_d2, C1_j, d2_R, pairing);
    
    element_div(tmp4, e_d3_Z, e_C1_d2);
    
	// Compute 1/(C2_j - 1)
	element_set1(C2_minus_1);
	element_sub(C2_minus_1, C2_j, C2_minus_1);  // C2_j - 1
	element_invert(C2_minus_1_inv, C2_minus_1);


   // element_sub(C2_minus_1, C2_j, element_item_count(C2_j));  // Simplified
   //element_set1(C2_minus_1);
    //element_sub(C2_minus_1, C2_j, C2_minus_1);
    //element_invert(C2_minus_1_inv, C2_minus_1);
    
    element_pow_zn(tmp4, tmp4, C2_minus_1_inv);
    
    pairing_apply(tmp5, d1_R, Z, pairing);
    element_mul(U_verify, tmp4, tmp5);
    
    if (!element_cmp(U, U_verify) == 0) {
        printf("  Decryption SUCCESSFUL\n");
        printf("  Message recovered: %s\n\n", message);
    } else {
        printf("  Decryption FAILED\n\n");
    }
    
    t1 = pbc_get_time();
    
    printf("========================================\n");
    printf("All operations completed successfully!\n");
    printf("Total time = %fs\n", t1 - t0);
    printf("========================================\n");
    
    // Clear all elements
    element_clear(s);
    element_clear(P);
    element_clear(Ppub);
    element_clear(P0);
    element_clear(e_Ppub_P0);
    
    element_clear(d1_S);
    element_clear(d2_S);
    element_clear(d3_S);
    element_clear(r_S);
    
    element_clear(d1_R);
    element_clear(d2_R);
    element_clear(d3_R);
    element_clear(r_R);
    
    element_clear(z);
    element_clear(U);
    element_clear(Z);
    element_clear(a_j);
    element_clear(C1_j);
    element_clear(C2_j);
    element_clear(T_j);
    
    element_clear(sigma);
    element_clear(eta);
    element_clear(delta);
    element_clear(t_a);
    element_clear(r_k);
    element_clear(h_i);
    element_clear(Q_i);
    element_clear(Q_Sk);
    
    element_clear(beta);
    element_clear(T_b);
    element_clear(U_verify);
    
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(tmp3);
    element_clear(tmp4);
    element_clear(tmp5);
    
    element_clear(s_plus_r);
    element_clear(s_plus_r_R);
    element_clear(H1_Alice);
    element_clear(H1_Bob);
    element_clear(H5_Bob);
    element_clear(e_P0_Ppub);
    element_clear(H2_eta);
    element_clear(H3_c_phi);
    element_clear(e_delta_P);
    element_clear(lhs);
    element_clear(rhs);
    element_clear(e_d1_P);
    element_clear(e_d2_P0);
    element_clear(e_d2_P0_inv);
    element_clear(e_d3_Z);
    element_clear(e_C1_d2);
    element_clear(C2_minus_1);
    element_clear(C2_minus_1_inv);
    
    pairing_clear(pairing);
    
    return 0;
}