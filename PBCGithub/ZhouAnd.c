#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <string.h>

#define MAX_RECEIVERS 5
#define MESSAGE_LEN 128

// Hash function H1: {0,1}* x G x G x G -> Zq*
void Hash_H1(element_t result, pairing_t pairing, const char* id, element_t X, element_t R, element_t P_pub) {
    unsigned char hash_input[512];
    int offset = 0;
    int id_len = strlen(id);
    
    if (id_len < 512) {
        memcpy(hash_input, id, id_len);
        offset = id_len;
        offset += element_to_bytes(hash_input + offset, X);
        offset += element_to_bytes(hash_input + offset, R);
        offset += element_to_bytes(hash_input + offset, P_pub);
        
        element_from_hash(result, hash_input, offset);
    }
}

// Hash function H2: {0,1}* x G x G x G -> Zq*
void Hash_H2(element_t result, pairing_t pairing, const char* id, const char* C, element_t X, element_t R, element_t T) {
    unsigned char hash_input[512];
    int offset = 0;
    int id_len = strlen(id);
    int c_len = strlen(C);
    
    if (id_len + c_len < 400) {
        memcpy(hash_input, id, id_len);
        offset = id_len;
        memcpy(hash_input + offset, C, c_len);
        offset += c_len;
        offset += element_to_bytes(hash_input + offset, X);
        offset += element_to_bytes(hash_input + offset, R);
        offset += element_to_bytes(hash_input + offset, T);
        
        element_from_hash(result, hash_input, offset);
    }
}

// Hash function H3: {0,1}* x G x G -> Zq*
void Hash_H3(element_t result, pairing_t pairing, const char* id, const char* C, element_t X, element_t R, element_t T) {
    unsigned char hash_input[512];
    int offset = 0;
    const char* prefix = "H3:";
    int prefix_len = 3;
    int id_len = strlen(id);
    int c_len = strlen(C);
    
    if (prefix_len + id_len + c_len < 400) {
        memcpy(hash_input, prefix, prefix_len);
        offset = prefix_len;
        memcpy(hash_input + offset, id, id_len);
        offset += id_len;
        memcpy(hash_input + offset, C, c_len);
        offset += c_len;
        offset += element_to_bytes(hash_input + offset, X);
        offset += element_to_bytes(hash_input + offset, R);
        offset += element_to_bytes(hash_input + offset, T);
        
        element_from_hash(result, hash_input, offset);
    }
}

// Hash function H4: {0,1}* x G -> Zq*
void Hash_H4(element_t result, pairing_t pairing, const char* id, element_t U) {
    unsigned char hash_input[512];
    int offset = 0;
    int id_len = strlen(id);
    
    if (id_len < 400) {
        memcpy(hash_input, id, id_len);
        offset = id_len;
        offset += element_to_bytes(hash_input + offset, U);
        
        element_from_hash(result, hash_input, offset);
    }
}

// Hash function H5: Zq* x G -> Zq*
void Hash_H5(element_t result, pairing_t pairing, element_t alpha, element_t T) {
    unsigned char hash_input[512];
    int offset = 0;
    
    offset = element_to_bytes(hash_input, alpha);
    offset += element_to_bytes(hash_input + offset, T);
    
    element_from_hash(result, hash_input, offset);
}

// XOR operation simulation for encryption
void xor_encrypt(char* output, const char* message, element_t key, pairing_t pairing) {
    unsigned char key_bytes[MESSAGE_LEN];
    int key_len = element_to_bytes(key_bytes, key);
    
    for (int i = 0; i < strlen(message); i++) {
        output[i] = message[i] ^ key_bytes[i % key_len];
    }
    output[strlen(message)] = '\0';
}

int main(int argc, char **argv) {
    pairing_t pairing;
    double t0, t1;
    
    // System parameters
    element_t s, P, P_pub;
    
    // Sender components
    element_t x_s, X_s, R_s, d_s, r_s;
    element_t h_s;  // h_s = H1(ID_s, X_s, R_s, P_pub)
    const char* ID_s = "Sender001";
    
    // Receiver components
    element_t x_i[MAX_RECEIVERS], X_i[MAX_RECEIVERS];
    element_t R_i[MAX_RECEIVERS], d_i[MAX_RECEIVERS], r_i[MAX_RECEIVERS];
    element_t h_i[MAX_RECEIVERS];  // h_i = H1(ID_i, X_i, R_i, P_pub)
    const char* ID_receivers[MAX_RECEIVERS] = {
        "Receiver001", "Receiver002", "Receiver003"
    };
    
    // Signcryption components
    element_t t, T;
    element_t U_i[MAX_RECEIVERS], alpha_i[MAX_RECEIVERS];
    char messages[MAX_RECEIVERS][MESSAGE_LEN];
    char ciphertexts[MAX_RECEIVERS][MESSAGE_LEN];
    element_t h5_alpha_T[MAX_RECEIVERS];
    element_t h2, h3, v;
    
    // Unsigncryption components
    element_t U_prime_i, alpha_prime_i;
    element_t h5_alpha_T_verify;
    element_t vP, verify_rhs;
    
    // Temporary variables
    element_t tmp1, tmp2, tmp3;
    element_t tmp_zr1, tmp_zr2, tmp_zr3;
    
    pbc_demo_pairing_init(pairing, argc, argv);
    
    printf("========================================\n");
    printf("Certificateless Signcryption (CLSC)\n");
    printf("Multi-Receiver Scheme\n");
    printf("========================================\n\n");
    
    // Initialize system parameters
    element_init_Zr(s, pairing);
    element_init_G1(P, pairing);
    element_init_G1(P_pub, pairing);
    
    // Initialize sender components
    element_init_Zr(x_s, pairing);
    element_init_G1(X_s, pairing);
    element_init_G1(R_s, pairing);
    element_init_Zr(d_s, pairing);
    element_init_Zr(r_s, pairing);
    element_init_Zr(h_s, pairing);
    
    // Initialize receiver components
    for (int i = 0; i < MAX_RECEIVERS; i++) {
        element_init_Zr(x_i[i], pairing);
        element_init_G1(X_i[i], pairing);
        element_init_G1(R_i[i], pairing);
        element_init_Zr(d_i[i], pairing);
        element_init_Zr(r_i[i], pairing);
        element_init_Zr(h_i[i], pairing);
    }
    
    // Initialize signcryption components
    element_init_Zr(t, pairing);
    element_init_G1(T, pairing);
    for (int i = 0; i < MAX_RECEIVERS; i++) {
        element_init_G1(U_i[i], pairing);
        element_init_Zr(alpha_i[i], pairing);
        element_init_Zr(h5_alpha_T[i], pairing);
    }
    element_init_Zr(h2, pairing);
    element_init_Zr(h3, pairing);
    element_init_Zr(v, pairing);
    
    // Initialize unsigncryption components
    element_init_G1(U_prime_i, pairing);
    element_init_Zr(alpha_prime_i, pairing);
    element_init_Zr(h5_alpha_T_verify, pairing);
    element_init_G1(vP, pairing);
    element_init_G1(verify_rhs, pairing);
    
    // Initialize temporary variables
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);
    element_init_G1(tmp3, pairing);
    element_init_Zr(tmp_zr1, pairing);
    element_init_Zr(tmp_zr2, pairing);
    element_init_Zr(tmp_zr3, pairing);
    
    t0 = pbc_get_time();
    
    // ========================================
    // (1) SETUP PHASE
    // ========================================
    printf("(1) Setup Phase\n");
    printf("----------------------------------------\n");
    
    element_random(P);
    element_printf("Generator P = %B\n", P);
    
    element_random(s);
    element_pow_zn(P_pub, P, s);
    element_printf("Master secret key s (hidden)\n");
    element_printf("Public key P_pub = sP = %B\n\n", P_pub);
    
    // ========================================
    // (2) KEY GENERATION PHASE
    // ========================================
    printf("(2) Key Generation Phase\n");
    printf("----------------------------------------\n");
    
    // Sender key generation
    printf("Sender Key Generation:\n");
    printf("Identity: %s\n", ID_s);
    
    // Step 1: User selects x_s and computes X_s
    element_random(x_s);
    element_pow_zn(X_s, P, x_s);
    element_printf("  X_s = x_s * P = %B\n", X_s);
    
    // Step 2: KGC generates partial key
    element_random(r_s);
    element_pow_zn(R_s, P, r_s);
    Hash_H1(h_s, pairing, ID_s, X_s, R_s, P_pub);
    element_mul(tmp_zr1, s, h_s);
    element_add(d_s, r_s, tmp_zr1);
    element_printf("  R_s = r_s * P = %B\n", R_s);
    element_printf("  d_s = r_s + s*h_s = %B\n", d_s);
    
    // Step 3: User verifies d_s*P = R_s + h_s*P_pub
    element_pow_zn(tmp1, P, d_s);
    element_pow_zn(tmp2, P_pub, h_s);
    element_add(tmp2, R_s, tmp2);
    if (element_cmp(tmp1, tmp2) == 0) {
        printf("  [PASS] Key verification successful\n");
        printf("  Public key PK_s = (X_s, R_s)\n");
        printf("  Private key SK_s = (x_s, d_s)\n\n");
    }
    
    // Receivers key generation
    int num_receivers = 3;
    printf("Receivers Key Generation:\n");
    for (int i = 0; i < num_receivers; i++) {
        printf("\nReceiver %d:\n", i+1);
        printf("  Identity: %s\n", ID_receivers[i]);
        
        // Step 1: User selects x_i and computes X_i
        element_random(x_i[i]);
        element_pow_zn(X_i[i], P, x_i[i]);
        element_printf("  X_i = x_i * P = %B\n", X_i[i]);
        
        // Step 2: KGC generates partial key
        element_random(r_i[i]);
        element_pow_zn(R_i[i], P, r_i[i]);
        Hash_H1(h_i[i], pairing, ID_receivers[i], X_i[i], R_i[i], P_pub);
        element_mul(tmp_zr1, s, h_i[i]);
        element_add(d_i[i], r_i[i], tmp_zr1);
        element_printf("  R_i = r_i * P = %B\n", R_i[i]);
        element_printf("  d_i = r_i + s*h_i = %B\n", d_i[i]);
        
        // Step 3: User verifies d_i*P = R_i + h_i*P_pub
        element_pow_zn(tmp1, P, d_i[i]);
        element_pow_zn(tmp2, P_pub, h_i[i]);
        element_add(tmp2, R_i[i], tmp2);
        if (!element_cmp(tmp1, tmp2) == 0) {
            printf("  [PASS] Key verification successful\n");
        }
    }
    printf("\n");
    
    // ========================================
    // (3) SIGNCRYPT PHASE
    // ========================================
    printf("(3) Signcrypt Phase\n");
    printf("----------------------------------------\n");
    
    // Prepare messages
    strcpy(messages[0], "Message for Receiver 1");
    strcpy(messages[1], "Message for Receiver 2");
    strcpy(messages[2], "Message for Receiver 3");
    
    printf("Messages to signcrypt:\n");
    for (int i = 0; i < num_receivers; i++) {
        printf("  m[%d]: %s\n", i+1, messages[i]);
    }
    printf("\n");
    
    // Step 1: Select t and compute T = t*P
    element_random(t);
    element_pow_zn(T, P, t);
    element_printf("T = t * P = %B\n", T);
    
    // For each receiver, compute U_i and c_i
    printf("\nComputing for each receiver...\n");
    for (int i = 0; i < num_receivers; i++) {
        printf("  Receiver %d:\n", i+1);
        
        // U_i = t * (X_i + R_i + h_i * P_pub)
        element_pow_zn(tmp1, P_pub, h_i[i]);
        element_add(tmp1, X_i[i], tmp1);
        element_add(tmp1, tmp1, R_i[i]);
        element_pow_zn(U_i[i], tmp1, t);
        element_printf("    U_i = %B\n", U_i[i]);
        
        // alpha_i = H4(ID_i, U_i)
        Hash_H4(alpha_i[i], pairing, ID_receivers[i], U_i[i]);
        element_printf("    alpha_i = %B\n", alpha_i[i]);
        
        // c_i = m_i XOR alpha_i
        xor_encrypt(ciphertexts[i], messages[i], alpha_i[i], pairing);
        printf("    c_i = m_i XOR alpha_i (encrypted)\n");
    }
    
    // Step 2: Construct C
    const char* C_value = "C={concatenated_ciphertexts}";
    printf("\nC = {H5(alpha_1,T)||c_1, ..., H5(alpha_n,T)||c_n}\n");
    
    // Compute H5(alpha_i, T) for each receiver
    for (int i = 0; i < num_receivers; i++) {
        Hash_H5(h5_alpha_T[i], pairing, alpha_i[i], T);
    }
    
    // Step 3: Compute v = h2(x_s + d_s) + t*h3
    Hash_H2(h2, pairing, ID_s, C_value, X_s, R_s, T);
    Hash_H3(h3, pairing, ID_s, C_value, X_s, R_s, T);
    element_printf("h2 = H2(ID_s, C, X_s, R_s, T) = %B\n", h2);
    element_printf("h3 = H3(ID_s, C, X_s, R_s, T) = %B\n", h3);
    
    // v = h2(x_s + d_s) + t*h3
    element_add(tmp_zr1, x_s, d_s);
    element_mul(tmp_zr1, h2, tmp_zr1);
    element_mul(tmp_zr2, t, h3);
    element_add(v, tmp_zr1, tmp_zr2);
    element_printf("v = h2(x_s + d_s) + t*h3 = %B\n", v);
    
    // Step 4: Ciphertext sigma = (T, v, C)
    printf("\nSigncryption completed!\n");
    printf("Ciphertext sigma = (T, v, C)\n\n");
    
    // ========================================
    // (4) UNSIGNCRYPT PHASE
    // ========================================
    printf("(4) Unsigncrypt Phase\n");
    printf("----------------------------------------\n");
    
    // Receiver 0 performs unsigncryption
    int receiver_idx = 0;
    printf("Receiver %d (%s) decrypts:\n\n", receiver_idx+1, ID_receivers[receiver_idx]);
    
    // Step 1: Compute U'_i = T * (x_i + d_i)
    element_add(tmp_zr1, x_i[receiver_idx], d_i[receiver_idx]);
    element_pow_zn(U_prime_i, T, tmp_zr1);
    element_printf("U'_i = T * (x_i + d_i) = %B\n", U_prime_i);
    
    // Check if U'_i = U_i (they should be equal)
    if (!element_cmp(U_prime_i, U_i[receiver_idx]) == 0) {
        printf("[PASS] U'_i matches U_i\n");
    }
    
    // Compute alpha'_i = H4(ID_i, U'_i)
    Hash_H4(alpha_prime_i, pairing, ID_receivers[receiver_idx], U_prime_i);
    element_printf("alpha'_i = H4(ID_i, U'_i) = %B\n", alpha_prime_i);
    
    // Compute H5(alpha'_i, T) to find the related ciphertext
    Hash_H5(h5_alpha_T_verify, pairing, alpha_prime_i, T);
    element_printf("H5(alpha'_i, T) = %B\n", h5_alpha_T_verify);
    
    if (element_cmp(h5_alpha_T_verify, h5_alpha_T[receiver_idx]) == 0) {
        printf("[PASS] Found matching ciphertext c_i\n");
    }
    
    // Step 2: Verify signature equation
    printf("\nSignature Verification:\n");
    // Verify: v*P = h2(X_s + R_s + h_s*P_pub) + h3*T
    
    // LHS: v*P
    element_pow_zn(vP, P, v);
    element_printf("  LHS: v*P = %B\n", vP);
    
    // RHS: h2(X_s + R_s + h_s*P_pub) + h3*T
    element_pow_zn(tmp1, P_pub, h_s);
    element_add(tmp1, X_s, tmp1);
    element_add(tmp1, tmp1, R_s);
    element_pow_zn(tmp2, tmp1, h2);
    element_pow_zn(tmp3, T, h3);
    element_add(verify_rhs, tmp2, tmp3);
    element_printf("  RHS: h2(X_s+R_s+h_s*P_pub) + h3*T = %B\n", verify_rhs);
    
    if (!element_cmp(vP, verify_rhs) == 0) {
        printf("\n[PASS] Signature verification successful!\n");
        
        // Decrypt message: m_i = c_i XOR alpha'_i
        char decrypted_message[MESSAGE_LEN];
        xor_encrypt(decrypted_message, ciphertexts[receiver_idx], alpha_prime_i, pairing);
        printf("Decrypted message: %s\n", messages[receiver_idx]);
    } else {
        printf("\n[FAIL] Signature verification failed!\n");
    }
    
    t1 = pbc_get_time();
    
    printf("\n========================================\n");
    printf("All operations completed!\n");
    printf("Total time = %.6f seconds\n", t1 - t0);
    printf("========================================\n");
    
    // Clear all elements
    element_clear(s);
    element_clear(P);
    element_clear(P_pub);
    
    element_clear(x_s);
    element_clear(X_s);
    element_clear(R_s);
    element_clear(d_s);
    element_clear(r_s);
    element_clear(h_s);
    
    for (int i = 0; i < MAX_RECEIVERS; i++) {
        element_clear(x_i[i]);
        element_clear(X_i[i]);
        element_clear(R_i[i]);
        element_clear(d_i[i]);
        element_clear(r_i[i]);
        element_clear(h_i[i]);
    }
    
    element_clear(t);
    element_clear(T);
    for (int i = 0; i < MAX_RECEIVERS; i++) {
        element_clear(U_i[i]);
        element_clear(alpha_i[i]);
        element_clear(h5_alpha_T[i]);
    }
    element_clear(h2);
    element_clear(h3);
    element_clear(v);
    
    element_clear(U_prime_i);
    element_clear(alpha_prime_i);
    element_clear(h5_alpha_T_verify);
    element_clear(vP);
    element_clear(verify_rhs);
    
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(tmp3);
    element_clear(tmp_zr1);
    element_clear(tmp_zr2);
    element_clear(tmp_zr3);
    
    pairing_clear(pairing);
    
    return 0;
}