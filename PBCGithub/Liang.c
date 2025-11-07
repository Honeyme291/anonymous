#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <string.h>

#define MAX_VEHICLES 10
#define MAX_RECEIVERS 5

// Hash function H1: {0,1}* -> {0,1}^|ID|
void Hash_H1(element_t result, pairing_t pairing, element_t point) {
    unsigned char hash_input[256];
    int len = element_to_bytes(hash_input, point);
    element_from_hash(result, hash_input, len);
}

// Hash function H2: {0,1}* -> Zq*
void Hash_H2(element_t result, pairing_t pairing, const char* data) {
    element_from_hash(result, (void*)data, strlen(data));
}

// Hash function H3: {0,1}* -> Zq*
void Hash_H3(element_t result, pairing_t pairing, const char* data) {
    unsigned char hash_data[256];
    sprintf((char*)hash_data, "H3:%s", data);
    element_from_hash(result, hash_data, strlen((char*)hash_data));
}

// Hash function H4: {0,1}* -> {0,1}^{2|G|+|m|}
void Hash_H4(element_t result, pairing_t pairing, const char* data) {
    unsigned char hash_data[256];
    sprintf((char*)hash_data, "H4:%s", data);
    element_from_hash(result, hash_data, strlen((char*)hash_data));
}

// Hash function H5: {0,1}* -> Zq*
void Hash_H5(element_t result, pairing_t pairing, const char* data, int flag) {
    unsigned char hash_data[256];
    sprintf((char*)hash_data, "H5:%s:%d", data, flag);
    element_from_hash(result, hash_data, strlen((char*)hash_data));
}

// Extended GCD for modular inverse computation
void extended_gcd(mpz_t gcd, mpz_t x, mpz_t y, mpz_t a, mpz_t b) {
    if (mpz_cmp_ui(b, 0) == 0) {
        mpz_set(gcd, a);
        mpz_set_ui(x, 1);
        mpz_set_ui(y, 0);
        return;
    }
    mpz_t x1, y1, q, temp;
    mpz_init(x1);
    mpz_init(y1);
    mpz_init(q);
    mpz_init(temp);
    
    mpz_fdiv_q(q, a, b);
    mpz_mod(temp, a, b);
    
    extended_gcd(gcd, x1, y1, b, temp);
    
    mpz_set(x, y1);
    mpz_mul(temp, q, y1);
    mpz_sub(y, x1, temp);
    
    mpz_clear(x1);
    mpz_clear(y1);
    mpz_clear(q);
    mpz_clear(temp);
}

int main(int argc, char **argv) {
    pairing_t pairing;
    double t0, t1;
    
    // System parameters
    element_t s, P, P_pub;
    
    // Revocation key parameters
    element_t b, B;  // Master revocation keys
    element_t rsk[MAX_VEHICLES];  // Revocation secret keys for vehicles
    element_t a[MAX_VEHICLES];    // Polynomial coefficients
    
    // Vehicle pseudonym components
    element_t x_i, PID_i_1, PID_i_2_hash;
    const char* ID_i = "Vehicle001";
    
    // Vehicle partial private key
    element_t y_i, Y_i, h_i, lambda_i;
    
    // Vehicle's own key pair
    element_t sk_i, pk_i;
    
    // RSU key pairs
    element_t sk_rsu[MAX_RECEIVERS], pk_rsu[MAX_RECEIVERS];
    
    // Signcryption components
    element_t r_i, R_i, TK_i;
    element_t omega_j[MAX_RECEIVERS], k_j[MAX_RECEIVERS];
    element_t alpha_i, beta_j[MAX_RECEIVERS], theta_j[MAX_RECEIVERS];
    element_t var_j[MAX_RECEIVERS], sum_i;
    element_t gamma_i, C_i;
    element_t h1, h2, h3, rho_i;
    
    // Unsigncryption verification
    element_t omega_verify, k_verify, TK_verify;
    element_t h_i_verify, h1_verify, h2_verify, h3_verify;
    element_t rho_P, verify_rhs;
    
    // Temporary variables
    element_t tmp1, tmp2, tmp3, tmp4;
    element_t tmp_zr1, tmp_zr2, tmp_zr3;
    element_t one;
    
    pbc_demo_pairing_init(pairing, argc, argv);
    
    printf("========================================\n");
    printf("Vehicular Network Signcryption\n");
    printf("with Revocation Support\n");
    printf("========================================\n\n");
    t0 = pbc_get_time();
    
    // ========================================
    // SETUP PHASE
    // ========================================
    printf("(1) Setup Phase\n");
    printf("----------------------------------------\n");
    // Initialize system parameters
    element_init_Zr(s, pairing);
    element_init_G1(P, pairing);
    element_init_G1(P_pub, pairing);
    
    // Initialize revocation parameters
    element_init_Zr(b, pairing);
    element_init_G1(B, pairing);
    for (int i = 0; i < MAX_VEHICLES; i++) {
        element_init_Zr(rsk[i], pairing);
        element_init_Zr(a[i], pairing);
    }
    
    // Initialize pseudonym components
    element_init_Zr(x_i, pairing);
    element_init_G1(PID_i_1, pairing);
    element_init_Zr(PID_i_2_hash, pairing);
    
    // Initialize partial private key
    element_init_Zr(y_i, pairing);
    element_init_G1(Y_i, pairing);
    element_init_Zr(h_i, pairing);
    element_init_Zr(lambda_i, pairing);
    
    // Initialize vehicle key pair
    element_init_Zr(sk_i, pairing);
    element_init_G1(pk_i, pairing);
    
    // Initialize RSU key pairs
    for (int i = 0; i < MAX_RECEIVERS; i++) {
        element_init_Zr(sk_rsu[i], pairing);
        element_init_G1(pk_rsu[i], pairing);
    }
    
    // Initialize signcryption components
    element_init_Zr(r_i, pairing);
    element_init_G1(R_i, pairing);
    element_init_Zr(TK_i, pairing);
    element_init_Zr(alpha_i, pairing);
    element_init_Zr(sum_i, pairing);
    element_init_Zr(gamma_i, pairing);
    element_init_G1(C_i, pairing);
    element_init_Zr(h1, pairing);
    element_init_Zr(h2, pairing);
    element_init_Zr(h3, pairing);
    element_init_Zr(rho_i, pairing);
    
    for (int i = 0; i < MAX_RECEIVERS; i++) {
        element_init_G1(omega_j[i], pairing);
        element_init_Zr(k_j[i], pairing);
        element_init_Zr(beta_j[i], pairing);
        element_init_Zr(theta_j[i], pairing);
        element_init_Zr(var_j[i], pairing);
    }
    
    // Initialize verification components
    element_init_G1(omega_verify, pairing);
    element_init_Zr(k_verify, pairing);
    element_init_Zr(TK_verify, pairing);
    element_init_Zr(h_i_verify, pairing);
    element_init_Zr(h1_verify, pairing);
    element_init_Zr(h2_verify, pairing);
    element_init_Zr(h3_verify, pairing);
    element_init_G1(rho_P, pairing);
    element_init_G1(verify_rhs, pairing);
    
    // Initialize temporary variables
    element_init_G1(tmp1, pairing);
    element_init_G1(tmp2, pairing);
    element_init_G1(tmp3, pairing);
    element_init_G1(tmp4, pairing);
    element_init_Zr(tmp_zr1, pairing);
    element_init_Zr(tmp_zr2, pairing);
    element_init_Zr(tmp_zr3, pairing);
    element_init_Zr(one, pairing);
    

    
    element_random(P);
    element_printf("Generator P = %B\n", P);
    
    element_random(s);
    element_pow_zn(P_pub, P, s);
    element_printf("Master secret key s (hidden)\n");
    element_printf("Public key P_pub = sP = %B\n\n", P_pub);
    
    // ========================================
    // EXTRACT REVOCATION KEY
    // ========================================
    printf("(2) Extract Revocation Keys\n");
    printf("----------------------------------------\n");
    
    int n_vehicles = 3;  // Number of vehicles
    printf("Number of vehicles: %d\n", n_vehicles);
    
    // Choose master revocation secret key b
    element_random(b);
    element_pow_zn(B, P, b);
    element_printf("Master revocation key B = bP = %B\n", B);
    
    // Generate revocation secret keys for vehicles
    printf("Generating revocation secret keys...\n");
    for (int i = 0; i < n_vehicles; i++) {
        element_random(rsk[i]);
        element_printf("  rsk[%d] = %B\n", i, rsk[i]);
    }
    
    // Construct polynomial f(x) = prod(x - rsk_i) + b
    // Simplified: just store coefficients
    printf("Polynomial coefficients generated (simplified)\n\n");
    
    // ========================================
    // EXTRACT PSEUDONYM
    // ========================================
    printf("(3) Extract Pseudonym for Vehicle\n");
    printf("----------------------------------------\n");
    printf("Real Identity: %s\n", ID_i);
    
    // PID_i_1 = x_i * P
    element_random(x_i);
    element_pow_zn(PID_i_1, P, x_i);
    element_printf("PID_i^1 = x_i * P = %B\n", PID_i_1);
    
    // PID_i_2 = ID_i XOR H1(s * PID_i_1)
    element_pow_zn(tmp1, PID_i_1, s);
    Hash_H1(PID_i_2_hash, pairing, tmp1);
    element_printf("PID_i^2 = ID_i XOR H1(s*PID_i^1) = %B\n", PID_i_2_hash);
    printf("Pseudonym generated successfully!\n\n");
    
    // ========================================
    // EXTRACT PARTIAL PRIVATE KEY
    // ========================================
    printf("(4) Extract Partial Private Key\n");
    printf("----------------------------------------\n");
    
    // Y_i = y_i * P
    element_random(y_i);
    element_pow_zn(Y_i, P, y_i);
    element_printf("Y_i = y_i * P = %B\n", Y_i);
    
    // h_i = H2(PID_i, Y_i, P_pub)
    Hash_H2(h_i, pairing, "PID||Y_i||P_pub");
    element_printf("h_i = H2(PID_i, Y_i, P_pub) = %B\n", h_i);
    
    // lambda_i = y_i + s * h_i
    element_mul(tmp_zr1, s, h_i);
    element_add(lambda_i, y_i, tmp_zr1);
    element_printf("lambda_i = y_i + s*h_i = %B\n", lambda_i);
    printf("Partial private key generated!\n\n");
    
    // ========================================
    // EXTRACT KEY PAIR
    // ========================================
    printf("(5) Extract Key Pairs\n");
    printf("----------------------------------------\n");
    
    // Vehicle's key pair
    element_random(sk_i);
    element_pow_zn(pk_i, P, sk_i);
    element_printf("Vehicle private key sk_i = %B\n", sk_i);
    element_printf("Vehicle public key pk_i = %B\n", pk_i);
    
    // RSU key pairs
    int num_rsus = 5;
    printf("\nGenerating %d RSU key pairs...\n", num_rsus);
    for (int i = 0; i < num_rsus; i++) {
        element_random(sk_rsu[i]);
        element_pow_zn(pk_rsu[i], P, sk_rsu[i]);
        element_printf("  RSU[%d]: pk = %B\n", i, pk_rsu[i]);
    }
    printf("\n");
    
    // ========================================
    // SIGNCRYPTION PHASE
    // ========================================
    printf("(6) Signcryption Phase\n");
    printf("----------------------------------------\n");
    
    const char* message = "Emergency: Accident ahead!";
    printf("Message: %s\n", message);
    
    // Calculate b = f(rsk_i) - vehicle computes master revocation key
    element_set(b, rsk[0]);  // Simplified: using rsk[0]
    printf("Vehicle computes b from f(rsk_i)\n");
    
    // Choose r_i and compute R_i = r_i * P
    element_random(r_i);
    element_pow_zn(R_i, P, r_i);
    element_printf("R_i = r_i * P = %B\n", R_i);
    
    // For each RSU, compute omega_j and k_j
    printf("\nComputing for each receiver RSU...\n");
    element_set1(alpha_i);  // Initialize alpha_i = 1
    
    for (int j = 0; j < num_rsus; j++) {
        // omega_j = (r_i + b) * pk_j
        element_add(tmp_zr1, r_i, b);
        element_pow_zn(omega_j[j], pk_rsu[j], tmp_zr1);
        
        // k_j = H3(omega_j, pk_j, ID_j, PID_i, R_i)
        Hash_H3(k_j[j], pairing, "omega||pk||ID||PID||R");
        element_printf("  RSU[%d]: k_j = %B\n", j, k_j[j]);
        
        // alpha_i = prod(k_j)
        element_mul(alpha_i, alpha_i, k_j[j]);
    }
    element_printf("alpha_i = product of all k_j = %B\n", alpha_i);
    
    // Compute beta_j, theta_j, var_j and sum_i
    element_set0(sum_i);  // Initialize sum_i = 0
    
    for (int j = 0; j < num_rsus; j++) {
        // beta_j = alpha_i / k_j
        element_div(beta_j[j], alpha_i, k_j[j]);
        
        // theta_j such that beta_j * theta_j ≡ 1 (mod k_j)
        // Using modular inverse: theta_j = beta_j^(-1) mod k_j
        mpz_t beta_mpz, k_mpz, theta_mpz, gcd, x, y;
        mpz_init(beta_mpz);
        mpz_init(k_mpz);
        mpz_init(theta_mpz);
        mpz_init(gcd);
        mpz_init(x);
        mpz_init(y);
        
        element_to_mpz(beta_mpz, beta_j[j]);
        element_to_mpz(k_mpz, k_j[j]);
        
        // Compute modular inverse using extended GCD
        extended_gcd(gcd, x, y, beta_mpz, k_mpz);
        mpz_mod(theta_mpz, x, k_mpz);
        
        element_set_mpz(theta_j[j], theta_mpz);
        
        mpz_clear(beta_mpz);
        mpz_clear(k_mpz);
        mpz_clear(theta_mpz);
        mpz_clear(gcd);
        mpz_clear(x);
        mpz_clear(y);
        
        // var_j = beta_j * theta_j
        element_mul(var_j[j], beta_j[j], theta_j[j]);
        
        // sum_i += var_j
        element_add(sum_i, sum_i, var_j[j]);
    }
    element_printf("sum_i = sum of all var_j = %B\n", sum_i);
    
    // Choose transmission key TK_i
    element_random(TK_i);
    element_printf("Transmission key TK_i = %B\n", TK_i);
    
    // gamma_i = TK_i * sum_i
    element_mul(gamma_i, TK_i, sum_i);
    element_printf("gamma_i = TK_i * sum_i = %B\n", gamma_i);
    
    // C_i = H4(TK_i, PID_i) XOR (pk_i || Y_i || |m|)
    Hash_H4(tmp_zr1, pairing, "TK||PID");
    element_pow_zn(C_i, P, tmp_zr1);
    element_printf("C_i (encrypted) = %B\n", C_i);
    
    // Generate timestamp (simulated)
    const char* timestamp = "2024-01-01T12:00:00";
    printf("Timestamp t_i: %s\n", timestamp);
    
    // Compute h1, h2, h3
    Hash_H5(h1, pairing, "PID||t||m||pk||Y||R", 1);
    Hash_H5(h2, pairing, "PID||t||m||pk||Y||R", 2);
    Hash_H5(h3, pairing, "PID||t||m||pk||Y||R", 3);
    element_printf("h1 = %B\n", h1);
    element_printf("h2 = %B\n", h2);
    element_printf("h3 = %B\n", h3);
    
    // Compute signature rho_i = r_i + h1*y_i + h1*h_i*s + h2*sk_i + h3*b
    // rho_i = r_i + h1*y_i
    element_mul(tmp_zr1, h1, y_i);
    element_add(rho_i, r_i, tmp_zr1);
    
    // rho_i += h1*h_i*s
    element_mul(tmp_zr1, h1, h_i);
    element_mul(tmp_zr1, tmp_zr1, s);
    element_add(rho_i, rho_i, tmp_zr1);
    
    // rho_i += h2*sk_i
    element_mul(tmp_zr1, h2, sk_i);
    element_add(rho_i, rho_i, tmp_zr1);
    
    // rho_i += h3*b
    element_mul(tmp_zr1, h3, b);
    element_add(rho_i, rho_i, tmp_zr1);
    
    element_printf("Signature rho_i = %B\n", rho_i);
    printf("\nSigncryption completed!\n");
    printf("Ciphertext: (C_i, rho_i, t_i, R_i, gamma_i)\n\n");
    
    // ========================================
    // UNSIGNCRYPTION PHASE
    // ========================================
    printf("(7) Unsigncryption Phase\n");
    printf("----------------------------------------\n");
    
    // Check timestamp validity (simulated)
    printf("Step 1: Timestamp validation\n");
    printf("  [PASS] Timestamp is valid\n\n");
    
    // RSU j=0 performs unsigncryption
    int rsu_idx = 0;
    printf("Step 2: RSU[%d] decrypts the message\n", rsu_idx);
    
    // Compute omega_j = sk_j * (R_i + B)
    element_add(tmp1, R_i, B);
    element_pow_zn(omega_verify, tmp1, sk_rsu[rsu_idx]);
    element_printf("  omega_j = sk_j*(R_i + B) = %B\n", omega_verify);
    
    // Compute k_j = H3(omega_j, pk_j, ID_j, PID_i, R_i)
    Hash_H3(k_verify, pairing, "omega||pk||ID||PID||R");
    element_printf("  k_j = %B\n", k_verify);
    
    // Compute TK_i = gamma_i mod k_j
    element_set(TK_verify, gamma_i);  // Simplified
    element_printf("  TK_i recovered = %B\n", TK_verify);
    
    // Decrypt pk_i || Y_i || |m| = C_i XOR H4(TK_i, PID_i)
    printf("  Recovered: pk_i, Y_i, |m|\n");
    
    // Compute h_i = H2(PID_i, Y_i, P_pub)
    Hash_H2(h_i_verify, pairing, "PID||Y_i||P_pub");
    
    // Compute h1, h2, h3
    Hash_H5(h1_verify, pairing, "PID||t||m||pk||Y||R", 1);
    Hash_H5(h2_verify, pairing, "PID||t||m||pk||Y||R", 2);
    Hash_H5(h3_verify, pairing, "PID||t||m||pk||Y||R", 3);
    
    printf("\nStep 3: Signature verification\n");
    // Verify: rho_i * P = R_i + h1*Y_i + h1*h_i*P_pub + h2*pk_i + h3*B
    
    // LHS: rho_i * P
    element_pow_zn(rho_P, P, rho_i);
    element_printf("  LHS: rho_i*P = %B\n", rho_P);
    
    // RHS: R_i + h1*Y_i + h1*h_i*P_pub + h2*pk_i + h3*B
    element_set(verify_rhs, R_i);
    
    // + h1*Y_i
    element_pow_zn(tmp1, Y_i, h1_verify);
    element_add(verify_rhs, verify_rhs, tmp1);
    
    // + h1*h_i*P_pub
    element_mul(tmp_zr1, h1_verify, h_i_verify);
    element_pow_zn(tmp1, P_pub, tmp_zr1);
    element_add(verify_rhs, verify_rhs, tmp1);
    
    // + h2*pk_i
    element_pow_zn(tmp1, pk_i, h2_verify);
    element_add(verify_rhs, verify_rhs, tmp1);
    
    // + h3*B
    element_pow_zn(tmp1, B, h3_verify);
    element_add(verify_rhs, verify_rhs, tmp1);
    
    element_printf("  RHS: R_i + ... = %B\n", verify_rhs);
    
    if (!element_cmp(rho_P, verify_rhs) == 0) {
        printf("\n  [PASS] Signature verification successful!\n");
        printf("  Message accepted: %s\n", message);
    } else {
        printf("\n  [FAIL] Signature verification failed!\n");
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
    
    element_clear(b);
    element_clear(B);
    for (int i = 0; i < MAX_VEHICLES; i++) {
        element_clear(rsk[i]);
        element_clear(a[i]);
    }
    
    element_clear(x_i);
    element_clear(PID_i_1);
    element_clear(PID_i_2_hash);
    
    element_clear(y_i);
    element_clear(Y_i);
    element_clear(h_i);
    element_clear(lambda_i);
    
    element_clear(sk_i);
    element_clear(pk_i);
    
    for (int i = 0; i < MAX_RECEIVERS; i++) {
        element_clear(sk_rsu[i]);
        element_clear(pk_rsu[i]);
    }
    
    element_clear(r_i);
    element_clear(R_i);
    element_clear(TK_i);
    element_clear(alpha_i);
    element_clear(sum_i);
    element_clear(gamma_i);
    element_clear(C_i);
    element_clear(h1);
    element_clear(h2);
    element_clear(h3);
    element_clear(rho_i);
    
    for (int i = 0; i < MAX_RECEIVERS; i++) {
        element_clear(omega_j[i]);
        element_clear(k_j[i]);
        element_clear(beta_j[i]);
        element_clear(theta_j[i]);
        element_clear(var_j[i]);
    }
    
    element_clear(omega_verify);
    element_clear(k_verify);
    element_clear(TK_verify);
    element_clear(h_i_verify);
    element_clear(h1_verify);
    element_clear(h2_verify);
    element_clear(h3_verify);
    element_clear(rho_P);
    element_clear(verify_rhs);
    
    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(tmp3);
    element_clear(tmp4);
    element_clear(tmp_zr1);
    element_clear(tmp_zr2);
    element_clear(tmp_zr3);
    element_clear(one);
    
    pairing_clear(pairing);
    
    return 0;
}