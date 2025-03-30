#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}


#include<sgx_gmp/include/sgx_tgmp.h>
#include<pbc/pbc.h>

//最新版本
pairing_t pairing;
element_t g2;      
static MSK msk;
static PK pk;
// 系统初始化
sgx_status_t ecall_init_system(PK* pk) {
    // 初始化双线性群
    pairing_init_set_str(pairing, "type a"); 

    // 生成主密钥（补充gamma）
    element_init_Zr(msk.alpha, pairing);
    element_random(msk.alpha);
    element_init_Zr(msk.beta, pairing);
    element_random(msk.beta);
    element_init_Zr(msk.gamma, pairing);  // 新增gamma
    element_random(msk.gamma);

    element_init_G2(g2, pairing);
    element_random(g2); // 明确初始化g2
    element_init_G2(msk.g2_alpha, pairing);
    element_pow_zn(msk.g2_alpha, g2, msk.alpha);

    // 生成公钥
    element_init_G1(pk->g1, pairing);
    element_random(pk->g1);
    element_init_G2(pk->h1, pairing);
    element_pow_zn(pk->h1, g2, msk.beta); // h1 = g2^β
    element_init_G1(pk->h2, pairing);
    element_pow_zn(pk->h2, pk->g1, msk.gamma); // h2 = g1^γ

    // 计算e(g1,g2)^α
    element_init_GT(pk->e_gg_alpha, pairing);
    pairing_apply(pk->e_gg_alpha, pk->g1, msk.g2_alpha, pairing);

    return SGX_SUCCESS;
}

sgx_status_t ecall_generate_user_key(const char** attrs, size_t attr_count,uint64_t expire_time,SK* sk) {
    element_t t;
    element_init_Zr(t, pairing);
    element_random(t);  // t ← Z_p^*

    // 核心组件
    element_init_G2(sk->K0, pairing);
    element_pow_zn(sk->K0, g2, msk.alpha);  // g2^α
    element_t temp;
    element_init_G2(temp, pairing);
    element_pow_zn(temp, pk.h1, t);            // h1^t = g2^{βt}
    element_add(sk->K0, sk->K0, temp);         // K0 = g2^{α+βt}

    element_init_G1(sk->K1, pairing);
    element_pow_zn(sk->K1, pk.g1, t);          // K1 = g1^t

    // 属性组件
    sk->Kx = (element_t**)malloc(attr_count * sizeof(element_t*));
    
    for (size_t i = 0; i < attr_count; ++i) {
        element_t Hx;
        element_init_G2(Hx, pairing);
        element_from_hash(Hx, (void*)attrs[i], sizeof(attrs[i]));// H(x) = g2^{a_x}
        sk->Kx[i] = (element_t*)malloc(sizeof(element_t));
        element_init_G2(*sk->Kx[i], pairing);
        element_pow_zn(*sk->Kx[i], Hx, t);  // Kx = H(x)^t
    }

    // 时间绑定组件
    sk->nonce=(uint8_t)1234561234561234;
    char expire_str[256];
    snprintf(expire_str, sizeof(expire_str), "%ld%02x", expire_time, sk->nonce);
    element_t H_tau;
    element_init_G2(H_tau, pairing);
    element_from_hash(H_tau, (void*)expire_str, sizeof(expire_str));// H(x) = g2^{a_x}
    element_init_G2(sk->K_tau, pairing);
    element_pow_zn(sk->K_tau, H_tau, t);

    
    return SGX_SUCCESS;
}


//SGX验证转换

sgx_status_t ecall_verify_and_transform(
    ciphertext_t* ct,
    SK* sk,
    merkle_proof_t* proof,
    ciphertext_t* ct_inter
) {
    // 时间验证
    uint64_t current_time;
    if (current_time > sk->expire_time) {
        return SGX_ERROR_FILE_BAD_STATUS;
    }

    // 验证时间绑定组件（防止伪造过期时间）
    char expire_str[256];
    snprintf(expire_str, sizeof(expire_str), "%ld", sk->expire_time);
    element_t H_tau_calc, left_pair, right_pair;
    
    // 计算H("ExpireTime"||expire||nonce)
    element_from_hash(H_tau_calc, (void*)"ExpireTime", sizeof("ExpireTime"));
    element_t H_expire;
    element_from_hash(H_expire, (void*)expire_str, sizeof(expire_str));
    element_mul(H_tau_calc, H_tau_calc, H_expire);
    element_t H_nonce;
    char nonce_hex[33];
    //to_hex(sk->nonce, 16, nonce_hex);
    element_from_hash(H_nonce, (void*)nonce_hex, sizeof(nonce_hex));
    element_mul(H_tau_calc, H_tau_calc, H_nonce);

    // 验证 e(K_tau, h2) == e(H_tau_calc, K1^γ)
    element_init_GT(left_pair, pairing);
    element_init_GT(right_pair, pairing);
    
    // 计算左式：e(K_tau, h2)
    pairing_apply(left_pair, sk->K_tau, pk.h2, pairing);
    
    // 计算右式：e(H_tau_calc, K1^γ)
    element_t K1_gamma;
    element_init_G1(K1_gamma, pairing);
    element_pow_zn(K1_gamma, sk->K1, msk.gamma);
    pairing_apply(right_pair, H_tau_calc, K1_gamma, pairing);
    
    if (element_cmp(left_pair, right_pair) != 0) {
        element_clear(left_pair);
        element_clear(right_pair);
        element_clear(K1_gamma);
        return SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE;
    }
    element_clear(left_pair);
    element_clear(right_pair);
    element_clear(K1_gamma);

    // // Merkle验证
    // uint8_t leaf_hash[32];
    // sha256_hash(sk->nonce, 16, leaf_hash);
    // if (!merkle_verify(proof, leaf_hash)) {
    //     return SGX_ERROR_INVALID_PARAMETER;
    // }

    // 消除盲因子
    element_t T;
    element_init_GT(T, pairing);
    
    // T = e(g1^β, g2^{rs}) = e(h1, tilde_C1)
    element_t g1_beta;
    element_pow_zn(g1_beta, pk.g1, msk.beta);
    pairing_apply(T, g1_beta, ct->tilde_C1, pairing);
    
    // C0'' = C0' / T
    ct=ct_inter;
    element_init_GT(ct_inter->C0_prime, pairing);
    element_div(ct_inter->C0_prime, ct->C0_prime, T);
    element_clear(T);
    
    return SGX_SUCCESS;
}