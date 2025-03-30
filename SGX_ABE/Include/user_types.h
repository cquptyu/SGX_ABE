#define LOOPS_PER_THREAD 500

typedef void *buffer_t;
typedef int array_t[10];

#include<pbc/pbc.h>

//最新版本
// 系统主密钥结构（仅存储在Enclave内存中）
/* 系统主密钥结构体（仅存在Enclave内存） */
typedef struct {
    element_t alpha, beta, gamma;  // Z_p^*元素
    element_t g2_alpha;            // G2群元素：g2^α
} MSK;

/* 系统公钥结构体 */
typedef struct {
    element_t g1;               // G1群生成元
    element_t h1;               // G2群元素：g2^β
    element_t h2;               // G1群元素：g1^γ
    element_t e_gg_alpha;       // GT群元素：e(g1,g2)^α
} PK;

/* 用户私钥 */
typedef struct {
    element_t K0;               // g2^{α+βt} ∈ G2
    element_t K1;               // g1^t ∈ G1
    element_t K_tau;            // H(expire||nonce)^t ∈ G2
    element_t** Kx;             // 属性密钥数组（g2^{a_x t}）
    uint64_t expire_time;
    uint8_t nonce;
} SK;


/* LSSS策略行 */
typedef struct {
    int32_t* vector;            // 策略向量
    size_t length;
    char attribute[32];         // 关联属性
} lsss_row_t;

/* 密文结构 */
typedef struct {
    element_t C0_prime;         // S·e(g1,g2)^{αs + βrs} ∈ GT
    element_t C1;               // g1^s ∈ G1
    element_t tilde_C1;         // g2^{rs} ∈ G2
    lsss_row_t* policy;         // LSSS策略数组
    size_t policy_size;
} ciphertext_t;

/* Merkel证明路径 */
typedef struct {
    uint8_t leaf_hash[32];
    uint8_t* sibling_hashes;
    size_t path_length;
} merkle_proof_t;