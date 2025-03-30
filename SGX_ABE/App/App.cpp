#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_MEMORY_MAP_FAILURE,
        "Failed to reserve memory for the enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave("/home/ubuntu204/linux-sgx/linux/installer/bin/opt/intel/sgxsdk/SampleCode/SampleEnclave/enclave.signed.so", SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        printf("飞地创建错误");
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);


    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
 
    /* Utilize edger8r attributes */
    edger8r_array_attributes();
    edger8r_pointer_attributes();
    edger8r_type_attributes();
    edger8r_function_attributes();
    
    /* Utilize trusted libraries */
    ecall_libc_functions();
    ecall_libcxx_functions();
    ecall_thread_functions();

    PK pk; 
    sgx_status_t status=SGX_SUCCESS;
    status=ecall_init_system(global_eid,&status,&pk);
    if (status != SGX_SUCCESS){
        printf("系统初始化失败",status);
    }
    const char *attrs[]={"A", "B" ,"C"};
    size_t attr_count=3;
    uint64_t expire_time=2025;
    SK* sk;
    status=ecall_generate_user_key(global_eid,&status,attrs, attr_count,expire_time,sk); 
    if (status != SGX_SUCCESS){
        printf("用户密钥生成失败",status);
    }
    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

// AES加密函数
void aes_encrypt(const unsigned char *plaintext, unsigned char *ciphertext, const unsigned char *key) {
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);
    AES_encrypt(plaintext, ciphertext, &aesKey);
}

// AES解密函数
void aes_decrypt(const unsigned char *ciphertext, unsigned char *decryptedtext, const unsigned char *key) {
    AES_KEY aesKey;
    AES_set_decrypt_key(key, 128, &aesKey);
    AES_decrypt(ciphertext, decryptedtext, &aesKey);
}


void encrypt(ciphertext_t* ct, const uint8_t* plaintext,size_t pt_len,const lsss_row_t* policy,size_t policy_size) 
{

    // 定义密钥和明文
    unsigned char key[AES_BLOCK_SIZE] = "012456789abcdef"; // 128-bit key
    unsigned char plaintext[AES_BLOCK_SIZE] = "Hello, AES!"; // 128-bit plaintext
    unsigned char ciphertext[AES_BLOCK_SIZE];
    unsigned char decryptedtext[AES_BLOCK_SIZE];

    // 加密
    aes_encrypt(plaintext, ciphertext, key);
    printf("Ciphertext: ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // 解密
    aes_decrypt(ciphertext, decryptedtext, key);
    printf("Decrypted text: %s\n", decryptedtext);


    // CP-ABE加密
    element_t s;
    element_init_Zr(s, pairing);
    element_random(s);

    // C1 = g1^s
    element_init_G1(ct->C1, bg.pairing);
    element_pow_zn(ct->C1, pk.g1, s);

    // 计算C0' = S·e(g1,g2)^{αs}
    element_t S;
    element_init_GT(S, bg.pairing);
    hash_to_GT(S, sym_key);  // 将对称密钥映射到GT

    element_t e_gg_alpha_s;
    pairing_apply(e_gg_alpha_s, pk.g1, msk.g2_alpha, bg.pairing);
    element_pow_zn(e_gg_alpha_s, e_gg_alpha_s, s);
    element_mul(ct->C0_prime, S, e_gg_alpha_s);

    // 盲化处理
    element_t r;
    element_init_Zr(r, bg.pairing);
    element_random(r);

    element_t rs;
    element_init_Zr(rs, bg.pairing);
    element_mul(rs, r, s);

    element_init_G2(ct->tilde_C1, bg.pairing);
    element_pow_zn(ct->tilde_C1, bg.g2, rs);

    // 策略分量
    ct->policy = (lsss_row_t*)malloc(policy_size * sizeof(lsss_row_t));
    ct->policy_size = policy_size;

    for (size_t i = 0; i < policy_size; ++i) {
    // 计算M_i · v
    element_t product;
    element_init_Zr(product, bg.pairing);
    inner_product(product, policy[i].vector, policy[i].length);

    // Ci1 = g1^{M_i·v}
    element_init_G1(ct->policy[i].Ci1, bg.pairing);
    element_pow_zn(ct->policy[i].Ci1, pk.g1, product);

    // Ci2 = H(ρ(i))^{M_i·v} · h1^{-s}
    element_t H_rho;
    hash_to_G2(H_rho, policy[i].attribute);
    element_pow_zn(ct->policy[i].Ci2, H_rho, product);

    element_t h1_inv_s;
    element_init_G2(h1_inv_s, bg.pairing);
    element_pow_zn(h1_inv_s, pk.h1, s);
    element_invert(h1_inv_s, h1_inv_s);
    element_mul(ct->policy[i].Ci2, ct->policy[i].Ci2, h1_inv_s);
    }   
}

//用户解密
int decrypt(const transformed_ct_t* ct_inter,const user_key_t* sk,uint8_t* plaintext)
{
// 属性匹配
int* matched_indices = find_matching_attributes(ct_inter->policy, sk->attributes);

// 拉格朗日系数
element_t* coeffs = compute_lagrange_coeffs(matched_indices);

// 解密节点
element_t numerator, denominator;
element_init_GT(numerator, bg.pairing);
element_init_GT(denominator, bg.pairing);

for (int i = 0; i < ct_inter->policy_size; ++i) {
  if (!is_matched(i)) continue;
  
  element_t e1, e2;
  pairing_apply(e1, ct_inter->policy[i].Ci1, sk->Kx[i], bg.pairing);
  pairing_apply(e2, ct_inter->policy[i].Ci2, sk->K1, bg.pairing);
  
  element_mul(e1, e1, coeffs[i]);
  element_mul(numerator, numerator, e1);
  element_mul(denominator, denominator, e2);
}

// 恢复对称密钥
element_t D;
element_init_GT(D, bg.pairing);
pairing_apply(D, ct_inter->C1, sk->K0, bg.pairing);
element_div(D, D, denominator);
element_div(D, numerator, D);

// 转换为AES密钥
uint8_t sym_key[32];
gt_to_bytes(D, sym_key);

// 解密数据
return aes_decrypt(sym_key, ct_inter->ciphertext, plaintext);
}