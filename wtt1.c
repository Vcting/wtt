#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <stdio.h>
#include <string.h>

#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"

#define assert_exit(cond, ret) \
    do { if (!(cond)) { \
        printf("  !. assert: failed [line: %d, error: -0x%04X]\n", __LINE__, -ret); \
        goto cleanup; \
    } } while (0)

static void dump_buf(char *info, uint8_t *buf, uint32_t len)//格式化输出
{
    mbedtls_printf("%s", info);
    for (int i = 0; i < len; i++) {
        mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\n     ":" ", 
                        buf[i], i == len - 1 ? "\n":"");
    }
}

static void dump_rsa_key(mbedtls_rsa_context *ctx)//输出密钥
{
    size_t olen;
    uint8_t buf[516];
    mbedtls_printf("\n  +++++++++++++++++ rsa keypair +++++++++++++++++\n\n");
    mbedtls_mpi_write_string(&ctx->N , 16, buf, sizeof(buf), &olen);//以16进制将N输出到buf，并记录输出的长度
    mbedtls_printf("N: %s\n", buf); 

    mbedtls_mpi_write_string(&ctx->E , 16, buf, sizeof(buf), &olen);
    mbedtls_printf("E: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->D , 16, buf, sizeof(buf), &olen);
    mbedtls_printf("D: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->P , 16, buf, sizeof(buf), &olen);
    mbedtls_printf("P: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->Q , 16, buf, sizeof(buf), &olen);
    mbedtls_printf("Q: %s\n", buf);

}

int main(void)
{
    int ret = 0;
    uint8_t msg[100];
    uint8_t sig[2048/8];
    uint8_t *pers = "wtt_rsa_sign";//用来初始化随机数的种子
    
    mbedtls_rsa_context ctx;//密钥结构体
    mbedtls_entropy_context entropy;//熵结构体
    mbedtls_ctr_drbg_context ctr_drbg;//随机数结构体

    mbedtls_entropy_init(&entropy);//初始化熵结构体
    mbedtls_ctr_drbg_init(&ctr_drbg);//初始化随机数结构体
	//RSA密钥对初始化       填充方式PSS(OAEP),散列算法SHA256
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                                (const uint8_t *) pers, strlen(pers));//根据个性化字符串更新种子
  
    //产生RSA密钥对
    mbedtls_printf("  ! RSA Generating large primes may take minutes! \n");
    ret = mbedtls_rsa_gen_key(&ctx, mbedtls_ctr_drbg_random, //随机数生成接口
                                        &ctr_drbg, //随机数结构体
                                        2048,  //RSA2048
                                        65537);//公开指数
    
    mbedtls_printf("  1. rsa generate keypair ... ok\n");
    dump_rsa_key(&ctx);
    //RSA用私钥签名 输出sig签名结果
    ret = mbedtls_rsa_pkcs1_sign(&ctx, mbedtls_ctr_drbg_random, //随机数生成接口
                                    &ctr_drbg, //随机数结构体
                                    MBEDTLS_RSA_PRIVATE, //私钥签名
                                    MBEDTLS_MD_SHA256,//掩码函数
                                    sizeof(msg),msg,sig
                                    );
    mbedtls_printf("  2. rsa generate signature:.. ok");
    //RSA公钥验签 返回0则验证成功
    ret = mbedtls_rsa_pkcs1_verify(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg, 
                                        MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 
                                        sizeof(msg), msg, sig);
 
    mbedtls_printf("  3. rsa verify signature ... ok\n\n");

    return ret;
}


