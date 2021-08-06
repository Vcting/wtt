#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <stdio.h>
#include <string.h>

#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
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
    int ret;
    size_t olen = 0;
    uint8_t out[2048/8];
    

    mbedtls_rsa_context ctx;    //RSA密钥结构体
    mbedtls_entropy_context entropy;//熵结构体
    mbedtls_ctr_drbg_context ctr_drbg;//随机数结构体
    const char *pers = "simple_rsa";//用来初始化随机数的种子
    const char *msg = "This is the RSA signature and verification!";//签名的消息

    mbedtls_entropy_init(&entropy);//初始化熵结构体
    mbedtls_ctr_drbg_init(&ctr_drbg);//初始化随机数结构体
    //rsa结构体初始化
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V21, //填充方案OAEP
    						MBEDTLS_MD_SHA256); //SHA256做散列算法

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                                    (const uint8_t *) pers, strlen(pers));//根据个性化字符串更新种子

    mbedtls_printf("\n  . setup rng ... ok\n");

    mbedtls_printf("\n  ! RSA Generating large primes may take minutes! \n");
	//生成RSA密钥
    ret = mbedtls_rsa_gen_key(&ctx, mbedtls_ctr_drbg_random, //随机数生成接口
                                        &ctr_drbg, //随机数结构体
                                        2048, //模数位长度
                                        65537);//公开指数0x01001
                                 
    mbedtls_printf("\n  1. RSA generate key ... ok\n");
    dump_rsa_key(&ctx);  
    //RSA加密
    ret = mbedtls_rsa_pkcs1_encrypt(&ctx, mbedtls_ctr_drbg_random, //随机数生成接口
                            &ctr_drbg,          //随机数结构体
                            MBEDTLS_RSA_PUBLIC, //公钥操作
                            strlen(msg),        //消息长度
                            msg,                //输入消息指针
                            out);               //输出密文指针
                              
     dump_buf("  2. rsa generate signature:", out, sizeof(out));
	//RSA解密
    ret = mbedtls_rsa_pkcs1_decrypt(&ctx, mbedtls_ctr_drbg_random,//随机数生成接口
    						&ctr_drbg,          //随机数结构体
                            MBEDTLS_RSA_PRIVATE, //私钥操作
                            &olen,           //输出长度
                            out,             //输入密文指针
                            out,             //输出明文指针
                            sizeof(out));    //最大输出明文数组长度
                          
    
    out[olen] = 0;
    mbedtls_printf("\n  3. RSA decryption ... ok\n     %s\n", out);

    ret = memcmp(out, msg, olen);
    mbedtls_printf("\n  4. RSA Compare results and plaintext ... ok\n");
    return ret;

}

