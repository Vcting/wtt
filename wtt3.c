#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "mbedtls/cipher.h"
#include "mbedtls/platform.h"


char *ptx = "This is CTR encryption and decryption";
uint8_t key[16] =//对称密钥
{
    0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b,
    0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06
};

uint8_t iv[16] =//计数器的初始值
{
    0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30,
    0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41
};

static void dump_buf(char *info, uint8_t *buf, uint32_t len)//格式化输出
{
    mbedtls_printf("%s", info);
    for (int i = 0; i < len; i++) {
        mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\n\t":" ", 
                        buf[i], i == len - 1 ? "\n":"");
    }
    mbedtls_printf("\n");
}

int my_aes_init(int type,mbedtls_cipher_context_t *ctx,const unsigned char *key,
        int key_bitlen, const mbedtls_operation_t operation,const unsigned char *iv, size_t iv_len)
{
    const mbedtls_cipher_info_t *info;

    mbedtls_cipher_init(ctx);//用0初始化加密结构体
    info = mbedtls_cipher_info_from_type(type);//检索与给定密码类型相关联的密码信息结构

    mbedtls_cipher_setup(ctx, info);//初始化并使用适当的值填充密码上下文结构
    mbedtls_printf("\n  cipher info setup, name: %s, block size: %d\n", 
                        mbedtls_cipher_get_name(ctx), //以字符串的形式返回给定密码的名称。
                        mbedtls_cipher_get_block_size(ctx));//返回给定密码块大小

    mbedtls_cipher_setkey(ctx, key, key_bitlen, operation);
    mbedtls_cipher_set_iv(ctx, iv, iv_len);//计数器初始值nonce
	return 0;
}
//更新计数器的值依次处理每个分组 进行加密
int my_aes_update(mbedtls_cipher_context_t *ctx, const unsigned char *input,
                   size_t ilen, unsigned char *output, size_t *olen )
{
	return mbedtls_cipher_update(ctx, input,ilen, output,olen);
}
//最后不完整的一块处理
int my_aes_finish(mbedtls_cipher_context_t *ctx,unsigned char *output, size_t *olen )
{
	return mbedtls_cipher_finish(ctx,output,olen);
}

void my_aes_deinit(mbedtls_cipher_context_t *ctx)
{
	mbedtls_cipher_free(ctx);//释放密钥结构体
}

int main(void)
{

    size_t len;
    int olen = 0;
    uint8_t buf[256];
//===========================================================
    //MBEDTLS_CIPHER_AES_128_CTR enc
	mbedtls_cipher_context_t aes_ctr_128_ctr;
	my_aes_init(MBEDTLS_CIPHER_AES_128_CTR,&aes_ctr_128_ctr,key,sizeof(key)*8,MBEDTLS_ENCRYPT,iv,sizeof(iv));//密钥初始化
	olen = 0;
	memset(buf,0,sizeof(buf));
	my_aes_update(&aes_ctr_128_ctr,ptx,strlen(ptx),buf,&len);//进行加密
	olen += len;
  	my_aes_finish(&aes_ctr_128_ctr,buf+olen,&len);//最后不完整的一块处理
	olen += len;
	my_aes_deinit(&aes_ctr_128_ctr);
	dump_buf("\n ctr cipher aes encrypt:", buf, olen);
    printf("%d\n",olen);

   int text_olen = 0;len = 0;
  uint8_t text_buf[256];
	//MBEDTLS_CIPHER_AES_128_CTR dec
	my_aes_init(MBEDTLS_CIPHER_AES_128_CTR,&aes_ctr_128_ctr,key,sizeof(key)*8,MBEDTLS_DECRYPT,iv,sizeof(iv));
	memset(text_buf,0,sizeof(text_buf));
	my_aes_update(&aes_ctr_128_ctr,buf,olen,text_buf,&len);
	text_olen +=len;
	my_aes_finish(&aes_ctr_128_ctr,text_buf+text_olen,&len);
	text_olen += len;
	my_aes_deinit(&aes_ctr_128_ctr);
	printf("text_olen :%d strlen(text_buf) :%ld\n",text_olen,strlen(text_buf));
	dump_buf("\n ctr text aes decrypt:", text_buf, text_olen);
	//dump_buf("\n ctr text aes decrypt:", text_buf, strlen(text_buf));

	printf("ctr decrypt: %s\n",text_buf);

    return 0;
}

