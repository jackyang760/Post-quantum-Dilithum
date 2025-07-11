#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../randombytes.h"
#include "../sign.h"
#include <openssl/evp.h>

// #define MLEN 128
// #define MAX_SIGNATURE_SIZE (CRYPTO_BYTES + MLEN) // 签名+消息的最大总长度
#define DIGEST_LEN 64  // SHA-512 输出长度
#define MAX_SIGNATURE_SIZE (CRYPTO_BYTES + DIGEST_LEN)

typedef struct {
    uint8_t signed_message[DIGEST_LEN + CRYPTO_BYTES];  // 包含消息的完整签名
    size_t signed_message_len;                    // 签名消息总长度
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];    // 公钥
} SignaturePacket;

// 函数原型声明
static void print_bytes(const char *label, const uint8_t *buf, size_t len);
int memcmp_const(const void *a, const void *b, size_t len);
int generate_keypair(uint8_t *pk, uint8_t *sk);
int message_sign(const uint8_t *sk, const uint8_t *pk, const uint8_t *msg, size_t msg_len, SignaturePacket *packet);
int signature_verify(const SignaturePacket *packet);
void extract_original_message(const SignaturePacket *packet, uint8_t *msg_out, size_t *len_out);
void print_algorithm_parameters(size_t msg_len, size_t sign_len);
void tamper_test(SignaturePacket *original_packet);

static void print_bytes(const char *label, const uint8_t *buf, size_t len) {
    printf("%s (长度 %zu):\n", label, len);
    for (size_t i = 0; i < len; i++) {
      printf("%02x", buf[i]);
      if ((i + 1) % 32 == 0) printf("\n");  // 每32字节换行
    }
    if (len % 32 != 0) printf("\n");
    printf("\n");
  }
  

// 从signed_message中提取原始消息
void extract_original_message(const SignaturePacket *packet, uint8_t *msg_out, size_t *len_out) {
    *len_out = 0;
    
    // 根据API文档，消息是倒序存储在签名之后
    if (packet->signed_message_len <= CRYPTO_BYTES) {
        fprintf(stderr, "错误: signed_message 太短，无法提取消息\n");
        return;
    }
    
    size_t msg_len = packet->signed_message_len - CRYPTO_BYTES;
    if (msg_len > DIGEST_LEN) {
        fprintf(stderr, "警告: 提取的消息长度 %zu 超过缓冲区大小 %d\n", msg_len, DIGEST_LEN);
        msg_len = DIGEST_LEN;
    }
    
    // 消息以倒序存储在签名缓冲区中 - 按原API实现反向复制
    for (size_t i = 0; i < msg_len; ++i) {
        msg_out[i] = packet->signed_message[CRYPTO_BYTES + msg_len - 1 - i];
    }
    
    *len_out = msg_len;
}

// 常量时间比较两个缓冲区内容
int memcmp_const(const void *a, const void *b, size_t len) {
    const uint8_t *ap = (const uint8_t *)a;
    const uint8_t *bp = (const uint8_t *)b;
    
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= ap[i] ^ bp[i];
    }
    
    return diff; // 返回0表示完全相等
}

// 生成密钥对
int generate_keypair(uint8_t *pk, uint8_t *sk) {
    printf("===== 第1阶段: 密钥生成 =====\n");
    printf("发送方Alice，调用crypto_sign_keypair函数，生成 Dilithium 公钥/私钥对...\n");
    
    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "密钥生成失败!\n");
        return -1;
    }
    
    printf("密钥生成成功:\n");
    print_bytes("公钥 (pk)", pk, CRYPTO_PUBLICKEYBYTES);
    print_bytes("私钥 (sk)", sk, CRYPTO_SECRETKEYBYTES);
    
    return 0;
}

// 消息签名
int message_sign(const uint8_t *sk, const uint8_t *pk, 
    const uint8_t *msg, size_t msg_len,
    SignaturePacket *packet) {

    uint8_t digest[DIGEST_LEN];  

    printf("\n===== 第2阶段: 签名生成 =====\n");

    // 1. 哈希原始消息
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new 失败\n");
        return -1;
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_sha512(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, msg, msg_len) != 1 ||
        EVP_DigestFinal_ex(mdctx, digest, NULL) != 1) {
        fprintf(stderr, "哈希失败\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    EVP_MD_CTX_free(mdctx);

    printf("发送方Alice，调用OpenSSL库对原消息进行哈希操作，获得64位哈希值\n");
    print_bytes("消息哈希 (SHA-512)", digest, DIGEST_LEN);

    // 2. 创建签名 (包括原始消息) [签名|原始消息(正序)] 
    printf("发送方Alice，调用crypto_sign函数使用Dilithium的私钥对哈希消息进行签名，获得签名值，签名结构为：[签名|哈希消息] \n");
    packet->signed_message_len = sizeof(packet->signed_message);
    // 清零 signed_message 缓冲区
    memset(packet->signed_message, 0, sizeof(packet->signed_message));
    if (crypto_sign(packet->signed_message, &packet->signed_message_len, digest, DIGEST_LEN, sk) != 0) {
        fprintf(stderr, "签名生成失败!\n");
        return -1;
    }
    printf("签名生成成功!\n");

    // 分开打印签名和消息哈希
    size_t signature_only_len = packet->signed_message_len - DIGEST_LEN;
    if (signature_only_len > CRYPTO_BYTES) signature_only_len = CRYPTO_BYTES;
    print_bytes("签名数据", packet->signed_message, signature_only_len);
    print_bytes("消息哈希", packet->signed_message + CRYPTO_BYTES, DIGEST_LEN);

    // 3. 打包公钥
    memcpy(packet->public_key, pk, CRYPTO_PUBLICKEYBYTES);
        
    return packet->signed_message_len;
}

// 签名验证 - 关键修复：使用包含消息的完整签名
int signature_verify(const SignaturePacket *packet) {
    printf("\n===== 第3阶段: 签名验证 =====\n");
    
    //uint8_t recovered_msg[MLEN] = {0};
    uint8_t recovered_msg[MAX_SIGNATURE_SIZE] = {0};
    size_t recovered_len = 0;

    if (packet->signed_message_len == 0 || packet->signed_message_len > MAX_SIGNATURE_SIZE) {
        fprintf(stderr, "无效的signed_message长度: %zu\n", packet->signed_message_len);
        return -1;
    }
    
    // 1. 验证签名 - 使用包含消息的完整签名数据
    printf("接受方Bob，调用crypto_sign_open函数，使用Dilithium公钥对签名解密，获得64位的还原值\n");
    int ret = crypto_sign_open(recovered_msg, &recovered_len, 
                              packet->signed_message, packet->signed_message_len, 
                              packet->public_key);
    
                              //print sign open
    if (ret != 0) {
        fprintf(stderr, "签名验证失败! 错误码: %d\n", ret);
        return -1;
    }
    
    // 2. 从签名中提取的原始消息
    printf("接受方Bob，将解密后的还原值与Alice发送过来的原始消息哈希值进行比对\n");
    uint8_t extracted_original_msg[DIGEST_LEN] = {0};
    for (size_t i = 0; i < DIGEST_LEN; ++i) {
        extracted_original_msg[i] = packet->signed_message[packet->signed_message_len - DIGEST_LEN + i];
    }

    // 内容比较 (常量时间)
    if (memcmp_const(extracted_original_msg, recovered_msg, DIGEST_LEN) != 0) {
        fprintf(stderr, "消息内容不匹配!\n");
            
        // 打印更多调试信息
        print_bytes("原始消息哈希", extracted_original_msg, DIGEST_LEN);
        print_bytes("恢复消息哈希", recovered_msg, recovered_len);
        return -1;
    }
        
    printf("✓ 验证成功! 签名有效且消息完整\n");
    print_bytes("原始消息哈希", extracted_original_msg, DIGEST_LEN);
    print_bytes("恢复消息哈希", recovered_msg, recovered_len);
    return 0;
}

// 打印算法参数
void print_algorithm_parameters(size_t msg_len, size_t sign_len) {
    printf("\n===== 算法参数报告 =====\n");
    printf("公钥长度 (CRYPTO_PUBLICKEYBYTES) : %d 字节\n", CRYPTO_PUBLICKEYBYTES);
    printf("私钥长度 (CRYPTO_SECRETKEYBYTES) : %d 字节\n", CRYPTO_SECRETKEYBYTES);
    printf("最大签名长度 (CRYPTO_BYTES)       : %d 字节\n", CRYPTO_BYTES);
    printf("原始消息长度                     : %zu 字节\n", msg_len);
    printf("签名-消息对总长度                : %zu 字节\n", sign_len);
}

// 篡改签名检测测试
void tamper_test(SignaturePacket *original_packet) {
    printf("\n===== 篡改检测测试 =====\n");
    SignaturePacket tampered = *original_packet;
    
    printf("修改签名数据后重新验证...\n");
    
    // 篡改签名数据（确保在有效范围内）
    if (tampered.signed_message_len > 10) {
        tampered.signed_message[10] ^= 0xAA;
        printf("篡改了签名数据的第11个字节\n");
    }
    
    if (signature_verify(&tampered) == 0) {
        fprintf(stderr, "✘ 篡改检测失败! 无效签名被接受了!\n");
    } else {
        printf("✓ 篡改检测成功! 无效签名被拒绝\n");
    }
}

// 主函数
int main(void) {
    int status = 0;
    const char *msg = "Dilithium数字签名演示!";
    size_t msg_len = strlen(msg);
    
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    SignaturePacket signed_packet;
    
    printf("================= Dilithium 签名/验证 测试 =================\n");
    printf("原始消息: \"%s\"\n", msg);
    print_bytes("原始消息 (十六进制)", (const uint8_t *)msg, msg_len);

    // 1. 密钥生成
    if (generate_keypair(pk, sk) != 0) {
        fprintf(stderr, "密钥生成失败!\n");
        return -1;
    }
    
    // 2. 签名
    size_t signature_len = message_sign(sk, pk, (const uint8_t *)msg, msg_len, &signed_packet);
    if (signature_len == 0) {
        fprintf(stderr, "签名生成失败!\n");
        return -1;
    }
    
    // 3. 验证签名
    if (signature_verify(&signed_packet) != 0) {
        fprintf(stderr, "签名验证失败!\n");
        status = -1;
    }
    
    // 4. 测试篡改检测
    printf("\n===== 篡改检测测试 =====\n");
    tamper_test(&signed_packet);
    
    // 5. 打印技术参数
    print_algorithm_parameters(msg_len, signature_len);
    
    return status;
}
