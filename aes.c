/**
 * @file  aes_test_nodma.c
 * @brief AES IP Test Suite – Không dùng DMA, CPU polling
 *
 * v2 – Fixes:
 *   - Thay poll BUSY=0 bằng poll RXNE=1 per-word (tránh race condition
 *     BUSY chưa kịp set sau khi ghi word cuối vào TX FIFO)
 *   - Thêm poll TXEM=1 trước khi đọc RX (chắc chắn AES đã nhận hết input)
 *   - Verbose debug: in AES_STAT tại mỗi bước quan trọng
 *   - In giá trị thanh ghi sau khi ghi để phát hiện ghi không thành công
 *
 * Register map (base = 0x62000000):
 *   AES_CONF  0x0004 | AES_DMA  0x0008 | AES_INTE 0x000C
 *   AES_STAT  0x0010 | AES_SWRS 0x0044 | AES_ENAB 0x0048
 *   AES_DATA  0x10000 (TX write / RX read, FIFO-mapped)
 *   Key: K0LR=0x0014, K0RR=0x0018, K1LR=0x001C, K1RR=0x0020
 *        K2LR=0x0024, K2RR=0x0028, K3LR=0x002C, K3RR=0x0030
 *   IV:  IV0L=0x0034, IV0R=0x0038, IV1L=0x003C, IV1R=0x0040
 */

#include <stdint.h>
#include <stdio.h>

/* ===========================================================================
 * Register access
 * =========================================================================*/
#define REG32(addr)         (*((volatile uint32_t *)(uintptr_t)(addr)))
#define REG_WR32(a, v)      (REG32(a) = (uint32_t)(v))
#define REG_RD32(a)         (REG32(a))

/* ===========================================================================
 * AES Register Map
 * =========================================================================*/
#ifndef AES_BASE
#define AES_BASE            0x62000000UL
#endif

#define AES_CONF            (AES_BASE + 0x0004U)
#define AES_DMA             (AES_BASE + 0x0008U)
#define AES_INTE            (AES_BASE + 0x000CU)
#define AES_STAT            (AES_BASE + 0x0010U)
#define AES_K0LR            (AES_BASE + 0x0014U)
#define AES_K0RR            (AES_BASE + 0x0018U)
#define AES_K1LR            (AES_BASE + 0x001CU)
#define AES_K1RR            (AES_BASE + 0x0020U)
#define AES_K2LR            (AES_BASE + 0x0024U)
#define AES_K2RR            (AES_BASE + 0x0028U)
#define AES_K3LR            (AES_BASE + 0x002CU)
#define AES_K3RR            (AES_BASE + 0x0030U)
#define AES_IV0L            (AES_BASE + 0x0034U)
#define AES_IV0R            (AES_BASE + 0x0038U)
#define AES_IV1L            (AES_BASE + 0x003CU)
#define AES_IV1R            (AES_BASE + 0x0040U)
#define AES_SWRS            (AES_BASE + 0x0044U)
#define AES_ENAB            (AES_BASE + 0x0048U)
#define AES_DATA            (AES_BASE + 0x10000U)

/* ---------- AES_CONF bits ---------- */
#define CONF_KEY256         (0x0U << 8)
#define CONF_KEY192         (0x2U << 8)
#define CONF_KEY128         (0x3U << 8)
#define CONF_DTYPE_NONE     (0x0U << 6)
#define CONF_DTYPE_HW       (0x1U << 6)
#define CONF_DTYPE_BYTE     (0x2U << 6)
#define CONF_MODE_ECB       (0x0U << 3)
#define CONF_MODE_CBC       (0x1U << 3)
#define CONF_MODE_CTR       (0x2U << 3)
#define CONF_DIR_ENC        (0x0U << 2)
#define CONF_DIR_DEC        (0x1U << 2)

/* ---------- AES_STAT bits ---------- */
#define STAT_BUSY           (1U << 6)
#define STAT_RXFU           (1U << 5)
#define STAT_RXNE           (1U << 4)
#define STAT_TXNF           (1U << 3)
#define STAT_TXEM           (1U << 2)
#define STAT_RXUF           (1U << 1)
#define STAT_TXOF           (1U << 0)

/* ---------- AES_SWRS bits ---------- */
#define SWRS_RFR            (1U << 2)
#define SWRS_TFR            (1U << 1)
#define SWRS_SCR            (1U << 0)

/* ---------- AES_ENAB bits ---------- */
#define ENAB_EN             (1U << 0)

/* ===========================================================================
 * Error codes
 * =========================================================================*/
typedef enum {
    AES_OK           = 0,
    AES_ERR_TIMEOUT  = 1,
    AES_ERR_DATA     = 2,
    AES_ERR_STAT     = 3,
} aes_err_t;

#define AES_BLOCK_WORDS     4U
#define TIMEOUT             2000000U

/* ===========================================================================
 * Debug helper
 * =========================================================================*/
static void print_stat(const char *tag)
{
    uint32_t s = REG_RD32(AES_STAT);
    printf("  [STAT] %-32s = 0x%02X  BUSY=%u RXFU=%u RXNE=%u TXNF=%u TXEM=%u RXUF=%u TXOF=%u\n",
           tag, (unsigned)s,
           (unsigned)((s>>6)&1), (unsigned)((s>>5)&1),
           (unsigned)((s>>4)&1), (unsigned)((s>>3)&1),
           (unsigned)((s>>2)&1), (unsigned)((s>>1)&1),
           (unsigned)((s>>0)&1));
}

/* ===========================================================================
 * Polling helpers
 * =========================================================================*/
static aes_err_t wait_swrs_clear(uint32_t bits)
{
    uint32_t t = TIMEOUT;
    while (REG_RD32(AES_SWRS) & bits) {
        if (--t == 0) {
            printf("  [ERR] SWRS timeout bits=0x%X\n", (unsigned)bits);
            return AES_ERR_TIMEOUT;
        }
    }
    return AES_OK;
}

static aes_err_t wait_txnf(void)
{
    uint32_t t = TIMEOUT;
    while (!(REG_RD32(AES_STAT) & STAT_TXNF)) {
        if (--t == 0) {
            printf("  [ERR] wait_txnf timeout  STAT=0x%02X\n",
                   (unsigned)REG_RD32(AES_STAT));
            return AES_ERR_TIMEOUT;
        }
    }
    return AES_OK;
}

static aes_err_t wait_txem(void)
{
    uint32_t t = TIMEOUT;
    while (!(REG_RD32(AES_STAT) & STAT_TXEM)) {
        if (--t == 0) {
            printf("  [ERR] wait_txem timeout  STAT=0x%02X\n",
                   (unsigned)REG_RD32(AES_STAT));
            return AES_ERR_TIMEOUT;
        }
    }
    return AES_OK;
}

static aes_err_t wait_rxne(void)
{
    uint32_t t = TIMEOUT;
    while (!(REG_RD32(AES_STAT) & STAT_RXNE)) {
        if (--t == 0) {
            printf("  [ERR] wait_rxne timeout  STAT=0x%02X\n",
                   (unsigned)REG_RD32(AES_STAT));
            return AES_ERR_TIMEOUT;
        }
    }
    return AES_OK;
}

/* ===========================================================================
 * AES Engine Control
 * =========================================================================*/
static aes_err_t aes_reset(void)
{
    REG_WR32(AES_ENAB, 0U);
    REG_WR32(AES_SWRS, SWRS_SCR);
    return wait_swrs_clear(SWRS_SCR);
}

/**
 * @brief Ghi CONF → load key → ENAB=1
 *        CONF set key_size TRƯỚC khi nạp key (IP cần biết bao nhiêu word).
 *        IV (nếu cần) phải được ghi TRƯỚC khi gọi hàm này vì IV cần EN=0.
 */
static void aes_setup128(const uint32_t *key, uint32_t conf_val)
{
    REG_WR32(AES_INTE, 0U);
    REG_WR32(AES_DMA,  0U);
    REG_WR32(AES_CONF, conf_val);
    printf("  [SETUP] CONF=0x%08X  readback=0x%08X\n",
           (unsigned)conf_val, (unsigned)REG_RD32(AES_CONF));

    REG_WR32(AES_K0LR, key[0]);
    REG_WR32(AES_K0RR, key[1]);
    REG_WR32(AES_K1LR, key[2]);
    REG_WR32(AES_K1RR, key[3]);
    printf("  [SETUP] Key: %08X %08X %08X %08X\n",
           (unsigned)REG_RD32(AES_K0LR), (unsigned)REG_RD32(AES_K0RR),
           (unsigned)REG_RD32(AES_K1LR), (unsigned)REG_RD32(AES_K1RR));

    REG_WR32(AES_ENAB, ENAB_EN);
    printf("  [SETUP] ENAB=0x%08X\n", (unsigned)REG_RD32(AES_ENAB));
    print_stat("after enable");
}

static void aes_setup256(const uint32_t *key, uint32_t conf_val)
{
    REG_WR32(AES_INTE, 0U);
    REG_WR32(AES_DMA,  0U);
    REG_WR32(AES_CONF, conf_val);
    printf("  [SETUP] CONF=0x%08X  readback=0x%08X\n",
           (unsigned)conf_val, (unsigned)REG_RD32(AES_CONF));

    REG_WR32(AES_K0LR, key[0]); REG_WR32(AES_K0RR, key[1]);
    REG_WR32(AES_K1LR, key[2]); REG_WR32(AES_K1RR, key[3]);
    REG_WR32(AES_K2LR, key[4]); REG_WR32(AES_K2RR, key[5]);
    REG_WR32(AES_K3LR, key[6]); REG_WR32(AES_K3RR, key[7]);

    REG_WR32(AES_ENAB, ENAB_EN);
    printf("  [SETUP] ENAB=0x%08X\n", (unsigned)REG_RD32(AES_ENAB));
    print_stat("after enable");
}

/* IV ghi khi EN=0 (trước khi gọi aes_setup) */
static void aes_load_iv(const uint32_t *iv)
{
    REG_WR32(AES_IV0L, iv[0]);
    REG_WR32(AES_IV0R, iv[1]);
    REG_WR32(AES_IV1L, iv[2]);
    REG_WR32(AES_IV1R, iv[3]);
    printf("  [SETUP] IV: %08X %08X %08X %08X\n",
           (unsigned)REG_RD32(AES_IV0L), (unsigned)REG_RD32(AES_IV0R),
           (unsigned)REG_RD32(AES_IV1L), (unsigned)REG_RD32(AES_IV1R));
}

/**
 * @brief Xử lý 1 block 128-bit (CPU polling, không dùng BUSY).
 *
 * Flow:
 *   1. Push 4 words: poll TXNF trước mỗi lần ghi
 *   2. Poll TXEM=1  → AES engine đã nhận hết input
 *   3. Pop 4 words : poll RXNE trước mỗi lần đọc
 *
 * Không dùng BUSY vì: sau khi ghi word thứ 4, engine cần vài clock
 * mới assert BUSY. Poll BUSY=0 ngay lập tức sẽ trả về "xong" sai.
 * Poll RXNE=1 là điều kiện đủ và an toàn hơn.
 */
static aes_err_t aes_process_block(const uint32_t *in, uint32_t *out)
{
    uint32_t i;
    aes_err_t r;

    for (i = 0; i < AES_BLOCK_WORDS; i++) {
        r = wait_txnf();
        if (r) return r;
        REG_WR32(AES_DATA, in[i]);
        printf("  [TX] word[%u]=0x%08X  ", (unsigned)i, (unsigned)in[i]);
        print_stat("");
    }

    r = wait_txem();
    if (r) return r;
    print_stat("TXEM done");

    for (i = 0; i < AES_BLOCK_WORDS; i++) {
        r = wait_rxne();
        if (r) return r;
        out[i] = REG_RD32(AES_DATA);
        printf("  [RX] word[%u]=0x%08X  ", (unsigned)i, (unsigned)out[i]);
        print_stat("");
    }

    {
        uint32_t s = REG_RD32(AES_STAT);
        if (s & (STAT_RXUF | STAT_TXOF)) {
            printf("  [WARN] sticky errors RXUF=%u TXOF=%u – clearing\n",
                   (unsigned)((s>>1)&1), (unsigned)(s&1));
            REG_WR32(AES_STAT, s & (STAT_RXUF | STAT_TXOF));
        }
    }
    return AES_OK;
}

/* ===========================================================================
 * Verify helper
 * =========================================================================*/
static aes_err_t verify_block(const uint32_t *got, const uint32_t *exp,
                               const char *label)
{
    uint32_t i; int ok = 1;
    for (i = 0; i < AES_BLOCK_WORDS; i++)
        if (got[i] != exp[i]) { ok = 0; break; }

    printf("  Got     : %08X %08X %08X %08X\n",
           (unsigned)got[0],(unsigned)got[1],(unsigned)got[2],(unsigned)got[3]);
    printf("  Expected: %08X %08X %08X %08X\n",
           (unsigned)exp[0],(unsigned)exp[1],(unsigned)exp[2],(unsigned)exp[3]);

    if (ok) { printf("  [PASS] %s\n", label); return AES_OK; }
    for (i = 0; i < AES_BLOCK_WORDS; i++)
        if (got[i] != exp[i])
            printf("  [FAIL] %s word[%u]: got=0x%08X exp=0x%08X\n",
                   label,(unsigned)i,(unsigned)got[i],(unsigned)exp[i]);
    return AES_ERR_DATA;
}

/* ===========================================================================
 * TEST CASES
 * =========================================================================*/

/* TEST 01 – ECB-128 Encrypt (NIST FIPS-197 App.B)
 *   Key: 2B7E1516 28AED2A6 ABF71588 09CF4F3C
 *   PT : 3243F6A8 885A308D 313198A2 E0370734
 *   CT : 3925841D 02DC09FB DC118597 196A0B32 */
static aes_err_t test01_ecb128_enc(void)
{
    printf("\n=== TEST 01: ECB-128 Encrypt ===\n");
    static const uint32_t key[4]={0x2B7E1516U,0x28AED2A6U,0xABF71588U,0x09CF4F3CU};
    static const uint32_t pt[4] ={0x3243F6A8U,0x885A308DU,0x313198A2U,0xE0370734U};
    static const uint32_t exp[4]={0x3925841DU,0x02DC09FBU,0xDC118597U,0x196A0B32U};
    uint32_t ct[4]; aes_err_t r;
    r = aes_reset(); if(r) return r;
    aes_setup128(key, CONF_MODE_ECB|CONF_DIR_ENC|CONF_KEY128|CONF_DTYPE_NONE);
    r = aes_process_block(pt, ct); if(r) return r;
    REG_WR32(AES_ENAB, 0U);
    return verify_block(ct, exp, "ECB-128 Encrypt");
}

/* TEST 02 – ECB-128 Decrypt */
static aes_err_t test02_ecb128_dec(void)
{
    printf("\n=== TEST 02: ECB-128 Decrypt ===\n");
    static const uint32_t key[4]={0x2B7E1516U,0x28AED2A6U,0xABF71588U,0x09CF4F3CU};
    static const uint32_t ct[4] ={0x3925841DU,0x02DC09FBU,0xDC118597U,0x196A0B32U};
    static const uint32_t exp[4]={0x3243F6A8U,0x885A308DU,0x313198A2U,0xE0370734U};
    uint32_t pt[4]; aes_err_t r;
    r = aes_reset(); if(r) return r;
    aes_setup128(key, CONF_MODE_ECB|CONF_DIR_DEC|CONF_KEY128|CONF_DTYPE_NONE);
    r = aes_process_block(ct, pt); if(r) return r;
    REG_WR32(AES_ENAB, 0U);
    return verify_block(pt, exp, "ECB-128 Decrypt");
}

/* TEST 03 – CBC-128 Encrypt (NIST SP 800-38A F.2.1 block-1)
 *   IV : 00010203 04050607 08090A0B 0C0D0E0F
 *   PT : 6BC1BEE2 2E409F96 E93D7E11 7393172A
 *   CT : 7649ABAC 8119B246 CEE98E9B 12E9197D */
static aes_err_t test03_cbc128_enc(void)
{
    printf("\n=== TEST 03: CBC-128 Encrypt ===\n");
    static const uint32_t key[4]={0x2B7E1516U,0x28AED2A6U,0xABF71588U,0x09CF4F3CU};
    static const uint32_t iv[4] ={0x00010203U,0x04050607U,0x08090A0BU,0x0C0D0E0FU};
    static const uint32_t pt[4] ={0x6BC1BEE2U,0x2E409F96U,0xE93D7E11U,0x7393172AU};
    static const uint32_t exp[4]={0x7649ABACU,0x8119B246U,0xCEE98E9BU,0x12E9197DU};
    uint32_t ct[4]; aes_err_t r;
    r = aes_reset(); if(r) return r;
    aes_load_iv(iv);   /* IV ghi khi EN=0, trước setup */
    aes_setup128(key, CONF_MODE_CBC|CONF_DIR_ENC|CONF_KEY128|CONF_DTYPE_NONE);
    r = aes_process_block(pt, ct); if(r) return r;
    REG_WR32(AES_ENAB, 0U);
    return verify_block(ct, exp, "CBC-128 Encrypt");
}

/* TEST 04 – CBC-128 Decrypt */
static aes_err_t test04_cbc128_dec(void)
{
    printf("\n=== TEST 04: CBC-128 Decrypt ===\n");
    static const uint32_t key[4]={0x2B7E1516U,0x28AED2A6U,0xABF71588U,0x09CF4F3CU};
    static const uint32_t iv[4] ={0x00010203U,0x04050607U,0x08090A0BU,0x0C0D0E0FU};
    static const uint32_t ct[4] ={0x7649ABACU,0x8119B246U,0xCEE98E9BU,0x12E9197DU};
    static const uint32_t exp[4]={0x6BC1BEE2U,0x2E409F96U,0xE93D7E11U,0x7393172AU};
    uint32_t pt[4]; aes_err_t r;
    r = aes_reset(); if(r) return r;
    aes_load_iv(iv);
    aes_setup128(key, CONF_MODE_CBC|CONF_DIR_DEC|CONF_KEY128|CONF_DTYPE_NONE);
    r = aes_process_block(ct, pt); if(r) return r;
    REG_WR32(AES_ENAB, 0U);
    return verify_block(pt, exp, "CBC-128 Decrypt");
}

/* TEST 05 – CTR-128 Encrypt (NIST SP 800-38A F.5.1 block-1)
 *   IV/CTR: F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF
 *   PT    : 6BC1BEE2 2E409F96 E93D7E11 7393172A
 *   CT    : 874D6191 B620E326 1BEF6864 990DB6CE */
static aes_err_t test05_ctr128_enc(void)
{
    printf("\n=== TEST 05: CTR-128 Encrypt ===\n");
    static const uint32_t key[4]={0x2B7E1516U,0x28AED2A6U,0xABF71588U,0x09CF4F3CU};
    static const uint32_t iv[4] ={0xF0F1F2F3U,0xF4F5F6F7U,0xF8F9FAFBU,0xFCFDFEFFU};
    static const uint32_t pt[4] ={0x6BC1BEE2U,0x2E409F96U,0xE93D7E11U,0x7393172AU};
    static const uint32_t exp[4]={0x874D6191U,0xB620E326U,0x1BEF6864U,0x990DB6CEU};
    uint32_t ct[4]; aes_err_t r;
    r = aes_reset(); if(r) return r;
    aes_load_iv(iv);
    aes_setup128(key, CONF_MODE_CTR|CONF_DIR_ENC|CONF_KEY128|CONF_DTYPE_NONE);
    r = aes_process_block(pt, ct); if(r) return r;
    REG_WR32(AES_ENAB, 0U);
    return verify_block(ct, exp, "CTR-128 Encrypt");
}

/* TEST 06 – CTR-128 Decrypt (CTR symmetric: encrypt ciphertext = plaintext) */
static aes_err_t test06_ctr128_dec(void)
{
    printf("\n=== TEST 06: CTR-128 Decrypt ===\n");
    static const uint32_t key[4]={0x2B7E1516U,0x28AED2A6U,0xABF71588U,0x09CF4F3CU};
    static const uint32_t iv[4] ={0xF0F1F2F3U,0xF4F5F6F7U,0xF8F9FAFBU,0xFCFDFEFFU};
    static const uint32_t ct[4] ={0x874D6191U,0xB620E326U,0x1BEF6864U,0x990DB6CEU};
    static const uint32_t exp[4]={0x6BC1BEE2U,0x2E409F96U,0xE93D7E11U,0x7393172AU};
    uint32_t pt[4]; aes_err_t r;
    r = aes_reset(); if(r) return r;
    aes_load_iv(iv);
    aes_setup128(key, CONF_MODE_CTR|CONF_DIR_ENC|CONF_KEY128|CONF_DTYPE_NONE);
    r = aes_process_block(ct, pt); if(r) return r;
    REG_WR32(AES_ENAB, 0U);
    return verify_block(pt, exp, "CTR-128 Decrypt");
}

/* TEST 07 – ECB-256 Encrypt (NIST FIPS-197, 256-bit key)
 *   PT : 00112233 44556677 8899AABB CCDDEEFF
 *   CT : 8EA2B7CA 516745BF EAFC4990 4B496089 */
static aes_err_t test07_ecb256_enc(void)
{
    printf("\n=== TEST 07: ECB-256 Encrypt ===\n");
    static const uint32_t key[8]={
        0x00010203U,0x04050607U,0x08090A0BU,0x0C0D0E0FU,
        0x10111213U,0x14151617U,0x18191A1BU,0x1C1D1E1FU};
    static const uint32_t pt[4] ={0x00112233U,0x44556677U,0x8899AABBU,0xCCDDEEFFU};
    static const uint32_t exp[4]={0x8EA2B7CAU,0x516745BFU,0xEAFC4990U,0x4B496089U};
    uint32_t ct[4]; aes_err_t r;
    r = aes_reset(); if(r) return r;
    aes_setup256(key, CONF_MODE_ECB|CONF_DIR_ENC|CONF_KEY256|CONF_DTYPE_NONE);
    r = aes_process_block(pt, ct); if(r) return r;
    REG_WR32(AES_ENAB, 0U);
    return verify_block(ct, exp, "ECB-256 Encrypt");
}

/* TEST 08 – TX FIFO Reset giữa chừng + Recovery */
static aes_err_t test08_partial_reset(void)
{
    printf("\n=== TEST 08: Partial TX Reset + Recovery ===\n");
    static const uint32_t key[4]={0x2B7E1516U,0x28AED2A6U,0xABF71588U,0x09CF4F3CU};
    static const uint32_t pt[4] ={0x3243F6A8U,0x885A308DU,0x313198A2U,0xE0370734U};
    static const uint32_t exp[4]={0x3925841DU,0x02DC09FBU,0xDC118597U,0x196A0B32U};
    uint32_t ct[4]; aes_err_t r; uint32_t s;

    r = aes_reset(); if(r) return r;
    aes_setup128(key, CONF_MODE_ECB|CONF_DIR_ENC|CONF_KEY128|CONF_DTYPE_NONE);

    printf("  Pushing 2 garbage words...\n");
    r = wait_txnf(); if(r) return r; REG_WR32(AES_DATA, 0xDEADBEEFU);
    r = wait_txnf(); if(r) return r; REG_WR32(AES_DATA, 0xCAFEBABEU);
    print_stat("after 2 garbage words");

    printf("  Resetting TX+RX FIFOs (EN must be 0)...\n");
    REG_WR32(AES_ENAB, 0U);
    REG_WR32(AES_SWRS, SWRS_TFR | SWRS_RFR);
    r = wait_swrs_clear(SWRS_TFR | SWRS_RFR); if(r) return r;
    print_stat("after FIFO reset");

    s = REG_RD32(AES_STAT);
    if (!(s & STAT_TXEM)) { printf("  [FAIL] TX not empty after reset\n"); return AES_ERR_STAT; }
    if (s & STAT_RXNE)    { printf("  [FAIL] RX not empty after reset\n"); return AES_ERR_STAT; }

    printf("  Re-enabling and processing valid block...\n");
    aes_setup128(key, CONF_MODE_ECB|CONF_DIR_ENC|CONF_KEY128|CONF_DTYPE_NONE);
    r = aes_process_block(pt, ct); if(r) return r;
    REG_WR32(AES_ENAB, 0U);
    return verify_block(ct, exp, "Partial Reset + Recovery");
}

/* ===========================================================================
 * MAIN
 * =========================================================================*/
int main(void)
{
    typedef struct { const char *name; aes_err_t (*fn)(void); } test_t;
    static const test_t tests[] = {
        { "01 ECB-128 Encrypt",          test01_ecb128_enc    },
        { "02 ECB-128 Decrypt",          test02_ecb128_dec    },
        { "03 CBC-128 Encrypt",          test03_cbc128_enc    },
        { "04 CBC-128 Decrypt",          test04_cbc128_dec    },
        { "05 CTR-128 Encrypt",          test05_ctr128_enc    },
        { "06 CTR-128 Decrypt",          test06_ctr128_dec    },
        { "07 ECB-256 Encrypt",          test07_ecb256_enc    },
        { "08 Partial Reset + Recovery", test08_partial_reset },
    };
    const uint32_t ntests = (uint32_t)(sizeof(tests)/sizeof(tests[0]));
    uint32_t pass = 0, fail = 0, i;

    printf("============================================================\n");
    printf("  AES No-DMA Test Suite  v2\n");
    printf("  AES_BASE = 0x%08X\n", (unsigned)AES_BASE);
    printf("============================================================\n");

    for (i = 0; i < ntests; i++) {
        aes_err_t rc = tests[i].fn();
        if (rc == AES_OK) {
            printf("[RESULT] Test %s --> PASS\n\n", tests[i].name); pass++;
        } else {
            printf("[RESULT] Test %s --> FAIL (err=%d)\n\n", tests[i].name, (int)rc); fail++;
        }
    }

    printf("============================================================\n");
    printf("  TOTAL %u:  PASS=%u  FAIL=%u\n", (unsigned)ntests, (unsigned)pass, (unsigned)fail);
    printf("============================================================\n");
    return (fail == 0) ? 0 : 1;
}
