/**
 * @file  aes_test_nodma.c
 * @brief AES IP Test Suite – Không dùng DMA, CPU đọc/ghi trực tiếp FIFO
 *
 * Register map từ tài liệu (base = 0x62000000):
 *   AES_CONF   0x0004   – mode, key size, dir, data type
 *   AES_DMA    0x0008   – DMA enable (để 0 trong test này)
 *   AES_INTE   0x000C   – interrupt enable (mask hết, dùng polling)
 *   AES_STAT   0x0010   – status: BUSY, RXFU, RXNE, TXNF, TXEM, errors
 *   AES_SWRS   0x0044   – software reset (core / TX FIFO / RX FIFO)
 *   AES_ENAB   0x0048   – global enable
 *   AES_K0LR   0x0014 .. AES_K3RR 0x0030  – 256-bit key
 *   AES_IV0L   0x0034 .. AES_IV1R 0x0040  – 128-bit IV
 *   AES_DATA   0x10000  – data FIFO (TX write / RX read, same address range)
 *
 * Test list:
 *   01 – ECB-128 encrypt  (NIST FIPS-197 Appendix B)
 *   02 – ECB-128 decrypt  (inverse của test 01)
 *   03 – CBC-128 encrypt  (NIST SP 800-38A F.2.1)
 *   04 – CBC-128 decrypt  (NIST SP 800-38A F.2.2)
 *   05 – CTR-128 encrypt  (NIST SP 800-38A F.5.1)
 *   06 – CTR-128 decrypt  (NIST SP 800-38A F.5.2, same as encrypt)
 *   07 – ECB-256 encrypt  (NIST FIPS-197 Appendix B extended key)
 *   08 – Reset giữa chừng (ghi nửa block rồi reset, verify FIFO trống)
 *
 * Ghi chú:
 *   - AES_DATA là FIFO-mapped: đọc/ghi ở BẤT KỲ địa chỉ trong
 *     range [base+0x10000 .. base+0x1FFFF] đều push/pop FIFO.
 *   - CPU push word vào TX FIFO, AES engine tự xử lý khi đủ block,
 *     CPU đợi BUSY=0 rồi pop RX FIFO.
 *   - Không enable AES_DMA (bit TXEN/RXEN = 0).
 *   - Không enable interrupt (AES_INTE = 0), dùng polling AES_STAT.
 */

#include <stdint.h>
#include <stdio.h>

/* ===========================================================================
 * Register access primitives
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
/* [9:8] key_size: 0x=256, 10=192, 11=128 */
#define CONF_KEY256         (0x0U << 8)
#define CONF_KEY192         (0x2U << 8)
#define CONF_KEY128         (0x3U << 8)
/* [7:6] data_type: 00=no swap, 01=16-bit, 1x=8-bit */
#define CONF_DTYPE_NONE     (0x0U << 6)
#define CONF_DTYPE_HW       (0x1U << 6)
#define CONF_DTYPE_BYTE     (0x2U << 6)
/* [5:3] mode */
#define CONF_MODE_ECB       (0x0U << 3)
#define CONF_MODE_CBC       (0x1U << 3)
#define CONF_MODE_CTR       (0x2U << 3)
#define CONF_MODE_GCM       (0x3U << 3)
#define CONF_MODE_XTS       (0x4U << 3)
#define CONF_MODE_CCM       (0x5U << 3)
#define CONF_MODE_CFB       (0x6U << 3)
#define CONF_MODE_OFB       (0x7U << 3)
/* [2] dir */
#define CONF_DIR_ENC        (0x0U << 2)
#define CONF_DIR_DEC        (0x1U << 2)

/* ---------- AES_STAT bits ---------- */
#define STAT_BUSY           (1U << 6)
#define STAT_RXFU           (1U << 5)   /* RX FIFO full              */
#define STAT_RXNE           (1U << 4)   /* RX FIFO not empty         */
#define STAT_TXNF           (1U << 3)   /* TX FIFO not full          */
#define STAT_TXEM           (1U << 2)   /* TX FIFO empty             */
#define STAT_RXUF           (1U << 1)   /* RX underflow  (R/W1C)     */
#define STAT_TXOF           (1U << 0)   /* TX overflow   (R/W1C)     */

/* ---------- AES_SWRS bits ---------- */
#define SWRS_RFR            (1U << 2)   /* RX FIFO reset (auto-clear)*/
#define SWRS_TFR            (1U << 1)   /* TX FIFO reset (auto-clear)*/
#define SWRS_SCR            (1U << 0)   /* Core + both FIFOs reset   */

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

/* ===========================================================================
 * Constants
 * =========================================================================*/
#define AES_BLOCK_WORDS     4U          /* 128-bit block = 4 x 32-bit words */
#define TIMEOUT             2000000U

/* ===========================================================================
 * Low-level helpers
 * =========================================================================*/

/** Đợi SWRS.SCR / SWRS.TFR / SWRS.RFR về 0 (auto-clear sau reset) */
static aes_err_t aes_wait_swrs_clear(uint32_t bits)
{
    uint32_t t = TIMEOUT;
    while (REG_RD32(AES_SWRS) & bits) {
        if (--t == 0) {
            printf("  [ERR] AES_SWRS timeout (bits=0x%X)\n", (unsigned)bits);
            return AES_ERR_TIMEOUT;
        }
    }
    return AES_OK;
}

/** Đợi AES engine xong xử lý block (BUSY → 0) */
static aes_err_t aes_wait_idle(void)
{
    uint32_t t = TIMEOUT;
    while (REG_RD32(AES_STAT) & STAT_BUSY) {
        if (--t == 0) {
            printf("  [ERR] AES BUSY timeout  STAT=0x%08X\n",
                   (unsigned)REG_RD32(AES_STAT));
            return AES_ERR_TIMEOUT;
        }
    }
    return AES_OK;
}

/** Đợi TX FIFO not full (ít nhất 1 slot trống để ghi) */
static aes_err_t aes_wait_txnf(void)
{
    uint32_t t = TIMEOUT;
    while (!(REG_RD32(AES_STAT) & STAT_TXNF)) {
        if (--t == 0) {
            printf("  [ERR] AES TX FIFO full timeout\n");
            return AES_ERR_TIMEOUT;
        }
    }
    return AES_OK;
}

/** Đợi RX FIFO not empty (có ít nhất 1 word để đọc) */
static aes_err_t aes_wait_rxne(void)
{
    uint32_t t = TIMEOUT;
    while (!(REG_RD32(AES_STAT) & STAT_RXNE)) {
        if (--t == 0) {
            printf("  [ERR] AES RX FIFO empty timeout\n");
            return AES_ERR_TIMEOUT;
        }
    }
    return AES_OK;
}

/* ===========================================================================
 * AES Engine Control
 * =========================================================================*/

/**
 * @brief Full reset + disable AES.
 *        Gọi trước mỗi test để đảm bảo trạng thái sạch.
 *        Note: SWRS chỉ có hiệu lực khi ENAB.EN = 0.
 */
static aes_err_t aes_reset(void)
{
    REG_WR32(AES_ENAB, 0U);                  /* disable trước        */
    REG_WR32(AES_SWRS, SWRS_SCR);            /* reset core + FIFOs   */
    return aes_wait_swrs_clear(SWRS_SCR);
}

/**
 * @brief Load key 128-bit (4 words).
 *        key[0] = most-significant word → K0LR
 */
static void aes_load_key128(const uint32_t *key)
{
    REG_WR32(AES_K0LR, key[0]);
    REG_WR32(AES_K0RR, key[1]);
    REG_WR32(AES_K1LR, key[2]);
    REG_WR32(AES_K1RR, key[3]);
}

/**
 * @brief Load key 256-bit (8 words).
 *        key[0..3] = K0LR..K1RR (high 128-bit)
 *        key[4..7] = K2LR..K3RR (low  128-bit)
 */
static void aes_load_key256(const uint32_t *key)
{
    REG_WR32(AES_K0LR, key[0]);
    REG_WR32(AES_K0RR, key[1]);
    REG_WR32(AES_K1LR, key[2]);
    REG_WR32(AES_K1RR, key[3]);
    REG_WR32(AES_K2LR, key[4]);
    REG_WR32(AES_K2RR, key[5]);
    REG_WR32(AES_K3LR, key[6]);
    REG_WR32(AES_K3RR, key[7]);
}

/**
 * @brief Load IV 128-bit (4 words).
 *        iv[0] → IV0L, iv[1] → IV0R, iv[2] → IV1L, iv[3] → IV1R
 */
static void aes_load_iv(const uint32_t *iv)
{
    REG_WR32(AES_IV0L, iv[0]);
    REG_WR32(AES_IV0R, iv[1]);
    REG_WR32(AES_IV1L, iv[2]);
    REG_WR32(AES_IV1R, iv[3]);
}

/**
 * @brief Cấu hình và enable AES engine.
 *        Phải gọi TRƯỚC khi ghi data.
 *        DMA disable (AES_DMA = 0), interrupt mask hết (AES_INTE = 0).
 */
static void aes_configure(uint32_t conf_val)
{
    REG_WR32(AES_INTE, 0U);         /* mask tất cả interrupt        */
    REG_WR32(AES_DMA,  0U);         /* không dùng DMA               */
    REG_WR32(AES_CONF, conf_val);
    REG_WR32(AES_ENAB, ENAB_EN);    /* enable AES                   */
}

/**
 * @brief Xử lý 1 block 128-bit: push 4 words vào TX, đợi BUSY,
 *        pop 4 words từ RX.
 * @param in   Con trỏ 4 words input
 * @param out  Con trỏ 4 words output
 */
static aes_err_t aes_process_block(const uint32_t *in, uint32_t *out)
{
    uint32_t i;
    aes_err_t r;

    /* Push 4 words vào TX FIFO */
    for (i = 0; i < AES_BLOCK_WORDS; i++) {
        r = aes_wait_txnf();
        if (r) return r;
        REG_WR32(AES_DATA, in[i]);
    }

    /* Đợi AES engine xử lý xong block */
    r = aes_wait_idle();
    if (r) return r;

    /* Kiểm tra RX FIFO có data */
    if (!(REG_RD32(AES_STAT) & STAT_RXNE)) {
        printf("  [ERR] RX FIFO empty after block done  STAT=0x%08X\n",
               (unsigned)REG_RD32(AES_STAT));
        return AES_ERR_STAT;
    }

    /* Pop 4 words từ RX FIFO */
    for (i = 0; i < AES_BLOCK_WORDS; i++) {
        r = aes_wait_rxne();
        if (r) return r;
        out[i] = REG_RD32(AES_DATA);
    }

    return AES_OK;
}

/* ===========================================================================
 * Verify helper
 * =========================================================================*/
static aes_err_t verify_block(const uint32_t *got,
                               const uint32_t *exp,
                               const char     *label)
{
    uint32_t i;
    int ok = 1;
    for (i = 0; i < AES_BLOCK_WORDS; i++) {
        if (got[i] != exp[i]) { ok = 0; break; }
    }

    printf("  Got      : %08X %08X %08X %08X\n",
           (unsigned)got[0], (unsigned)got[1],
           (unsigned)got[2], (unsigned)got[3]);
    printf("  Expected : %08X %08X %08X %08X\n",
           (unsigned)exp[0], (unsigned)exp[1],
           (unsigned)exp[2], (unsigned)exp[3]);

    if (ok) {
        printf("  [PASS] %s\n", label);
        return AES_OK;
    }
    for (i = 0; i < AES_BLOCK_WORDS; i++) {
        if (got[i] != exp[i])
            printf("  [FAIL] %s: word[%u] got=0x%08X exp=0x%08X\n",
                   label, (unsigned)i, (unsigned)got[i], (unsigned)exp[i]);
    }
    return AES_ERR_DATA;
}

/* ===========================================================================
 * TEST 01 – ECB-128 Encrypt
 *
 * NIST FIPS-197 Appendix B:
 *   Key       : 2B7E1516 28AED2A6 ABF71588 09CF4F3C
 *   Plaintext : 3243F6A8 885A308D 313198A2 E0370734
 *   Cipher    : 3925841D 02DC09FB DC118597 196A0B32
 * =========================================================================*/
static aes_err_t test01_ecb128_enc(void)
{
    printf("\n=== TEST 01: ECB-128 Encrypt (NIST FIPS-197 App.B) ===\n");

    static const uint32_t key[4] = {
        0x2B7E1516U, 0x28AED2A6U, 0xABF71588U, 0x09CF4F3CU
    };
    static const uint32_t plain[4] = {
        0x3243F6A8U, 0x885A308DU, 0x313198A2U, 0xE0370734U
    };
    static const uint32_t expected[4] = {
        0x3925841DU, 0x02DC09FBU, 0xDC118597U, 0x196A0B32U
    };
    uint32_t cipher[4];
    aes_err_t r;

    r = aes_reset();                                   if (r) return r;
    aes_load_key128(key);
    aes_configure(CONF_MODE_ECB | CONF_DIR_ENC | CONF_KEY128 | CONF_DTYPE_NONE);

    printf("  Plaintext: %08X %08X %08X %08X\n",
           (unsigned)plain[0], (unsigned)plain[1],
           (unsigned)plain[2], (unsigned)plain[3]);

    r = aes_process_block(plain, cipher);              if (r) return r;

    REG_WR32(AES_ENAB, 0U);
    return verify_block(cipher, expected, "ECB-128 Encrypt");
}

/* ===========================================================================
 * TEST 02 – ECB-128 Decrypt  (inverse của test 01)
 * =========================================================================*/
static aes_err_t test02_ecb128_dec(void)
{
    printf("\n=== TEST 02: ECB-128 Decrypt ===\n");

    static const uint32_t key[4] = {
        0x2B7E1516U, 0x28AED2A6U, 0xABF71588U, 0x09CF4F3CU
    };
    /* Input là ciphertext từ test 01 */
    static const uint32_t cipher[4] = {
        0x3925841DU, 0x02DC09FBU, 0xDC118597U, 0x196A0B32U
    };
    static const uint32_t expected[4] = {
        0x3243F6A8U, 0x885A308DU, 0x313198A2U, 0xE0370734U
    };
    uint32_t plain[4];
    aes_err_t r;

    r = aes_reset();                                   if (r) return r;
    aes_load_key128(key);
    aes_configure(CONF_MODE_ECB | CONF_DIR_DEC | CONF_KEY128 | CONF_DTYPE_NONE);

    printf("  Ciphertext: %08X %08X %08X %08X\n",
           (unsigned)cipher[0], (unsigned)cipher[1],
           (unsigned)cipher[2], (unsigned)cipher[3]);

    r = aes_process_block(cipher, plain);              if (r) return r;

    REG_WR32(AES_ENAB, 0U);
    return verify_block(plain, expected, "ECB-128 Decrypt");
}

/* ===========================================================================
 * TEST 03 – CBC-128 Encrypt  (NIST SP 800-38A F.2.1, block 1 only)
 *
 *   Key : 2B7E1516 28AED2A6 ABF71588 09CF4F3C
 *   IV  : 00010203 04050607 08090A0B 0C0D0E0F
 *   PT  : 6BC1BEE2 2E409F96 E93D7E11 7393172A
 *   CT  : 7649ABAC 8119B246 CEE98E9B 12E9197D
 * =========================================================================*/
static aes_err_t test03_cbc128_enc(void)
{
    printf("\n=== TEST 03: CBC-128 Encrypt (NIST SP 800-38A F.2.1 block-1) ===\n");

    static const uint32_t key[4] = {
        0x2B7E1516U, 0x28AED2A6U, 0xABF71588U, 0x09CF4F3CU
    };
    static const uint32_t iv[4] = {
        0x00010203U, 0x04050607U, 0x08090A0BU, 0x0C0D0E0FU
    };
    static const uint32_t plain[4] = {
        0x6BC1BEE2U, 0x2E409F96U, 0xE93D7E11U, 0x7393172AU
    };
    static const uint32_t expected[4] = {
        0x7649ABACU, 0x8119B246U, 0xCEE98E9BU, 0x12E9197DU
    };
    uint32_t cipher[4];
    aes_err_t r;

    r = aes_reset();                                   if (r) return r;
    aes_load_key128(key);
    aes_load_iv(iv);
    aes_configure(CONF_MODE_CBC | CONF_DIR_ENC | CONF_KEY128 | CONF_DTYPE_NONE);

    printf("  IV       : %08X %08X %08X %08X\n",
           (unsigned)iv[0], (unsigned)iv[1],
           (unsigned)iv[2], (unsigned)iv[3]);
    printf("  Plaintext: %08X %08X %08X %08X\n",
           (unsigned)plain[0], (unsigned)plain[1],
           (unsigned)plain[2], (unsigned)plain[3]);

    r = aes_process_block(plain, cipher);              if (r) return r;

    REG_WR32(AES_ENAB, 0U);
    return verify_block(cipher, expected, "CBC-128 Encrypt");
}

/* ===========================================================================
 * TEST 04 – CBC-128 Decrypt  (NIST SP 800-38A F.2.2, block 1)
 * =========================================================================*/
static aes_err_t test04_cbc128_dec(void)
{
    printf("\n=== TEST 04: CBC-128 Decrypt (NIST SP 800-38A F.2.2 block-1) ===\n");

    static const uint32_t key[4] = {
        0x2B7E1516U, 0x28AED2A6U, 0xABF71588U, 0x09CF4F3CU
    };
    static const uint32_t iv[4] = {
        0x00010203U, 0x04050607U, 0x08090A0BU, 0x0C0D0E0FU
    };
    static const uint32_t cipher[4] = {
        0x7649ABACU, 0x8119B246U, 0xCEE98E9BU, 0x12E9197DU
    };
    static const uint32_t expected[4] = {
        0x6BC1BEE2U, 0x2E409F96U, 0xE93D7E11U, 0x7393172AU
    };
    uint32_t plain[4];
    aes_err_t r;

    r = aes_reset();                                   if (r) return r;
    aes_load_key128(key);
    aes_load_iv(iv);
    aes_configure(CONF_MODE_CBC | CONF_DIR_DEC | CONF_KEY128 | CONF_DTYPE_NONE);

    printf("  Ciphertext: %08X %08X %08X %08X\n",
           (unsigned)cipher[0], (unsigned)cipher[1],
           (unsigned)cipher[2], (unsigned)cipher[3]);

    r = aes_process_block(cipher, plain);              if (r) return r;

    REG_WR32(AES_ENAB, 0U);
    return verify_block(plain, expected, "CBC-128 Decrypt");
}

/* ===========================================================================
 * TEST 05 – CTR-128 Encrypt  (NIST SP 800-38A F.5.1, block 1)
 *
 *   Key    : 2B7E1516 28AED2A6 ABF71588 09CF4F3C
 *   CTR/IV : F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF
 *   PT     : 6BC1BEE2 2E409F96 E93D7E11 7393172A
 *   CT     : 874D6191 B620E326 1BEF6864 990DB6CE
 * =========================================================================*/
static aes_err_t test05_ctr128_enc(void)
{
    printf("\n=== TEST 05: CTR-128 Encrypt (NIST SP 800-38A F.5.1 block-1) ===\n");

    static const uint32_t key[4] = {
        0x2B7E1516U, 0x28AED2A6U, 0xABF71588U, 0x09CF4F3CU
    };
    static const uint32_t iv[4] = {
        0xF0F1F2F3U, 0xF4F5F6F7U, 0xF8F9FAFBU, 0xFCFDFEFFU
    };
    static const uint32_t plain[4] = {
        0x6BC1BEE2U, 0x2E409F96U, 0xE93D7E11U, 0x7393172AU
    };
    static const uint32_t expected[4] = {
        0x874D6191U, 0xB620E326U, 0x1BEF6864U, 0x990DB6CEU
    };
    uint32_t cipher[4];
    aes_err_t r;

    r = aes_reset();                                   if (r) return r;
    aes_load_key128(key);
    aes_load_iv(iv);
    aes_configure(CONF_MODE_CTR | CONF_DIR_ENC | CONF_KEY128 | CONF_DTYPE_NONE);

    printf("  IV/CTR   : %08X %08X %08X %08X\n",
           (unsigned)iv[0], (unsigned)iv[1],
           (unsigned)iv[2], (unsigned)iv[3]);
    printf("  Plaintext: %08X %08X %08X %08X\n",
           (unsigned)plain[0], (unsigned)plain[1],
           (unsigned)plain[2], (unsigned)plain[3]);

    r = aes_process_block(plain, cipher);              if (r) return r;

    REG_WR32(AES_ENAB, 0U);
    return verify_block(cipher, expected, "CTR-128 Encrypt");
}

/* ===========================================================================
 * TEST 06 – CTR-128 Decrypt  (CTR mode: decrypt = encrypt lại)
 * =========================================================================*/
static aes_err_t test06_ctr128_dec(void)
{
    printf("\n=== TEST 06: CTR-128 Decrypt (đối xứng với test 05) ===\n");

    static const uint32_t key[4] = {
        0x2B7E1516U, 0x28AED2A6U, 0xABF71588U, 0x09CF4F3CU
    };
    static const uint32_t iv[4] = {
        0xF0F1F2F3U, 0xF4F5F6F7U, 0xF8F9FAFBU, 0xFCFDFEFFU
    };
    /* Input là ciphertext của test 05 */
    static const uint32_t cipher[4] = {
        0x874D6191U, 0xB620E326U, 0x1BEF6864U, 0x990DB6CEU
    };
    static const uint32_t expected[4] = {
        0x6BC1BEE2U, 0x2E409F96U, 0xE93D7E11U, 0x7393172AU
    };
    uint32_t plain[4];
    aes_err_t r;

    r = aes_reset();                                   if (r) return r;
    aes_load_key128(key);
    aes_load_iv(iv);
    /* CTR decrypt dùng cùng DIR_ENC vì CTR là XOR symmetric */
    aes_configure(CONF_MODE_CTR | CONF_DIR_ENC | CONF_KEY128 | CONF_DTYPE_NONE);

    printf("  Ciphertext: %08X %08X %08X %08X\n",
           (unsigned)cipher[0], (unsigned)cipher[1],
           (unsigned)cipher[2], (unsigned)cipher[3]);

    r = aes_process_block(cipher, plain);              if (r) return r;

    REG_WR32(AES_ENAB, 0U);
    return verify_block(plain, expected, "CTR-128 Decrypt");
}

/* ===========================================================================
 * TEST 07 – ECB-256 Encrypt  (NIST FIPS-197 Appendix B, 256-bit key)
 *
 *   Key-256  : 000102030405060708090A0B0C0D0E0F
 *              101112131415161718191A1B1C1D1E1F
 *   Plaintext: 00112233445566778899AABBCCDDEEFF
 *   Cipher   : 8EA2B7CA516745BFEAFC49904B496089
 * =========================================================================*/
static aes_err_t test07_ecb256_enc(void)
{
    printf("\n=== TEST 07: ECB-256 Encrypt (NIST FIPS-197 App.B 256-key) ===\n");

    static const uint32_t key[8] = {
        0x00010203U, 0x04050607U, 0x08090A0BU, 0x0C0D0E0FU,
        0x10111213U, 0x14151617U, 0x18191A1BU, 0x1C1D1E1FU
    };
    static const uint32_t plain[4] = {
        0x00112233U, 0x44556677U, 0x8899AABBU, 0xCCDDEEFFU
    };
    static const uint32_t expected[4] = {
        0x8EA2B7CAU, 0x516745BFU, 0xEAFC4990U, 0x4B496089U
    };
    uint32_t cipher[4];
    aes_err_t r;

    r = aes_reset();                                   if (r) return r;
    aes_load_key256(key);
    aes_configure(CONF_MODE_ECB | CONF_DIR_ENC | CONF_KEY256 | CONF_DTYPE_NONE);

    printf("  Key[0..3]: %08X %08X %08X %08X\n",
           (unsigned)key[0], (unsigned)key[1],
           (unsigned)key[2], (unsigned)key[3]);
    printf("  Key[4..7]: %08X %08X %08X %08X\n",
           (unsigned)key[4], (unsigned)key[5],
           (unsigned)key[6], (unsigned)key[7]);
    printf("  Plaintext: %08X %08X %08X %08X\n",
           (unsigned)plain[0], (unsigned)plain[1],
           (unsigned)plain[2], (unsigned)plain[3]);

    r = aes_process_block(plain, cipher);              if (r) return r;

    REG_WR32(AES_ENAB, 0U);
    return verify_block(cipher, expected, "ECB-256 Encrypt");
}

/* ===========================================================================
 * TEST 08 – Reset giữa chừng (Partial TX + Reset)
 *
 * Mục đích: Verify SWRS.TFR reset TX FIFO đúng cách, không có data cũ sót
 *           trong FIFO ảnh hưởng block sau.
 *
 * Sequence:
 *   1. Configure AES ECB-128 encrypt
 *   2. Push 2 words (nửa block) vào TX FIFO
 *   3. Disable AES (EN=0)
 *   4. Reset TX FIFO (SWRS.TFR) và RX FIFO (SWRS.RFR)
 *   5. Enable lại, push đủ 4 words block hợp lệ
 *   6. Verify output đúng → không bị nhiễm data cũ
 * =========================================================================*/
static aes_err_t test08_partial_reset(void)
{
    printf("\n=== TEST 08: Partial TX Reset + Recovery ===\n");

    static const uint32_t key[4] = {
        0x2B7E1516U, 0x28AED2A6U, 0xABF71588U, 0x09CF4F3CU
    };
    static const uint32_t plain[4] = {
        0x3243F6A8U, 0x885A308DU, 0x313198A2U, 0xE0370734U
    };
    /* Expected = output của test 01 với cùng key+plaintext */
    static const uint32_t expected[4] = {
        0x3925841DU, 0x02DC09FBU, 0xDC118597U, 0x196A0B32U
    };
    uint32_t cipher[4];
    aes_err_t r;
    uint32_t stat;

    /* --- Step 1: cấu hình AES --- */
    r = aes_reset();                                   if (r) return r;
    aes_load_key128(key);
    aes_configure(CONF_MODE_ECB | CONF_DIR_ENC | CONF_KEY128 | CONF_DTYPE_NONE);

    /* --- Step 2: push 2 words rác vào TX FIFO --- */
    printf("  Pushing 2 garbage words into TX FIFO...\n");
    r = aes_wait_txnf(); if (r) return r;
    REG_WR32(AES_DATA, 0xDEADBEEFU);
    r = aes_wait_txnf(); if (r) return r;
    REG_WR32(AES_DATA, 0xCAFEBABEU);

    stat = REG_RD32(AES_STAT);
    printf("  STAT after 2 garbage words: 0x%08X (TXEM should be 0)\n",
           (unsigned)stat);
    if (stat & STAT_TXEM) {
        printf("  [WARN] TX FIFO reports empty unexpectedly\n");
    }

    /* --- Step 3+4: disable và reset cả hai FIFO --- */
    printf("  Disabling AES and resetting TX+RX FIFOs...\n");
    REG_WR32(AES_ENAB, 0U);
    REG_WR32(AES_SWRS, SWRS_TFR | SWRS_RFR);
    r = aes_wait_swrs_clear(SWRS_TFR | SWRS_RFR);     if (r) return r;

    stat = REG_RD32(AES_STAT);
    printf("  STAT after FIFO reset: 0x%08X (expect TXEM=1, RXNE=0)\n",
           (unsigned)stat);
    if (!(stat & STAT_TXEM)) {
        printf("  [FAIL] TX FIFO not empty after reset\n");
        return AES_ERR_STAT;
    }
    if (stat & STAT_RXNE) {
        printf("  [FAIL] RX FIFO not empty after reset\n");
        return AES_ERR_STAT;
    }

    /* --- Step 5: re-enable và xử lý block hợp lệ --- */
    printf("  Re-enabling AES and processing valid block...\n");
    /* Key vẫn còn hiệu lực sau FIFO reset (SCR không gọi) */
    aes_configure(CONF_MODE_ECB | CONF_DIR_ENC | CONF_KEY128 | CONF_DTYPE_NONE);

    r = aes_process_block(plain, cipher);              if (r) return r;

    REG_WR32(AES_ENAB, 0U);

    /* --- Step 6: verify --- */
    return verify_block(cipher, expected, "Partial Reset + Recovery");
}

/* ===========================================================================
 * MAIN
 * =========================================================================*/
int main(void)
{
    typedef struct {
        const char  *name;
        aes_err_t  (*fn)(void);
    } test_t;

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

    const uint32_t ntests = (uint32_t)(sizeof(tests) / sizeof(tests[0]));
    uint32_t pass = 0, fail = 0, i;

    printf("============================================================\n");
    printf("  AES IP Test Suite (no DMA)\n");
    printf("  AES_BASE = 0x%08X\n", (unsigned)AES_BASE);
    printf("============================================================\n");

    for (i = 0; i < ntests; i++) {
        aes_err_t rc = tests[i].fn();
        if (rc == AES_OK) {
            printf("[RESULT] Test %s --> PASS\n", tests[i].name);
            pass++;
        } else {
            printf("[RESULT] Test %s --> FAIL (err=%d)\n",
                   tests[i].name, (int)rc);
            fail++;
        }
    }

    printf("\n============================================================\n");
    printf("  TOTAL %u:  PASS=%u  FAIL=%u\n",
           (unsigned)ntests, (unsigned)pass, (unsigned)fail);
    printf("============================================================\n");
    return (fail == 0) ? 0 : 1;
}
