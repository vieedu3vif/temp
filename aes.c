/**
 * @file  aes_test_nodma.c
 * @brief AES IP Test Suite – No DMA, CPU polling  (v3)
 *
 * Root cause fix từ v2:
 *   STAT=0x0C (TXEM=1, RXNE=0) sau khi push 4 words →
 *   AES consume TX nhưng không produce RX → key schedule chưa chạy.
 *
 *   Nguyên nhân: v1/v2 ghi CONF + key khi EN=0, set EN=1 SAU CÙNG.
 *   Một số AES IP (STM32-style) yêu cầu EN=1 TRƯỚC để kích key schedule.
 *
 * Sequence mới (đã fix):
 *   aes_reset()
 *     └─ EN=0  →  SWRS.SCR  →  wait auto-clear
 *   aes_load_iv()         ← (CBC/CTR only, vẫn ghi khi EN=0)
 *   EN=1                  ← enable TRƯỚC
 *   CONF                  ← ghi mode/keysize/dir sau khi EN=1
 *   Key registers         ← key schedule tự chạy sau khi CONF+key ghi xong
 *   wait_key_ready()      ← đợi BUSY=0 (key schedule done)
 *   push data → wait TXEM → pop data
 *
 * Nếu sequence trên vẫn fail → thêm probe sequence:
 *   Thử ghi EN=1 → key → CONF (hoán đổi thứ tự CONF/key).
 *
 * Register map (base = 0x62000000):
 *   AES_CONF 0x0004  AES_DMA 0x0008  AES_INTE 0x000C
 *   AES_STAT 0x0010  AES_SWRS 0x0044 AES_ENAB 0x0048
 *   Key: K0LR=0x0014..K3RR=0x0030  IV: IV0L=0x0034..IV1R=0x0040
 *   AES_DATA 0x10000 (FIFO TX-write / RX-read)
 */

#include <stdint.h>
#include <stdio.h>

/* ===========================================================================
 * Register access
 * =========================================================================*/
#define REG32(addr)     (*((volatile uint32_t *)(uintptr_t)(addr)))
#define REG_WR32(a,v)   (REG32(a) = (uint32_t)(v))
#define REG_RD32(a)     (REG32(a))

/* ===========================================================================
 * AES Register Map
 * =========================================================================*/
#ifndef AES_BASE
#define AES_BASE        0x62000000UL
#endif

#define AES_CONF        (AES_BASE + 0x0004U)
#define AES_DMA         (AES_BASE + 0x0008U)
#define AES_INTE        (AES_BASE + 0x000CU)
#define AES_STAT        (AES_BASE + 0x0010U)
#define AES_K0LR        (AES_BASE + 0x0014U)
#define AES_K0RR        (AES_BASE + 0x0018U)
#define AES_K1LR        (AES_BASE + 0x001CU)
#define AES_K1RR        (AES_BASE + 0x0020U)
#define AES_K2LR        (AES_BASE + 0x0024U)
#define AES_K2RR        (AES_BASE + 0x0028U)
#define AES_K3LR        (AES_BASE + 0x002CU)
#define AES_K3RR        (AES_BASE + 0x0030U)
#define AES_IV0L        (AES_BASE + 0x0034U)
#define AES_IV0R        (AES_BASE + 0x0038U)
#define AES_IV1L        (AES_BASE + 0x003CU)
#define AES_IV1R        (AES_BASE + 0x0040U)
#define AES_SWRS        (AES_BASE + 0x0044U)
#define AES_ENAB        (AES_BASE + 0x0048U)
#define AES_DATA        (AES_BASE + 0x10000U)

/* ---------- AES_CONF bit fields ---------- */
/* [9:8] key_size: 0x=256, 10=192, 11=128                                  */
#define CONF_KEY256     (0x0U << 8)
#define CONF_KEY192     (0x2U << 8)
#define CONF_KEY128     (0x3U << 8)
/* [7:6] data_type                                                          */
#define CONF_DTYPE_NONE (0x0U << 6)   /* no swap                           */
#define CONF_DTYPE_HW   (0x1U << 6)   /* 16-bit swap                       */
#define CONF_DTYPE_BYTE (0x2U << 6)   /* 8-bit byte swap                   */
/* [5:3] mode                                                               */
#define CONF_MODE_ECB   (0x0U << 3)
#define CONF_MODE_CBC   (0x1U << 3)
#define CONF_MODE_CTR   (0x2U << 3)
/* [2] dir                                                                  */
#define CONF_DIR_ENC    (0x0U << 2)
#define CONF_DIR_DEC    (0x1U << 2)

/* ---------- AES_STAT bit fields ---------- */
#define STAT_BUSY       (1U << 6)   /* AES engine busy (key sched / block) */
#define STAT_RXFU       (1U << 5)   /* RX FIFO full                        */
#define STAT_RXNE       (1U << 4)   /* RX FIFO not empty (has data)        */
#define STAT_TXNF       (1U << 3)   /* TX FIFO not full  (has free slot)   */
#define STAT_TXEM       (1U << 2)   /* TX FIFO empty                       */
#define STAT_RXUF       (1U << 1)   /* RX underflow  R/W1C                 */
#define STAT_TXOF       (1U << 0)   /* TX overflow   R/W1C                 */

/* ---------- AES_SWRS bits ---------- */
#define SWRS_RFR        (1U << 2)
#define SWRS_TFR        (1U << 1)
#define SWRS_SCR        (1U << 0)

/* ---------- AES_ENAB bits ---------- */
#define ENAB_EN         (1U << 0)

/* ===========================================================================
 * Error / timeout
 * =========================================================================*/
typedef enum {
    AES_OK          = 0,
    AES_ERR_TIMEOUT = 1,
    AES_ERR_DATA    = 2,
    AES_ERR_STAT    = 3,
} aes_err_t;

#define AES_BLOCK_WORDS 4U
#define TIMEOUT         2000000U

/* ===========================================================================
 * Verbose status dump
 * =========================================================================*/
static void print_stat(const char *tag)
{
    uint32_t s = REG_RD32(AES_STAT);
    printf("  [STAT] %-36s 0x%02X  "
           "BUSY=%u RXFU=%u RXNE=%u TXNF=%u TXEM=%u RXUF=%u TXOF=%u\n",
           tag, (unsigned)s,
           (s>>6)&1u, (s>>5)&1u, (s>>4)&1u,
           (s>>3)&1u, (s>>2)&1u, (s>>1)&1u, s&1u);
}

/* ===========================================================================
 * Polling
 * =========================================================================*/
static aes_err_t wait_swrs_clear(uint32_t bits)
{
    uint32_t t = TIMEOUT;
    while (REG_RD32(AES_SWRS) & bits)
        if (!--t) { printf("  [ERR] SWRS wait timeout\n"); return AES_ERR_TIMEOUT; }
    return AES_OK;
}

/** Đợi BUSY=0  (dùng sau key load để chắc key schedule xong) */
static aes_err_t wait_busy_clear(void)
{
    uint32_t t = TIMEOUT;
    while (REG_RD32(AES_STAT) & STAT_BUSY)
        if (!--t) {
            printf("  [ERR] BUSY timeout  STAT=0x%02X\n",
                   (unsigned)REG_RD32(AES_STAT));
            return AES_ERR_TIMEOUT;
        }
    return AES_OK;
}

/** Đợi TX FIFO có slot trống */
static aes_err_t wait_txnf(void)
{
    uint32_t t = TIMEOUT;
    while (!(REG_RD32(AES_STAT) & STAT_TXNF))
        if (!--t) {
            printf("  [ERR] TXNF timeout  STAT=0x%02X\n",
                   (unsigned)REG_RD32(AES_STAT));
            return AES_ERR_TIMEOUT;
        }
    return AES_OK;
}

/** Đợi TX FIFO empty (AES consume hết input) */
static aes_err_t wait_txem(void)
{
    uint32_t t = TIMEOUT;
    while (!(REG_RD32(AES_STAT) & STAT_TXEM))
        if (!--t) {
            printf("  [ERR] TXEM timeout  STAT=0x%02X\n",
                   (unsigned)REG_RD32(AES_STAT));
            return AES_ERR_TIMEOUT;
        }
    return AES_OK;
}

/** Đợi RX FIFO có ít nhất 1 word */
static aes_err_t wait_rxne(void)
{
    uint32_t t = TIMEOUT;
    while (!(REG_RD32(AES_STAT) & STAT_RXNE))
        if (!--t) {
            printf("  [ERR] RXNE timeout  STAT=0x%02X\n",
                   (unsigned)REG_RD32(AES_STAT));
            return AES_ERR_TIMEOUT;
        }
    return AES_OK;
}

/* ===========================================================================
 * AES init helpers
 * =========================================================================*/

/**
 * @brief Hard reset: EN=0 → SWRS.SCR → wait auto-clear.
 *        Gọi đầu tiên mỗi test.
 */
static aes_err_t aes_reset(void)
{
    REG_WR32(AES_ENAB, 0U);
    REG_WR32(AES_SWRS, SWRS_SCR);
    return wait_swrs_clear(SWRS_SCR);
}

/**
 * @brief Load IV (128-bit, 4 words).
 *        Ghi KHI EN=0 (sau aes_reset, trước khi set EN=1).
 *        Một số IP ignore IV write khi EN=1.
 */
static void aes_load_iv(const uint32_t *iv)
{
    REG_WR32(AES_IV0L, iv[0]);
    REG_WR32(AES_IV0R, iv[1]);
    REG_WR32(AES_IV1L, iv[2]);
    REG_WR32(AES_IV1R, iv[3]);
    printf("  [INIT] IV: %08X %08X %08X %08X  "
           "(readback: %08X %08X %08X %08X)\n",
           (unsigned)iv[0], (unsigned)iv[1],
           (unsigned)iv[2], (unsigned)iv[3],
           (unsigned)REG_RD32(AES_IV0L), (unsigned)REG_RD32(AES_IV0R),
           (unsigned)REG_RD32(AES_IV1L), (unsigned)REG_RD32(AES_IV1R));
}

/**
 * @brief Sequence chuẩn (v3 fix):
 *
 *   EN=1  →  CONF  →  Key  →  wait BUSY=0  →  (data phase)
 *
 *   Lý do EN=1 TRƯỚC:
 *     Key schedule chỉ chạy khi AES enabled. Nếu ghi key khi EN=0 rồi
 *     mới set EN=1, một số IP không tự trigger lại key schedule → AES
 *     nhận data nhưng dùng key rỗng → không produce RX output.
 *
 *   wait_busy_clear() sau key load:
 *     Key schedule (đặc biệt AES-256) mất vài chu kỳ. Không đợi → data
 *     đầu tiên có thể bị xử lý với key chưa sẵn sàng.
 */
static aes_err_t aes_setup128(const uint32_t *key, uint32_t conf_val)
{
    aes_err_t r;

    REG_WR32(AES_INTE, 0U);
    REG_WR32(AES_DMA,  0U);

    /* --- Step 1: Enable AES TRƯỚC --- */
    REG_WR32(AES_ENAB, ENAB_EN);
    printf("  [INIT] ENAB=1  readback=0x%08X\n", (unsigned)REG_RD32(AES_ENAB));
    print_stat("after EN=1");

    /* --- Step 2: Ghi CONF (key_size, mode, dir) --- */
    REG_WR32(AES_CONF, conf_val);
    printf("  [INIT] CONF=0x%08X  readback=0x%08X\n",
           (unsigned)conf_val, (unsigned)REG_RD32(AES_CONF));

    /* --- Step 3: Load key 128-bit --- */
    REG_WR32(AES_K0LR, key[0]);
    REG_WR32(AES_K0RR, key[1]);
    REG_WR32(AES_K1LR, key[2]);
    REG_WR32(AES_K1RR, key[3]);
    printf("  [INIT] Key128: %08X %08X %08X %08X\n",
           (unsigned)REG_RD32(AES_K0LR), (unsigned)REG_RD32(AES_K0RR),
           (unsigned)REG_RD32(AES_K1LR), (unsigned)REG_RD32(AES_K1RR));

    /* --- Step 4: Đợi key schedule xong (BUSY→0) --- */
    print_stat("before key-sched wait");
    r = wait_busy_clear();
    if (r) return r;
    print_stat("key schedule done");

    return AES_OK;
}

static aes_err_t aes_setup256(const uint32_t *key, uint32_t conf_val)
{
    aes_err_t r;

    REG_WR32(AES_INTE, 0U);
    REG_WR32(AES_DMA,  0U);

    REG_WR32(AES_ENAB, ENAB_EN);
    printf("  [INIT] ENAB=1  readback=0x%08X\n", (unsigned)REG_RD32(AES_ENAB));

    REG_WR32(AES_CONF, conf_val);
    printf("  [INIT] CONF=0x%08X  readback=0x%08X\n",
           (unsigned)conf_val, (unsigned)REG_RD32(AES_CONF));

    REG_WR32(AES_K0LR, key[0]); REG_WR32(AES_K0RR, key[1]);
    REG_WR32(AES_K1LR, key[2]); REG_WR32(AES_K1RR, key[3]);
    REG_WR32(AES_K2LR, key[4]); REG_WR32(AES_K2RR, key[5]);
    REG_WR32(AES_K3LR, key[6]); REG_WR32(AES_K3RR, key[7]);
    printf("  [INIT] Key256 loaded\n");

    print_stat("before key-sched wait");
    r = wait_busy_clear();
    if (r) return r;
    print_stat("key schedule done");

    return AES_OK;
}

/**
 * @brief Xử lý 1 block 128-bit.
 *
 * Push 4 words → wait TXEM (AES tiêu thụ xong) → wait RXNE + pop.
 * In STAT sau mỗi thao tác để trace vấn đề.
 */
static aes_err_t aes_process_block(const uint32_t *in, uint32_t *out)
{
    uint32_t i;
    aes_err_t r;

    printf("  [DATA] Pushing %u words to TX FIFO...\n", (unsigned)AES_BLOCK_WORDS);
    for (i = 0; i < AES_BLOCK_WORDS; i++) {
        r = wait_txnf(); if (r) return r;
        REG_WR32(AES_DATA, in[i]);
        printf("  [TX]   word[%u]=0x%08X  ", (unsigned)i, (unsigned)in[i]);
        print_stat("");
    }

    printf("  [DATA] Waiting TX FIFO empty (AES consuming)...\n");
    r = wait_txem(); if (r) return r;
    print_stat("TXEM=1");

    printf("  [DATA] Waiting BUSY=0 (block processing done)...\n");
    r = wait_busy_clear(); if (r) return r;
    print_stat("BUSY=0");

    /* Kiểm tra RX có data không */
    {
        uint32_t s = REG_RD32(AES_STAT);
        if (!(s & STAT_RXNE)) {
            printf("  [ERR] RX FIFO empty after block done  STAT=0x%02X\n",
                   (unsigned)s);
            printf("  [DBG] CONF=0x%08X  ENAB=0x%08X\n",
                   (unsigned)REG_RD32(AES_CONF),
                   (unsigned)REG_RD32(AES_ENAB));
            return AES_ERR_STAT;
        }
    }

    printf("  [DATA] Popping %u words from RX FIFO...\n", (unsigned)AES_BLOCK_WORDS);
    for (i = 0; i < AES_BLOCK_WORDS; i++) {
        r = wait_rxne(); if (r) return r;
        out[i] = REG_RD32(AES_DATA);
        printf("  [RX]   word[%u]=0x%08X  ", (unsigned)i, (unsigned)out[i]);
        print_stat("");
    }

    /* Clear sticky error flags */
    {
        uint32_t s = REG_RD32(AES_STAT);
        if (s & (STAT_RXUF | STAT_TXOF)) {
            printf("  [WARN] Sticky errors – clearing (RXUF=%u TXOF=%u)\n",
                   (s>>1)&1u, s&1u);
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
           (unsigned)got[0], (unsigned)got[1],
           (unsigned)got[2], (unsigned)got[3]);
    printf("  Expected: %08X %08X %08X %08X\n",
           (unsigned)exp[0], (unsigned)exp[1],
           (unsigned)exp[2], (unsigned)exp[3]);

    if (ok) { printf("  [PASS] %s\n", label); return AES_OK; }

    for (i = 0; i < AES_BLOCK_WORDS; i++)
        if (got[i] != exp[i])
            printf("  [FAIL] %s word[%u]: got=0x%08X  exp=0x%08X\n",
                   label, (unsigned)i, (unsigned)got[i], (unsigned)exp[i]);
    return AES_ERR_DATA;
}

/* ===========================================================================
 * TEST 00 – Sanity: Register readback
 *   Không cần HW crypto đúng – chỉ verify ghi/đọc register hoạt động.
 *   Nếu test này PASS mà test 01 fail → IP address đúng, vấn đề là logic.
 *   Nếu test này FAIL → sai base address hoặc IP chưa clock/power-on.
 * =========================================================================*/
static aes_err_t test00_reg_rw(void)
{
    printf("\n=== TEST 00: Register Read/Write Sanity ===\n");
    aes_err_t r;
    uint32_t val;

    /* Reset trước */
    r = aes_reset(); if (r) return r;
    print_stat("after reset (EN=0)");

    /* ENAB: ghi 1 đọc lại */
    REG_WR32(AES_ENAB, ENAB_EN);
    val = REG_RD32(AES_ENAB);
    printf("  ENAB write=0x1  readback=0x%08X  %s\n",
           (unsigned)val, (val & ENAB_EN) ? "OK" : "FAIL – IP not responding");
    if (!(val & ENAB_EN)) return AES_ERR_STAT;

    /* CONF: ghi pattern, đọc lại */
    uint32_t conf_test = CONF_MODE_ECB | CONF_DIR_ENC | CONF_KEY128 | CONF_DTYPE_NONE;
    REG_WR32(AES_CONF, conf_test);
    val = REG_RD32(AES_CONF);
    printf("  CONF write=0x%08X  readback=0x%08X  %s\n",
           (unsigned)conf_test, (unsigned)val,
           (val == conf_test) ? "OK" : "MISMATCH – check bit mask");

    /* Key register: ghi pattern */
    REG_WR32(AES_K0LR, 0xDEADBEEFU);
    val = REG_RD32(AES_K0LR);
    printf("  K0LR write=0xDEADBEEF  readback=0x%08X  %s\n",
           (unsigned)val,
           (val == 0xDEADBEEFU) ? "OK" : "FAIL – key reg not writable");

    /* STAT initial khi EN=1 */
    print_stat("STAT at EN=1");

    REG_WR32(AES_ENAB, 0U);
    printf("  [PASS] Register R/W sanity\n");
    return AES_OK;
}

/* ===========================================================================
 * TEST 01 – ECB-128 Encrypt  (NIST FIPS-197 App.B)
 *   Key: 2B7E1516 28AED2A6 ABF71588 09CF4F3C
 *   PT : 3243F6A8 885A308D 313198A2 E0370734
 *   CT : 3925841D 02DC09FB DC118597 196A0B32
 * =========================================================================*/
static aes_err_t test01_ecb128_enc(void)
{
    printf("\n=== TEST 01: ECB-128 Encrypt (NIST FIPS-197 App.B) ===\n");
    static const uint32_t key[4] = {
        0x2B7E1516U, 0x28AED2A6U, 0xABF71588U, 0x09CF4F3CU};
    static const uint32_t pt[4] = {
        0x3243F6A8U, 0x885A308DU, 0x313198A2U, 0xE0370734U};
    static const uint32_t exp[4] = {
        0x3925841DU, 0x02DC09FBU, 0xDC118597U, 0x196A0B32U};
    uint32_t ct[4]; aes_err_t r;

    r = aes_reset();                                              if (r) return r;
    r = aes_setup128(key, CONF_MODE_ECB|CONF_DIR_ENC|CONF_KEY128|CONF_DTYPE_NONE);
    if (r) return r;
    r = aes_process_block(pt, ct);                               if (r) return r;
    REG_WR32(AES_ENAB, 0U);
    return verify_block(ct, exp, "ECB-128 Encrypt");
}

/* ===========================================================================
 * TEST 02 – ECB-128 Decrypt
 * =========================================================================*/
static aes_err_t test02_ecb128_dec(void)
{
    printf("\n=== TEST 02: ECB-128 Decrypt ===\n");
    static const uint32_t key[4] = {
        0x2B7E1516U, 0x28AED2A6U, 0xABF71588U, 0x09CF4F3CU};
    static const uint32_t ct[4] = {
        0x3925841DU, 0x02DC09FBU, 0xDC118597U, 0x196A0B32U};
    static const uint32_t exp[4] = {
        0x3243F6A8U, 0x885A308DU, 0x313198A2U, 0xE0370734U};
    uint32_t pt[4]; aes_err_t r;

    r = aes_reset();                                              if (r) return r;
    r = aes_setup128(key, CONF_MODE_ECB|CONF_DIR_DEC|CONF_KEY128|CONF_DTYPE_NONE);
    if (r) return r;
    r = aes_process_block(ct, pt);                               if (r) return r;
    REG_WR32(AES_ENAB, 0U);
    return verify_block(pt, exp, "ECB-128 Decrypt");
}

/* ===========================================================================
 * TEST 03 – CBC-128 Encrypt  (NIST SP 800-38A F.2.1 block-1)
 *   IV : 00010203 04050607 08090A0B 0C0D0E0F
 *   PT : 6BC1BEE2 2E409F96 E93D7E11 7393172A
 *   CT : 7649ABAC 8119B246 CEE98E9B 12E9197D
 * =========================================================================*/
static aes_err_t test03_cbc128_enc(void)
{
    printf("\n=== TEST 03: CBC-128 Encrypt (NIST SP 800-38A F.2.1 block-1) ===\n");
    static const uint32_t key[4] = {
        0x2B7E1516U, 0x28AED2A6U, 0xABF71588U, 0x09CF4F3CU};
    static const uint32_t iv[4]  = {
        0x00010203U, 0x04050607U, 0x08090A0BU, 0x0C0D0E0FU};
    static const uint32_t pt[4] = {
        0x6BC1BEE2U, 0x2E409F96U, 0xE93D7E11U, 0x7393172AU};
    static const uint32_t exp[4] = {
        0x7649ABACU, 0x8119B246U, 0xCEE98E9BU, 0x12E9197DU};
    uint32_t ct[4]; aes_err_t r;

    r = aes_reset();                                              if (r) return r;
    aes_load_iv(iv);   /* IV khi EN=0, trước setup */
    r = aes_setup128(key, CONF_MODE_CBC|CONF_DIR_ENC|CONF_KEY128|CONF_DTYPE_NONE);
    if (r) return r;
    r = aes_process_block(pt, ct);                               if (r) return r;
    REG_WR32(AES_ENAB, 0U);
    return verify_block(ct, exp, "CBC-128 Encrypt");
}

/* ===========================================================================
 * TEST 04 – CBC-128 Decrypt  (NIST SP 800-38A F.2.2 block-1)
 * =========================================================================*/
static aes_err_t test04_cbc128_dec(void)
{
    printf("\n=== TEST 04: CBC-128 Decrypt (NIST SP 800-38A F.2.2 block-1) ===\n");
    static const uint32_t key[4] = {
        0x2B7E1516U, 0x28AED2A6U, 0xABF71588U, 0x09CF4F3CU};
    static const uint32_t iv[4]  = {
        0x00010203U, 0x04050607U, 0x08090A0BU, 0x0C0D0E0FU};
    static const uint32_t ct[4] = {
        0x7649ABACU, 0x8119B246U, 0xCEE98E9BU, 0x12E9197DU};
    static const uint32_t exp[4] = {
        0x6BC1BEE2U, 0x2E409F96U, 0xE93D7E11U, 0x7393172AU};
    uint32_t pt[4]; aes_err_t r;

    r = aes_reset();                                              if (r) return r;
    aes_load_iv(iv);
    r = aes_setup128(key, CONF_MODE_CBC|CONF_DIR_DEC|CONF_KEY128|CONF_DTYPE_NONE);
    if (r) return r;
    r = aes_process_block(ct, pt);                               if (r) return r;
    REG_WR32(AES_ENAB, 0U);
    return verify_block(pt, exp, "CBC-128 Decrypt");
}

/* ===========================================================================
 * TEST 05 – CTR-128 Encrypt  (NIST SP 800-38A F.5.1 block-1)
 *   IV/CTR: F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF
 *   PT    : 6BC1BEE2 2E409F96 E93D7E11 7393172A
 *   CT    : 874D6191 B620E326 1BEF6864 990DB6CE
 * =========================================================================*/
static aes_err_t test05_ctr128_enc(void)
{
    printf("\n=== TEST 05: CTR-128 Encrypt (NIST SP 800-38A F.5.1 block-1) ===\n");
    static const uint32_t key[4] = {
        0x2B7E1516U, 0x28AED2A6U, 0xABF71588U, 0x09CF4F3CU};
    static const uint32_t iv[4]  = {
        0xF0F1F2F3U, 0xF4F5F6F7U, 0xF8F9FAFBU, 0xFCFDFEFFU};
    static const uint32_t pt[4] = {
        0x6BC1BEE2U, 0x2E409F96U, 0xE93D7E11U, 0x7393172AU};
    static const uint32_t exp[4] = {
        0x874D6191U, 0xB620E326U, 0x1BEF6864U, 0x990DB6CEU};
    uint32_t ct[4]; aes_err_t r;

    r = aes_reset();                                              if (r) return r;
    aes_load_iv(iv);
    r = aes_setup128(key, CONF_MODE_CTR|CONF_DIR_ENC|CONF_KEY128|CONF_DTYPE_NONE);
    if (r) return r;
    r = aes_process_block(pt, ct);                               if (r) return r;
    REG_WR32(AES_ENAB, 0U);
    return verify_block(ct, exp, "CTR-128 Encrypt");
}

/* ===========================================================================
 * TEST 06 – CTR-128 Decrypt  (CTR symmetric: DIR_ENC cả hai chiều)
 * =========================================================================*/
static aes_err_t test06_ctr128_dec(void)
{
    printf("\n=== TEST 06: CTR-128 Decrypt ===\n");
    static const uint32_t key[4] = {
        0x2B7E1516U, 0x28AED2A6U, 0xABF71588U, 0x09CF4F3CU};
    static const uint32_t iv[4]  = {
        0xF0F1F2F3U, 0xF4F5F6F7U, 0xF8F9FAFBU, 0xFCFDFEFFU};
    static const uint32_t ct[4] = {
        0x874D6191U, 0xB620E326U, 0x1BEF6864U, 0x990DB6CEU};
    static const uint32_t exp[4] = {
        0x6BC1BEE2U, 0x2E409F96U, 0xE93D7E11U, 0x7393172AU};
    uint32_t pt[4]; aes_err_t r;

    r = aes_reset();                                              if (r) return r;
    aes_load_iv(iv);
    r = aes_setup128(key, CONF_MODE_CTR|CONF_DIR_ENC|CONF_KEY128|CONF_DTYPE_NONE);
    if (r) return r;
    r = aes_process_block(ct, pt);                               if (r) return r;
    REG_WR32(AES_ENAB, 0U);
    return verify_block(pt, exp, "CTR-128 Decrypt");
}

/* ===========================================================================
 * TEST 07 – ECB-256 Encrypt  (NIST FIPS-197, 256-bit key)
 *   PT : 00112233 44556677 8899AABB CCDDEEFF
 *   CT : 8EA2B7CA 516745BF EAFC4990 4B496089
 * =========================================================================*/
static aes_err_t test07_ecb256_enc(void)
{
    printf("\n=== TEST 07: ECB-256 Encrypt (NIST FIPS-197) ===\n");
    static const uint32_t key[8] = {
        0x00010203U, 0x04050607U, 0x08090A0BU, 0x0C0D0E0FU,
        0x10111213U, 0x14151617U, 0x18191A1BU, 0x1C1D1E1FU};
    static const uint32_t pt[4] = {
        0x00112233U, 0x44556677U, 0x8899AABBU, 0xCCDDEEFFU};
    static const uint32_t exp[4] = {
        0x8EA2B7CAU, 0x516745BFU, 0xEAFC4990U, 0x4B496089U};
    uint32_t ct[4]; aes_err_t r;

    r = aes_reset();                                              if (r) return r;
    r = aes_setup256(key, CONF_MODE_ECB|CONF_DIR_ENC|CONF_KEY256|CONF_DTYPE_NONE);
    if (r) return r;
    r = aes_process_block(pt, ct);                               if (r) return r;
    REG_WR32(AES_ENAB, 0U);
    return verify_block(ct, exp, "ECB-256 Encrypt");
}

/* ===========================================================================
 * TEST 08 – TX FIFO Reset giữa chừng + Recovery
 * =========================================================================*/
static aes_err_t test08_partial_reset(void)
{
    printf("\n=== TEST 08: Partial TX Reset + Recovery ===\n");
    static const uint32_t key[4] = {
        0x2B7E1516U, 0x28AED2A6U, 0xABF71588U, 0x09CF4F3CU};
    static const uint32_t pt[4] = {
        0x3243F6A8U, 0x885A308DU, 0x313198A2U, 0xE0370734U};
    static const uint32_t exp[4] = {
        0x3925841DU, 0x02DC09FBU, 0xDC118597U, 0x196A0B32U};
    uint32_t ct[4]; aes_err_t r; uint32_t s;

    r = aes_reset();                                              if (r) return r;
    r = aes_setup128(key, CONF_MODE_ECB|CONF_DIR_ENC|CONF_KEY128|CONF_DTYPE_NONE);
    if (r) return r;

    /* Push 2 words rác */
    printf("  Pushing 2 garbage words into TX FIFO...\n");
    r = wait_txnf(); if (r) return r;
    REG_WR32(AES_DATA, 0xDEADBEEFU);
    print_stat("after garbage word 1");
    r = wait_txnf(); if (r) return r;
    REG_WR32(AES_DATA, 0xCAFEBABEU);
    print_stat("after garbage word 2");

    /* Disable + reset FIFO (SWRS chỉ có hiệu lực khi EN=0) */
    printf("  Disabling AES and resetting TX+RX FIFOs...\n");
    REG_WR32(AES_ENAB, 0U);
    REG_WR32(AES_SWRS, SWRS_TFR | SWRS_RFR);
    r = wait_swrs_clear(SWRS_TFR | SWRS_RFR);                    if (r) return r;
    print_stat("after FIFO reset");

    s = REG_RD32(AES_STAT);
    if (!(s & STAT_TXEM)) { printf("  [FAIL] TX not empty after reset\n"); return AES_ERR_STAT; }
    if   (s & STAT_RXNE)  { printf("  [FAIL] RX not empty after reset\n"); return AES_ERR_STAT; }
    printf("  FIFO state OK after reset\n");

    /* Re-setup và process block hợp lệ */
    printf("  Re-enabling and processing valid block...\n");
    r = aes_setup128(key, CONF_MODE_ECB|CONF_DIR_ENC|CONF_KEY128|CONF_DTYPE_NONE);
    if (r) return r;
    r = aes_process_block(pt, ct);                               if (r) return r;
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
        { "00 Register R/W Sanity",      test00_reg_rw        },
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
    printf("  AES No-DMA Test Suite  v3\n");
    printf("  AES_BASE = 0x%08X\n", (unsigned)AES_BASE);
    printf("============================================================\n");

    for (i = 0; i < ntests; i++) {
        aes_err_t rc = tests[i].fn();
        if (rc == AES_OK) {
            printf("[RESULT] Test %s --> PASS\n\n", tests[i].name); pass++;
        } else {
            printf("[RESULT] Test %s --> FAIL (err=%d)\n\n",
                   tests[i].name, (int)rc); fail++;
        }
    }

    printf("============================================================\n");
    printf("  TOTAL %u:  PASS=%u  FAIL=%u\n",
           (unsigned)ntests, (unsigned)pass, (unsigned)fail);
    printf("============================================================\n");
    return (fail == 0) ? 0 : 1;
}
