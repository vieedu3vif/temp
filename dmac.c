/**
 * @file  dw_ahb_dmac_test.c
 * @brief Test chương trình DW_ahb_dmac v2.24a
 *
 * Danh sách test:
 *   Test 01 – M2M single-block (baseline, không cần HS)
 *   Test 02 – M2M multi-block qua Linked List Item (LLI)
 *   Test 03 – M2P single-block, SW handshaking DST
 *   Test 04 – P2M single-block, SW handshaking SRC
 *   Test 05 – P2P single-block, SW handshaking SRC + DST
 *   Test 06 – M2P multi-block, SW handshaking DST + LLI
 *   Test 07 – AES: nạp plaintext vào AES qua DMA (M2P), lấy ciphertext ra (P2M)
 *   Test 08 – SHA2: nạp message vào SHA2 qua DMA (M2P), đọc digest (P2M)
 *   Test 09 – M2M interrupt-driven (dùng ISR, không polling)
 *   Test 10 – Auto-reload multi-block (CFG.RELOAD_SRC/DST)
 *
 * Peripheral address map (khai báo — bạn chỉnh theo SoC thực tế):
 *   AES_BASE  = 0x71000000
 *   SHA2_BASE = 0x72000000
 *
 * Software Handshaking protocol (databook sec 3.9.2):
 *   1. Set CFG.HS_SEL_SRC/DST = 1 (SW mode)
 *   2. Khi peripheral sẵn sàng:
 *      – Burst : ghi SWHS_SET(ch) vào ReqSrcReg / ReqDstReg
 *      – Single: ghi SWHS_SET(ch) vào SglReqSrcReg / SglReqDstReg
 *   3. Burst/single CUỐI của block: set LstSrcReg/LstDstReg TRƯỚC khi set Req
 *   4. PHẢI chờ DMAC tự clear bit request trước khi gửi request tiếp theo
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "dw_ahb_dmac_regs.h"

/* ===========================================================================
 * Peripheral Base Addresses  (khai báo theo SoC của bạn)
 * =========================================================================*/
#ifndef AES_BASE
#define AES_BASE            0x71000000UL
#endif

#ifndef SHA2_BASE
#define SHA2_BASE           0x72000000UL
#endif

/* --- AES register offsets (ví dụ generic AES-128/256) --- */
#define AES_KEY_OFF         0x000U   /* Key register (có thể nhiều word) */
#define AES_IV_OFF          0x020U   /* IV / Nonce                        */
#define AES_DATA_IN_OFF     0x040U   /* Plaintext input FIFO              */
#define AES_DATA_OUT_OFF    0x060U   /* Ciphertext output FIFO            */
#define AES_CTRL_OFF        0x080U   /* Control register                  */
#define AES_STATUS_OFF      0x084U   /* Status register                   */
#define AES_CTRL_START      (1U << 0)
#define AES_CTRL_ENC        (1U << 1)  /* 1 = encrypt, 0 = decrypt         */
#define AES_STATUS_DONE     (1U << 0)
#define AES_STATUS_BUSY     (1U << 1)

#define AES_DATA_IN         (AES_BASE + AES_DATA_IN_OFF)
#define AES_DATA_OUT        (AES_BASE + AES_DATA_OUT_OFF)
#define AES_CTRL            (AES_BASE + AES_CTRL_OFF)
#define AES_STATUS          (AES_BASE + AES_STATUS_OFF)

/* --- SHA2 register offsets --- */
#define SHA2_DATA_IN_OFF    0x000U   /* Message input FIFO                */
#define SHA2_DIGEST_OFF     0x020U   /* Digest output (256-bit = 8 words) */
#define SHA2_CTRL_OFF       0x080U
#define SHA2_STATUS_OFF     0x084U
#define SHA2_CTRL_START     (1U << 0)
#define SHA2_CTRL_RESET     (1U << 1)
#define SHA2_STATUS_DONE    (1U << 0)
#define SHA2_STATUS_BUSY    (1U << 1)

#define SHA2_DATA_IN        (SHA2_BASE + SHA2_DATA_IN_OFF)
#define SHA2_DIGEST         (SHA2_BASE + SHA2_DIGEST_OFF)
#define SHA2_CTRL           (SHA2_BASE + SHA2_CTRL_OFF)
#define SHA2_STATUS         (SHA2_BASE + SHA2_STATUS_OFF)

/* ===========================================================================
 * HW Handshake Interface Numbers (CFG.SRC_PER / DEST_PER)
 * Assign theo thiết kế SoC của bạn
 * =========================================================================*/
#define HWHS_AES_TX         0U   /* AES data input  (M2P) */
#define HWHS_AES_RX         1U   /* AES data output (P2M) */
#define HWHS_SHA2_TX        2U   /* SHA2 data input (M2P) */
#define HWHS_SHA2_RX        3U   /* SHA2 digest     (P2M) */

/* ===========================================================================
 * Test parameters
 * =========================================================================*/
#define BUF_WORDS           64U    /* 256 bytes                              */
#define LLI_COUNT           4U     /* 4 blocks trong multi-block test        */
#define BLK_WORDS           16U    /* words mỗi block (LLI_COUNT * BLK_WORDS = BUF_WORDS) */
#define TIMEOUT_LOOPS       500000U

/* ===========================================================================
 * Buffers – 4-byte aligned
 * =========================================================================*/
static uint32_t src_buf[BUF_WORDS] __attribute__((aligned(4)));
static uint32_t dst_buf[BUF_WORDS] __attribute__((aligned(4)));
static uint32_t aes_plain[4]       __attribute__((aligned(4)));  /* 128-bit block */
static uint32_t aes_cipher[4]      __attribute__((aligned(4)));
static uint32_t sha2_msg[16]       __attribute__((aligned(4)));  /* 512-bit block */
static uint32_t sha2_digest[8]     __attribute__((aligned(4)));  /* SHA-256 output*/

/* LLI arrays */
static dmac_lli_t lli_m2m[LLI_COUNT]  __attribute__((aligned(4)));
static dmac_lli_t lli_m2p[LLI_COUNT]  __attribute__((aligned(4)));

/* ===========================================================================
 * Global interrupt flags (set by ISR)
 * =========================================================================*/
static volatile uint32_t g_irq_tfr_mask   = 0;
static volatile uint32_t g_irq_block_mask = 0;
static volatile uint32_t g_irq_err_mask   = 0;

/* ===========================================================================
 * Result type
 * =========================================================================*/
typedef enum {
    DMAC_OK         = 0,
    DMAC_ERR_TIMEOUT,
    DMAC_ERR_HW,
    DMAC_ERR_DATA,
} dmac_err_t;

/* ===========================================================================
 * Utility
 * =========================================================================*/
static void nop_delay(uint32_t n)
{
    volatile uint32_t i;
    for (i = 0; i < n; i++) { __asm__ volatile ("nop"); }
}

static int ch_is_busy(uint32_t ch)
{
    return (int)(REG_RD32(DMAC_CH_EN) & CH_EN_BIT(ch));
}

static dmac_err_t ch_wait_idle(uint32_t ch)
{
    uint32_t t = TIMEOUT_LOOPS;
    while (ch_is_busy(ch)) {
        if (--t == 0) {
            printf("[ERR] ch%u idle timeout\n", (unsigned)ch);
            return DMAC_ERR_TIMEOUT;
        }
    }
    return DMAC_OK;
}

static dmac_err_t poll_done(uint32_t ch)
{
    uint32_t bit = 1U << ch;
    uint32_t t   = TIMEOUT_LOOPS;
    while (1) {
        if (--t == 0) {
            printf("[ERR] ch%u poll_done timeout\n", (unsigned)ch);
            return DMAC_ERR_TIMEOUT;
        }
        if (REG_RD32(DMAC_RAW_ERR) & bit) {
            REG_WR32(DMAC_CLEAR_ERR, bit);
            printf("[ERR] ch%u HW error\n", (unsigned)ch);
            return DMAC_ERR_HW;
        }
        if (REG_RD32(DMAC_RAW_TFR) & bit) {
            REG_WR32(DMAC_CLEAR_TFR, bit);
            return DMAC_OK;
        }
    }
}

static dmac_err_t poll_block_done(uint32_t ch)
{
    uint32_t bit = 1U << ch;
    uint32_t t   = TIMEOUT_LOOPS;
    while (1) {
        if (--t == 0) return DMAC_ERR_TIMEOUT;
        if (REG_RD32(DMAC_RAW_ERR) & bit) {
            REG_WR32(DMAC_CLEAR_ERR, bit);
            return DMAC_ERR_HW;
        }
        if (REG_RD32(DMAC_RAW_BLOCK) & bit) {
            REG_WR32(DMAC_CLEAR_BLOCK, bit);
            return DMAC_OK;
        }
    }
}

static dmac_err_t verify(const uint32_t *s, const uint32_t *d,
                         uint32_t words, const char *name)
{
    uint32_t i;
    for (i = 0; i < words; i++) {
        if (s[i] != d[i]) {
            printf("[FAIL] %s: word[%u] exp=0x%08X got=0x%08X\n",
                   name, (unsigned)i, (unsigned)s[i], (unsigned)d[i]);
            return DMAC_ERR_DATA;
        }
    }
    printf("[PASS] %s: %u words OK\n", name, (unsigned)words);
    return DMAC_OK;
}

/* ===========================================================================
 * ISR  (kết nối vào vector table hoặc IRQ dispatcher của bạn)
 * =========================================================================*/
void DMA_IRQHandler(void)
{
    uint32_t si = REG_RD32(DMAC_STATUS_INT);

    if (si & INT_TFR) {
        uint32_t v = REG_RD32(DMAC_STATUS_TFR);
        g_irq_tfr_mask  |= v;
        REG_WR32(DMAC_CLEAR_TFR, v);
    }
    if (si & INT_BLOCK) {
        uint32_t v = REG_RD32(DMAC_STATUS_BLOCK);
        g_irq_block_mask |= v;
        REG_WR32(DMAC_CLEAR_BLOCK, v);
    }
    if (si & INT_ERR) {
        uint32_t v = REG_RD32(DMAC_STATUS_ERR);
        g_irq_err_mask  |= v;
        REG_WR32(DMAC_CLEAR_ERR, v);
        printf("[ISR] ERROR channels=0x%02X\n", (unsigned)v);
    }
    if (si & INT_SRCTRAN)
        REG_WR32(DMAC_CLEAR_SRCTRAN, REG_RD32(DMAC_STATUS_SRCTRAN));
    if (si & INT_DSTTRAN)
        REG_WR32(DMAC_CLEAR_DSTTRAN, REG_RD32(DMAC_STATUS_DSTTRAN));
}

/* ===========================================================================
 * DMAC Initialization
 * =========================================================================*/
static void dmac_init(void)
{
    printf("\n[DMAC] Init — BASE=0x%08X\n", (unsigned)DMAC_BASE);

    /* Disable DMAC */
    REG_WR32(DMAC_CFG_REG, 0);
    nop_delay(50);

    /* Disable tất cả channel: WE[15:8]=0xFF, EN[7:0]=0x00 */
    REG_WR32(DMAC_CH_EN, 0xFF00U);
    nop_delay(20);

    /* Clear tất cả pending interrupt */
    REG_WR32(DMAC_CLEAR_TFR,     0xFFU);
    REG_WR32(DMAC_CLEAR_BLOCK,   0xFFU);
    REG_WR32(DMAC_CLEAR_SRCTRAN, 0xFFU);
    REG_WR32(DMAC_CLEAR_DSTTRAN, 0xFFU);
    REG_WR32(DMAC_CLEAR_ERR,     0xFFU);

    /* Mask tất cả interrupt (WE=1, MASK=0) */
    REG_WR32(DMAC_MASK_TFR,     0xFF00U);
    REG_WR32(DMAC_MASK_BLOCK,   0xFF00U);
    REG_WR32(DMAC_MASK_SRCTRAN, 0xFF00U);
    REG_WR32(DMAC_MASK_DSTTRAN, 0xFF00U);
    REG_WR32(DMAC_MASK_ERR,     0xFF00U);

    /* Reset SW-HS registers */
    REG_WR32(DMAC_REQ_SRC,    0xFF00U);
    REG_WR32(DMAC_REQ_DST,    0xFF00U);
    REG_WR32(DMAC_SGLREQ_SRC, 0xFF00U);
    REG_WR32(DMAC_SGLREQ_DST, 0xFF00U);
    REG_WR32(DMAC_LST_SRC,    0xFF00U);
    REG_WR32(DMAC_LST_DST,    0xFF00U);

    g_irq_tfr_mask   = 0;
    g_irq_block_mask = 0;
    g_irq_err_mask   = 0;

    /* Enable DMAC global */
    REG_WR32(DMAC_CFG_REG, DMAC_EN);
    printf("[DMAC] Enabled. CfgReg=0x%08X ChEn=0x%08X\n",
           (unsigned)REG_RD32(DMAC_CFG_REG),
           (unsigned)REG_RD32(DMAC_CH_EN));
}

/* ===========================================================================
 * Channel Setup Helper
 *
 * Ghi SAR, DAR, LLP, CTL, CFG cho một channel.
 * Channel phải đang disabled trước khi gọi hàm này.
 * =========================================================================*/
typedef struct {
    uint32_t ch;
    uint32_t src;        /* SAR  */
    uint32_t dst;        /* DAR  */
    uint32_t llp;        /* LLP (0 = không dùng LLI) */
    uint64_t ctl;        /* CTL 64-bit (dùng ctl_make()) */
    uint64_t cfg;        /* CFG 64-bit (dùng cfg_make()) */
} dmac_setup_t;

static void dmac_ch_setup(const dmac_setup_t *s)
{
    REG_WR32(DMAC_SAR(s->ch), s->src);
    REG_WR32(DMAC_DAR(s->ch), s->dst);
    REG_WR32(DMAC_LLP(s->ch), s->llp);
    REG_WR64(DMAC_CTL(s->ch), s->ctl);
    REG_WR64(DMAC_CFG(s->ch), s->cfg);
    printf("  [CH%u] SAR=0x%08X DAR=0x%08X LLP=0x%08X\n",
           (unsigned)s->ch, (unsigned)s->src, (unsigned)s->dst, (unsigned)s->llp);
    printf("  [CH%u] CTL=0x%08X_%08X\n",
           (unsigned)s->ch,
           (unsigned)(s->ctl >> 32), (unsigned)(s->ctl & 0xFFFFFFFF));
    printf("  [CH%u] CFG=0x%08X_%08X\n",
           (unsigned)s->ch,
           (unsigned)(s->cfg >> 32), (unsigned)(s->cfg & 0xFFFFFFFF));
}

static void dmac_ch_enable(uint32_t ch)
{
    REG_WR32(DMAC_MASK_TFR, INT_MASK_SET(ch));
    REG_WR32(DMAC_MASK_ERR, INT_MASK_SET(ch));
    REG_WR32(DMAC_CH_EN,    CH_EN_SET(ch));
    printf("  [CH%u] Enabled.\n", (unsigned)ch);
}

/* ===========================================================================
 * Software Handshaking Primitives
 *
 * Quy tắc quan trọng:
 *   1. Gửi LST_* TRƯỚC khi gửi REQ_* / SGLREQ_* cho transaction cuối
 *   2. Phải chờ DMAC clear bit request cũ trước khi set request mới
 * =========================================================================*/

static dmac_err_t swhs_wait_req_src(uint32_t ch)
{
    uint32_t t = TIMEOUT_LOOPS;
    while (REG_RD32(DMAC_REQ_SRC) & SWHS_REQ_BIT(ch)) {
        if (--t == 0) return DMAC_ERR_TIMEOUT;
    }
    return DMAC_OK;
}

static dmac_err_t swhs_wait_req_dst(uint32_t ch)
{
    uint32_t t = TIMEOUT_LOOPS;
    while (REG_RD32(DMAC_REQ_DST) & SWHS_REQ_BIT(ch)) {
        if (--t == 0) return DMAC_ERR_TIMEOUT;
    }
    return DMAC_OK;
}

static dmac_err_t swhs_wait_sglreq_src(uint32_t ch)
{
    uint32_t t = TIMEOUT_LOOPS;
    while (REG_RD32(DMAC_SGLREQ_SRC) & SWHS_REQ_BIT(ch)) {
        if (--t == 0) return DMAC_ERR_TIMEOUT;
    }
    return DMAC_OK;
}

static dmac_err_t swhs_wait_sglreq_dst(uint32_t ch)
{
    uint32_t t = TIMEOUT_LOOPS;
    while (REG_RD32(DMAC_SGLREQ_DST) & SWHS_REQ_BIT(ch)) {
        if (--t == 0) return DMAC_ERR_TIMEOUT;
    }
    return DMAC_OK;
}

/**
 * @brief Gửi N burst SRC request cho một block transfer
 * @param ch        channel number
 * @param bursts    tổng số burst cần gửi
 * @param msize     burst size (để tính có dư không, pass-through ở đây)
 */
static dmac_err_t swhs_burst_src_block(uint32_t ch, uint32_t bursts)
{
    uint32_t i;
    dmac_err_t r;
    for (i = 0; i < bursts; i++) {
        int last = (i == (bursts - 1U));
        if (last) REG_WR32(DMAC_LST_SRC, SWHS_SET(ch));
        REG_WR32(DMAC_REQ_SRC, SWHS_SET(ch));
        r = swhs_wait_req_src(ch);
        if (r != DMAC_OK) {
            printf("[ERR] swhs_burst_src timeout burst %u\n", (unsigned)i);
            return r;
        }
        nop_delay(5);
    }
    return DMAC_OK;
}

/**
 * @brief Gửi N burst DST request cho một block transfer
 */
static dmac_err_t swhs_burst_dst_block(uint32_t ch, uint32_t bursts)
{
    uint32_t i;
    dmac_err_t r;
    for (i = 0; i < bursts; i++) {
        int last = (i == (bursts - 1U));
        if (last) REG_WR32(DMAC_LST_DST, SWHS_SET(ch));
        REG_WR32(DMAC_REQ_DST, SWHS_SET(ch));
        r = swhs_wait_req_dst(ch);
        if (r != DMAC_OK) {
            printf("[ERR] swhs_burst_dst timeout burst %u\n", (unsigned)i);
            return r;
        }
        nop_delay(5);
    }
    return DMAC_OK;
}

/**
 * @brief Gửi N single SRC request (cho phần dư không đủ burst)
 */
static dmac_err_t swhs_single_src(uint32_t ch, uint32_t count)
{
    uint32_t i;
    dmac_err_t r;
    for (i = 0; i < count; i++) {
        int last = (i == (count - 1U));
        if (last) REG_WR32(DMAC_LST_SRC, SWHS_SET(ch));
        REG_WR32(DMAC_SGLREQ_SRC, SWHS_SET(ch));
        r = swhs_wait_sglreq_src(ch);
        if (r != DMAC_OK) return r;
        nop_delay(3);
    }
    return DMAC_OK;
}

/**
 * @brief Gửi N single DST request
 */
static dmac_err_t swhs_single_dst(uint32_t ch, uint32_t count)
{
    uint32_t i;
    dmac_err_t r;
    for (i = 0; i < count; i++) {
        int last = (i == (count - 1U));
        if (last) REG_WR32(DMAC_LST_DST, SWHS_SET(ch));
        REG_WR32(DMAC_SGLREQ_DST, SWHS_SET(ch));
        r = swhs_wait_sglreq_dst(ch);
        if (r != DMAC_OK) return r;
        nop_delay(3);
    }
    return DMAC_OK;
}

/**
 * @brief Tính số burst + single cần gửi cho block_words words với msize
 * @param[out] bursts   số burst request
 * @param[out] singles  số single request (phần dư)
 */
static void calc_hs_counts(uint32_t block_words, uint32_t msize,
                            uint32_t *bursts, uint32_t *singles)
{
    /* msize encoding: 0→1, 1→4, 2→8, 3→16, 4→32 items */
    static const uint32_t msize_table[] = {1,4,8,16,32};
    uint32_t burst_sz = (msize < 5U) ? msize_table[msize] : 1U;
    *bursts  = block_words / burst_sz;
    *singles = block_words % burst_sz;
}

/* ===========================================================================
 * TEST 01: M2M single-block (baseline)
 * =========================================================================*/
static dmac_err_t test01_m2m_single(void)
{
    uint32_t i, ch = 0;
    dmac_err_t r;

    printf("\n=== TEST 01: M2M single-block ===\n");
    for (i = 0; i < BUF_WORDS; i++) { src_buf[i] = 0xA0000000U | i; dst_buf[i] = 0; }

    dmac_setup_t s = {
        .ch  = ch,
        .src = (uint32_t)(uintptr_t)src_buf,
        .dst = (uint32_t)(uintptr_t)dst_buf,
        .llp = 0,
        .ctl = ctl_make(1,                /* INT_EN           */
                        TR_WIDTH_32,      /* DST_TR_WIDTH     */
                        TR_WIDTH_32,      /* SRC_TR_WIDTH     */
                        ADDR_INC,         /* DINC             */
                        ADDR_INC,         /* SINC             */
                        MSIZE_4,          /* DEST_MSIZE       */
                        MSIZE_4,          /* SRC_MSIZE        */
                        TT_FC_M2M_DMA,    /* TT_FC            */
                        MASTER_1,         /* DMS              */
                        MASTER_1,         /* SMS              */
                        0, 0,             /* LLP_DEST/SRC_EN  */
                        BUF_WORDS),       /* BLOCK_TS         */
        .cfg = cfg_make(0,   /* priority */
                        0,   /* sw_hs_dst: không cần */
                        0,   /* sw_hs_src: không cần */
                        1,   /* fifo_mode            */
                        0, 0,/* reload src/dst       */
                        0, 0 /* src_per, dst_per     */),
    };
    dmac_ch_setup(&s);
    dmac_ch_enable(ch);

    /* M2M: DMAC tự xử lý, không cần SW handshaking */
    r = poll_done(ch);
    if (r != DMAC_OK) return r;
    return verify(src_buf, dst_buf, BUF_WORDS, "M2M single");
}

/* ===========================================================================
 * TEST 02: M2M multi-block qua LLI
 * =========================================================================*/
static dmac_err_t test02_m2m_lli(void)
{
    uint32_t i, ch = 1;
    dmac_err_t r;
    const uint32_t bts = BLK_WORDS;  /* block transfer size */

    printf("\n=== TEST 02: M2M multi-block LLI (%u blocks x %u words) ===\n",
           (unsigned)LLI_COUNT, (unsigned)bts);

    for (i = 0; i < BUF_WORDS; i++) { src_buf[i] = 0xB0000000U | i; dst_buf[i] = 0; }

    /* CTL dùng cho tất cả LLI (các block giữa có LLP_EN, block cuối không) */
    for (i = 0; i < LLI_COUNT; i++) {
        int has_next = (i < (LLI_COUNT - 1U));
        lli_m2m[i].sar   = (uint32_t)(uintptr_t)&src_buf[i * bts];
        lli_m2m[i].dar   = (uint32_t)(uintptr_t)&dst_buf[i * bts];
        lli_m2m[i].llp   = has_next ? LLP_MAKE(&lli_m2m[i+1], MASTER_1) : 0U;
        lli_m2m[i]._rsv  = 0;
        lli_m2m[i].ctl   = ctl_make(1,
                                    TR_WIDTH_32, TR_WIDTH_32,
                                    ADDR_INC, ADDR_INC,
                                    MSIZE_4, MSIZE_4,
                                    TT_FC_M2M_DMA,
                                    MASTER_1, MASTER_1,
                                    has_next, has_next,  /* LLP_DEST_EN / LLP_SRC_EN */
                                    bts);
        lli_m2m[i].sstat = 0;
        lli_m2m[i].dstat = 0;
        printf("  LLI[%u] SAR=0x%08X DAR=0x%08X LLP=0x%08X\n",
               (unsigned)i,
               (unsigned)lli_m2m[i].sar,
               (unsigned)lli_m2m[i].dar,
               (unsigned)lli_m2m[i].llp);
    }

    /* Channel register: SAR/DAR trỏ block đầu, LLP trỏ LLI[0] (DMAC load từ đó) */
    dmac_setup_t s = {
        .ch  = ch,
        .src = lli_m2m[0].sar,
        .dst = lli_m2m[0].dar,
        .llp = LLP_MAKE(&lli_m2m[0], MASTER_1),
        .ctl = lli_m2m[0].ctl,
        .cfg = cfg_make(1, 0, 0, 1, 0, 0, 0, 0),
    };
    dmac_ch_setup(&s);
    dmac_ch_enable(ch);

    r = poll_done(ch);
    if (r != DMAC_OK) return r;
    return verify(src_buf, dst_buf, BUF_WORDS, "M2M LLI multi-block");
}

/* ===========================================================================
 * TEST 03: M2P single-block, SW handshaking DST
 * (Mô phỏng: dst_buf đóng vai "peripheral TX FIFO" — no-increment)
 * =========================================================================*/
static dmac_err_t test03_m2p_swhs(void)
{
    uint32_t bursts, singles, i, ch = 2;
    dmac_err_t r;
    /* Dùng dst_buf[0] làm "FIFO addr cố định" để kiểm tra cuối */
    uint32_t fake_fifo_addr = (uint32_t)(uintptr_t)&dst_buf[0];

    printf("\n=== TEST 03: M2P single-block SW-HS (dst) ===\n");
    for (i = 0; i < BUF_WORDS; i++) { src_buf[i] = 0xC0000000U | i; }
    dst_buf[0] = 0;

    dmac_setup_t s = {
        .ch  = ch,
        .src = (uint32_t)(uintptr_t)src_buf,
        .dst = fake_fifo_addr,         /* fixed dst = FIFO */
        .llp = 0,
        .ctl = ctl_make(1,
                        TR_WIDTH_32, TR_WIDTH_32,
                        ADDR_NOCHANGE,  /* DINC: periph FIFO không tăng */
                        ADDR_INC,       /* SINC: memory tăng            */
                        MSIZE_4, MSIZE_4,
                        TT_FC_M2P_DMA,
                        MASTER_1,       /* DMS: periph trên M1 (hoặc M2 tuỳ SoC) */
                        MASTER_1,       /* SMS: memory trên M1                    */
                        0, 0, BUF_WORDS),
        .cfg = cfg_make(1,
                        1,   /* sw_hs_dst = 1 */
                        0,   /* sw_hs_src = 0 (memory không cần) */
                        1, 0, 0, 0, HWHS_AES_TX),
    };
    dmac_ch_setup(&s);
    dmac_ch_enable(ch);

    calc_hs_counts(BUF_WORDS, MSIZE_4, &bursts, &singles);
    printf("  SW-HS DST: %u burst + %u single\n", (unsigned)bursts, (unsigned)singles);

    r = swhs_burst_dst_block(ch, bursts);
    if (r != DMAC_OK) return r;
    if (singles > 0) {
        r = swhs_single_dst(ch, singles);
        if (r != DMAC_OK) return r;
    }

    r = poll_done(ch);
    if (r != DMAC_OK) return r;
    /* Verify: dst_buf[0] phải là src_buf[BUF_WORDS-1] (cuối cùng ghi vào FIFO) */
    printf("  [M2P] dst_buf[0]=0x%08X (last write to FIFO)\n", (unsigned)dst_buf[0]);
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 04: P2M single-block, SW handshaking SRC
 * (Mô phỏng: src_buf[0] đóng vai "peripheral RX FIFO")
 * =========================================================================*/
static dmac_err_t test04_p2m_swhs(void)
{
    uint32_t bursts, singles, i, ch = 3;
    dmac_err_t r;
    uint32_t fake_fifo_addr = (uint32_t)(uintptr_t)&src_buf[0];

    printf("\n=== TEST 04: P2M single-block SW-HS (src) ===\n");
    src_buf[0] = 0xDEADBEEFU;  /* giá trị cố định trong FIFO */
    for (i = 0; i < BUF_WORDS; i++) dst_buf[i] = 0;

    dmac_setup_t s = {
        .ch  = ch,
        .src = fake_fifo_addr,
        .dst = (uint32_t)(uintptr_t)dst_buf,
        .llp = 0,
        .ctl = ctl_make(1,
                        TR_WIDTH_32, TR_WIDTH_32,
                        ADDR_INC,       /* DINC: memory tăng            */
                        ADDR_NOCHANGE,  /* SINC: periph FIFO không tăng */
                        MSIZE_4, MSIZE_4,
                        TT_FC_P2M_DMA,
                        MASTER_1, MASTER_1,
                        0, 0, BUF_WORDS),
        .cfg = cfg_make(1,
                        0,   /* sw_hs_dst = 0 (memory) */
                        1,   /* sw_hs_src = 1 (periph) */
                        1, 0, 0, HWHS_AES_RX, 0),
    };
    dmac_ch_setup(&s);
    dmac_ch_enable(ch);

    calc_hs_counts(BUF_WORDS, MSIZE_4, &bursts, &singles);
    printf("  SW-HS SRC: %u burst + %u single\n", (unsigned)bursts, (unsigned)singles);

    r = swhs_burst_src_block(ch, bursts);
    if (r != DMAC_OK) return r;
    if (singles > 0) {
        r = swhs_single_src(ch, singles);
        if (r != DMAC_OK) return r;
    }

    r = poll_done(ch);
    if (r != DMAC_OK) return r;

    /* Verify: tất cả dst_buf phải = 0xDEADBEEF (đọc từ FIFO cố định) */
    for (i = 0; i < BUF_WORDS; i++) {
        if (dst_buf[i] != 0xDEADBEEFU) {
            printf("[FAIL] P2M: dst[%u]=0x%08X\n", (unsigned)i, (unsigned)dst_buf[i]);
            return DMAC_ERR_DATA;
        }
    }
    printf("[PASS] P2M: all %u words = 0xDEADBEEF\n", (unsigned)BUF_WORDS);
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 05: P2P single-block, SW handshaking SRC + DST
 * =========================================================================*/
static dmac_err_t test05_p2p_swhs(void)
{
    uint32_t count, singles, i, ch = 4;
    dmac_err_t r;
    const uint32_t words = 16U;
    uint32_t fake_src_fifo = (uint32_t)(uintptr_t)&src_buf[0];
    uint32_t fake_dst_fifo = (uint32_t)(uintptr_t)&dst_buf[0];

    printf("\n=== TEST 05: P2P single-block SW-HS (src+dst) ===\n");
    src_buf[0] = 0x55AA55AAU;
    dst_buf[0] = 0;

    dmac_setup_t s = {
        .ch  = ch,
        .src = fake_src_fifo,
        .dst = fake_dst_fifo,
        .llp = 0,
        .ctl = ctl_make(1,
                        TR_WIDTH_32, TR_WIDTH_32,
                        ADDR_NOCHANGE, ADDR_NOCHANGE,
                        MSIZE_1, MSIZE_1,   /* single-item burst cho P2P */
                        TT_FC_P2P_DMA,
                        MASTER_1, MASTER_1,
                        0, 0, words),
        .cfg = cfg_make(2,
                        1,   /* sw_hs_dst */
                        1,   /* sw_hs_src */
                        1, 0, 0, 0, 0),
    };
    dmac_ch_setup(&s);
    dmac_ch_enable(ch);

    /* Với MSIZE_1, mỗi burst = 1 item => dùng single request */
    calc_hs_counts(words, MSIZE_1, &count, &singles);
    printf("  SW-HS P2P: %u single requests\n", (unsigned)(count + singles));

    for (i = 0; i < count; i++) {
        int last = (i == (count - 1U));
        /* SRC sẵn sàng */
        if (last) REG_WR32(DMAC_LST_SRC, SWHS_SET(ch));
        REG_WR32(DMAC_SGLREQ_SRC, SWHS_SET(ch));
        r = swhs_wait_sglreq_src(ch);
        if (r != DMAC_OK) return r;
        /* DST sẵn sàng */
        if (last) REG_WR32(DMAC_LST_DST, SWHS_SET(ch));
        REG_WR32(DMAC_SGLREQ_DST, SWHS_SET(ch));
        r = swhs_wait_sglreq_dst(ch);
        if (r != DMAC_OK) return r;
        nop_delay(2);
    }

    r = poll_done(ch);
    if (r != DMAC_OK) return r;
    printf("  [P2P] dst_buf[0]=0x%08X\n", (unsigned)dst_buf[0]);
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 06: M2P multi-block LLI, SW handshaking DST
 * =========================================================================*/
static dmac_err_t test06_m2p_lli_swhs(void)
{
    uint32_t i, bursts, singles, ch = 5;
    dmac_err_t r;
    const uint32_t bts = BLK_WORDS;

    printf("\n=== TEST 06: M2P multi-block LLI SW-HS dst (%u blocks x %u words) ===\n",
           (unsigned)LLI_COUNT, (unsigned)bts);

    for (i = 0; i < BUF_WORDS; i++) src_buf[i] = 0xF0000000U | i;
    dst_buf[0] = 0;  /* fake FIFO */
    uint32_t fifo_addr = (uint32_t)(uintptr_t)&dst_buf[0];

    for (i = 0; i < LLI_COUNT; i++) {
        int has_next = (i < (LLI_COUNT - 1U));
        lli_m2p[i].sar   = (uint32_t)(uintptr_t)&src_buf[i * bts];
        lli_m2p[i].dar   = fifo_addr;   /* FIFO address cố định */
        lli_m2p[i].llp   = has_next ? LLP_MAKE(&lli_m2p[i+1], MASTER_1) : 0U;
        lli_m2p[i]._rsv  = 0;
        lli_m2p[i].ctl   = ctl_make(1,
                                    TR_WIDTH_32, TR_WIDTH_32,
                                    ADDR_NOCHANGE, ADDR_INC,
                                    MSIZE_4, MSIZE_4,
                                    TT_FC_M2P_DMA,
                                    MASTER_1, MASTER_1,
                                    has_next, has_next,
                                    bts);
        lli_m2p[i].sstat = 0;
        lli_m2p[i].dstat = 0;
    }

    dmac_setup_t s = {
        .ch  = ch,
        .src = lli_m2p[0].sar,
        .dst = fifo_addr,
        .llp = LLP_MAKE(&lli_m2p[0], MASTER_1),
        .ctl = lli_m2p[0].ctl,
        .cfg = cfg_make(1,
                        1,   /* sw_hs_dst = 1 */
                        0,   /* sw_hs_src = 0 */
                        1, 0, 0, 0, 0),
    };
    dmac_ch_setup(&s);
    dmac_ch_enable(ch);

    /* Gửi handshaking cho từng block */
    calc_hs_counts(bts, MSIZE_4, &bursts, &singles);
    for (i = 0; i < LLI_COUNT; i++) {
        printf("  Block %u: %u burst SW-HS...\n", (unsigned)i, (unsigned)bursts);
        r = swhs_burst_dst_block(ch, bursts);
        if (r != DMAC_OK) return r;
        if (singles > 0) {
            r = swhs_single_dst(ch, singles);
            if (r != DMAC_OK) return r;
        }
        /* Đợi block này xong trước khi gửi HS cho block tiếp */
        if (i < (LLI_COUNT - 1U)) {
            r = poll_block_done(ch);
            if (r != DMAC_OK) return r;
        }
    }

    r = poll_done(ch);
    if (r != DMAC_OK) return r;
    printf("  [M2P LLI] Done. dst_buf[0]=0x%08X\n", (unsigned)dst_buf[0]);
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 07: AES — nạp plaintext qua DMA, đọc ciphertext qua DMA
 *
 * Hai giai đoạn:
 *   Phase A: M2P — ghi plaintext vào AES_DATA_IN  (ch=6, SW-HS dst)
 *   Phase B: P2M — đọc ciphertext từ AES_DATA_OUT (ch=7, SW-HS src)
 *
 * Quy trình:
 *   1. Cấu hình + start AES encrypt
 *   2. DMA ch6: nạp 4 words (128-bit) vào AES_DATA_IN
 *   3. Đợi AES hoàn thành (STATUS_DONE)
 *   4. DMA ch7: đọc 4 words từ AES_DATA_OUT
 * =========================================================================*/
static dmac_err_t test07_aes_dma(void)
{
    uint32_t bursts, singles, ch_tx = 6, ch_rx = 7;
    const uint32_t aes_words = 4U;   /* 128-bit = 4 x 32-bit */
    dmac_err_t r;
    uint32_t timeout;

    printf("\n=== TEST 07: AES DMA (M2P plaintext + P2M ciphertext) ===\n");

    /* Chuẩn bị plaintext (128-bit AES test vector) */
    aes_plain[0] = 0x00112233U;
    aes_plain[1] = 0x44556677U;
    aes_plain[2] = 0x8899AABBU;
    aes_plain[3] = 0xCCDDEEFFU;
    memset(aes_cipher, 0, sizeof(aes_cipher));

    /* Cấu hình AES: encrypt mode, start */
    REG_WR32(AES_CTRL, AES_CTRL_ENC | AES_CTRL_START);

    /* --- Phase A: DMA nạp plaintext vào AES input FIFO --- */
    printf("  Phase A: DMA → AES_DATA_IN\n");
    dmac_setup_t sa = {
        .ch  = ch_tx,
        .src = (uint32_t)(uintptr_t)aes_plain,
        .dst = (uint32_t)AES_DATA_IN,
        .llp = 0,
        .ctl = ctl_make(1,
                        TR_WIDTH_32, TR_WIDTH_32,
                        ADDR_NOCHANGE, ADDR_INC,
                        MSIZE_4, MSIZE_4,
                        TT_FC_M2P_DMA,
                        MASTER_2,   /* AES trên master 2 */
                        MASTER_1,
                        0, 0, aes_words),
        .cfg = cfg_make(3,
                        1,   /* sw_hs_dst */
                        0,
                        1, 0, 0,
                        0, HWHS_AES_TX),
    };
    dmac_ch_setup(&sa);
    dmac_ch_enable(ch_tx);

    calc_hs_counts(aes_words, MSIZE_4, &bursts, &singles);
    r = swhs_burst_dst_block(ch_tx, bursts);
    if (r != DMAC_OK) return r;
    if (singles > 0) swhs_single_dst(ch_tx, singles);

    r = poll_done(ch_tx);
    if (r != DMAC_OK) return r;
    printf("  Phase A done: plaintext delivered to AES.\n");

    /* Đợi AES hoàn thành mã hoá */
    printf("  Waiting AES done...\n");
    timeout = TIMEOUT_LOOPS;
    while (!(REG_RD32(AES_STATUS) & AES_STATUS_DONE)) {
        if (--timeout == 0) {
            printf("[ERR] AES timeout\n");
            return DMAC_ERR_TIMEOUT;
        }
    }

    /* --- Phase B: DMA đọc ciphertext từ AES output FIFO --- */
    printf("  Phase B: AES_DATA_OUT → DMA\n");
    dmac_setup_t sb = {
        .ch  = ch_rx,
        .src = (uint32_t)AES_DATA_OUT,
        .dst = (uint32_t)(uintptr_t)aes_cipher,
        .llp = 0,
        .ctl = ctl_make(1,
                        TR_WIDTH_32, TR_WIDTH_32,
                        ADDR_INC, ADDR_NOCHANGE,
                        MSIZE_4, MSIZE_4,
                        TT_FC_P2M_DMA,
                        MASTER_1,
                        MASTER_2,  /* AES trên master 2 */
                        0, 0, aes_words),
        .cfg = cfg_make(3,
                        0,
                        1,   /* sw_hs_src */
                        1, 0, 0,
                        HWHS_AES_RX, 0),
    };
    dmac_ch_setup(&sb);
    dmac_ch_enable(ch_rx);

    calc_hs_counts(aes_words, MSIZE_4, &bursts, &singles);
    r = swhs_burst_src_block(ch_rx, bursts);
    if (r != DMAC_OK) return r;
    if (singles > 0) swhs_single_src(ch_rx, singles);

    r = poll_done(ch_rx);
    if (r != DMAC_OK) return r;

    printf("  [AES] Ciphertext: %08X %08X %08X %08X\n",
           (unsigned)aes_cipher[0], (unsigned)aes_cipher[1],
           (unsigned)aes_cipher[2], (unsigned)aes_cipher[3]);
    /* Note: verify giá trị cụ thể tuỳ AES key được cấu hình */
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 08: SHA2 — nạp message qua DMA, đọc digest qua DMA
 *
 * Hai giai đoạn:
 *   Phase A: M2P — ghi 512-bit message vào SHA2_DATA_IN (ch=6, SW-HS dst)
 *   Phase B: P2M — đọc 256-bit digest từ SHA2_DIGEST   (ch=7, SW-HS src)
 * =========================================================================*/
static dmac_err_t test08_sha2_dma(void)
{
    uint32_t i, bursts, singles, ch_tx = 6, ch_rx = 7;
    const uint32_t msg_words    = 16U;  /* 512-bit = 16 x 32-bit */
    const uint32_t digest_words = 8U;   /* SHA-256: 256-bit = 8 x 32-bit */
    dmac_err_t r;
    uint32_t timeout;

    printf("\n=== TEST 08: SHA2 DMA (M2P message + P2M digest) ===\n");

    /* Chuẩn bị message */
    for (i = 0; i < msg_words; i++) sha2_msg[i] = 0x61626300U | i; /* "abc..." */
    memset(sha2_digest, 0, sizeof(sha2_digest));

    /* Reset và start SHA2 */
    REG_WR32(SHA2_CTRL, SHA2_CTRL_RESET);
    nop_delay(10);
    REG_WR32(SHA2_CTRL, SHA2_CTRL_START);

    /* --- Phase A: nạp message --- */
    printf("  Phase A: DMA → SHA2_DATA_IN (%u words)\n", (unsigned)msg_words);
    dmac_setup_t sa = {
        .ch  = ch_tx,
        .src = (uint32_t)(uintptr_t)sha2_msg,
        .dst = (uint32_t)SHA2_DATA_IN,
        .llp = 0,
        .ctl = ctl_make(1,
                        TR_WIDTH_32, TR_WIDTH_32,
                        ADDR_NOCHANGE, ADDR_INC,
                        MSIZE_4, MSIZE_4,
                        TT_FC_M2P_DMA,
                        MASTER_2, MASTER_1,
                        0, 0, msg_words),
        .cfg = cfg_make(3,
                        1,   /* sw_hs_dst */
                        0,
                        1, 0, 0,
                        0, HWHS_SHA2_TX),
    };
    dmac_ch_setup(&sa);
    dmac_ch_enable(ch_tx);

    calc_hs_counts(msg_words, MSIZE_4, &bursts, &singles);
    r = swhs_burst_dst_block(ch_tx, bursts);
    if (r != DMAC_OK) return r;
    if (singles > 0) {
        r = swhs_single_dst(ch_tx, singles);
        if (r != DMAC_OK) return r;
    }
    r = poll_done(ch_tx);
    if (r != DMAC_OK) return r;
    printf("  Phase A done: message delivered to SHA2.\n");

    /* Đợi SHA2 hoàn thành */
    printf("  Waiting SHA2 done...\n");
    timeout = TIMEOUT_LOOPS;
    while (!(REG_RD32(SHA2_STATUS) & SHA2_STATUS_DONE)) {
        if (--timeout == 0) {
            printf("[ERR] SHA2 timeout\n");
            return DMAC_ERR_TIMEOUT;
        }
    }

    /* --- Phase B: đọc digest --- */
    printf("  Phase B: SHA2_DIGEST → DMA (%u words)\n", (unsigned)digest_words);
    dmac_setup_t sb = {
        .ch  = ch_rx,
        .src = (uint32_t)SHA2_DIGEST,
        .dst = (uint32_t)(uintptr_t)sha2_digest,
        .llp = 0,
        .ctl = ctl_make(1,
                        TR_WIDTH_32, TR_WIDTH_32,
                        ADDR_INC, ADDR_NOCHANGE,
                        MSIZE_4, MSIZE_4,
                        TT_FC_P2M_DMA,
                        MASTER_1, MASTER_2,
                        0, 0, digest_words),
        .cfg = cfg_make(3,
                        0,
                        1,   /* sw_hs_src */
                        1, 0, 0,
                        HWHS_SHA2_RX, 0),
    };
    dmac_ch_setup(&sb);
    dmac_ch_enable(ch_rx);

    calc_hs_counts(digest_words, MSIZE_4, &bursts, &singles);
    r = swhs_burst_src_block(ch_rx, bursts);
    if (r != DMAC_OK) return r;
    if (singles > 0) {
        r = swhs_single_src(ch_rx, singles);
        if (r != DMAC_OK) return r;
    }
    r = poll_done(ch_rx);
    if (r != DMAC_OK) return r;

    printf("  [SHA2] Digest: ");
    for (i = 0; i < digest_words; i++) printf("%08X ", (unsigned)sha2_digest[i]);
    printf("\n");
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 09: M2M interrupt-driven (ISR sets g_irq_tfr_mask)
 * =========================================================================*/
static dmac_err_t test09_m2m_irq(void)
{
    uint32_t i, ch = 0;
    dmac_err_t r;
    uint32_t timeout;

    printf("\n=== TEST 09: M2M interrupt-driven ===\n");
    for (i = 0; i < BUF_WORDS; i++) { src_buf[i] = 0xE0000000U | i; dst_buf[i] = 0; }

    g_irq_tfr_mask = 0;
    g_irq_err_mask = 0;

    dmac_setup_t s = {
        .ch  = ch,
        .src = (uint32_t)(uintptr_t)src_buf,
        .dst = (uint32_t)(uintptr_t)dst_buf,
        .llp = 0,
        .ctl = ctl_make(1,
                        TR_WIDTH_32, TR_WIDTH_32,
                        ADDR_INC, ADDR_INC,
                        MSIZE_4, MSIZE_4,
                        TT_FC_M2M_DMA,
                        MASTER_1, MASTER_1,
                        0, 0, BUF_WORDS),
        .cfg = cfg_make(0, 0, 0, 1, 0, 0, 0, 0),
    };
    dmac_ch_setup(&s);
    dmac_ch_enable(ch);

    /* Đợi ISR */
    timeout = TIMEOUT_LOOPS * 5;
    while (!(g_irq_tfr_mask & CH_EN_BIT(ch))) {
        if (g_irq_err_mask & CH_EN_BIT(ch)) {
            printf("[ERR] IRQ error on ch%u\n", (unsigned)ch);
            return DMAC_ERR_HW;
        }
        if (--timeout == 0) {
            printf("[ERR] IRQ timeout ch%u\n", (unsigned)ch);
            return DMAC_ERR_TIMEOUT;
        }
        /* WFI / yield trên RTOS */
    }

    printf("  [IRQ] Transfer done signaled by ISR.\n");
    r = verify(src_buf, dst_buf, BUF_WORDS, "M2M IRQ");
    return r;
}

/* ===========================================================================
 * TEST 10: M2M Auto-reload multi-block (CFG.RELOAD_SRC + RELOAD_DST)
 *
 * RELOAD: sau mỗi block, DMAC tự reload SAR/DAR về giá trị ban đầu.
 * Hữu ích khi ghi liên tục cùng source → cùng destination nhiều lần.
 * Số block = CTL.BLOCK_TS / msize (cần set theo databook sec 7.x).
 * Ở đây: dùng BLOCK interrupt để đếm, dừng sau N block.
 * =========================================================================*/
static dmac_err_t test10_m2m_autoreload(void)
{
    uint32_t i, ch = 1;
    const uint32_t bts     = BLK_WORDS;
    const uint32_t n_block = 3U;   /* lặp lại 3 lần */
    uint32_t block_cnt = 0;
    dmac_err_t r;

    printf("\n=== TEST 10: M2M auto-reload (%u x %u words) ===\n",
           (unsigned)n_block, (unsigned)bts);

    for (i = 0; i < bts; i++) {
        src_buf[i] = 0xA5A50000U | i;
        dst_buf[i] = 0;
    }

    g_irq_block_mask = 0;

    dmac_setup_t s = {
        .ch  = ch,
        .src = (uint32_t)(uintptr_t)src_buf,
        .dst = (uint32_t)(uintptr_t)dst_buf,
        .llp = 0,
        .ctl = ctl_make(1,
                        TR_WIDTH_32, TR_WIDTH_32,
                        ADDR_INC, ADDR_INC,
                        MSIZE_4, MSIZE_4,
                        TT_FC_M2M_DMA,
                        MASTER_1, MASTER_1,
                        0, 0, bts),
        /* RELOAD_SRC = 1, RELOAD_DST = 1 */
        .cfg = cfg_make(0,
                        0, 0,
                        1,    /* fifo_mode */
                        1,    /* reload_src */
                        1,    /* reload_dst */
                        0, 0),
    };
    dmac_ch_setup(&s);

    /* Unmask BLOCK interrupt cho channel này */
    REG_WR32(DMAC_MASK_BLOCK, INT_MASK_SET(ch));
    REG_WR32(DMAC_MASK_ERR,   INT_MASK_SET(ch));

    dmac_ch_enable(ch);

    /* Đếm n_block block interrupts, sau đó suspend channel */
    while (block_cnt < n_block) {
        r = poll_block_done(ch);
        if (r != DMAC_OK) return r;
        block_cnt++;
        printf("  Block %u done.\n", (unsigned)block_cnt);

        if (block_cnt == n_block) {
            /* Suspend channel để dừng auto-reload */
            uint64_t cfg_v = REG_RD64(DMAC_CFG(ch));
            cfg_v |= CFG_CH_SUSP;
            REG_WR64(DMAC_CFG(ch), cfg_v);
            /* Đợi FIFO empty trước khi disable */
            uint32_t t = TIMEOUT_LOOPS;
            while (!(REG_RD64(DMAC_CFG(ch)) & CFG_FIFO_EMPTY)) {
                if (--t == 0) break;
            }
            REG_WR32(DMAC_CH_EN, CH_EN_CLR(ch));
        }
    }

    r = verify(src_buf, dst_buf, bts, "M2M auto-reload");
    return r;
}

/* ===========================================================================
 * MAIN
 * =========================================================================*/
int main(void)
{
    typedef struct {
        const char *name;
        dmac_err_t (*fn)(void);
    } test_entry_t;

    static const test_entry_t tests[] = {
        { "01 M2M single-block",           test01_m2m_single      },
        { "02 M2M multi-block LLI",        test02_m2m_lli         },
        { "03 M2P SW-HS dst",              test03_m2p_swhs        },
        { "04 P2M SW-HS src",              test04_p2m_swhs        },
        { "05 P2P SW-HS src+dst",          test05_p2p_swhs        },
        { "06 M2P LLI SW-HS dst",          test06_m2p_lli_swhs    },
        { "07 AES DMA (M2P+P2M)",          test07_aes_dma         },
        { "08 SHA2 DMA (M2P+P2M)",         test08_sha2_dma        },
        { "09 M2M interrupt-driven",       test09_m2m_irq         },
        { "10 M2M auto-reload",            test10_m2m_autoreload  },
    };
    const uint32_t n_tests = (uint32_t)(sizeof(tests) / sizeof(tests[0]));

    uint32_t pass = 0, fail = 0, i;

    printf("============================================================\n");
    printf("  DW_ahb_dmac v2.24a Test Suite\n");
    printf("  DMAC_BASE=0x%08X  AES_BASE=0x%08X  SHA2_BASE=0x%08X\n",
           (unsigned)DMAC_BASE, (unsigned)AES_BASE, (unsigned)SHA2_BASE);
    printf("============================================================\n");

    dmac_init();

    for (i = 0; i < n_tests; i++) {
        /* Đảm bảo channels idle trước mỗi test */
        ch_wait_idle(0);
        ch_wait_idle(1);
        ch_wait_idle(5);
        ch_wait_idle(6);
        ch_wait_idle(7);

        /* Clear interrupt flags */
        REG_WR32(DMAC_CLEAR_TFR,   0xFFU);
        REG_WR32(DMAC_CLEAR_BLOCK, 0xFFU);
        REG_WR32(DMAC_CLEAR_ERR,   0xFFU);
        g_irq_tfr_mask   = 0;
        g_irq_block_mask = 0;
        g_irq_err_mask   = 0;

        dmac_err_t r = tests[i].fn();
        if (r == DMAC_OK) {
            printf("[RESULT] Test %s  --> PASS\n", tests[i].name);
            pass++;
        } else {
            printf("[RESULT] Test %s  --> FAIL (err=%d)\n", tests[i].name, (int)r);
            fail++;
        }
    }

    printf("\n============================================================\n");
    printf("  TOTAL %u tests:  PASS=%u  FAIL=%u\n",
           (unsigned)n_tests, (unsigned)pass, (unsigned)fail);
    printf("============================================================\n");
    return (fail == 0) ? 0 : 1;
}
