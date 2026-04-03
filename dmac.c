/**
 * @file  dw_ahb_dmac_test.c
 * @brief DW_ahb_dmac v2.24a – Test Suite
 *
 * Không dùng libc (memset/memcmp thay bằng hàm local).
 * Có readback register sau khi ghi để xác nhận HW nhận đúng.
 *
 * Test list:
 *   01 – M2M single-block
 *   02 – M2M multi-block LLI
 *   03 – M2P single-block, SW-HS dst
 *   04 – P2M single-block, SW-HS src
 *   05 – P2P single-block, SW-HS src+dst
 *   06 – M2P multi-block LLI, SW-HS dst
 *   07 – AES: M2P plaintext + P2M ciphertext
 *   08 – SHA2: M2P message + P2M digest
 *   09 – M2M interrupt-driven
 *   10 – M2M auto-reload (CFG.RELOAD_SRC/DST)
 *
 * Peripheral addresses (khai báo – chỉnh theo SoC):
 *   AES_BASE  = 0x71000000
 *   SHA2_BASE = 0x72000000
 */

#include <stdint.h>
#include <stdio.h>
#include "dw_ahb_dmac_regs.h"

/* ===========================================================================
 * Peripheral addresses
 * =========================================================================*/
#ifndef AES_BASE
#define AES_BASE            0x71000000UL
#endif
#ifndef SHA2_BASE
#define SHA2_BASE           0x72000000UL
#endif

/* AES register offsets */
#define AES_DATA_IN_OFF     0x040U
#define AES_DATA_OUT_OFF    0x060U
#define AES_CTRL_OFF        0x080U
#define AES_STATUS_OFF      0x084U
#define AES_CTRL_START      (1U << 0)
#define AES_CTRL_ENC        (1U << 1)
#define AES_STATUS_DONE     (1U << 0)
#define AES_DATA_IN         (AES_BASE  + AES_DATA_IN_OFF)
#define AES_DATA_OUT        (AES_BASE  + AES_DATA_OUT_OFF)
#define AES_CTRL            (AES_BASE  + AES_CTRL_OFF)
#define AES_STATUS          (AES_BASE  + AES_STATUS_OFF)

/* SHA2 register offsets */
#define SHA2_DATA_IN_OFF    0x000U
#define SHA2_DIGEST_OFF     0x020U
#define SHA2_CTRL_OFF       0x080U
#define SHA2_STATUS_OFF     0x084U
#define SHA2_CTRL_START     (1U << 0)
#define SHA2_CTRL_RESET     (1U << 1)
#define SHA2_STATUS_DONE    (1U << 0)
#define SHA2_DATA_IN        (SHA2_BASE + SHA2_DATA_IN_OFF)
#define SHA2_DIGEST         (SHA2_BASE + SHA2_DIGEST_OFF)
#define SHA2_CTRL           (SHA2_BASE + SHA2_CTRL_OFF)
#define SHA2_STATUS         (SHA2_BASE + SHA2_STATUS_OFF)

/* HW Handshake interface numbers (assign theo SoC) */
#define HWHS_AES_TX         0U
#define HWHS_AES_RX         1U
#define HWHS_SHA2_TX        2U
#define HWHS_SHA2_RX        3U

/* ===========================================================================
 * Test parameters
 * =========================================================================*/
#define BUF_WORDS           64U     /* 256 bytes                 */
#define LLI_BLOCKS          4U      /* số block trong multi-block*/
#define BLK_WORDS           16U     /* words/block = BUF_WORDS/LLI_BLOCKS */
#define TIMEOUT             1000000U

/* ===========================================================================
 * Buffers
 * =========================================================================*/
static uint32_t src_buf[BUF_WORDS]  __attribute__((aligned(4)));
static uint32_t dst_buf[BUF_WORDS]  __attribute__((aligned(4)));
static uint32_t aes_plain[4]        __attribute__((aligned(4)));
static uint32_t aes_cipher[4]       __attribute__((aligned(4)));
static uint32_t sha2_msg[16]        __attribute__((aligned(4)));
static uint32_t sha2_digest[8]      __attribute__((aligned(4)));

/* LLI arrays – align 4 để LLP_MAKE hợp lệ */
static dmac_lli_t lli_a[LLI_BLOCKS] __attribute__((aligned(4)));
static dmac_lli_t lli_b[LLI_BLOCKS] __attribute__((aligned(4)));

/* ===========================================================================
 * ISR flags
 * =========================================================================*/
static volatile uint32_t g_irq_tfr   = 0;
static volatile uint32_t g_irq_block = 0;
static volatile uint32_t g_irq_err   = 0;

/* ===========================================================================
 * Error codes
 * =========================================================================*/
typedef enum {
    DMAC_OK          = 0,
    DMAC_ERR_TIMEOUT = 1,
    DMAC_ERR_HW      = 2,
    DMAC_ERR_DATA    = 3,
    DMAC_ERR_REG     = 4,   /* register readback mismatch */
} dmac_err_t;

/* ===========================================================================
 * Bare-metal string utilities (không dùng libc)
 * =========================================================================*/
static void bm_memset32(uint32_t *buf, uint32_t val, uint32_t words)
{
    uint32_t i;
    for (i = 0; i < words; i++) buf[i] = val;
}

static int bm_memcmp32(const uint32_t *a, const uint32_t *b, uint32_t words)
{
    uint32_t i;
    for (i = 0; i < words; i++) {
        if (a[i] != b[i]) return (int)i + 1;
    }
    return 0;
}

/* ===========================================================================
 * Register verify helper – đọc lại sau khi ghi
 * =========================================================================*/
static dmac_err_t reg_verify32(uint32_t addr, uint32_t expected,
                                uint32_t mask, const char *name)
{
    uint32_t got = REG_RD32(addr) & mask;
    uint32_t exp = expected & mask;
    if (got != exp) {
        printf("  [REG-CHK FAIL] %s @ 0x%08X: wrote 0x%08X got 0x%08X (mask 0x%08X)\n",
               name, (unsigned)addr, (unsigned)exp, (unsigned)got, (unsigned)mask);
        return DMAC_ERR_REG;
    }
    return DMAC_OK;
}

/* ===========================================================================
 * Polling helpers
 * =========================================================================*/
static int ch_is_busy(uint32_t ch) {
    return (int)(REG_RD32(DMAC_CH_EN) & CH_EN_BIT(ch));
}

static dmac_err_t ch_wait_idle(uint32_t ch)
{
    uint32_t t = TIMEOUT;
    while (ch_is_busy(ch)) {
        if (--t == 0) {
            printf("  [ERR] ch%u wait-idle timeout\n", (unsigned)ch);
            return DMAC_ERR_TIMEOUT;
        }
    }
    return DMAC_OK;
}

static dmac_err_t poll_tfr_done(uint32_t ch)
{
    uint32_t bit = 1U << ch;
    uint32_t t   = TIMEOUT;
    while (1) {
        if (--t == 0) {
            printf("  [ERR] ch%u poll_done timeout  RAW_TFR=0x%X RAW_ERR=0x%X ChEn=0x%X\n",
                   (unsigned)ch,
                   (unsigned)REG_RD32(DMAC_RAW_TFR),
                   (unsigned)REG_RD32(DMAC_RAW_ERR),
                   (unsigned)REG_RD32(DMAC_CH_EN));
            return DMAC_ERR_TIMEOUT;
        }
        if (REG_RD32(DMAC_RAW_ERR) & bit) {
            REG_WR32(DMAC_CLEAR_ERR, bit);
            printf("  [ERR] ch%u HW error\n", (unsigned)ch);
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
    uint32_t t   = TIMEOUT;
    while (1) {
        if (--t == 0) return DMAC_ERR_TIMEOUT;
        if (REG_RD32(DMAC_RAW_ERR)   & bit) { REG_WR32(DMAC_CLEAR_ERR,   bit); return DMAC_ERR_HW; }
        if (REG_RD32(DMAC_RAW_BLOCK) & bit) { REG_WR32(DMAC_CLEAR_BLOCK, bit); return DMAC_OK; }
    }
}

static dmac_err_t verify_buf(const uint32_t *s, const uint32_t *d,
                              uint32_t words, const char *name)
{
    int r = bm_memcmp32(s, d, words);
    if (r) {
        uint32_t idx = (uint32_t)(r - 1);
        printf("  [FAIL] %s: [%u] exp=0x%08X got=0x%08X\n",
               name, (unsigned)idx, (unsigned)s[idx], (unsigned)d[idx]);
        return DMAC_ERR_DATA;
    }
    printf("  [PASS] %s: %u words OK\n", name, (unsigned)words);
    return DMAC_OK;
}

/* ===========================================================================
 * ISR
 * =========================================================================*/
void DMA_IRQHandler(void)
{
    uint32_t si = REG_RD32(DMAC_STATUS_INT);
    if (si & INT_TFR)  { g_irq_tfr   |= REG_RD32(DMAC_STATUS_TFR);   REG_WR32(DMAC_CLEAR_TFR,     REG_RD32(DMAC_STATUS_TFR));   }
    if (si & INT_BLOCK){ g_irq_block |= REG_RD32(DMAC_STATUS_BLOCK); REG_WR32(DMAC_CLEAR_BLOCK,   REG_RD32(DMAC_STATUS_BLOCK)); }
    if (si & INT_ERR)  { g_irq_err   |= REG_RD32(DMAC_STATUS_ERR);   REG_WR32(DMAC_CLEAR_ERR,     REG_RD32(DMAC_STATUS_ERR));
                         printf("[ISR] ERR channels=0x%02X\n", (unsigned)g_irq_err); }
    if (si & INT_SRCTRAN) REG_WR32(DMAC_CLEAR_SRCTRAN, REG_RD32(DMAC_STATUS_SRCTRAN));
    if (si & INT_DSTTRAN) REG_WR32(DMAC_CLEAR_DSTTRAN, REG_RD32(DMAC_STATUS_DSTTRAN));
}

/* ===========================================================================
 * DMAC Initialization
 * =========================================================================*/
static void dmac_init(void)
{
    printf("\n[DMAC] Init BASE=0x%08X\n", (unsigned)DMAC_BASE);

    REG_WR32(DMAC_CFG_REG, 0U);          /* Disable DMAC                  */

    REG_WR32(DMAC_CH_EN, 0xFF00U);       /* Disable all channels (WE+0)   */

    REG_WR32(DMAC_CLEAR_TFR,     0xFFU);
    REG_WR32(DMAC_CLEAR_BLOCK,   0xFFU);
    REG_WR32(DMAC_CLEAR_SRCTRAN, 0xFFU);
    REG_WR32(DMAC_CLEAR_DSTTRAN, 0xFFU);
    REG_WR32(DMAC_CLEAR_ERR,     0xFFU);

    /* Mask tất cả interrupt */
    REG_WR32(DMAC_MASK_TFR,     0xFF00U);
    REG_WR32(DMAC_MASK_BLOCK,   0xFF00U);
    REG_WR32(DMAC_MASK_SRCTRAN, 0xFF00U);
    REG_WR32(DMAC_MASK_DSTTRAN, 0xFF00U);
    REG_WR32(DMAC_MASK_ERR,     0xFF00U);

    /* Clear SW-HS requests */
    REG_WR32(DMAC_REQ_SRC,    0xFF00U);
    REG_WR32(DMAC_REQ_DST,    0xFF00U);
    REG_WR32(DMAC_SGLREQ_SRC, 0xFF00U);
    REG_WR32(DMAC_SGLREQ_DST, 0xFF00U);
    REG_WR32(DMAC_LST_SRC,    0xFF00U);
    REG_WR32(DMAC_LST_DST,    0xFF00U);

    g_irq_tfr = g_irq_block = g_irq_err = 0U;

    REG_WR32(DMAC_CFG_REG, DMAC_EN);

    printf("[DMAC] DmaCfgReg=0x%08X  ChEnReg=0x%08X\n",
           (unsigned)REG_RD32(DMAC_CFG_REG),
           (unsigned)REG_RD32(DMAC_CH_EN));
}

/* ===========================================================================
 * Channel setup & enable
 *
 * Thứ tự ghi register ĐÚNG:
 *   1. SAR, DAR, LLP (có thể ghi bất kỳ thứ tự nào khi ch disabled)
 *   2. CFG_LO, CFG_HI  (phải ghi CFG TRƯỚC khi enable)
 *   3. CTL_LO, CTL_HI  (ghi low word trước)
 *   4. Enable channel
 * =========================================================================*/
typedef struct {
    uint32_t ch;
    uint32_t sar;
    uint32_t dar;
    uint32_t llp;
    uint32_t ctl_lo;
    uint32_t ctl_hi;
    uint32_t cfg_lo;
    uint32_t cfg_hi;
} ch_params_t;

static dmac_err_t ch_setup(const ch_params_t *p)
{
    dmac_err_t r = DMAC_OK;
    uint32_t ch = p->ch;

    /* 1. Ghi SAR, DAR, LLP */
    REG_WR32(DMAC_SAR(ch), p->sar);
    REG_WR32(DMAC_DAR(ch), p->dar);
    REG_WR32(DMAC_LLP(ch), p->llp);

    /* 2. CFG (low word trước, high word sau) */
    REG_WR32(DMAC_CFG_LO(ch), p->cfg_lo);
    REG_WR32(DMAC_CFG_HI(ch), p->cfg_hi);

    /* 3. CTL (low word trước, high word sau) */
    REG_WR32(DMAC_CTL_LO(ch), p->ctl_lo);
    REG_WR32(DMAC_CTL_HI(ch), p->ctl_hi);

    /* 4. Readback verification */
    r |= reg_verify32(DMAC_SAR(ch),    p->sar,    0xFFFFFFFFU, "SAR");
    r |= reg_verify32(DMAC_DAR(ch),    p->dar,    0xFFFFFFFFU, "DAR");
    r |= reg_verify32(DMAC_CTL_LO(ch), p->ctl_lo, 0xFFFFFFFFU, "CTL_LO");
    r |= reg_verify32(DMAC_CTL_HI(ch), p->ctl_hi, 0x00000FFFU, "CTL_HI"); /* [11:0] */
    r |= reg_verify32(DMAC_CFG_LO(ch), p->cfg_lo, 0xFFFFFFFFU, "CFG_LO");

    if (r != DMAC_OK) {
        printf("  [ERR] ch%u register write verify FAILED\n", (unsigned)ch);
    }
    return r;
}

static void ch_enable(uint32_t ch, int unmask_tfr, int unmask_block)
{
    /* Clear pending trước khi enable */
    REG_WR32(DMAC_CLEAR_TFR,   CH_EN_BIT(ch));
    REG_WR32(DMAC_CLEAR_BLOCK, CH_EN_BIT(ch));
    REG_WR32(DMAC_CLEAR_ERR,   CH_EN_BIT(ch));

    /* Unmask interrupt nếu cần */
    if (unmask_tfr)   REG_WR32(DMAC_MASK_TFR,   INT_MASK_SET(ch));
    if (unmask_block) REG_WR32(DMAC_MASK_BLOCK,  INT_MASK_SET(ch));
    REG_WR32(DMAC_MASK_ERR, INT_MASK_SET(ch));

    REG_WR32(DMAC_CH_EN, CH_EN_SET(ch));
    printf("  [CH%u] Enabled  ChEn=0x%04X\n",
           (unsigned)ch, (unsigned)REG_RD32(DMAC_CH_EN));
}

/* ===========================================================================
 * Software Handshaking helpers
 *
 * QUAN TRỌNG:
 *   - Ghi LST_SRC / LST_DST TRƯỚC khi ghi REQ / SGLREQ cho transaction cuối
 *   - Chờ DMAC tự clear bit request trước khi gửi request tiếp theo
 * =========================================================================*/
static dmac_err_t sw_hs_wait_clr(volatile uint32_t *reg_addr, uint32_t ch)
{
    uint32_t t = TIMEOUT;
    while ((*reg_addr) & SWHS_REQ_BIT(ch)) {
        if (--t == 0) { printf("  [ERR] SW-HS wait clr timeout ch%u\n", (unsigned)ch); return DMAC_ERR_TIMEOUT; }
    }
    return DMAC_OK;
}

/* Macro tiện để đọc trực tiếp volatile register */
#define WAIT_CLR_SRC(ch)    sw_hs_wait_clr((volatile uint32_t *)(uintptr_t)DMAC_REQ_SRC,    ch)
#define WAIT_CLR_DST(ch)    sw_hs_wait_clr((volatile uint32_t *)(uintptr_t)DMAC_REQ_DST,    ch)
#define WAIT_CLR_SGLSRC(ch) sw_hs_wait_clr((volatile uint32_t *)(uintptr_t)DMAC_SGLREQ_SRC, ch)
#define WAIT_CLR_SGLDST(ch) sw_hs_wait_clr((volatile uint32_t *)(uintptr_t)DMAC_SGLREQ_DST, ch)

/**
 * @brief Gửi đủ burst SRC request cho một block (block_words items, msize=MSIZE_x)
 */
static dmac_err_t sw_hs_src_burst_block(uint32_t ch, uint32_t block_words, uint32_t msize)
{
    uint32_t burst_sz = (msize < 8U) ? g_msize_items[msize] : 1U;
    uint32_t bursts   = block_words / burst_sz;
    uint32_t rem      = block_words % burst_sz;
    uint32_t i;
    dmac_err_t r;

    for (i = 0; i < bursts; i++) {
        if (i == bursts - 1U && rem == 0U) REG_WR32(DMAC_LST_SRC, SWHS_SET(ch));
        REG_WR32(DMAC_REQ_SRC, SWHS_SET(ch));
        r = WAIT_CLR_SRC(ch);
        if (r) return r;
    }
    for (i = 0; i < rem; i++) {
        if (i == rem - 1U) REG_WR32(DMAC_LST_SRC, SWHS_SET(ch));
        REG_WR32(DMAC_SGLREQ_SRC, SWHS_SET(ch));
        r = WAIT_CLR_SGLSRC(ch);
        if (r) return r;
    }
    return DMAC_OK;
}

/**
 * @brief Gửi đủ burst DST request cho một block
 */
static dmac_err_t sw_hs_dst_burst_block(uint32_t ch, uint32_t block_words, uint32_t msize)
{
    uint32_t burst_sz = (msize < 8U) ? g_msize_items[msize] : 1U;
    uint32_t bursts   = block_words / burst_sz;
    uint32_t rem      = block_words % burst_sz;
    uint32_t i;
    dmac_err_t r;

    for (i = 0; i < bursts; i++) {
        if (i == bursts - 1U && rem == 0U) REG_WR32(DMAC_LST_DST, SWHS_SET(ch));
        REG_WR32(DMAC_REQ_DST, SWHS_SET(ch));
        r = WAIT_CLR_DST(ch);
        if (r) return r;
    }
    for (i = 0; i < rem; i++) {
        if (i == rem - 1U) REG_WR32(DMAC_LST_DST, SWHS_SET(ch));
        REG_WR32(DMAC_SGLREQ_DST, SWHS_SET(ch));
        r = WAIT_CLR_SGLDST(ch);
        if (r) return r;
    }
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 01 – M2M single-block
 * =========================================================================*/
static dmac_err_t test01_m2m_single(void)
{
    uint32_t i, ch = 0;
    dmac_err_t r;

    printf("\n=== TEST 01: M2M single-block ===\n");
    for (i = 0; i < BUF_WORDS; i++) { src_buf[i] = 0xA0000000U | i; }
    bm_memset32(dst_buf, 0U, BUF_WORDS);

    ch_params_t p = {
        .ch     = ch,
        .sar    = (uint32_t)(uintptr_t)src_buf,
        .dar    = (uint32_t)(uintptr_t)dst_buf,
        .llp    = 0U,
        .ctl_lo = ctl_lo_make(1,
                              TR_WIDTH_32, TR_WIDTH_32,
                              ADDR_INC, ADDR_INC,
                              MSIZE_4, MSIZE_4,
                              TT_FC_M2M_DMA,
                              MASTER_1, MASTER_1,
                              0, 0),
        .ctl_hi = ctl_hi_make(BUF_WORDS),
        /* CFG: priority=0, SW-HS none, fifo_mode=1 */
        .cfg_lo = cfg_lo_make(0, 0, 0, 0, 0),
        .cfg_hi = cfg_hi_make(1, 0, 0),
    };

    r = ch_setup(&p);
    if (r) return r;
    ch_enable(ch, 0, 0);

    r = poll_tfr_done(ch);
    if (r) return r;
    return verify_buf(src_buf, dst_buf, BUF_WORDS, "M2M single");
}

/* ===========================================================================
 * TEST 02 – M2M multi-block LLI
 * =========================================================================*/
static dmac_err_t test02_m2m_lli(void)
{
    uint32_t i, ch = 1;
    dmac_err_t r;
    const uint32_t bts = BLK_WORDS;

    printf("\n=== TEST 02: M2M multi-block LLI (%u x %u words) ===\n",
           (unsigned)LLI_BLOCKS, (unsigned)bts);
    for (i = 0; i < BUF_WORDS; i++) src_buf[i] = 0xB0000000U | i;
    bm_memset32(dst_buf, 0U, BUF_WORDS);

    for (i = 0; i < LLI_BLOCKS; i++) {
        int has_next = (i < (LLI_BLOCKS - 1U));
        lli_a[i].sar    = (uint32_t)(uintptr_t)&src_buf[i * bts];
        lli_a[i].dar    = (uint32_t)(uintptr_t)&dst_buf[i * bts];
        lli_a[i].llp    = has_next ? LLP_MAKE(&lli_a[i+1U], MASTER_1) : 0U;
        lli_a[i].ctl_lo = ctl_lo_make(1,
                                      TR_WIDTH_32, TR_WIDTH_32,
                                      ADDR_INC, ADDR_INC,
                                      MSIZE_4, MSIZE_4,
                                      TT_FC_M2M_DMA,
                                      MASTER_1, MASTER_1,
                                      has_next, has_next);
        lli_a[i].ctl_hi = ctl_hi_make(bts);
        lli_a[i].sstat  = 0U;
        lli_a[i].dstat  = 0U;
        printf("  LLI[%u] SAR=0x%08X DAR=0x%08X LLP=0x%08X CTL_LO=0x%08X CTL_HI=0x%08X\n",
               (unsigned)i,
               (unsigned)lli_a[i].sar, (unsigned)lli_a[i].dar,
               (unsigned)lli_a[i].llp,
               (unsigned)lli_a[i].ctl_lo, (unsigned)lli_a[i].ctl_hi);
    }

    ch_params_t p = {
        .ch     = ch,
        .sar    = lli_a[0].sar,
        .dar    = lli_a[0].dar,
        .llp    = LLP_MAKE(&lli_a[0], MASTER_1),
        .ctl_lo = lli_a[0].ctl_lo,
        .ctl_hi = lli_a[0].ctl_hi,
        .cfg_lo = cfg_lo_make(1, 0, 0, 0, 0),
        .cfg_hi = cfg_hi_make(1, 0, 0),
    };

    r = ch_setup(&p);
    if (r) return r;
    ch_enable(ch, 0, 0);

    r = poll_tfr_done(ch);
    if (r) return r;
    return verify_buf(src_buf, dst_buf, BUF_WORDS, "M2M LLI");
}

/* ===========================================================================
 * TEST 03 – M2P single-block, SW-HS dst
 *
 * Mô phỏng: dst_buf[0] làm "FIFO addr cố định" (ADDR_NOCHANGE cho DINC)
 * =========================================================================*/
static dmac_err_t test03_m2p_swhs(void)
{
    uint32_t i, ch = 2;
    dmac_err_t r;
    uint32_t fifo_addr = (uint32_t)(uintptr_t)&dst_buf[0];

    printf("\n=== TEST 03: M2P SW-HS dst ===\n");
    for (i = 0; i < BUF_WORDS; i++) src_buf[i] = 0xC0000000U | i;
    bm_memset32(dst_buf, 0U, BUF_WORDS);

    ch_params_t p = {
        .ch     = ch,
        .sar    = (uint32_t)(uintptr_t)src_buf,
        .dar    = fifo_addr,
        .llp    = 0U,
        .ctl_lo = ctl_lo_make(1,
                              TR_WIDTH_32, TR_WIDTH_32,
                              ADDR_NOCHANGE, ADDR_INC,  /* DINC=NC, SINC=INC */
                              MSIZE_4, MSIZE_4,
                              TT_FC_M2P_DMA,
                              MASTER_1, MASTER_1,
                              0, 0),
        .ctl_hi = ctl_hi_make(BUF_WORDS),
        .cfg_lo = cfg_lo_make(1, 1, 0, 0, 0),  /* sw_hs_dst=1 */
        .cfg_hi = cfg_hi_make(1, 0, HWHS_AES_TX),
    };

    r = ch_setup(&p);
    if (r) return r;
    ch_enable(ch, 0, 0);

    r = sw_hs_dst_burst_block(ch, BUF_WORDS, MSIZE_4);
    if (r) return r;

    r = poll_tfr_done(ch);
    if (r) return r;

    /* Giá trị cuối cùng ghi vào FIFO (no-increment) là src_buf[BUF_WORDS-1] */
    printf("  [M2P] FIFO last word = 0x%08X (expect 0x%08X)\n",
           (unsigned)dst_buf[0], (unsigned)src_buf[BUF_WORDS - 1U]);
    if (dst_buf[0] != src_buf[BUF_WORDS - 1U]) return DMAC_ERR_DATA;
    printf("  [PASS] M2P SW-HS dst\n");
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 04 – P2M single-block, SW-HS src
 *
 * Mô phỏng: src_buf[0] làm "FIFO cố định" (ADDR_NOCHANGE cho SINC)
 * =========================================================================*/
static dmac_err_t test04_p2m_swhs(void)
{
    uint32_t i, ch = 3;
    dmac_err_t r;
    const uint32_t FIFO_VAL = 0xCAFEBABEU;
    uint32_t fifo_addr = (uint32_t)(uintptr_t)&src_buf[0];

    printf("\n=== TEST 04: P2M SW-HS src ===\n");
    src_buf[0] = FIFO_VAL;
    bm_memset32(dst_buf, 0U, BUF_WORDS);

    ch_params_t p = {
        .ch     = ch,
        .sar    = fifo_addr,
        .dar    = (uint32_t)(uintptr_t)dst_buf,
        .llp    = 0U,
        .ctl_lo = ctl_lo_make(1,
                              TR_WIDTH_32, TR_WIDTH_32,
                              ADDR_INC, ADDR_NOCHANGE,  /* DINC=INC, SINC=NC */
                              MSIZE_4, MSIZE_4,
                              TT_FC_P2M_DMA,
                              MASTER_1, MASTER_1,
                              0, 0),
        .ctl_hi = ctl_hi_make(BUF_WORDS),
        .cfg_lo = cfg_lo_make(1, 0, 1, 0, 0),  /* sw_hs_src=1 */
        .cfg_hi = cfg_hi_make(1, HWHS_AES_RX, 0),
    };

    r = ch_setup(&p);
    if (r) return r;
    ch_enable(ch, 0, 0);

    r = sw_hs_src_burst_block(ch, BUF_WORDS, MSIZE_4);
    if (r) return r;

    r = poll_tfr_done(ch);
    if (r) return r;

    for (i = 0; i < BUF_WORDS; i++) {
        if (dst_buf[i] != FIFO_VAL) {
            printf("  [FAIL] P2M: dst[%u]=0x%08X != 0x%08X\n",
                   (unsigned)i, (unsigned)dst_buf[i], (unsigned)FIFO_VAL);
            return DMAC_ERR_DATA;
        }
    }
    printf("  [PASS] P2M SW-HS src: %u words = 0x%08X\n",
           (unsigned)BUF_WORDS, (unsigned)FIFO_VAL);
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 05 – P2P single-block, SW-HS src+dst
 * =========================================================================*/
static dmac_err_t test05_p2p_swhs(void)
{
    uint32_t i, ch = 4;
    const uint32_t words = 16U;
    dmac_err_t r;
    uint32_t src_fifo = (uint32_t)(uintptr_t)&src_buf[0];
    uint32_t dst_fifo = (uint32_t)(uintptr_t)&dst_buf[0];

    printf("\n=== TEST 05: P2P SW-HS src+dst ===\n");
    src_buf[0] = 0x55AA55AAU;
    dst_buf[0] = 0U;

    ch_params_t p = {
        .ch     = ch,
        .sar    = src_fifo,
        .dar    = dst_fifo,
        .llp    = 0U,
        .ctl_lo = ctl_lo_make(1,
                              TR_WIDTH_32, TR_WIDTH_32,
                              ADDR_NOCHANGE, ADDR_NOCHANGE,
                              MSIZE_1, MSIZE_1,
                              TT_FC_P2P_DMA,
                              MASTER_1, MASTER_1,
                              0, 0),
        .ctl_hi = ctl_hi_make(words),
        .cfg_lo = cfg_lo_make(2, 1, 1, 0, 0),  /* sw_hs_dst=1, sw_hs_src=1 */
        .cfg_hi = cfg_hi_make(1, 0, 0),
    };

    r = ch_setup(&p);
    if (r) return r;
    ch_enable(ch, 0, 0);

    /* Với MSIZE_1: mỗi burst = 1 item, gửi single request xen kẽ SRC rồi DST */
    for (i = 0; i < words; i++) {
        int last = (i == (words - 1U));
        if (last) REG_WR32(DMAC_LST_SRC, SWHS_SET(ch));
        REG_WR32(DMAC_SGLREQ_SRC, SWHS_SET(ch));
        r = WAIT_CLR_SGLSRC(ch);
        if (r) return r;

        if (last) REG_WR32(DMAC_LST_DST, SWHS_SET(ch));
        REG_WR32(DMAC_SGLREQ_DST, SWHS_SET(ch));
        r = WAIT_CLR_SGLDST(ch);
        if (r) return r;
    }

    r = poll_tfr_done(ch);
    if (r) return r;
    printf("  [P2P] dst_buf[0]=0x%08X (expect 0x55AA55AA)\n", (unsigned)dst_buf[0]);
    if (dst_buf[0] != 0x55AA55AAU) return DMAC_ERR_DATA;
    printf("  [PASS] P2P SW-HS\n");
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 06 – M2P multi-block LLI, SW-HS dst
 * =========================================================================*/
static dmac_err_t test06_m2p_lli_swhs(void)
{
    uint32_t i, ch = 5;
    const uint32_t bts = BLK_WORDS;
    dmac_err_t r;
    uint32_t fifo_addr = (uint32_t)(uintptr_t)&dst_buf[0];

    printf("\n=== TEST 06: M2P LLI SW-HS dst (%u x %u words) ===\n",
           (unsigned)LLI_BLOCKS, (unsigned)bts);
    for (i = 0; i < BUF_WORDS; i++) src_buf[i] = 0xF0000000U | i;
    bm_memset32(dst_buf, 0U, BUF_WORDS);

    for (i = 0; i < LLI_BLOCKS; i++) {
        int has_next = (i < (LLI_BLOCKS - 1U));
        lli_b[i].sar    = (uint32_t)(uintptr_t)&src_buf[i * bts];
        lli_b[i].dar    = fifo_addr;
        lli_b[i].llp    = has_next ? LLP_MAKE(&lli_b[i+1U], MASTER_1) : 0U;
        lli_b[i].ctl_lo = ctl_lo_make(1,
                                      TR_WIDTH_32, TR_WIDTH_32,
                                      ADDR_NOCHANGE, ADDR_INC,
                                      MSIZE_4, MSIZE_4,
                                      TT_FC_M2P_DMA,
                                      MASTER_1, MASTER_1,
                                      has_next, has_next);
        lli_b[i].ctl_hi = ctl_hi_make(bts);
        lli_b[i].sstat  = 0U;
        lli_b[i].dstat  = 0U;
    }

    ch_params_t p = {
        .ch     = ch,
        .sar    = lli_b[0].sar,
        .dar    = fifo_addr,
        .llp    = LLP_MAKE(&lli_b[0], MASTER_1),
        .ctl_lo = lli_b[0].ctl_lo,
        .ctl_hi = lli_b[0].ctl_hi,
        .cfg_lo = cfg_lo_make(1, 1, 0, 0, 0),
        .cfg_hi = cfg_hi_make(1, 0, 0),
    };

    r = ch_setup(&p);
    if (r) return r;
    ch_enable(ch, 0, 1);  /* unmask block interrupt để poll per-block */

    for (i = 0; i < LLI_BLOCKS; i++) {
        printf("  Block %u: sending %u-word SW-HS dst...\n", (unsigned)i, (unsigned)bts);
        r = sw_hs_dst_burst_block(ch, bts, MSIZE_4);
        if (r) return r;
        /* Đợi block này xong trước khi gửi HS block tiếp */
        if (i < (LLI_BLOCKS - 1U)) {
            r = poll_block_done(ch);
            if (r) return r;
        }
    }

    r = poll_tfr_done(ch);
    if (r) return r;
    printf("  [M2P LLI] dst_buf[0]=0x%08X\n", (unsigned)dst_buf[0]);
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 07 – AES DMA
 * =========================================================================*/
static dmac_err_t test07_aes_dma(void)
{
    uint32_t ch_tx = 6, ch_rx = 7;
    const uint32_t aes_words = 4U;   /* 128-bit */
    dmac_err_t r;
    uint32_t timeout;

    printf("\n=== TEST 07: AES DMA (M2P + P2M) ===\n");
    aes_plain[0] = 0x00112233U; aes_plain[1] = 0x44556677U;
    aes_plain[2] = 0x8899AABBU; aes_plain[3] = 0xCCDDEEFFU;
    bm_memset32(aes_cipher, 0U, 4U);

    /* Cấu hình AES: start encrypt */
    REG_WR32(AES_CTRL, AES_CTRL_ENC | AES_CTRL_START);

    /* Phase A: M2P → AES_DATA_IN */
    printf("  Phase A: DMA → AES_DATA_IN\n");
    ch_params_t pa = {
        .ch     = ch_tx,
        .sar    = (uint32_t)(uintptr_t)aes_plain,
        .dar    = (uint32_t)AES_DATA_IN,
        .llp    = 0U,
        .ctl_lo = ctl_lo_make(1, TR_WIDTH_32, TR_WIDTH_32,
                              ADDR_NOCHANGE, ADDR_INC,
                              MSIZE_4, MSIZE_4,
                              TT_FC_M2P_DMA,
                              MASTER_2, MASTER_1,
                              0, 0),
        .ctl_hi = ctl_hi_make(aes_words),
        .cfg_lo = cfg_lo_make(3, 1, 0, 0, 0),
        .cfg_hi = cfg_hi_make(1, 0, HWHS_AES_TX),
    };
    r = ch_setup(&pa); if (r) return r;
    ch_enable(ch_tx, 0, 0);
    r = sw_hs_dst_burst_block(ch_tx, aes_words, MSIZE_4); if (r) return r;
    r = poll_tfr_done(ch_tx); if (r) return r;
    printf("  Phase A done.\n");

    /* Đợi AES xong */
    timeout = TIMEOUT;
    while (!(REG_RD32(AES_STATUS) & AES_STATUS_DONE))
        if (--timeout == 0) { printf("  [ERR] AES timeout\n"); return DMAC_ERR_TIMEOUT; }

    /* Phase B: P2M AES_DATA_OUT → buffer */
    printf("  Phase B: AES_DATA_OUT → DMA\n");
    ch_params_t pb = {
        .ch     = ch_rx,
        .sar    = (uint32_t)AES_DATA_OUT,
        .dar    = (uint32_t)(uintptr_t)aes_cipher,
        .llp    = 0U,
        .ctl_lo = ctl_lo_make(1, TR_WIDTH_32, TR_WIDTH_32,
                              ADDR_INC, ADDR_NOCHANGE,
                              MSIZE_4, MSIZE_4,
                              TT_FC_P2M_DMA,
                              MASTER_1, MASTER_2,
                              0, 0),
        .ctl_hi = ctl_hi_make(aes_words),
        .cfg_lo = cfg_lo_make(3, 0, 1, 0, 0),
        .cfg_hi = cfg_hi_make(1, HWHS_AES_RX, 0),
    };
    r = ch_setup(&pb); if (r) return r;
    ch_enable(ch_rx, 0, 0);
    r = sw_hs_src_burst_block(ch_rx, aes_words, MSIZE_4); if (r) return r;
    r = poll_tfr_done(ch_rx); if (r) return r;

    printf("  [AES] Cipher: %08X %08X %08X %08X\n",
           (unsigned)aes_cipher[0], (unsigned)aes_cipher[1],
           (unsigned)aes_cipher[2], (unsigned)aes_cipher[3]);
    printf("  [PASS] AES DMA done (verify cipher against expected key-dependent value)\n");
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 08 – SHA2 DMA
 * =========================================================================*/
static dmac_err_t test08_sha2_dma(void)
{
    uint32_t i, ch_tx = 6, ch_rx = 7;
    const uint32_t msg_words    = 16U;   /* 512-bit block */
    const uint32_t digest_words = 8U;    /* SHA-256 = 256-bit */
    dmac_err_t r;
    uint32_t timeout;

    printf("\n=== TEST 08: SHA2 DMA (M2P + P2M) ===\n");
    for (i = 0; i < msg_words; i++) sha2_msg[i] = 0x61626300U | i;
    bm_memset32(sha2_digest, 0U, digest_words);

    REG_WR32(SHA2_CTRL, SHA2_CTRL_RESET);
    /* small delay */
    { volatile uint32_t d = 100U; while(d--); }
    REG_WR32(SHA2_CTRL, SHA2_CTRL_START);

    /* Phase A */
    printf("  Phase A: DMA → SHA2_DATA_IN (%u words)\n", (unsigned)msg_words);
    ch_params_t pa = {
        .ch     = ch_tx,
        .sar    = (uint32_t)(uintptr_t)sha2_msg,
        .dar    = (uint32_t)SHA2_DATA_IN,
        .llp    = 0U,
        .ctl_lo = ctl_lo_make(1, TR_WIDTH_32, TR_WIDTH_32,
                              ADDR_NOCHANGE, ADDR_INC,
                              MSIZE_4, MSIZE_4,
                              TT_FC_M2P_DMA,
                              MASTER_2, MASTER_1,
                              0, 0),
        .ctl_hi = ctl_hi_make(msg_words),
        .cfg_lo = cfg_lo_make(3, 1, 0, 0, 0),
        .cfg_hi = cfg_hi_make(1, 0, HWHS_SHA2_TX),
    };
    r = ch_setup(&pa); if (r) return r;
    ch_enable(ch_tx, 0, 0);
    r = sw_hs_dst_burst_block(ch_tx, msg_words, MSIZE_4); if (r) return r;
    r = poll_tfr_done(ch_tx); if (r) return r;
    printf("  Phase A done.\n");

    timeout = TIMEOUT;
    while (!(REG_RD32(SHA2_STATUS) & SHA2_STATUS_DONE))
        if (--timeout == 0) { printf("  [ERR] SHA2 timeout\n"); return DMAC_ERR_TIMEOUT; }

    /* Phase B */
    printf("  Phase B: SHA2_DIGEST → DMA (%u words)\n", (unsigned)digest_words);
    ch_params_t pb = {
        .ch     = ch_rx,
        .sar    = (uint32_t)SHA2_DIGEST,
        .dar    = (uint32_t)(uintptr_t)sha2_digest,
        .llp    = 0U,
        .ctl_lo = ctl_lo_make(1, TR_WIDTH_32, TR_WIDTH_32,
                              ADDR_INC, ADDR_NOCHANGE,
                              MSIZE_4, MSIZE_4,
                              TT_FC_P2M_DMA,
                              MASTER_1, MASTER_2,
                              0, 0),
        .ctl_hi = ctl_hi_make(digest_words),
        .cfg_lo = cfg_lo_make(3, 0, 1, 0, 0),
        .cfg_hi = cfg_hi_make(1, HWHS_SHA2_RX, 0),
    };
    r = ch_setup(&pb); if (r) return r;
    ch_enable(ch_rx, 0, 0);
    r = sw_hs_src_burst_block(ch_rx, digest_words, MSIZE_4); if (r) return r;
    r = poll_tfr_done(ch_rx); if (r) return r;

    printf("  [SHA2] Digest: ");
    for (i = 0; i < digest_words; i++) printf("%08X ", (unsigned)sha2_digest[i]);
    printf("\n  [PASS] SHA2 DMA done\n");
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 09 – M2M interrupt-driven
 * =========================================================================*/
static dmac_err_t test09_m2m_irq(void)
{
    uint32_t i, ch = 0;
    dmac_err_t r;
    uint32_t timeout;

    printf("\n=== TEST 09: M2M interrupt-driven ===\n");
    for (i = 0; i < BUF_WORDS; i++) src_buf[i] = 0xE0000000U | i;
    bm_memset32(dst_buf, 0U, BUF_WORDS);

    g_irq_tfr = 0U; g_irq_err = 0U;

    ch_params_t p = {
        .ch     = ch,
        .sar    = (uint32_t)(uintptr_t)src_buf,
        .dar    = (uint32_t)(uintptr_t)dst_buf,
        .llp    = 0U,
        .ctl_lo = ctl_lo_make(1, TR_WIDTH_32, TR_WIDTH_32,
                              ADDR_INC, ADDR_INC,
                              MSIZE_4, MSIZE_4, TT_FC_M2M_DMA,
                              MASTER_1, MASTER_1, 0, 0),
        .ctl_hi = ctl_hi_make(BUF_WORDS),
        .cfg_lo = cfg_lo_make(0, 0, 0, 0, 0),
        .cfg_hi = cfg_hi_make(1, 0, 0),
    };
    r = ch_setup(&p); if (r) return r;
    ch_enable(ch, 1, 0);  /* unmask TFR interrupt */

    /* Chờ ISR set g_irq_tfr */
    timeout = TIMEOUT;
    while (!(g_irq_tfr & CH_EN_BIT(ch))) {
        if (g_irq_err & CH_EN_BIT(ch)) { printf("  [ERR] IRQ error\n"); return DMAC_ERR_HW; }
        if (--timeout == 0) { printf("  [ERR] IRQ timeout\n"); return DMAC_ERR_TIMEOUT; }
        /* WFI / yield on RTOS */
    }
    printf("  [IRQ] ISR signaled ch%u done\n", (unsigned)ch);
    return verify_buf(src_buf, dst_buf, BUF_WORDS, "M2M IRQ");
}

/* ===========================================================================
 * TEST 10 – M2M auto-reload (CFG.RELOAD_SRC + RELOAD_DST)
 *
 * DMAC tự reload SAR/DAR về giá trị ban đầu sau mỗi block.
 * SW đếm N block interrupts rồi suspend channel.
 * =========================================================================*/
static dmac_err_t test10_m2m_autoreload(void)
{
    uint32_t i, ch = 1;
    const uint32_t bts     = BLK_WORDS;
    const uint32_t n_block = 3U;
    uint32_t cnt = 0U;
    dmac_err_t r;

    printf("\n=== TEST 10: M2M auto-reload (%u x %u words) ===\n",
           (unsigned)n_block, (unsigned)bts);
    for (i = 0; i < bts; i++) { src_buf[i] = 0xA5A50000U | i; dst_buf[i] = 0U; }

    ch_params_t p = {
        .ch     = ch,
        .sar    = (uint32_t)(uintptr_t)src_buf,
        .dar    = (uint32_t)(uintptr_t)dst_buf,
        .llp    = 0U,
        .ctl_lo = ctl_lo_make(1, TR_WIDTH_32, TR_WIDTH_32,
                              ADDR_INC, ADDR_INC,
                              MSIZE_4, MSIZE_4, TT_FC_M2M_DMA,
                              MASTER_1, MASTER_1, 0, 0),
        .ctl_hi = ctl_hi_make(bts),
        /* RELOAD_SRC=1, RELOAD_DST=1 */
        .cfg_lo = cfg_lo_make(0, 0, 0, 1, 1),
        .cfg_hi = cfg_hi_make(1, 0, 0),
    };
    r = ch_setup(&p); if (r) return r;
    ch_enable(ch, 0, 0);  /* poll RAW_BLOCK trực tiếp */

    while (cnt < n_block) {
        r = poll_block_done(ch);
        if (r) return r;
        cnt++;
        printf("  Block %u done\n", (unsigned)cnt);

        if (cnt == n_block) {
            /* Suspend channel: set CH_SUSP trong CFG_LO */
            uint32_t cfg_lo = REG_RD32(DMAC_CFG_LO(ch));
            cfg_lo |= CFG_CH_SUSP_BIT;
            REG_WR32(DMAC_CFG_LO(ch), cfg_lo);

            /* Đợi FIFO_EMPTY (CFG_LO bit 9) trước khi disable */
            uint32_t t = TIMEOUT;
            while (!(REG_RD32(DMAC_CFG_LO(ch)) & CFG_FIFO_EMPTY_BIT))
                if (--t == 0) break;

            REG_WR32(DMAC_CH_EN, CH_EN_CLR(ch));
        }
    }

    return verify_buf(src_buf, dst_buf, bts, "M2M auto-reload");
}

/* ===========================================================================
 * MAIN
 * =========================================================================*/
int main(void)
{
    typedef struct {
        const char  *name;
        dmac_err_t (*fn)(void);
    } test_t;

    static const test_t tests[] = {
        { "01 M2M single-block",        test01_m2m_single    },
        { "02 M2M multi-block LLI",     test02_m2m_lli       },
        { "03 M2P SW-HS dst",           test03_m2p_swhs      },
        { "04 P2M SW-HS src",           test04_p2m_swhs      },
        { "05 P2P SW-HS src+dst",       test05_p2p_swhs      },
        { "06 M2P LLI SW-HS dst",       test06_m2p_lli_swhs  },
        { "07 AES DMA",                 test07_aes_dma       },
        { "08 SHA2 DMA",                test08_sha2_dma      },
        { "09 M2M interrupt",           test09_m2m_irq       },
        { "10 M2M auto-reload",         test10_m2m_autoreload},
    };
    const uint32_t ntests = (uint32_t)(sizeof(tests)/sizeof(tests[0]));
    uint32_t pass = 0, fail = 0, i;

    printf("============================================================\n");
    printf("  DW_ahb_dmac v2.24a Test Suite\n");
    printf("  DMAC=0x%08X  AES=0x%08X  SHA2=0x%08X\n",
           (unsigned)DMAC_BASE, (unsigned)AES_BASE, (unsigned)SHA2_BASE);
    printf("  LLI size = %u bytes (must be 28)\n", (unsigned)sizeof(dmac_lli_t));
    printf("============================================================\n");

    dmac_init();

    for (i = 0; i < ntests; i++) {
        /* Make sure relevant channels are idle before each test */
        ch_wait_idle(0); ch_wait_idle(1); ch_wait_idle(2);
        ch_wait_idle(3); ch_wait_idle(4); ch_wait_idle(5);
        ch_wait_idle(6); ch_wait_idle(7);

        /* Clear interrupt state */
        REG_WR32(DMAC_CLEAR_TFR,   0xFFU);
        REG_WR32(DMAC_CLEAR_BLOCK, 0xFFU);
        REG_WR32(DMAC_CLEAR_ERR,   0xFFU);
        g_irq_tfr = g_irq_block = g_irq_err = 0U;

        dmac_err_t rc = tests[i].fn();

        if (rc == DMAC_OK) {
            printf("[RESULT] Test %s --> PASS\n", tests[i].name);
            pass++;
        } else {
            printf("[RESULT] Test %s --> FAIL (err=%d)\n", tests[i].name, (int)rc);
            fail++;
        }
    }

    printf("\n============================================================\n");
    printf("  TOTAL %u:  PASS=%u  FAIL=%u\n",
           (unsigned)ntests, (unsigned)pass, (unsigned)fail);
    printf("============================================================\n");
    return (fail == 0) ? 0 : 1;
}
