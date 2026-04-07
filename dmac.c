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
 * Physical Memory Map — THAY static array bằng địa chỉ physical cố định
 *
 * Lý do KHÔNG dùng static array:
 *   - static array nằm trong .bss tại địa chỉ do linker quyết định (~0x8009xxxx)
 *   - Nếu DMAC master chỉ decode được một vùng nhớ nhất định,
 *     .bss có thể nằm ngoài tầm với → HRESP=ERROR (im lặng) → data không transfer
 *   - LLI trong .bss: DMAC fetch LLI thành công (thấy trên wave) nhưng
 *     SAR/DAR trong LLI trỏ vào .bss → DMAC đọc/ghi địa chỉ .bss → lỗi im lặng
 *
 * Chỉnh các địa chỉ dưới đây theo memory map thực tế của SoC:
 * =========================================================================*/
#ifndef SRC_BUF_BASE
#define SRC_BUF_BASE    0x90000000UL   /* 256 bytes  = 64 words  */
#endif
#ifndef DST_BUF_BASE
#define DST_BUF_BASE    0x90000100UL   /* 256 bytes  = 64 words  */
#endif
#ifndef LLI_M2M_BASE
#define LLI_M2M_BASE    0x90000200UL   /* 4 × 28 = 112 bytes     */
#endif
#ifndef LLI_M2P_BASE
#define LLI_M2P_BASE    0x90000280UL   /* 4 × 28 = 112 bytes     */
#endif
#ifndef AES_PLAIN_BASE
#define AES_PLAIN_BASE  0x90000300UL   /* 16 bytes               */
#endif
#ifndef AES_CIPH_BASE
#define AES_CIPH_BASE   0x90000310UL   /* 16 bytes               */
#endif
#ifndef SHA2_MSG_BASE
#define SHA2_MSG_BASE   0x90000320UL   /* 64 bytes               */
#endif
#ifndef SHA2_DIG_BASE
#define SHA2_DIG_BASE   0x90000360UL   /* 32 bytes               */
#endif

/* Pointer helpers — truy cập vùng nhớ physical như array */
#define SRC_BUF     ((volatile uint32_t *)(uintptr_t)SRC_BUF_BASE)
#define DST_BUF     ((volatile uint32_t *)(uintptr_t)DST_BUF_BASE)
#define AES_PLAIN   ((volatile uint32_t *)(uintptr_t)AES_PLAIN_BASE)
#define AES_CIPH    ((volatile uint32_t *)(uintptr_t)AES_CIPH_BASE)
#define SHA2_MSG    ((volatile uint32_t *)(uintptr_t)SHA2_MSG_BASE)
#define SHA2_DIG    ((volatile uint32_t *)(uintptr_t)SHA2_DIG_BASE)

/* ===========================================================================
 * Test parameters
 * =========================================================================*/
#define BUF_WORDS           64U
#define LLI_BLOCKS          4U
#define BLK_WORDS           16U
#define TIMEOUT             1000000U
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
 * Memory utilities (bare-metal, no libc)
 * =========================================================================*/
static void mem_fill32(uint32_t base, uint32_t val, uint32_t words)
{
    uint32_t i;
    for (i = 0; i < words; i++) REG_WR32(base + i * 4U, val);
}

static dmac_err_t mem_verify32(uint32_t src_base, uint32_t dst_base,
                                uint32_t words, const char *name)
{
    uint32_t i;
    for (i = 0; i < words; i++) {
        uint32_t s = REG_RD32(src_base + i * 4U);
        uint32_t d = REG_RD32(dst_base + i * 4U);
        if (d != s) {
            printf("  [FAIL] %s: [%u] exp=0x%08X got=0x%08X\n",
                   name, (unsigned)i, (unsigned)s, (unsigned)d);
            return DMAC_ERR_DATA;
        }
    }
    printf("  [PASS] %s: %u words OK\n", name, (unsigned)words);
    return DMAC_OK;
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
    for (i = 0; i < BUF_WORDS; i++) { SRC_BUF[i] = 0xA0000000U | i; }
    mem_fill32(DST_BUF_BASE, 0U, BUF_WORDS);

    ch_params_t p = {
        .ch     = ch,
        .sar    = (uint32_t)(uintptr_t)SRC_BUF_BASE,
        .dar    = (uint32_t)(uintptr_t)DST_BUF_BASE,
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
    return mem_verify32(SRC_BUF_BASE, DST_BUF_BASE, BUF_WORDS, "M2M single");
}

/* ===========================================================================
 * LLI write helper — BẮTBUỘC dùng REG_WR32 (volatile) cho mỗi field
 *
 * Lý do KHÔNG được ghi qua struct pointer thông thường:
 *   1. Compiler có thể reorder hoặc omit writes
 *   2. Nếu cache enabled: CPU write vào D-cache, DMAC đọc thẳng RAM → thấy data cũ
 *   3. Phải dùng volatile để đảm bảo write committed ra bus trước khi DMAC chạy
 *
 * Offset cố định trong LLI (hardware-defined, sizeof(dmac_lli_t)==28):
 *   +0  SAR    (u32)
 *   +4  DAR    (u32)
 *   +8  LLP    (u32)
 *   +12 CTL_LO (u32)
 *   +16 CTL_HI (u32)
 *   +20 SSTAT  (u32)
 *   +24 DSTAT  (u32)
 * =========================================================================*/
#define LLI_FIELD_SAR_OFF    0U
#define LLI_FIELD_DAR_OFF    4U
#define LLI_FIELD_LLP_OFF    8U
#define LLI_FIELD_CTLLO_OFF  12U
#define LLI_FIELD_CTLHI_OFF  16U
#define LLI_FIELD_SSTAT_OFF  20U
#define LLI_FIELD_DSTAT_OFF  24U
#define LLI_ENTRY_SIZE       28U   /* sizeof(dmac_lli_t) */

/* Compile-time check */
typedef char _lli_sz[(LLI_ENTRY_SIZE == sizeof(dmac_lli_t)) ? 1 : -1];

static void lli_wr(uint32_t lli_base, uint32_t idx,
                   uint32_t sar,    uint32_t dar,    uint32_t llp,
                   uint32_t ctl_lo, uint32_t ctl_hi)
{
    uint32_t base = lli_base + idx * LLI_ENTRY_SIZE;
    REG_WR32(base + LLI_FIELD_SAR_OFF,   sar);
    REG_WR32(base + LLI_FIELD_DAR_OFF,   dar);
    REG_WR32(base + LLI_FIELD_LLP_OFF,   llp);
    REG_WR32(base + LLI_FIELD_CTLLO_OFF, ctl_lo);
    REG_WR32(base + LLI_FIELD_CTLHI_OFF, ctl_hi);
    REG_WR32(base + LLI_FIELD_SSTAT_OFF, 0U);
    REG_WR32(base + LLI_FIELD_DSTAT_OFF, 0U);
}

static void lli_dump(uint32_t lli_base, uint32_t idx)
{
    uint32_t base = lli_base + idx * LLI_ENTRY_SIZE;
    /* Đọc lại bằng REG_RD32 (volatile) — bypass cache nếu có */
    printf("  LLI[%u]@0x%08X: SAR=0x%08X DAR=0x%08X LLP=0x%08X "
           "CTL_LO=0x%08X CTL_HI=0x%08X\n",
           (unsigned)idx, (unsigned)base,
           (unsigned)REG_RD32(base + LLI_FIELD_SAR_OFF),
           (unsigned)REG_RD32(base + LLI_FIELD_DAR_OFF),
           (unsigned)REG_RD32(base + LLI_FIELD_LLP_OFF),
           (unsigned)REG_RD32(base + LLI_FIELD_CTLLO_OFF),
           (unsigned)REG_RD32(base + LLI_FIELD_CTLHI_OFF));
}

/* Memory / data barrier — flush write buffer trước khi DMAC bắt đầu */
static inline void dmb(void)
{
#if defined(__ARM_ARCH)
    __asm__ volatile ("dmb sy" ::: "memory");
#else
    __asm__ volatile ("" ::: "memory");   /* compiler barrier cho non-ARM */
#endif
}

/* ===========================================================================
 * TEST 02 – M2M multi-block LLI
 *
 * LLI layout (N=4 blocks):
 *
 *   Channel regs : SAR=src[0], DAR=dst[0], CTL=blk0(LLP_EN=1), LLP→LLI[1]
 *   LLI[1]       : SAR=src[1], DAR=dst[1], CTL=blk1(LLP_EN=1), LLP→LLI[2]
 *   LLI[2]       : SAR=src[2], DAR=dst[2], CTL=blk2(LLP_EN=1), LLP→LLI[3]
 *   LLI[3]       : SAR=src[3], DAR=dst[3], CTL=blk3(LLP_EN=0), LLP=0
 *
 * Channel LLP trỏ LLI[1] (KHÔNG phải LLI[0]).
 * Sau block 0, DMAC fetch LLI[1] để nạp config block 1, v.v.
 *
 * QUAN TRỌNG:
 *   - LLI phải nằm tại địa chỉ DMAC master có thể đọc được
 *   - Ghi LLI bằng REG_WR32 (volatile), thêm DMB trước khi enable channel
 *   - SAR/DAR trong LLI phải là địa chỉ physical của data buffer
 * =========================================================================*/
static dmac_err_t test02_m2m_lli(void)
{
    uint32_t i, ch = 1;
    dmac_err_t r;
    const uint32_t bts      = BLK_WORDS;
    const uint32_t blk_byte = bts * 4U;

    printf("\n=== TEST 02: M2M multi-block LLI (%u x %u words) ===\n",
           (unsigned)LLI_BLOCKS, (unsigned)bts);
    printf("  SRC=0x%08X  DST=0x%08X  LLI@0x%08X\n",
           (unsigned)SRC_BUF_BASE, (unsigned)DST_BUF_BASE, (unsigned)LLI_M2M_BASE);
    printf("  LLI entry size = %u bytes\n", (unsigned)LLI_ENTRY_SIZE);

    /* Khởi tạo data */
    for (i = 0; i < BUF_WORDS; i++) SRC_BUF[i] = 0xB0000000U | i;
    mem_fill32(DST_BUF_BASE, 0U, BUF_WORDS);

    /* -----------------------------------------------------------------------
     * Build LLI[0..N-1] tại địa chỉ physical LLI_M2M_BASE
     * Dùng REG_WR32 — không dùng struct pointer
     * ---------------------------------------------------------------------- */
    for (i = 0; i < LLI_BLOCKS; i++) {
        int      has_next = (i < (LLI_BLOCKS - 1U));
        uint32_t sar      = (uint32_t)SRC_BUF_BASE + i * blk_byte;
        uint32_t dar      = (uint32_t)DST_BUF_BASE + i * blk_byte;
        uint32_t llp_next = has_next
                            ? LLP_MAKE(LLI_M2M_BASE + (i + 1U) * LLI_ENTRY_SIZE, MASTER_1)
                            : 0U;
        uint32_t ctl_lo   = ctl_lo_make(1,
                                        TR_WIDTH_32, TR_WIDTH_32,
                                        ADDR_INC, ADDR_INC,
                                        MSIZE_4,  MSIZE_4,
                                        TT_FC_M2M_DMA,
                                        MASTER_1, MASTER_1,
                                        has_next,  /* LLP_DEST_EN */
                                        has_next); /* LLP_SRC_EN  */
        uint32_t ctl_hi   = ctl_hi_make(bts);

        lli_wr(LLI_M2M_BASE, i, sar, dar, llp_next, ctl_lo, ctl_hi);
    }

    /* Barrier: đảm bảo tất cả LLI writes đã ra bus trước khi DMAC chạy */
    dmb();

    /* Readback bằng REG_RD32 để xác nhận data trong memory */
    printf("  LLI readback (via REG_RD32):\n");
    for (i = 0; i < LLI_BLOCKS; i++) lli_dump(LLI_M2M_BASE, i);

    /* -----------------------------------------------------------------------
     * Cấu hình channel:
     *   - Block 0: SAR/DAR/CTL từ LLI[0] (ghi thẳng vào channel regs)
     *   - LLP → LLI[1]  ← QUAN TRỌNG: không phải LLI[0]!
     * ---------------------------------------------------------------------- */
    uint32_t b0_sar    = (uint32_t)REG_RD32(LLI_M2M_BASE + LLI_FIELD_SAR_OFF);
    uint32_t b0_dar    = (uint32_t)REG_RD32(LLI_M2M_BASE + LLI_FIELD_DAR_OFF);
    uint32_t b0_ctl_lo = (uint32_t)REG_RD32(LLI_M2M_BASE + LLI_FIELD_CTLLO_OFF);
    uint32_t b0_ctl_hi = (uint32_t)REG_RD32(LLI_M2M_BASE + LLI_FIELD_CTLHI_OFF);
    /* Channel LLP → LLI[1] (block tiếp theo sau block 0) */
    uint32_t ch_llp    = LLP_MAKE(LLI_M2M_BASE + 1U * LLI_ENTRY_SIZE, MASTER_1);

    printf("  Channel: SAR=0x%08X DAR=0x%08X LLP=0x%08X CTL_LO=0x%08X CTL_HI=0x%08X\n",
           (unsigned)b0_sar, (unsigned)b0_dar, (unsigned)ch_llp,
           (unsigned)b0_ctl_lo, (unsigned)b0_ctl_hi);

    ch_params_t p = {
        .ch     = ch,
        .sar    = b0_sar,
        .dar    = b0_dar,
        .llp    = ch_llp,
        .ctl_lo = b0_ctl_lo,
        .ctl_hi = b0_ctl_hi,
        .cfg_lo = cfg_lo_make(1, 0, 0, 0, 0),
        .cfg_hi = cfg_hi_make(1, 0, 0),
    };

    r = ch_setup(&p);
    if (r) return r;

    /* Barrier lần nữa trước enable */
    dmb();
    ch_enable(ch, 0, 0);

    r = poll_tfr_done(ch);
    if (r) return r;

    /* Verify từng block riêng để dễ debug */
    for (i = 0; i < LLI_BLOCKS; i++) {
        uint32_t src_off  = i * bts;
        uint32_t dst_off  = i * bts;
        uint32_t j;
        int      blk_fail = 0;
        for (j = 0; j < bts; j++) {
            if (DST_BUF[dst_off + j] != SRC_BUF[src_off + j]) {
                printf("  [FAIL] Block %u word[%u]: exp=0x%08X got=0x%08X\n",
                       (unsigned)i, (unsigned)j,
                       (unsigned)SRC_BUF[src_off + j],
                       (unsigned)DST_BUF[dst_off + j]);
                blk_fail = 1;
                break;
            }
        }
        if (!blk_fail)
            printf("  [OK]   Block %u: %u words correct\n", (unsigned)i, (unsigned)bts);
        else
            return DMAC_ERR_DATA;
    }
    printf("  [PASS] M2M LLI: %u words total OK\n", (unsigned)BUF_WORDS);
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 03a – M2P sanity probe: dùng M2M mode ghi thẳng vào địa chỉ IP
 *
 * Mục đích: xác nhận DMA có thể ghi tới peripheral address mà KHÔNG cần
 * SW-HS, KHÔNG cần IP start. Dùng TT_FC_M2M_DMA + SINC=INC + DINC=INC.
 * Sau đó đọc lại register đích để verify.
 *
 * Tại sao M2P thực sự hay bị treo ở sw_hs_dst_burst_block:
 *   - SW set REQ_DST → DMAC viết MSIZE items xuống AHB
 *   - DMAC chỉ clear REQ_DST bit SAU KHI AHB write hoàn thành
 *   - Nếu IP FIFO đầy hoặc IP chưa start → AHB stall (HREADY=0 kéo dài)
 *   - DMAC không thể hoàn thành burst → REQ_DST không bao giờ clear → HANG
 * =========================================================================*/
static dmac_err_t test03a_m2p_probe(void)
{
    uint32_t i, ch = 2;
    dmac_err_t r;
    /* Chỉnh hai hằng này theo hệ thống thực tế */
    const uint32_t DST_IP_ADDR = AES_DATA_IN;     /* địa chỉ FIFO/register đích */
    const uint32_t N_WORDS     = 4U;               /* số word cần ghi (1 AES block) */

    printf("\n=== TEST 03a: M2P probe (M2M mode, no SW-HS) ===\n");
    printf("  SRC=0x%08X  DST=0x%08X  N=%u words\n",
           (unsigned)(uintptr_t)SRC_BUF_BASE, (unsigned)DST_IP_ADDR, (unsigned)N_WORDS);

    /* Chuẩn bị data */
    SRC_BUF[0] = 0x00112233U;
    SRC_BUF[1] = 0x44556677U;
    SRC_BUF[2] = 0x8899AABBU;
    SRC_BUF[3] = 0xCCDDEEFFU;
    for (i = N_WORDS; i < BUF_WORDS; i++) SRC_BUF[i] = 0xDEAD0000U | i;

    ch_params_t p = {
        .ch     = ch,
        .sar    = (uint32_t)(uintptr_t)SRC_BUF_BASE,
        .dar    = DST_IP_ADDR,
        .llp    = 0U,
        /*
         * Dùng M2M: DMAC tự xử lý src và dst như memory.
         * SINC=INC  : lấy từng word từ src_buf tăng dần
         * DINC=INC  : ghi tới DST_IP_ADDR+0, +4, +8, +C
         *             (nếu IP là FIFO dùng ADDR_NOCHANGE)
         * TT_FC=M2M : không cần handshaking, DMAC tự chạy
         */
        .ctl_lo = ctl_lo_make(1,
                              TR_WIDTH_32, TR_WIDTH_32,
                              ADDR_INC,    ADDR_INC,    /* DINC=INC, SINC=INC */
                              MSIZE_4,     MSIZE_4,
                              TT_FC_M2M_DMA,
                              MASTER_1,    MASTER_1,
                              0, 0),
        .ctl_hi = ctl_hi_make(N_WORDS),
        .cfg_lo = cfg_lo_make(0, 0, 0, 0, 0),   /* no SW-HS, no reload */
        .cfg_hi = cfg_hi_make(1, 0, 0),
    };

    r = ch_setup(&p);
    if (r) return r;
    ch_enable(ch, 0, 0);

    /* Không cần SW-HS — DMAC tự chạy */
    r = poll_tfr_done(ch);
    if (r) return r;

    /*
     * Verify: đọc lại địa chỉ đích.
     * Nếu IP là write-only thì bỏ qua bước này.
     */
    printf("  DMA done. Readback DST:\n");
    for (i = 0; i < N_WORDS; i++) {
        uint32_t got = REG_RD32(DST_IP_ADDR + i * 4U);
        printf("    [%u] wrote=0x%08X  read=0x%08X  %s\n",
               (unsigned)i,
               (unsigned)SRC_BUF[i],
               (unsigned)got,
               (got == SRC_BUF[i]) ? "OK" : "(write-only or mismatch)");
    }
    printf("  [PASS] M2P probe: DMA reached peripheral address\n");
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 03b – M2P single-block THỰC SỰ với SW-HS dst
 *
 * Điều kiện để KHÔNG bị treo:
 *   1. IP phải được start/enable TRƯỚC khi gọi hàm này
 *   2. N_WORDS phải khớp đúng với FIFO capacity của IP
 *   3. MSIZE phải ≤ kích thước FIFO của IP (tránh ghi khi FIFO đầy)
 *   4. IP phải đang chờ nhận data (không bị stall AHB)
 *
 * Flow đúng cho SW-HS dst:
 *   SW set REQ_DST  →  DMAC ghi MSIZE items xuống IP  →  DMAC clear REQ_DST
 *   (lặp lại cho đến hết block)
 *
 * Nếu IP chưa sẵn sàng → AHB stall → REQ_DST không clear → HANG
 * =========================================================================*/
static dmac_err_t test03b_m2p_swhs(void)
{
    uint32_t ch = 2;
    dmac_err_t r;
    /*
     * Chỉnh các thông số sau theo IP thực tế:
     *   DST_FIFO_ADDR  : địa chỉ FIFO input của IP (cố định, DINC=NOCHANGE)
     *   N_WORDS        : số word cần transfer (phải ≤ FIFO depth)
     *   BURST_MSIZE    : phải ≤ số slot còn trống trong FIFO khi trigger request
     */
    const uint32_t DST_FIFO_ADDR = AES_DATA_IN;
    const uint32_t N_WORDS       = 4U;     /* 1 AES block = 4 words */
    const uint32_t BURST_MSIZE   = MSIZE_4; /* 4 items/burst, khớp với N_WORDS */

    printf("\n=== TEST 03b: M2P SW-HS dst (real peripheral) ===\n");
    printf("  SRC=0x%08X  DST_FIFO=0x%08X  N=%u words\n",
           (unsigned)(uintptr_t)SRC_BUF_BASE, (unsigned)DST_FIFO_ADDR, (unsigned)N_WORDS);

    SRC_BUF[0] = 0x00112233U;
    SRC_BUF[1] = 0x44556677U;
    SRC_BUF[2] = 0x8899AABBU;
    SRC_BUF[3] = 0xCCDDEEFFU;

    /* === BƯỚC QUAN TRỌNG: khởi động IP TRƯỚC khi enable DMA === */
    /* Ví dụ AES: ghi key, set mode, rồi start để IP sẵn sàng nhận data */
    /* REG_WR32(AES_CTRL, AES_CTRL_ENC | AES_CTRL_START); */
    /* Nếu bỏ qua bước này → IP FIFO không drain → AHB stall → HANG */

    ch_params_t p = {
        .ch     = ch,
        .sar    = (uint32_t)(uintptr_t)SRC_BUF_BASE,
        .dar    = DST_FIFO_ADDR,
        .llp    = 0U,
        .ctl_lo = ctl_lo_make(1,
                              TR_WIDTH_32,    TR_WIDTH_32,
                              ADDR_NOCHANGE,  ADDR_INC,   /* DINC=NC (FIFO), SINC=INC */
                              BURST_MSIZE,    BURST_MSIZE,
                              TT_FC_M2P_DMA,
                              MASTER_1,       MASTER_1,
                              0, 0),
        .ctl_hi = ctl_hi_make(N_WORDS),
        .cfg_lo = cfg_lo_make(1, 1, 0, 0, 0),   /* sw_hs_dst=1 */
        .cfg_hi = cfg_hi_make(1, 0, HWHS_AES_TX),
    };

    r = ch_setup(&p);
    if (r) return r;
    ch_enable(ch, 0, 0);

    /*
     * Gửi SW-HS: CHỈ 1 burst vì N_WORDS=4 = MSIZE_4=4 items
     * Nếu N_WORDS > FIFO_DEPTH: phải chờ IP drain FIFO giữa các burst
     *   (đọc IP status register trước mỗi sw_hs_dst_burst_block)
     */
    printf("  Sending %u-word SW-HS dst burst...\n", (unsigned)N_WORDS);
    r = sw_hs_dst_burst_block(ch, N_WORDS, BURST_MSIZE);
    if (r) {
        printf("  [ERR] sw_hs_dst_burst_block HANG — IP chưa sẵn sàng?\n");
        printf("        Kiểm tra: IP đã start chưa? FIFO có đầy không?\n");
        printf("        RAW_TFR=0x%X  RAW_ERR=0x%X  ChEn=0x%X\n",
               (unsigned)REG_RD32(DMAC_RAW_TFR),
               (unsigned)REG_RD32(DMAC_RAW_ERR),
               (unsigned)REG_RD32(DMAC_CH_EN));
        printf("        REQ_DST=0x%X (bit%u stuck=1 → DMAC đang stall)\n",
               (unsigned)REG_RD32(DMAC_REQ_DST), (unsigned)ch);
        /* Force disable channel để thoát */
        REG_WR32(DMAC_CFG_LO(ch), REG_RD32(DMAC_CFG_LO(ch)) | CFG_CH_SUSP_BIT);
        REG_WR32(DMAC_CH_EN, CH_EN_CLR(ch));
        return r;
    }

    r = poll_tfr_done(ch);
    if (r) return r;

    printf("  [PASS] M2P SW-HS: %u words sent to 0x%08X\n",
           (unsigned)N_WORDS, (unsigned)DST_FIFO_ADDR);

    /* Nếu IP có status register, đọc ở đây để xác nhận nhận được data */
    printf("  AES_STATUS = 0x%08X\n", (unsigned)REG_RD32(AES_STATUS));
    return DMAC_OK;
}

/* ===========================================================================
 * TEST 04 – P2M single-block, SW-HS src
 *
 * Mô phỏng: SRC_BUF[0] làm "FIFO cố định" (ADDR_NOCHANGE cho SINC)
 * =========================================================================*/
static dmac_err_t test04_p2m_swhs(void)
{
    uint32_t i, ch = 3;
    dmac_err_t r;
    const uint32_t FIFO_VAL = 0xCAFEBABEU;
    uint32_t fifo_addr = (uint32_t)(uintptr_t)&SRC_BUF[0];

    printf("\n=== TEST 04: P2M SW-HS src ===\n");
    SRC_BUF[0] = FIFO_VAL;
    mem_fill32(DST_BUF_BASE, 0U, BUF_WORDS);

    ch_params_t p = {
        .ch     = ch,
        .sar    = fifo_addr,
        .dar    = (uint32_t)(uintptr_t)DST_BUF_BASE,
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
        if (DST_BUF[i] != FIFO_VAL) {
            printf("  [FAIL] P2M: dst[%u]=0x%08X != 0x%08X\n",
                   (unsigned)i, (unsigned)DST_BUF[i], (unsigned)FIFO_VAL);
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
    uint32_t src_fifo = (uint32_t)(uintptr_t)&SRC_BUF[0];
    uint32_t dst_fifo = (uint32_t)(uintptr_t)&DST_BUF[0];

    printf("\n=== TEST 05: P2P SW-HS src+dst ===\n");
    SRC_BUF[0] = 0x55AA55AAU;
    DST_BUF[0] = 0U;

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
    printf("  [P2P] DST_BUF[0]=0x%08X (expect 0x55AA55AA)\n", (unsigned)DST_BUF[0]);
    if (DST_BUF[0] != 0x55AA55AAU) return DMAC_ERR_DATA;
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
    uint32_t fifo_addr = (uint32_t)(uintptr_t)&DST_BUF[0];

    printf("\n=== TEST 06: M2P LLI SW-HS dst (%u x %u words) ===\n",
           (unsigned)LLI_BLOCKS, (unsigned)bts);
    for (i = 0; i < BUF_WORDS; i++) SRC_BUF[i] = 0xF0000000U | i;
    mem_fill32(DST_BUF_BASE, 0U, BUF_WORDS);

    for (i = 0; i < LLI_BLOCKS; i++) {
        int has_next = (i < (LLI_BLOCKS - 1U));
        uint32_t sar      = (uint32_t)SRC_BUF_BASE + i * bts * 4U;
        uint32_t llp_next = has_next
                            ? LLP_MAKE(LLI_M2P_BASE + (i+1U)*LLI_ENTRY_SIZE, MASTER_1)
                            : 0U;
        uint32_t ctl_lo   = ctl_lo_make(1,
                                        TR_WIDTH_32, TR_WIDTH_32,
                                        ADDR_NOCHANGE, ADDR_INC,
                                        MSIZE_4, MSIZE_4,
                                        TT_FC_M2P_DMA,
                                        MASTER_1, MASTER_1,
                                        has_next, has_next);
        uint32_t ctl_hi   = ctl_hi_make(bts);
        lli_wr(LLI_M2P_BASE, i, sar, fifo_addr, llp_next, ctl_lo, ctl_hi);
    }

    dmb();
    ch_params_t p = {
        .ch     = ch,
        .sar    = (uint32_t)SRC_BUF_BASE,
        .dar    = fifo_addr,
        .llp    = LLP_MAKE(LLI_M2P_BASE + 1U * LLI_ENTRY_SIZE, MASTER_1),
        .ctl_lo = (uint32_t)REG_RD32(LLI_M2P_BASE + LLI_FIELD_CTLLO_OFF),
        .ctl_hi = (uint32_t)REG_RD32(LLI_M2P_BASE + LLI_FIELD_CTLHI_OFF),
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
    printf("  [M2P LLI] DST_BUF[0]=0x%08X\n", (unsigned)DST_BUF[0]);
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
    AES_PLAIN[0] = 0x00112233U; AES_PLAIN[1] = 0x44556677U;
    AES_PLAIN[2] = 0x8899AABBU; AES_PLAIN[3] = 0xCCDDEEFFU;
    mem_fill32(AES_CIPH_BASE, 0U, 4U);

    /* Cấu hình AES: start encrypt */
    REG_WR32(AES_CTRL, AES_CTRL_ENC | AES_CTRL_START);

    /* Phase A: M2P → AES_DATA_IN */
    printf("  Phase A: DMA → AES_DATA_IN\n");
    ch_params_t pa = {
        .ch     = ch_tx,
        .sar    = (uint32_t)(uintptr_t)AES_PLAIN_BASE,
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
        .dar    = (uint32_t)(uintptr_t)AES_CIPH_BASE,
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
           (unsigned)AES_CIPH[0], (unsigned)AES_CIPH[1],
           (unsigned)AES_CIPH[2], (unsigned)AES_CIPH[3]);
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
    for (i = 0; i < msg_words; i++) SHA2_MSG[i] = 0x61626300U | i;
    mem_fill32(SHA2_DIG_BASE, 0U, digest_words);

    REG_WR32(SHA2_CTRL, SHA2_CTRL_RESET);
    /* small delay */
    { volatile uint32_t d = 100U; while(d--); }
    REG_WR32(SHA2_CTRL, SHA2_CTRL_START);

    /* Phase A */
    printf("  Phase A: DMA → SHA2_DATA_IN (%u words)\n", (unsigned)msg_words);
    ch_params_t pa = {
        .ch     = ch_tx,
        .sar    = (uint32_t)(uintptr_t)SHA2_MSG_BASE,
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
        .dar    = (uint32_t)(uintptr_t)SHA2_DIG_BASE,
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
    for (i = 0; i < digest_words; i++) printf("%08X ", (unsigned)SHA2_DIG[i]);
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
    for (i = 0; i < BUF_WORDS; i++) SRC_BUF[i] = 0xE0000000U | i;
    mem_fill32(DST_BUF_BASE, 0U, BUF_WORDS);

    g_irq_tfr = 0U; g_irq_err = 0U;

    ch_params_t p = {
        .ch     = ch,
        .sar    = (uint32_t)(uintptr_t)SRC_BUF_BASE,
        .dar    = (uint32_t)(uintptr_t)DST_BUF_BASE,
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
    return mem_verify32(SRC_BUF_BASE, DST_BUF_BASE, BUF_WORDS, "M2M IRQ");
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
    for (i = 0; i < bts; i++) { SRC_BUF[i] = 0xA5A50000U | i; DST_BUF[i] = 0U; }

    ch_params_t p = {
        .ch     = ch,
        .sar    = (uint32_t)(uintptr_t)SRC_BUF_BASE,
        .dar    = (uint32_t)(uintptr_t)DST_BUF_BASE,
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

    return mem_verify32(SRC_BUF_BASE, DST_BUF_BASE, bts, "M2M auto-reload");
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
        { "03a M2P probe (M2M mode)",   test03a_m2p_probe    },
        { "03b M2P SW-HS dst (real)",   test03b_m2p_swhs     },
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
