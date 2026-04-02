/**
 * @file  dw_ahb_dmac_regs.h
 * @brief DesignWare AHB DMA Controller (DW_ahb_dmac v2.24a) - Register Map
 *
 * Cấu hình phần cứng:
 *   - 8 channel tối đa
 *   - CTL  : 1 thanh ghi 64-bit, offset 0x18 (KHÔNG tách Hi/Lo)
 *   - CFG  : 1 thanh ghi 64-bit, offset 0x40 (KHÔNG tách Hi/Lo)
 *   - SAR, DAR, LLP : 32-bit
 *   - Stride mỗi channel: 0x58 bytes
 *   - DMAC_BASE = 0x70000000
 *
 * Truy cập thanh ghi 64-bit trên AHB 32-bit:
 *   Ghi word thấp (offset+0) trước, sau đó word cao (offset+4).
 */

#ifndef DW_AHB_DMAC_REGS_H
#define DW_AHB_DMAC_REGS_H

#include <stdint.h>

/* ===========================================================================
 * Base address DMAC
 * =========================================================================*/
#ifndef DMAC_BASE
#define DMAC_BASE           0x70000000UL
#endif

/* ===========================================================================
 * Per-Channel Register Offsets  (stride = 0x58 mỗi channel)
 * =========================================================================*/
#define DMAC_CH_STRIDE      0x58U

#define CH_SAR_OFF          0x000U  /* Source Address Register     (32-bit) */
#define CH_DAR_OFF          0x008U  /* Destination Address Register(32-bit) */
#define CH_LLP_OFF          0x010U  /* Linked List Pointer         (32-bit) */
#define CH_CTL_OFF          0x018U  /* Channel Control Register    (64-bit) */
#define CH_SSTAT_OFF        0x020U  /* Source Status Register      (32-bit) */
#define CH_DSTAT_OFF        0x028U  /* Destination Status Register (32-bit) */
#define CH_SSTATAR_OFF      0x030U  /* Source Status Addr Reg      (32-bit) */
#define CH_DSTATAR_OFF      0x038U  /* Dest Status Addr Register   (32-bit) */
#define CH_CFG_OFF          0x040U  /* Channel Config Register     (64-bit) */
#define CH_SGR_OFF          0x048U  /* Source Gather Register      (32-bit) */
#define CH_DSR_OFF          0x050U  /* Destination Scatter Register(32-bit) */

/* Channel register address macros */
#define DMAC_CH_BASE(ch)    (DMAC_BASE + (uint32_t)(ch) * DMAC_CH_STRIDE)
#define DMAC_SAR(ch)        (DMAC_CH_BASE(ch) + CH_SAR_OFF)
#define DMAC_DAR(ch)        (DMAC_CH_BASE(ch) + CH_DAR_OFF)
#define DMAC_LLP(ch)        (DMAC_CH_BASE(ch) + CH_LLP_OFF)
#define DMAC_CTL(ch)        (DMAC_CH_BASE(ch) + CH_CTL_OFF)   /* 64-bit */
#define DMAC_SSTAT(ch)      (DMAC_CH_BASE(ch) + CH_SSTAT_OFF)
#define DMAC_DSTAT(ch)      (DMAC_CH_BASE(ch) + CH_DSTAT_OFF)
#define DMAC_SSTATAR(ch)    (DMAC_CH_BASE(ch) + CH_SSTATAR_OFF)
#define DMAC_DSTATAR(ch)    (DMAC_CH_BASE(ch) + CH_DSTATAR_OFF)
#define DMAC_CFG(ch)        (DMAC_CH_BASE(ch) + CH_CFG_OFF)   /* 64-bit */
#define DMAC_SGR(ch)        (DMAC_CH_BASE(ch) + CH_SGR_OFF)
#define DMAC_DSR(ch)        (DMAC_CH_BASE(ch) + CH_DSR_OFF)

/* ===========================================================================
 * Global Register Offsets (từ DMAC_BASE, tất cả 32-bit trừ ghi chú)
 * =========================================================================*/
#define DMAC_RAW_TFR_OFF        0x2C0U  /* Raw Transfer-Complete Interrupt    */
#define DMAC_RAW_BLOCK_OFF      0x2C8U  /* Raw Block-Complete Interrupt       */
#define DMAC_RAW_SRCTRAN_OFF    0x2D0U  /* Raw Source-Transaction Interrupt   */
#define DMAC_RAW_DSTTRAN_OFF    0x2D8U  /* Raw Dest-Transaction Interrupt     */
#define DMAC_RAW_ERR_OFF        0x2E0U  /* Raw Error Interrupt                */
#define DMAC_STATUS_TFR_OFF     0x2E8U
#define DMAC_STATUS_BLOCK_OFF   0x2F0U
#define DMAC_STATUS_SRCTRAN_OFF 0x2F8U
#define DMAC_STATUS_DSTTRAN_OFF 0x300U
#define DMAC_STATUS_ERR_OFF     0x308U
#define DMAC_MASK_TFR_OFF       0x310U
#define DMAC_MASK_BLOCK_OFF     0x318U
#define DMAC_MASK_SRCTRAN_OFF   0x320U
#define DMAC_MASK_DSTTRAN_OFF   0x328U
#define DMAC_MASK_ERR_OFF       0x330U
#define DMAC_CLEAR_TFR_OFF      0x338U
#define DMAC_CLEAR_BLOCK_OFF    0x340U
#define DMAC_CLEAR_SRCTRAN_OFF  0x348U
#define DMAC_CLEAR_DSTTRAN_OFF  0x350U
#define DMAC_CLEAR_ERR_OFF      0x358U
#define DMAC_STATUS_INT_OFF     0x360U  /* Combined Interrupt Status (RO)     */
/* Software Handshaking Registers */
#define DMAC_REQ_SRC_OFF        0x368U  /* Burst Src Transaction Request      */
#define DMAC_REQ_DST_OFF        0x370U  /* Burst Dst Transaction Request      */
#define DMAC_SGLREQ_SRC_OFF     0x378U  /* Single Src Transaction Request     */
#define DMAC_SGLREQ_DST_OFF     0x380U  /* Single Dst Transaction Request     */
#define DMAC_LST_SRC_OFF        0x388U  /* Last Src Transaction Request       */
#define DMAC_LST_DST_OFF        0x390U  /* Last Dst Transaction Request       */
/* DMAC Global Control */
#define DMAC_CFG_REG_OFF        0x398U  /* DMAC Enable Register               */
#define DMAC_CH_EN_OFF          0x3A0U  /* Channel Enable Register            */
#define DMAC_ID_OFF             0x3A8U  /* DMAC Component ID (RO)             */
#define DMAC_TEST_OFF           0x3B0U  /* DMAC Test Register                 */

/* Global register address macros */
#define DMAC_RAW_TFR        (DMAC_BASE + DMAC_RAW_TFR_OFF)
#define DMAC_RAW_BLOCK      (DMAC_BASE + DMAC_RAW_BLOCK_OFF)
#define DMAC_RAW_SRCTRAN    (DMAC_BASE + DMAC_RAW_SRCTRAN_OFF)
#define DMAC_RAW_DSTTRAN    (DMAC_BASE + DMAC_RAW_DSTTRAN_OFF)
#define DMAC_RAW_ERR        (DMAC_BASE + DMAC_RAW_ERR_OFF)
#define DMAC_STATUS_TFR     (DMAC_BASE + DMAC_STATUS_TFR_OFF)
#define DMAC_STATUS_BLOCK   (DMAC_BASE + DMAC_STATUS_BLOCK_OFF)
#define DMAC_STATUS_SRCTRAN (DMAC_BASE + DMAC_STATUS_SRCTRAN_OFF)
#define DMAC_STATUS_DSTTRAN (DMAC_BASE + DMAC_STATUS_DSTTRAN_OFF)
#define DMAC_STATUS_ERR     (DMAC_BASE + DMAC_STATUS_ERR_OFF)
#define DMAC_MASK_TFR       (DMAC_BASE + DMAC_MASK_TFR_OFF)
#define DMAC_MASK_BLOCK     (DMAC_BASE + DMAC_MASK_BLOCK_OFF)
#define DMAC_MASK_SRCTRAN   (DMAC_BASE + DMAC_MASK_SRCTRAN_OFF)
#define DMAC_MASK_DSTTRAN   (DMAC_BASE + DMAC_MASK_DSTTRAN_OFF)
#define DMAC_MASK_ERR       (DMAC_BASE + DMAC_MASK_ERR_OFF)
#define DMAC_CLEAR_TFR      (DMAC_BASE + DMAC_CLEAR_TFR_OFF)
#define DMAC_CLEAR_BLOCK    (DMAC_BASE + DMAC_CLEAR_BLOCK_OFF)
#define DMAC_CLEAR_SRCTRAN  (DMAC_BASE + DMAC_CLEAR_SRCTRAN_OFF)
#define DMAC_CLEAR_DSTTRAN  (DMAC_BASE + DMAC_CLEAR_DSTTRAN_OFF)
#define DMAC_CLEAR_ERR      (DMAC_BASE + DMAC_CLEAR_ERR_OFF)
#define DMAC_STATUS_INT     (DMAC_BASE + DMAC_STATUS_INT_OFF)
#define DMAC_REQ_SRC        (DMAC_BASE + DMAC_REQ_SRC_OFF)
#define DMAC_REQ_DST        (DMAC_BASE + DMAC_REQ_DST_OFF)
#define DMAC_SGLREQ_SRC     (DMAC_BASE + DMAC_SGLREQ_SRC_OFF)
#define DMAC_SGLREQ_DST     (DMAC_BASE + DMAC_SGLREQ_DST_OFF)
#define DMAC_LST_SRC        (DMAC_BASE + DMAC_LST_SRC_OFF)
#define DMAC_LST_DST        (DMAC_BASE + DMAC_LST_DST_OFF)
#define DMAC_CFG_REG        (DMAC_BASE + DMAC_CFG_REG_OFF)
#define DMAC_CH_EN          (DMAC_BASE + DMAC_CH_EN_OFF)

/* ===========================================================================
 * CTL Register (64-bit, offset 0x18)
 *
 *  [63:45] rsv
 *  [44]    DONE          – set bởi HW khi block transfer kết thúc
 *  [43:32] BLOCK_TS      – 12 bits, số data items trong block
 *  [31:29] rsv
 *  [28]    LLP_SRC_EN    – enable load SAR từ LLI
 *  [27]    LLP_DEST_EN   – enable load DAR từ LLI
 *  [26:25] SMS           – Source Master Select (0=M1, 1=M2)
 *  [24:23] DMS           – Destination Master Select
 *  [22:20] TT_FC         – Transfer Type & Flow Control
 *  [19]    rsv
 *  [18]    DST_SCATTER_EN
 *  [17]    SRC_GATHER_EN
 *  [16:14] SRC_MSIZE     – Source Burst Transaction Length
 *  [13:11] DEST_MSIZE    – Destination Burst Transaction Length
 *  [10:9]  SINC          – Source Address Increment
 *  [8:7]   DINC          – Destination Address Increment
 *  [6:4]   SRC_TR_WIDTH  – Source Transfer Width
 *  [3:1]   DST_TR_WIDTH  – Destination Transfer Width
 *  [0]     INT_EN        – Interrupt Enable
 * =========================================================================*/
#define CTL_INT_EN              (1ULL <<  0)

#define CTL_DST_TR_WIDTH_SHIFT  1
#define CTL_DST_TR_WIDTH_MASK   (0x7ULL <<  1)

#define CTL_SRC_TR_WIDTH_SHIFT  4
#define CTL_SRC_TR_WIDTH_MASK   (0x7ULL <<  4)

#define CTL_DINC_SHIFT          7
#define CTL_DINC_MASK           (0x3ULL <<  7)

#define CTL_SINC_SHIFT          9
#define CTL_SINC_MASK           (0x3ULL <<  9)

#define CTL_DEST_MSIZE_SHIFT    11
#define CTL_DEST_MSIZE_MASK     (0x7ULL << 11)

#define CTL_SRC_MSIZE_SHIFT     14
#define CTL_SRC_MSIZE_MASK      (0x7ULL << 14)

#define CTL_SRC_GATHER_EN       (1ULL << 17)
#define CTL_DST_SCATTER_EN      (1ULL << 18)

#define CTL_TT_FC_SHIFT         20
#define CTL_TT_FC_MASK          (0x7ULL << 20)

#define CTL_DMS_SHIFT           23
#define CTL_DMS_MASK            (0x3ULL << 23)

#define CTL_SMS_SHIFT           25
#define CTL_SMS_MASK            (0x3ULL << 25)

#define CTL_LLP_DEST_EN         (1ULL << 27)
#define CTL_LLP_SRC_EN          (1ULL << 28)

#define CTL_BLOCK_TS_SHIFT      32
#define CTL_BLOCK_TS_MASK       (0xFFFULL << 32)  /* bits [43:32] */

#define CTL_DONE                (1ULL << 44)

/* --- Transfer Width --- */
#define TR_WIDTH_8              0U
#define TR_WIDTH_16             1U
#define TR_WIDTH_32             2U
#define TR_WIDTH_64             3U

/* --- Address Increment --- */
#define ADDR_INC                0U   /* Increment   */
#define ADDR_DEC                1U   /* Decrement   */
#define ADDR_NOCHANGE           2U   /* No change   */

/* --- Burst size (MSIZE) --- */
#define MSIZE_1                 0U
#define MSIZE_4                 1U
#define MSIZE_8                 2U
#define MSIZE_16                3U
#define MSIZE_32                4U

/* --- Transfer Type & Flow Control --- */
#define TT_FC_M2M_DMA           0U   /* MEM→MEM,    DMA ctrl   */
#define TT_FC_M2P_DMA           1U   /* MEM→Periph, DMA ctrl   */
#define TT_FC_P2M_DMA           2U   /* Periph→MEM, DMA ctrl   */
#define TT_FC_P2P_DMA           3U   /* Periph→Periph, DMA ctrl*/
#define TT_FC_P2M_PERIPH        4U   /* Periph→MEM, Peri ctrl  */
#define TT_FC_M2P_PERIPH        6U   /* MEM→Periph, Peri ctrl  */

/* --- Master Select --- */
#define MASTER_1                0U
#define MASTER_2                1U

/**
 * @brief Tạo giá trị thanh ghi CTL 64-bit
 */
static inline uint64_t ctl_make(uint32_t int_en,
                                uint32_t dst_tr_w, uint32_t src_tr_w,
                                uint32_t dinc,     uint32_t sinc,
                                uint32_t dst_ms,   uint32_t src_ms,
                                uint32_t tt_fc,
                                uint32_t dms,      uint32_t sms,
                                int      llp_dst,  int      llp_src,
                                uint32_t block_ts)
{
    uint64_t v = 0;
    v |= (uint64_t)(int_en  & 0x1U);
    v |= (uint64_t)(dst_tr_w & 0x7U) << CTL_DST_TR_WIDTH_SHIFT;
    v |= (uint64_t)(src_tr_w & 0x7U) << CTL_SRC_TR_WIDTH_SHIFT;
    v |= (uint64_t)(dinc     & 0x3U) << CTL_DINC_SHIFT;
    v |= (uint64_t)(sinc     & 0x3U) << CTL_SINC_SHIFT;
    v |= (uint64_t)(dst_ms   & 0x7U) << CTL_DEST_MSIZE_SHIFT;
    v |= (uint64_t)(src_ms   & 0x7U) << CTL_SRC_MSIZE_SHIFT;
    v |= (uint64_t)(tt_fc    & 0x7U) << CTL_TT_FC_SHIFT;
    v |= (uint64_t)(dms      & 0x3U) << CTL_DMS_SHIFT;
    v |= (uint64_t)(sms      & 0x3U) << CTL_SMS_SHIFT;
    if (llp_dst) v |= CTL_LLP_DEST_EN;
    if (llp_src) v |= CTL_LLP_SRC_EN;
    v |= (uint64_t)(block_ts & 0xFFFU) << CTL_BLOCK_TS_SHIFT;
    return v;
}

/* ===========================================================================
 * CFG Register (64-bit, offset 0x40)
 *
 *  [63:47] rsv
 *  [46:43] DEST_PER     – Dst HW Handshake Interface (4 bits)
 *  [42:39] SRC_PER      – Src HW Handshake Interface (4 bits)
 *  [38]    SS_UPD_EN    – Source Status Update Enable
 *  [37]    DS_UPD_EN    – Destination Status Update Enable
 *  [36:34] PROTCTL      – AHB HPROT[3:1]
 *  [33]    FIFO_MODE    – 0=space/data available, 1=use full FIFO
 *  [32]    FCMODE       – Flow Control Mode
 *  [31]    RELOAD_DST   – Auto-reload DAR cho multi-block
 *  [30]    RELOAD_SRC   – Auto-reload SAR cho multi-block
 *  [29:20] MAX_ABRST    – Max AMBA Burst Length (0=no limit)
 *  [19]    SRC_HS_POL   – Src Handshake Polarity (0=active high)
 *  [18]    DST_HS_POL   – Dst Handshake Polarity (0=active high)
 *  [17]    LOCK_B
 *  [16]    LOCK_CH
 *  [15:14] LOCK_B_L
 *  [13:12] LOCK_CH_L
 *  [11]    HS_SEL_SRC   – 1=SW handshake, 0=HW handshake
 *  [10]    HS_SEL_DST   – 1=SW handshake, 0=HW handshake
 *  [9]     FIFO_EMPTY   – RO: FIFO empty flag
 *  [8]     CH_SUSP      – Channel Suspend
 *  [7:5]   CH_PRIOR     – Channel Priority (0=thấp nhất, 7=cao nhất)
 *  [4:0]   rsv
 * =========================================================================*/
#define CFG_CH_PRIOR_SHIFT      5
#define CFG_CH_PRIOR_MASK       (0x7ULL <<  5)

#define CFG_CH_SUSP             (1ULL <<  8)
#define CFG_FIFO_EMPTY          (1ULL <<  9)   /* RO */
#define CFG_HS_SEL_DST          (1ULL << 10)   /* 1 = SW HS dst */
#define CFG_HS_SEL_SRC          (1ULL << 11)   /* 1 = SW HS src */

#define CFG_LOCK_CH_L_SHIFT     12
#define CFG_LOCK_CH_L_MASK      (0x3ULL << 12)
#define CFG_LOCK_B_L_SHIFT      14
#define CFG_LOCK_B_L_MASK       (0x3ULL << 14)

#define CFG_LOCK_CH             (1ULL << 16)
#define CFG_LOCK_B              (1ULL << 17)

#define CFG_DST_HS_POL          (1ULL << 18)   /* 0 = active high */
#define CFG_SRC_HS_POL          (1ULL << 19)   /* 0 = active high */

#define CFG_MAX_ABRST_SHIFT     20
#define CFG_MAX_ABRST_MASK      (0x3FFULL << 20)

#define CFG_RELOAD_SRC          (1ULL << 30)
#define CFG_RELOAD_DST          (1ULL << 31)

#define CFG_FCMODE              (1ULL << 32)
#define CFG_FIFO_MODE           (1ULL << 33)

#define CFG_PROTCTL_SHIFT       34
#define CFG_PROTCTL_MASK        (0x7ULL << 34)

#define CFG_DS_UPD_EN           (1ULL << 37)
#define CFG_SS_UPD_EN           (1ULL << 38)

#define CFG_SRC_PER_SHIFT       39             /* bits [42:39] */
#define CFG_SRC_PER_MASK        (0xFULL << 39)

#define CFG_DEST_PER_SHIFT      43             /* bits [46:43] */
#define CFG_DEST_PER_MASK       (0xFULL << 43)

/**
 * @brief Tạo giá trị thanh ghi CFG 64-bit
 */
static inline uint64_t cfg_make(uint32_t priority,
                                int      sw_hs_dst, int sw_hs_src,
                                int      fifo_mode,
                                int      reload_src, int reload_dst,
                                uint32_t src_per,    uint32_t dst_per)
{
    uint64_t v = 0;
    v |= (uint64_t)(priority & 0x7U) << CFG_CH_PRIOR_SHIFT;
    if (sw_hs_dst)   v |= CFG_HS_SEL_DST;
    if (sw_hs_src)   v |= CFG_HS_SEL_SRC;
    if (fifo_mode)   v |= CFG_FIFO_MODE;
    if (reload_src)  v |= CFG_RELOAD_SRC;
    if (reload_dst)  v |= CFG_RELOAD_DST;
    v |= (uint64_t)(src_per & 0xFU) << CFG_SRC_PER_SHIFT;
    v |= (uint64_t)(dst_per & 0xFU) << CFG_DEST_PER_SHIFT;
    return v;
}

/* ===========================================================================
 * Software Handshaking Registers  (32-bit)
 *
 * Format tất cả SW-HS registers:
 *   bits[15:8] = Write-Enable (WE) – phải set tương ứng mới được ghi
 *   bits[7:0]  = Request / Last flag
 *
 *  Để SET:   ghi (WE_ch | REQ_ch)
 *  Để CLEAR: ghi (WE_ch | 0)
 * =========================================================================*/
#define SWHS_REQ_BIT(ch)    (1U        << (ch))
#define SWHS_WE_BIT(ch)     (1U        << ((ch) + 8U))
#define SWHS_SET(ch)        (SWHS_WE_BIT(ch) | SWHS_REQ_BIT(ch))
#define SWHS_CLR(ch)        (SWHS_WE_BIT(ch))

/* ===========================================================================
 * ChEnReg (32-bit)
 *   bits[15:8] = Write-Enable
 *   bits[7:0]  = Channel Enable
 * =========================================================================*/
#define CH_EN_BIT(ch)       (1U << (ch))
#define CH_EN_WE(ch)        (1U << ((ch) + 8U))
#define CH_EN_SET(ch)       (CH_EN_WE(ch) | CH_EN_BIT(ch))
#define CH_EN_CLR(ch)       (CH_EN_WE(ch))

/* ===========================================================================
 * DmaCfgReg bits
 * =========================================================================*/
#define DMAC_EN             (1U << 0)

/* ===========================================================================
 * StatusInt bits (DMAC_STATUS_INT)
 * =========================================================================*/
#define INT_TFR             (1U << 0)
#define INT_BLOCK           (1U << 1)
#define INT_SRCTRAN         (1U << 2)
#define INT_DSTTRAN         (1U << 3)
#define INT_ERR             (1U << 4)

/* Interrupt mask/clear helper (cùng format WE như SW-HS) */
#define INT_MASK_SET(ch)    (SWHS_WE_BIT(ch) | SWHS_REQ_BIT(ch))
#define INT_MASK_CLR(ch)    (SWHS_WE_BIT(ch))

/* ===========================================================================
 * Register Access Primitives
 * =========================================================================*/
#define REG32(addr)         (*((volatile uint32_t *)(uintptr_t)(addr)))
#define REG_WR32(addr, v)   (REG32(addr) = (uint32_t)(v))
#define REG_RD32(addr)      (REG32(addr))

/* 64-bit via hai lần 32-bit, little-endian */
static inline void reg_wr64(uint32_t base, uint64_t val)
{
    REG_WR32(base,      (uint32_t)(val         & 0xFFFFFFFFULL));
    REG_WR32(base + 4U, (uint32_t)((val >> 32) & 0xFFFFFFFFULL));
}

static inline uint64_t reg_rd64(uint32_t base)
{
    uint64_t lo = (uint64_t)REG_RD32(base);
    uint64_t hi = (uint64_t)REG_RD32(base + 4U);
    return lo | (hi << 32);
}

#define REG_WR64(addr, v)   reg_wr64((uint32_t)(addr), (uint64_t)(v))
#define REG_RD64(addr)      reg_rd64((uint32_t)(addr))

/* ===========================================================================
 * LLI (Linked List Item) structure  —  align 4 bytes
 *
 * Thứ tự field đúng theo DW_ahb_dmac databook:
 *   SAR (32), DAR (32), LLP (32), [pad 32], CTL (64), SSTAT (32), DSTAT (32)
 * =========================================================================*/
typedef struct __attribute__((aligned(4))) {
    uint32_t sar;       /* Source address                              */
    uint32_t dar;       /* Destination address                         */
    uint32_t llp;       /* Next LLI address [31:2], LMS[1:0]           */
    uint32_t _rsv;      /* Reserved / alignment pad                    */
    uint64_t ctl;       /* CTL register value cho block này            */
    uint32_t sstat;     /* Source status (dùng nếu SS_UPD_EN)          */
    uint32_t dstat;     /* Destination status (dùng nếu DS_UPD_EN)     */
} dmac_lli_t;

/* Tạo giá trị LLP register: addr phải align 4, lms = master select bits */
#define LLP_MAKE(addr, lms) \
    (((uint32_t)(uintptr_t)(addr) & 0xFFFFFFFCU) | ((uint32_t)(lms) & 0x3U))

#endif /* DW_AHB_DMAC_REGS_H */
