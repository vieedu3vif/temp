/**
 * @file  dw_ahb_dmac_regs.h
 * @brief DW_ahb_dmac v2.24a  –  Register map & bit-field definitions
 *
 * Cấu hình phần cứng:
 *   - 8 channel, stride 0x58 bytes/channel
 *   - CTL : 1 thanh ghi 64-bit, per-channel offset 0x18
 *   - CFG : 1 thanh ghi 64-bit, per-channel offset 0x40
 *   - DMAC_BASE = 0x70000000
 *
 * Lưu ý truy cập 64-bit trên AHB 32-bit:
 *   Ghi low-word (offset + 0) TRƯỚC, sau đó high-word (offset + 4).
 *
 * LLI memory layout (28 bytes, hardware-defined):
 *   +00  SAR    (u32)
 *   +04  DAR    (u32)
 *   +08  LLP    (u32)
 *   +12  CTL_LO (u32)   <-- bits [31:0]  của CTL
 *   +16  CTL_HI (u32)   <-- bits [63:32] của CTL
 *   +20  SSTAT  (u32)
 *   +24  DSTAT  (u32)
 */

#ifndef DW_AHB_DMAC_REGS_H
#define DW_AHB_DMAC_REGS_H

#include <stdint.h>

/* ===========================================================================
 * Base address
 * =========================================================================*/
#ifndef DMAC_BASE
#define DMAC_BASE           0x70000000UL
#endif

/* ===========================================================================
 * Per-Channel Register Offsets  (stride = 0x58 per channel)
 *
 *  Mỗi slot là 8 bytes (do bus 64-bit), kể cả các register 32-bit.
 * =========================================================================*/
#define DMAC_CH_STRIDE      0x58U

#define CH_SAR_OFF          0x000U   /* Source Address Reg        32-bit  */
#define CH_DAR_OFF          0x008U   /* Destination Address Reg   32-bit  */
#define CH_LLP_OFF          0x010U   /* Linked List Pointer Reg   32-bit  */
#define CH_CTL_OFF          0x018U   /* Channel Control Reg       64-bit  */
#define CH_SSTAT_OFF        0x020U   /* Source Status Reg         32-bit  */
#define CH_DSTAT_OFF        0x028U   /* Destination Status Reg    32-bit  */
#define CH_SSTATAR_OFF      0x030U   /* Source Status Addr Reg    32-bit  */
#define CH_DSTATAR_OFF      0x038U   /* Dest Status Addr Reg      32-bit  */
#define CH_CFG_OFF          0x040U   /* Channel Config Reg        64-bit  */
#define CH_SGR_OFF          0x048U   /* Source Gather Reg         32-bit  */
#define CH_DSR_OFF          0x050U   /* Destination Scatter Reg   32-bit  */

/* Word offsets cho low/high của 64-bit registers */
#define CH_CTL_LO_OFF       (CH_CTL_OFF + 0U)   /* CTL bits [31:0]   */
#define CH_CTL_HI_OFF       (CH_CTL_OFF + 4U)   /* CTL bits [63:32]  */
#define CH_CFG_LO_OFF       (CH_CFG_OFF + 0U)   /* CFG bits [31:0]   */
#define CH_CFG_HI_OFF       (CH_CFG_OFF + 4U)   /* CFG bits [63:32]  */

/* Channel register address macros */
#define DMAC_CH_BASE(ch)    (DMAC_BASE + (uint32_t)(ch) * DMAC_CH_STRIDE)
#define DMAC_SAR(ch)        (DMAC_CH_BASE(ch) + CH_SAR_OFF)
#define DMAC_DAR(ch)        (DMAC_CH_BASE(ch) + CH_DAR_OFF)
#define DMAC_LLP(ch)        (DMAC_CH_BASE(ch) + CH_LLP_OFF)
#define DMAC_CTL_LO(ch)     (DMAC_CH_BASE(ch) + CH_CTL_LO_OFF)
#define DMAC_CTL_HI(ch)     (DMAC_CH_BASE(ch) + CH_CTL_HI_OFF)
#define DMAC_SSTAT(ch)      (DMAC_CH_BASE(ch) + CH_SSTAT_OFF)
#define DMAC_DSTAT(ch)      (DMAC_CH_BASE(ch) + CH_DSTAT_OFF)
#define DMAC_SSTATAR(ch)    (DMAC_CH_BASE(ch) + CH_SSTATAR_OFF)
#define DMAC_DSTATAR(ch)    (DMAC_CH_BASE(ch) + CH_DSTATAR_OFF)
#define DMAC_CFG_LO(ch)     (DMAC_CH_BASE(ch) + CH_CFG_LO_OFF)
#define DMAC_CFG_HI(ch)     (DMAC_CH_BASE(ch) + CH_CFG_HI_OFF)
#define DMAC_SGR(ch)        (DMAC_CH_BASE(ch) + CH_SGR_OFF)
#define DMAC_DSR(ch)        (DMAC_CH_BASE(ch) + CH_DSR_OFF)

/* ===========================================================================
 * Global Register Offsets (từ DMAC_BASE)
 * =========================================================================*/
#define DMAC_RAW_TFR_OFF        0x2C0U
#define DMAC_RAW_BLOCK_OFF      0x2C8U
#define DMAC_RAW_SRCTRAN_OFF    0x2D0U
#define DMAC_RAW_DSTTRAN_OFF    0x2D8U
#define DMAC_RAW_ERR_OFF        0x2E0U
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
#define DMAC_STATUS_INT_OFF     0x360U
#define DMAC_REQ_SRC_OFF        0x368U
#define DMAC_REQ_DST_OFF        0x370U
#define DMAC_SGLREQ_SRC_OFF     0x378U
#define DMAC_SGLREQ_DST_OFF     0x380U
#define DMAC_LST_SRC_OFF        0x388U
#define DMAC_LST_DST_OFF        0x390U
#define DMAC_CFG_REG_OFF        0x398U
#define DMAC_CH_EN_OFF          0x3A0U
#define DMAC_ID_OFF             0x3A8U

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
 * Bits [31:0]  -- low word (viết vào offset +0x18)
 * Bits [63:32] -- high word (viết vào offset +0x1C)
 *
 *  [63:45]  rsv
 *  [44]     DONE          – HW set khi block kết thúc
 *  [43:32]  BLOCK_TS      – số data-item trong một block (12-bit)
 *  [31:29]  rsv
 *  [28]     LLP_SRC_EN    – reload SAR từ LLI
 *  [27]     LLP_DEST_EN   – reload DAR từ LLI
 *  [26:25]  SMS           – Source Master Select (0=M1, 1=M2)
 *  [24:23]  DMS           – Dest Master Select
 *  [22:20]  TT_FC         – Transfer Type & Flow Control
 *  [19]     rsv
 *  [18]     DST_SCATTER_EN
 *  [17]     SRC_GATHER_EN
 *  [16:14]  SRC_MSIZE     – Source burst length
 *  [13:11]  DEST_MSIZE    – Dest burst length
 *  [10:9]   SINC          – Source address increment
 *  [8:7]    DINC          – Dest address increment
 *  [6:4]    SRC_TR_WIDTH  – Source transfer width
 *  [3:1]    DST_TR_WIDTH  – Dest transfer width
 *  [0]      INT_EN
 * =========================================================================*/

/* --- Bit positions trong 64-bit CTL --- */
#define CTL_INT_EN_POS          0U
#define CTL_DST_TR_WIDTH_POS    1U
#define CTL_SRC_TR_WIDTH_POS    4U
#define CTL_DINC_POS            7U
#define CTL_SINC_POS            9U
#define CTL_DEST_MSIZE_POS      11U
#define CTL_SRC_MSIZE_POS       14U
#define CTL_SRC_GATHER_EN_POS   17U
#define CTL_DST_SCATTER_EN_POS  18U
#define CTL_TT_FC_POS           20U
#define CTL_DMS_POS             23U
#define CTL_SMS_POS             25U
#define CTL_LLP_DEST_EN_POS     27U
#define CTL_LLP_SRC_EN_POS      28U
#define CTL_BLOCK_TS_POS        32U   /* [43:32] */
#define CTL_DONE_POS            44U

/* --- Masks --- */
#define CTL_BLOCK_TS_MASK       0xFFFU   /* 12 bits */

/* --- Transfer Width values --- */
#define TR_WIDTH_8              0U
#define TR_WIDTH_16             1U
#define TR_WIDTH_32             2U
#define TR_WIDTH_64             3U

/* --- Address Increment values --- */
#define ADDR_INC                0U
#define ADDR_DEC                1U
#define ADDR_NOCHANGE           2U

/* --- Burst size (MSIZE) values --- */
#define MSIZE_1                 0U
#define MSIZE_4                 1U
#define MSIZE_8                 2U
#define MSIZE_16                3U
#define MSIZE_32                4U

/* Lookup: MSIZE enum → actual item count */
static const uint32_t g_msize_items[8] = {1U,4U,8U,16U,32U,64U,128U,256U};

/* --- Transfer Type & Flow Control values --- */
#define TT_FC_M2M_DMA           0U
#define TT_FC_M2P_DMA           1U
#define TT_FC_P2M_DMA           2U
#define TT_FC_P2P_DMA           3U
#define TT_FC_P2M_PERIPH        4U
#define TT_FC_M2P_PERIPH        6U

/* --- Master Select values --- */
#define MASTER_1                0U
#define MASTER_2                1U

/**
 * @brief Tạo giá trị CTL_LO (bits [31:0])
 */
static inline uint32_t ctl_lo_make(uint32_t int_en,
                                   uint32_t dst_tr_w, uint32_t src_tr_w,
                                   uint32_t dinc,     uint32_t sinc,
                                   uint32_t dst_ms,   uint32_t src_ms,
                                   uint32_t tt_fc,
                                   uint32_t dms,      uint32_t sms,
                                   int      llp_dst,  int      llp_src)
{
    uint32_t v = 0;
    v |= (int_en   & 0x1U);
    v |= (dst_tr_w & 0x7U) << CTL_DST_TR_WIDTH_POS;
    v |= (src_tr_w & 0x7U) << CTL_SRC_TR_WIDTH_POS;
    v |= (dinc     & 0x3U) << CTL_DINC_POS;
    v |= (sinc     & 0x3U) << CTL_SINC_POS;
    v |= (dst_ms   & 0x7U) << CTL_DEST_MSIZE_POS;
    v |= (src_ms   & 0x7U) << CTL_SRC_MSIZE_POS;
    v |= (tt_fc    & 0x7U) << CTL_TT_FC_POS;
    v |= (dms      & 0x3U) << CTL_DMS_POS;
    v |= (sms      & 0x3U) << CTL_SMS_POS;
    if (llp_dst) v |= (1U << CTL_LLP_DEST_EN_POS);
    if (llp_src) v |= (1U << CTL_LLP_SRC_EN_POS);
    return v;
}

/**
 * @brief Tạo giá trị CTL_HI (bits [63:32])
 *        Chứa BLOCK_TS tại bits [43:32] → tức là bits [11:0] của high-word
 */
static inline uint32_t ctl_hi_make(uint32_t block_ts)
{
    return (block_ts & CTL_BLOCK_TS_MASK);   /* bits [11:0] of high word = [43:32] total */
}

/* ===========================================================================
 * CFG Register (64-bit, offset 0x40)
 *
 * Bits [31:0]  -- low word (viết vào offset +0x40)
 * Bits [63:32] -- high word (viết vào offset +0x44)
 *
 *  [63:47]  rsv
 *  [46:43]  DEST_PER     – Dst HW HS interface number (4-bit)
 *  [42:39]  SRC_PER      – Src HW HS interface number (4-bit)
 *  [38]     SS_UPD_EN
 *  [37]     DS_UPD_EN
 *  [36:34]  PROTCTL
 *  [33]     FIFO_MODE
 *  [32]     FCMODE
 *  [31]     RELOAD_DST
 *  [30]     RELOAD_SRC
 *  [29:20]  MAX_ABRST    – Max AMBA burst (0 = no limit)
 *  [19]     SRC_HS_POL   – 0 = active high
 *  [18]     DST_HS_POL   – 0 = active high
 *  [17]     LOCK_B
 *  [16]     LOCK_CH
 *  [15:14]  LOCK_B_L
 *  [13:12]  LOCK_CH_L
 *  [11]     HS_SEL_SRC   – 1 = SW handshake
 *  [10]     HS_SEL_DST   – 1 = SW handshake
 *  [9]      FIFO_EMPTY   – RO
 *  [8]      CH_SUSP
 *  [7:5]    CH_PRIOR
 *  [4:0]    rsv
 * =========================================================================*/

/* Bit positions trong 64-bit CFG */
#define CFG_CH_PRIOR_POS        5U
#define CFG_CH_SUSP_POS         8U
#define CFG_FIFO_EMPTY_POS      9U
#define CFG_HS_SEL_DST_POS      10U
#define CFG_HS_SEL_SRC_POS      11U
#define CFG_LOCK_CH_L_POS       12U
#define CFG_LOCK_B_L_POS        14U
#define CFG_LOCK_CH_POS         16U
#define CFG_LOCK_B_POS          17U
#define CFG_DST_HS_POL_POS      18U
#define CFG_SRC_HS_POL_POS      19U
#define CFG_MAX_ABRST_POS       20U
#define CFG_RELOAD_SRC_POS      30U
#define CFG_RELOAD_DST_POS      31U
/* High word positions (relative to full 64-bit) */
#define CFG_FCMODE_POS          32U
#define CFG_FIFO_MODE_POS       33U
#define CFG_PROTCTL_POS         34U
#define CFG_DS_UPD_EN_POS       37U
#define CFG_SS_UPD_EN_POS       38U
#define CFG_SRC_PER_POS         39U   /* [42:39] */
#define CFG_DEST_PER_POS        43U   /* [46:43] */

/* Bit masks để đọc CFG_HI */
#define CFG_CH_SUSP_BIT         (1U << (CFG_CH_SUSP_POS))
#define CFG_FIFO_EMPTY_BIT      (1U << (CFG_FIFO_EMPTY_POS))
#define CFG_HS_SEL_DST_BIT      (1U << (CFG_HS_SEL_DST_POS))
#define CFG_HS_SEL_SRC_BIT      (1U << (CFG_HS_SEL_SRC_POS))
#define CFG_RELOAD_SRC_BIT      (1U << (CFG_RELOAD_SRC_POS))
#define CFG_RELOAD_DST_BIT      (1U << (CFG_RELOAD_DST_POS))

/**
 * @brief Tạo giá trị CFG_LO (bits [31:0])
 */
static inline uint32_t cfg_lo_make(uint32_t priority,
                                   int      sw_hs_dst, int sw_hs_src,
                                   int      reload_src, int reload_dst)
{
    uint32_t v = 0;
    v |= (priority & 0x7U) << CFG_CH_PRIOR_POS;
    if (sw_hs_dst)  v |= (1U << CFG_HS_SEL_DST_POS);
    if (sw_hs_src)  v |= (1U << CFG_HS_SEL_SRC_POS);
    if (reload_src) v |= (1U << CFG_RELOAD_SRC_POS);
    if (reload_dst) v |= (1U << CFG_RELOAD_DST_POS);
    return v;
}

/**
 * @brief Tạo giá trị CFG_HI (bits [63:32])
 *        Các field ở đây đều tính relative đến high-word (tức offset - 32)
 */
static inline uint32_t cfg_hi_make(int      fifo_mode,
                                   uint32_t src_per, uint32_t dst_per)
{
    uint32_t v = 0;
    if (fifo_mode) v |= (1U << (CFG_FIFO_MODE_POS - 32U));  /* bit 1 of high word */
    v |= ((src_per & 0xFU) << (CFG_SRC_PER_POS  - 32U));   /* bits [10:7]        */
    v |= ((dst_per & 0xFU) << (CFG_DEST_PER_POS - 32U));   /* bits [14:11]       */
    return v;
}

/* ===========================================================================
 * Software Handshaking Registers  (32-bit)
 *
 *  bits[15:8] = Write-Enable (WE)
 *  bits[7:0]  = Request / Last flag
 *
 *  SET:   ghi (WE | REQ) → DMAC nhận request, tự clear REQ sau khi xử lý
 *  CLEAR: ghi (WE | 0)   → xoá request (ít khi dùng)
 * =========================================================================*/
#define SWHS_REQ_BIT(ch)        (1U << (ch))
#define SWHS_WE_BIT(ch)         (1U << ((ch) + 8U))
#define SWHS_SET(ch)            (SWHS_WE_BIT(ch) | SWHS_REQ_BIT(ch))
#define SWHS_CLR(ch)            (SWHS_WE_BIT(ch))

/* ===========================================================================
 * ChEnReg (32-bit)  –  bits[15:8]=WE, bits[7:0]=CH_EN
 * =========================================================================*/
#define CH_EN_BIT(ch)           (1U << (ch))
#define CH_EN_WE(ch)            (1U << ((ch) + 8U))
#define CH_EN_SET(ch)           (CH_EN_WE(ch) | CH_EN_BIT(ch))
#define CH_EN_CLR(ch)           (CH_EN_WE(ch))

/* ===========================================================================
 * DmaCfgReg
 * =========================================================================*/
#define DMAC_EN                 (1U << 0)

/* ===========================================================================
 * StatusInt bits
 * =========================================================================*/
#define INT_TFR                 (1U << 0)
#define INT_BLOCK               (1U << 1)
#define INT_SRCTRAN             (1U << 2)
#define INT_DSTTRAN             (1U << 3)
#define INT_ERR                 (1U << 4)

/* Interrupt MASK register: same WE format as SW-HS
 *   SET = unmask (enable) interrupt for channel ch
 *   CLR = mask (disable) interrupt for channel ch       */
#define INT_MASK_SET(ch)        (SWHS_WE_BIT(ch) | SWHS_REQ_BIT(ch))
#define INT_MASK_CLR(ch)        (SWHS_WE_BIT(ch))

/* ===========================================================================
 * Register Access Primitives
 * =========================================================================*/
#define REG32(addr)             (*((volatile uint32_t *)(uintptr_t)(addr)))
#define REG_WR32(addr, v)       (REG32(addr) = (uint32_t)(v))
#define REG_RD32(addr)          (REG32(addr))

/* ===========================================================================
 * LLI (Linked List Item) – memory layout khớp DMAC hardware
 *
 * QUAN TRỌNG: CTL phải nằm tại offset +12 (ngay sau LLP),
 * không được để compiler thêm padding. Dùng packed struct.
 *
 *  Offset  Field    Size
 *   +00    sar      4
 *   +04    dar      4
 *   +08    llp      4
 *   +12    ctl_lo   4   ← bits [31:0]  của CTL
 *   +16    ctl_hi   4   ← bits [63:32] của CTL
 *   +20    sstat    4
 *   +24    dstat    4
 *   Total: 28 bytes
 * =========================================================================*/
typedef struct __attribute__((packed)) {
    uint32_t sar;       /* Source Address                              */
    uint32_t dar;       /* Destination Address                         */
    uint32_t llp;       /* Next LLI pointer [31:2], LMS[1:0]           */
    uint32_t ctl_lo;    /* CTL bits [31:0]                             */
    uint32_t ctl_hi;    /* CTL bits [63:32]  (BLOCK_TS ở [11:0] đây)  */
    uint32_t sstat;     /* Source Status                               */
    uint32_t dstat;     /* Destination Status                          */
} dmac_lli_t;

/* Compile-time check kích thước LLI */
typedef char _lli_size_check[(sizeof(dmac_lli_t) == 28U) ? 1 : -1];

/* Tạo giá trị LLP register:
 *   addr  = địa chỉ LLI kế tiếp (phải align 4)
 *   lms   = master select của bus chứa LLI (thường = MASTER_1)   */
#define LLP_MAKE(addr, lms) \
    (((uint32_t)(uintptr_t)(addr) & 0xFFFFFFFCU) | ((uint32_t)(lms) & 0x3U))

#endif /* DW_AHB_DMAC_REGS_H */
