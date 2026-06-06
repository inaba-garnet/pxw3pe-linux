// SPDX-License-Identifier: GPL-2.0
/*
 * PLEX PX-W3PE (ASICEN ASV5220) ISDB-S/T PCIe driver — clean-room implementation.
 *
 * Copyright (c) 2026 Inaba <admin@inaba.dev>
 *
 * Implemented from a functional device specification (register offsets,
 * sequences, I2C addresses, tuner tables). No vendor driver code is reused;
 * kernel DVB/I2C/PCI API usage follows standard patterns. Per-model device
 * secrets are not embedded — they are loaded at probe via request_firmware()
 * (see pxw3pe_load_firmware()).
 *
 * Hardware: ASV5220 PCIe bridge + 2x TC905xx dual demod (each = one ISDB-T OFDM
 * core + one ISDB-S 8PSK core) + 2x Fitipower FC0012 (ISDB-T tuner) + 2x
 * write-only raw-PLL synth (ISDB-S tuner) + ASIE5606 control chip + ASV5606
 * transport-crypto controller.
 *
 *   chip0: T-core 0x30 (T0) + S-core 0x32 (S0)
 *   chip1: T-core 0x34 (T1) + S-core 0x36 (S1)
 *
 * Provides four DVB adapters (2x ISDB-S + 2x ISDB-T) with hardware frontends,
 * per-chip tune serialization, ping-pong DMA dispatched by per-packet source
 * tag, and ASV5606 transport descramble. The S and T cores of one chip share an
 * analog front-end, so a full power-cycle gives the most reliable cold state.
 *
 * Portions modeled on GPL-2.0 sources (no code copied; license-compatible):
 * TC90522 sleep / TS-output-pin register values from px4_drv (tsukumijima);
 * the des_xor_idx[] index table, ASV5220 bridge teardown, and DMA/dispatch
 * patterns from the in-tree PX-Q3PE driver (Copyright Budi Rachmanto, AreMa Inc.).
 */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <media/dvbdev.h>
#include <media/dvb_demux.h>
#include <media/dmxdev.h>
#include <media/dvb_frontend.h>
#include <linux/firmware.h>
#include <crypto/des.h>

#define PXW3PE_NAME	"pxw3pe"

/* TS packet/buffer geometry. */
#define TS_SIZE		188
#define TS_SYNC		0x47
/*
 * source tag the ASV5220 bridge writes into each packet's sync
 * byte. The two demod cores that share a DMA port are multiplexed onto the
 * port's TS stream and are told apart ONLY by this tag: 0x47 = the ISDB-S
 * core, 0xC7 = the ISDB-T core (cross-checked against the GPL pxq3pe rule
 * table, where ISDB-S addrs 0x12/0x1A map to tag 0x47 and ISDB-T addrs
 * 0x10/0x18 to 0xC7, and the official W3PE dispatch rule table which uses
 * only these two tags). The DMA channel a packet lands in is NOT a reliable
 * source indicator, so dispatch keys on the tag, never on (port,ch).
 */
#define TS_TAG_SAT	0x47
#define TS_TAG_TER	0xc7
#define PKT_NUM_MIN	312			/* clamp floor for the pkt_num param */
#define NR_PORT		2
#define NR_CH		2
#define NR_ADAP		(NR_PORT * NR_CH)	/* S0/S1/T0/T1 */
/*
 * Two TC905xx composite chips, each carrying one ISDB-T (OFDM) core and one
 * ISDB-S (8PSK) core that share the chip's clock/PLL and analog AGC/gain
 * stage. The chip index is derived straight from the demod
 * I2C address: 0x30/0x32 -> chip0, 0x34/0x36 -> chip1.
 */
#define NR_CHIP		2
/*
 * Drop-zero hardening: give each DMA channel N_DMABUF physical buffers and
 * ping-pong between them. On a buffer-full IRQ we point the engine at the
 * next buffer and re-arm *before* copying the just-filled one. Both DMA
 * channels of a port must be armed while any feed on that port is active: the
 * hardware carries the combined S+T TS stream over the port, and source is
 * determined by per-packet tag, not by channel number. Multi-bit IRQ status is
 * handled per stream so a full interrupt cannot be cleared without re-arming
 * its channel.
 */
#define N_DMABUF_MAX	8
#define PXW3PE_PEND	64			/* IRQ top->bottom filled-buffer ring */
#define PKT_NUM_MAX	16384			/* caps per-channel DMA buffer (<4 MiB) */
#define SBUF_NPKT	(PKT_NUM_MAX * 2)	/* per-adapter stream ring     */
#define SBUF_SIZE	(TS_SIZE * SBUF_NPKT)

/* SPEC-DMA-IRQ / SPEC-DMA-REG: DMA + interrupt registers. */
enum {
	REG_IRQ_STAT	= 0x808,
	REG_IRQ_CLEAR	= 0x80c,
	REG_IRQ_FLUSH	= 0x810,
	REG_IRQ_ACTIVE	= 0x814,
	REG_IRQ_DISABLE	= 0x818,
	REG_IRQ_ENABLE	= 0x81c,

	DMA_OFF_PORT	= 0x140,	/* per-port stride               */
	DMA_OFF_CH	= 0x10,		/* per-channel stride            */
	DMA_TSMODE	= 0xa00,	/* per-port; |0x80 = TS output   */
	DMA_MGMT	= 0xae0,	/* per-port; arm/re-arm bits     */
	DMA_ADR_LO	= 0xac0,	/* per-ch DMA buffer addr lo     */
	DMA_ADR_HI	= 0xac4,
	DMA_XFR_STAT	= 0xac8,	/* per-ch; &0x3fffff transferred */
	DMA_CTL		= 0xacc,	/* per-ch control word           */
};
#define DMA_CTL_FLAGS	0x11c00000		/* CTL hi bits; lo = bufsz */
#define DMA_XFR_MASK	0x3fffff

/* BAR register map (cross-validated with GPL pxq3pe). */
enum {
	REG_GP880	= 0x880,	/* general control (RMW at init)   */
	REG_CLK900	= 0x900,	/* clock/PLL                       */
	REG_CLK904	= 0x904,
	REG_I2C_CTL	= 0x940,	/* I2C control/status              */
	REG_I2C_ADR	= 0x944,	/* I2C command/address             */
	REG_I2C_SWCTL	= 0x948,	/* I2C SW strobe                   */
	REG_I2C_FSTAT	= 0x950,	/* I2C FIFO status                 */
	REG_I2C_FDATA	= 0x960,	/* I2C FIFO data                   */
};

/* engine status bits. */
#define I2C_FSTAT_STATE	0x1f		/* FIFO state mask; 0x10 == idle    */
#define I2C_FSTAT_IDLE	0x10
#define I2C_CTL_DONE	0x400000	/* transaction done                 */
#define I2C_CTL_ERR	0x280000	/* error bits                       */

/* control bytes (from official i2c_write jump table). */
#define CTRL_WR		0xc0		/* config/GPIO write + stop         */
#define CTRL_RD		0xe0		/* config/GPIO read                 */
#define CTRL_DMOD_WR	0x80		/* demod/tuner write                */
#define CTRL_DMOD_RD	0xa0		/* demod/tuner read                 */

/* demod 8-bit I2C addresses (TC905xx family). */
#define DEMOD_T0	0x30		/* chip0 ISDB-T (OFDM) core         */
#define DEMOD_S0	0x32		/* chip0 ISDB-S (8PSK) core         */
#define DEMOD_T1	0x34		/* chip1 ISDB-T (OFDM) core         */
#define DEMOD_S1	0x36		/* chip1 ISDB-S (8PSK) core         */
static const u8 demod_addr[4] = { DEMOD_T0, DEMOD_S0, DEMOD_T1, DEMOD_S1 };

/* Composite-chip index a demod core lives on (0x30/0x32 -> 0, 0x34/0x36 -> 1).
 * The two cores on one chip share the analog front-end, so their tune/acquire
 * sequences must be serialized against each other (see chip_lock).
 */
static inline int chip_of(u8 demod)
{
	return (demod >> 2) & 1;
}

/* ASIE5606 control chip. */
#define ASIE_ADDR	0x4a
#define ASIE_GPIO_REG	0x0b

struct pxw3pe;

/* One DVB adapter == one demod core (ISDB-T or ISDB-S). */
struct pxw3pe_adap {
	struct pxw3pe		*card;
	u8			demod;		/* demod I2C address     */
	bool			is_sat;		/* ISDB-S vs ISDB-T      */
	int			port, ch;	/* DMA stream mapping    */

	struct dvb_adapter	dvb;
	struct dvb_demux	demux;
	struct dmxdev		dmxdev;
	struct dvb_frontend	fe;
	bool			dvb_ready;

	/* TS stream ring (ISR producer -> kthread consumer). */
	u8			*sbuf;
	u32			sbuf_w, sbuf_r, sbuf_cnt;
	spinlock_t		sbuf_lock;
	struct task_struct	*thread;
	wait_queue_head_t	wq;
	int			feeds;		/* active demux feeds    */
	bool			streaming;
	/* ISDB-S state shared between the tune and read_status paths. Updated
	 * without a lock by design: both paths only gate idempotent register
	 * writes (re-kick acquisition / re-latch TSID), so a racing update at
	 * worst causes one redundant or one-poll-late re-latch, never corruption.
	 */
	bool			s_stream_set;	/* ISDB-S TSID selected  */
	bool			s_carrier;	/* ISDB-S carrier last seen locked */

	/* per-adapter diagnostics */
	u64			c_drop;		/* ring-overflow drops     */
	u32			c_dropmax;	/* worst ring fill seen    */
	u64			c_bytes;	/* bytes -> swfilter       */
};

struct pxw3pe {
	struct pci_dev	*pdev;
	void __iomem	*bar;
	struct mutex	i2c_lock;	/* serialize transactions */
	/*
	 * Per-composite-chip serialization. The S and T cores of one chip share
	 * the analog front-end (AGC/PLL); their multi-step tune+acquire sequences
	 * must not overlap or the slow ISDB-S 8PSK loop loses lock while the
	 * ISDB-T FC0012 RSSI/VCO recalibration swings the shared gain. This is the
	 * OUTER, sequence-level lock; i2c_lock stays the INNER per-transaction lock
	 * (lock order is always chip_lock -> i2c_lock, never the reverse).
	 * s_acquiring lets a same-chip T tune yield so the S core converges first.
	 */
	struct mutex	chip_lock[NR_CHIP];
	atomic_t	s_acquiring[NR_CHIP];
	/*
	 * last ISDB-S downlink key (sat_map kHz) successfully
	 * programmed, per composite chip. The vendor keeps its prev-freq in a
	 * once-per-device heap buffer that the reference init sequence never zeroes (and the
	 * raw S PLL synth divider survives a re-init), so this
	 * persists across re-inits: it is only set on a
	 * successful S tune, never cleared. Drives the two vendor edge-transition
	 * intermediate PLL kicks (sat_edge_intermediate). 0 = no prior S tune.
	 * Only written under chip_lock from the S tune path.
	 */
	u32		s_prev_key[NR_CHIP];

	struct {
		dma_addr_t	adr;
		void		*dat;
	} dma[NR_ADAP][N_DMABUF_MAX];	/* each ping-pong buffer allocated
					 * separately so a single coherent
					 * block stays under the buddy limit
					 * (~4 MiB), letting pkt_num scale up
					 */
	u32		pkt_bufsz;	/* per-buffer size (= TS_SIZE*pkt_num) */
	u32		dma_ctl;	/* CTL word (flags | pkt_bufsz) */
	int		nbuf;		/* ping-pong buffers per channel */
	bool		dma_ch_on[NR_PORT][NR_CH];
	u8		dma_cur[NR_PORT][NR_CH];	/* ping-pong buffer idx */
	spinlock_t	reg_lock;	/* serialize DMA mgmt RMW vs ISR */
	/* IRQ top-half -> threaded bottom-half handoff: filled DMA buffers to
	 * dispatch + copy outside the hardirq. Produced under reg_lock by the top
	 * half, consumed (also under reg_lock to dequeue) by pxw3pe_irq_thread.
	 */
	struct { u8 port, ch, buf; } pend[PXW3PE_PEND];
	u32		pend_head, pend_tail;
	u64		c_pend_drop;	/* filled buffers dropped (ring full) */
	bool		irq_on;
	u64		c_irq;		/* total IRQs with stat&0xf set  */
	u64		c_irq_multi;	/* IRQs with >1 stream bit set   */
	/* dispatch diagnostics (per DMA channel / per card). The
	 * tag histogram is decisive on the bench: a single active core must show
	 * packets under exactly one source tag. The DMA channel is not a source
	 * indicator; both channels of a port may carry tagged packets from either
	 * demod core.
	 */
	u64		c_full[NR_PORT][NR_CH];	/* buffer-full IRQs        */
	u64		c_skip[NR_PORT][NR_CH];	/* IRQ, XFR != pkt_bufsz   */
	u64		c_tag_sat[NR_PORT][NR_CH];/* 0x47-tagged pkts seen   */
	u64		c_tag_ter[NR_PORT][NR_CH];/* 0xC7-tagged pkts seen   */
	u64		c_unknown;		/* pkts with neither tag   */
	bool		enc_present;
	u8		enc_addr;
	u8		enc_mode;
	struct pxw3pe_adap adap[NR_ADAP];
};

#ifdef CONFIG_DVB_PXW3PE_DEBUG
static bool selftest;
module_param(selftest, bool, 0444);
MODULE_PARM_DESC(selftest,
		 "Run a per-core tuner lock self-test during probe (default off)");
#endif

/*
 * Drop mitigation: the DMA engine loses ~1 multiplex round of TS at every
 * buffer-full -> re-arm transition (a fixed hardware restart penalty, NOT
 * IRQ latency; MSI/immediate re-arm/ping-pong do not change it). Total loss
 * is proportional to the number of buffer boundaries, so a larger per-buffer
 * size reduces it (CC discontinuities scale as ~1/pkt_num): 312->2.9%,
 * 2048->0.9%, 8192->0.30%, 16384->0.15%. The loss is functionally harmless
 * (PSI/ECM are sent redundantly, so b25 decodes fully; verified). Default to
 * 8192 packets (~1.5 MiB, ~1.5 s ISDB-T fill latency) as a balance; raise
 * pkt_num for fewer drops at the cost of latency (each ping-pong buffer is
 * allocated separately, so up to PKT_NUM_MAX stays under the buddy limit).
 */
static int pkt_num = 8192;
module_param(pkt_num, int, 0444);
MODULE_PARM_DESC(pkt_num,
		 "TS packets per DMA buffer (default 8192; larger = fewer boundary drops, more latency)");

static int n_dmabuf = 2;
module_param(n_dmabuf, int, 0444);
MODULE_PARM_DESC(n_dmabuf,
		 "Ping-pong DMA buffers per channel (default 2, max 8)");

static bool use_msi = true;
module_param(use_msi, bool, 0444);
MODULE_PARM_DESC(use_msi,
		 "Use MSI interrupts instead of shared legacy INTx (default on)");

static int s_acquire_retries = 1;
module_param(s_acquire_retries, int, 0444);
MODULE_PARM_DESC(s_acquire_retries,
		 "Retry ISDB-S PLL/acquisition when carrier does not lock (default 1)");

/*
 * SPEC-ENC-DES: ASV5606 transport descramble.
 *
 * The control chip scrambles every TS packet's 184-byte payload (the 4-byte
 * header is left clear) so that even tsc=0 PSI (PAT/PMT) is unreadable
 * downstream. Per 188-byte packet the descramble is:
 *   1. per 8-byte block: payload[i] ^= xor_mask[i], where xor_mask is expanded
 *      from a 4-byte seed via the fixed index table des_xor_idx.
 *   2. standard DES-ECB *decrypt* (crypto/des.h): payload[0:128] (16 blocks)
 *      with the even key, payload[128:184] (7 blocks) with the odd key.
 *
 * The per-model KEY MATERIAL (ASV5606 chip seed, DES even/odd keys, XOR seed)
 * and the ASIE control-chip enable string are device secrets and are NOT shipped
 * in this source. They are loaded at probe from a firmware blob (PXW3PE_FW_NAME)
 * that the operator provides for their own hardware (see README). Without the
 * blob the driver still loads, but the ASIE enable string and transport
 * descramble are unavailable (the card may not initialise / PSI stays scrambled).
 */
static bool descramble = true;
module_param(descramble, bool, 0644);
MODULE_PARM_DESC(descramble,
		 "Apply ASV5606 transport DES descramble when key firmware is present (default on)");

/*
 * Firmware blob layout (PXW3PE_FW_NAME): 4-byte magic "PXWF", 1-byte version,
 * 3 reserved, then the per-model secrets. The operator builds this from their
 * own device; this source ships none of the byte values.
 */
#define PXW3PE_FW_NAME		"pxw3pe.fw"
enum {
	FW_OFF_AUTH	= 8,	/* 16  ASIE enable string */
	FW_OFF_SEED	= 24,	/* 16  ASV5606 chip seed  */
	FW_OFF_DESEVEN	= 40,	/* 8   DES even key       */
	FW_OFF_DESODD	= 48,	/* 8   DES odd key        */
	FW_OFF_DESXOR	= 56,	/* 4   pre-DES XOR seed   */
	FW_SIZE		= 60,
};

/* Expands the 4-byte XOR seed into the 8-byte block mask (algorithm constant,
 * not secret). This index table is identical to the one in the GPL-2.0 PX-Q3PE
 * driver (Copyright Budi Rachmanto, AreMa Inc.); reused under GPL-2.0.
 */
static const u8 des_xor_idx[8] = { 0, 0, 3, 1, 0, 2, 1, 2 };

/* Secrets + derived schedules loaded from firmware; invalid until loaded. */
static u8 fw_auth[16];
static u8 fw_chip_seed[16];
static struct des_ctx des_sched_even;
static struct des_ctx des_sched_odd;
static u8 des_xor_mask[8];
static bool des_ready;	/* DES schedules built from firmware keys */
static bool fw_valid;	/* firmware blob present and parsed       */

static const u8 asv5606_seed_zero[16];

/*
 * Load the per-model key firmware and build the DES schedules + XOR mask.
 * Missing/invalid firmware is non-fatal: fw_valid stays false, asie_auth_enable
 * has no enable string and transport descramble is disabled. des_expand_key()
 * returns -ENOKEY for keys flagged weak but still yields a valid schedule, so
 * only a hard error is fatal.
 */
static void pxw3pe_load_firmware(struct pxw3pe *p)
{
	const struct firmware *fw = NULL;
	struct device *dev = &p->pdev->dev;
	u8 xor_seed[4];
	int re, ro, i;

	if (request_firmware(&fw, PXW3PE_FW_NAME, dev)) {
		dev_warn(dev,
			 "key firmware '%s' not found: ASIE enable string and transport descramble disabled\n",
			 PXW3PE_FW_NAME);
		return;
	}
	if (fw->size < FW_SIZE || memcmp(fw->data, "PXWF", 4) ||
	    fw->data[4] != 1) {
		dev_warn(dev, "key firmware '%s' invalid (size %zu): ignored\n",
			 PXW3PE_FW_NAME, fw->size);
		release_firmware(fw);
		return;
	}
	memcpy(fw_auth, fw->data + FW_OFF_AUTH, sizeof(fw_auth));
	memcpy(fw_chip_seed, fw->data + FW_OFF_SEED, sizeof(fw_chip_seed));
	memcpy(xor_seed, fw->data + FW_OFF_DESXOR, sizeof(xor_seed));
	for (i = 0; i < 8; i++)
		des_xor_mask[i] = xor_seed[des_xor_idx[i]];
	re = des_expand_key(&des_sched_even, fw->data + FW_OFF_DESEVEN,
			    DES_KEY_SIZE);
	ro = des_expand_key(&des_sched_odd, fw->data + FW_OFF_DESODD,
			    DES_KEY_SIZE);
	des_ready = (re == 0 || re == -ENOKEY) && (ro == 0 || ro == -ENOKEY);
	fw_valid = true;
	release_firmware(fw);
	dev_info(dev, "key firmware '%s' loaded (descramble %savailable)\n",
		 PXW3PE_FW_NAME, des_ready ? "" : "NOT ");
}

/* ====================================================================== */
/* BAR-level I2C engine                                     */
/* ====================================================================== */

static int i2c_wait_idle(struct pxw3pe *p)
{
	void __iomem *bar = p->bar;
	u32 fstat = REG_I2C_FSTAT;
	int i, retry;

	for (retry = 0; retry < 2; retry++) {
		for (i = 0; i < 1000; i++) {
			u32 s = readl(bar + fstat);

			if ((s & I2C_FSTAT_STATE) == I2C_FSTAT_IDLE && !(s & 0x1f00))
				return 0;
			usleep_range(20, 50);
		}

		/* SPEC-I2C-010: recover a stuck bridge I2C FSM with SW strobe. */
		writel(0, bar + REG_I2C_CTL);
		writel(readl(bar + REG_I2C_SWCTL) | 0x20, bar + REG_I2C_SWCTL);
		udelay(1);
		writel(readl(bar + REG_I2C_SWCTL) & ~0x20u, bar + REG_I2C_SWCTL);
		usleep_range(20, 50);
	}
	return -EBUSY;
}

/* Write @len bytes (<=16) of @payload to 8-bit @addr with register @reg. */
static int i2c_xfer_wr(struct pxw3pe *p, u8 ctrl, u8 addr, u8 reg,
		       const u8 *payload, u8 len)
{
	void __iomem *bar = p->bar;
	u32 ctl = REG_I2C_CTL;
	u32 adr = REG_I2C_ADR;
	u32 fdata = REG_I2C_FDATA;
	int i, j;

	if (len > 16)
		return -EINVAL;
	if (i2c_wait_idle(p))
		return -EBUSY;
	writel(0, bar + ctl);
	writel(((u32)addr << 8) | reg, bar + adr);

	for (i = 0; i < len; i += 4) {
		u32 w = 0;
		int k;

		for (k = 0; k < 4 && i + k < len; k++)
			w |= (u32)payload[i + k] << (8 * k);
		writel(w, bar + fdata);
	}
	writew(((u16)len << 8) | ctrl, bar + ctl);

	for (j = 0; j < 1000; j++) {
		udelay(10);
		if (readl(bar + ctl) & I2C_CTL_DONE)
			break;
	}
	if (j >= 1000 || (readl(bar + ctl) & I2C_CTL_ERR))
		return -EIO;
	return 0;
}

/* Read @len bytes (<=16) from 8-bit @addr, register @reg into @rbuf. */
static int i2c_xfer_rd(struct pxw3pe *p, u8 ctrl, u8 addr, u8 reg,
		       u8 *rbuf, u8 len)
{
	void __iomem *bar = p->bar;
	u32 ctl = REG_I2C_CTL;
	u32 adr = REG_I2C_ADR;
	u32 fstat = REG_I2C_FSTAT;
	u32 fdata = REG_I2C_FDATA;
	int i = 0, j;

	if (len > 16)
		return -EINVAL;
	if (i2c_wait_idle(p))
		return -EBUSY;
	writel(0, bar + ctl);
	writel(((u32)addr << 8) | reg, bar + adr);
	writew(((u16)len << 8) | ctrl, bar + ctl);

	for (j = 0; j < 500 && i < len; j++) {
		u32 st = readl(bar + ctl);
		u8 rsz = (readl(bar + fstat) >> 8) & 0x1f;

		if ((st >> 16) & 0x28)
			return -EIO;
		/*
		 * Wait only while fewer than a full 32-bit word is available AND
		 * that is also fewer than the bytes still needed. Otherwise drain
		 * now — this also handles the final partial word of an odd-length
		 * read (which never reaches a 4-byte multiple).
		 */
		if (rsz < 4 && rsz < (len - i)) {
			udelay(10);
			continue;
		}
		while (rsz && i < len) {
			u32 w = readl(bar + fdata);
			int k;

			for (k = 0; k < 4 && i < len; k++, i++)
				rbuf[i] = (w >> (8 * k)) & 0xff;
			rsz = rsz > 4 ? rsz - 4 : 0;
		}
		udelay(10);
	}
	return i == len ? 0 : -EIO;
}

/* ====================================================================== */
/* Device register helpers (demod + ASIE5606)                             */
/* ====================================================================== */

/* Demod register read: TC905xx needs a reg-pointer write then a read. */
static int demod_rd(struct pxw3pe *p, u8 addr, u8 reg, u8 *val)
{
	int ret;

	mutex_lock(&p->i2c_lock);
	ret = i2c_xfer_wr(p, CTRL_DMOD_WR, addr, 0, &reg, 1);
	if (!ret)
		ret = i2c_xfer_rd(p, CTRL_DMOD_RD, addr, 0, val, 1);
	mutex_unlock(&p->i2c_lock);
	return ret;
}

/* Demod buffered read (auto-increment from @reg), e.g. ISDB-S TSID table. */
static int demod_rd_buf(struct pxw3pe *p, u8 addr, u8 reg, u8 *buf, u8 len)
{
	int ret;

	mutex_lock(&p->i2c_lock);
	ret = i2c_xfer_wr(p, CTRL_DMOD_WR, addr, 0, &reg, 1);
	if (!ret)
		ret = i2c_xfer_rd(p, CTRL_DMOD_RD, addr, 0, buf, len);
	mutex_unlock(&p->i2c_lock);
	return ret;
}

/* Demod write (TUNER mode: reg+data carried in the FIFO payload). */
static int demod_wr(struct pxw3pe *p, u8 addr, const u8 *payload, u8 len)
{
	int ret;

	mutex_lock(&p->i2c_lock);
	ret = i2c_xfer_wr(p, CTRL_DMOD_WR, addr, 0, payload, len);
	mutex_unlock(&p->i2c_lock);
	return ret;
}

static int demod_wr_reg(struct pxw3pe *p, u8 addr, u8 reg, u8 val)
{
	u8 b[2] = { reg, val };

	return demod_wr(p, addr, b, 2);
}

/* ASIE5606 control register access. */
static int asie_rd(struct pxw3pe *p, u8 reg, u8 *val)
{
	int ret;

	mutex_lock(&p->i2c_lock);
	ret = i2c_xfer_rd(p, CTRL_RD, ASIE_ADDR, reg, val, 1);
	mutex_unlock(&p->i2c_lock);
	return ret;
}

static int asie_wr(struct pxw3pe *p, u8 reg, u8 val)
{
	int ret;
	u8 v = val;

	/* GPIO/config mode: register in ADR low byte, value in FIFO. */
	mutex_lock(&p->i2c_lock);
	ret = i2c_xfer_wr(p, CTRL_WR, ASIE_ADDR, reg, &v, 1);
	mutex_unlock(&p->i2c_lock);
	return ret;
}

static void asie_rmw(struct pxw3pe *p, u8 reg, u8 val, u8 mask)
{
	u8 v;

	if (asie_rd(p, reg, &v))
		return;
	asie_wr(p, reg, (v & ~mask) | (val & mask));
}

/* ASV5606 encryption/passthrough chip access.
 *
 * The ASV5606 uses bridge control bytes 0xc0/0xe0 (register addressed directly
 * in ADR low), unlike the TC905xx demods which use a payload register pointer.
 */
static int enc_rd(struct pxw3pe *p, u8 addr, u8 reg, u8 *val)
{
	int ret;

	mutex_lock(&p->i2c_lock);
	switch (p->enc_mode) {
	case 1:
		ret = i2c_xfer_wr(p, CTRL_DMOD_WR, addr, 0, &reg, 1);
		if (!ret)
			ret = i2c_xfer_rd(p, CTRL_DMOD_RD, addr, 0, val, 1);
		break;
	case 2:
		ret = i2c_xfer_rd(p, CTRL_RD, addr, reg, val, 1);
		break;
	default:
		ret = i2c_xfer_rd(p, CTRL_DMOD_RD, addr, reg, val, 1);
		break;
	}
	mutex_unlock(&p->i2c_lock);
	return ret;
}

static int enc_wr(struct pxw3pe *p, u8 addr, u8 reg, u8 val)
{
	u8 v = val;
	int ret;

	mutex_lock(&p->i2c_lock);
	if (p->enc_mode == 2)
		ret = i2c_xfer_wr(p, CTRL_WR, addr, reg, &v, 1);
	else
		ret = i2c_xfer_wr(p, CTRL_DMOD_WR, addr, reg, &v, 1);
	mutex_unlock(&p->i2c_lock);
	return ret;
}

static bool enc_version_ok(u8 raw)
{
	u8 ver = (raw & 0x3e) >> 1;

	return ver == 0x0f || ver == 0x04 || ver == 0x11;
}

static int enc_try_addr(struct pxw3pe *p, u8 addr, u8 *raw)
{
	u8 v = 0;
	int ret;

	ret = enc_rd(p, addr, 0x09, &v);
	if (!ret)
		*raw = v;
	return ret;
}

static int enc_try_addr_mode(struct pxw3pe *p, u8 addr, u8 mode, u8 *raw)
{
	int ret;

	p->enc_mode = mode;
	ret = enc_try_addr(p, addr, raw);
	if (ret)
		p->enc_mode = 0;
	return ret;
}

static void enc_gpio_reset(struct pxw3pe *p)
{
	asie_rmw(p, ASIE_GPIO_REG, 0x80, 0x80);
	msleep(25);
	asie_rmw(p, ASIE_GPIO_REG, 0x00, 0x80);
	msleep(25);
	asie_rmw(p, ASIE_GPIO_REG, 0x80, 0x80);
	msleep(50);
}

/* ASIE5606 enable: write the 16-byte enable string (from firmware) then the
 * enable register. Without firmware the string is unknown, so the chip likely
 * will not enable — demod_scan then reports no ACKs and probe warns.
 */
static int asie_auth_enable(struct pxw3pe *p)
{
	int i, ret;

	if (!fw_valid)
		dev_warn(&p->pdev->dev,
			 "no key firmware: ASIE enable string unavailable, card may not initialise\n");

	for (i = 0; i < ARRAY_SIZE(fw_auth); i++) {
		ret = asie_wr(p, 0x10 + i, fw_valid ? fw_auth[i] : 0x00);
		if (ret)
			return ret;
	}

	return asie_wr(p, 0x05, 0xa0);
}

static void enc_probe(struct pxw3pe *p)
{
	static const u8 first[] = { 0x5a, 0x4a };
	static const u8 second[] = { 0x5c, 0x4c, 0x5a, 0x4a };
	struct device *dev = &p->pdev->dev;
	u8 raw = 0;
	int i;

	p->enc_present = false;
	p->enc_addr = 0;
	p->enc_mode = 0;

	for (i = 0; i < ARRAY_SIZE(first); i++) {
		u8 addr = first[i];
		u8 mode;

		for (mode = 0; mode < 3; mode++) {
			if (enc_try_addr_mode(p, addr, mode, &raw)) {
				dev_dbg(dev, "enc scan @0x%02x mode%u no-ack\n",
					 addr, mode);
				continue;
			}
			dev_dbg(dev, "enc scan @0x%02x mode%u reg09=0x%02x ver=0x%02x\n",
				 addr, mode, raw, (raw & 0x3e) >> 1);
			if (enc_version_ok(raw)) {
				p->enc_present = true;
				p->enc_addr = addr;
				return;
			}
		}
	}

	enc_gpio_reset(p);

	for (i = 0; i < ARRAY_SIZE(second); i++) {
		u8 addr = second[i];
		u8 mode;

		for (mode = 0; mode < 3; mode++) {
			if (enc_try_addr_mode(p, addr, mode, &raw)) {
				dev_dbg(dev, "enc post-reset @0x%02x mode%u no-ack\n",
					 addr, mode);
				continue;
			}
			dev_dbg(dev, "enc post-reset @0x%02x mode%u reg09=0x%02x ver=0x%02x\n",
				 addr, mode, raw, (raw & 0x3e) >> 1);
			if (enc_version_ok(raw)) {
				p->enc_present = true;
				p->enc_addr = addr;
				return;
			}
		}
	}

	dev_warn(dev, "enc chip not detected; TS passthrough gate not enabled\n");
}

static void enc_enable_ts_output(struct pxw3pe *p)
{
	struct device *dev = &p->pdev->dev;
	u8 val, rb = 0;
	int ret;

	if (!p->enc_present)
		return;

	val = 0x10;
	ret = enc_wr(p, p->enc_addr, 0x05, val);
	if (!ret && !enc_rd(p, p->enc_addr, 0x05, &rb))
		dev_dbg(dev, "enc @0x%02x init reg05=0x%02x rb=0x%02x\n",
			 p->enc_addr, val, rb);
	else
		dev_warn(dev, "enc @0x%02x init reg05=0x%02x failed: %d\n",
			 p->enc_addr, val, ret);
}

/* ====================================================================== */
/* SPEC-BRG / SPEC-PWR: GPIO, bridge hw_init, power                        */
/* ====================================================================== */

/* GPIO over BAR 0x890/0x894 (SPEC-PWR): logical bit0 -> BAR
 * 0x890 bit2; the remaining bits map to BAR 0x894 (RMW). The "Ex" bank
 * (gpio1) maps to BAR 0x890 shifted <<3.
 */
static void gpio0(struct pxw3pe *p, u8 dat, u8 mask)
{
	void __iomem *bar = p->bar;

	if (mask & 1)
		writeb((readb(bar + 0x890) & ~0x04) | ((dat & 1) ? 0x04 : 0),
		       bar + 0x890);
	writeb((readb(bar + 0x894) & ~mask) | (dat & mask), bar + 0x894);
}

static void gpio1(struct pxw3pe *p, u8 dat, u8 mask)
{
	void __iomem *bar = p->bar;

	mask <<= 3;
	writeb((readb(bar + 0x890) & ~mask) | ((dat << 3) & mask), bar + 0x890);
}

/*
 * SPEC-ENC: ASV5606 stream-start gate: program the 16 seed regs (0x10..0x1f)
 * then the enable register (reg 5). Both writes, applied right before the DMA is
 * armed, are required for TS to leave the demod and reach the bridge; without
 * them the demod locks but the bridge DMA never advances.
 *
 * reg 5 = 0xA0 puts the controller in TS pass-through (same value GPL pxq3pe
 * uses). reg 5 = 0x90 instead enables the controller's bus encryption (bit
 * 0x10), which corrupts the transport — most visibly on the ISDB-S streams.
 *
 * The 16 seed bytes select the controller's transport scrambling keys. We
 * program the firmware-supplied chip seed so the hardware scrambles with the
 * keys ts_process() descrambles with (SPEC-ENC-DES). With descramble off or no
 * key firmware we write zeros (pass-through; PSI stays scrambled).
 */
static void enc_stream_start(struct pxw3pe *p)
{
	const u8 *seed;
	struct device *dev = &p->pdev->dev;
	u8 rb;
	int ret = 0;
	u8 i;

	if (!p->enc_present)
		return;

	/* Program the firmware chip seed when descramble is active, else zeros. */
	seed = (descramble && fw_valid) ? fw_chip_seed : asv5606_seed_zero;
	for (i = 0; i < 16; i++)
		ret |= enc_wr(p, p->enc_addr, 0x10 + i, seed[i]);
	ret |= enc_wr(p, p->enc_addr, 0x05, 0xa0);
	if (!enc_rd(p, p->enc_addr, 0x05, &rb))
		dev_dbg(dev, "enc @0x%02x stream gate reg05=0xa0 rb=0x%02x ret=%d\n",
			p->enc_addr, rb, ret);
	else
		dev_warn(dev, "enc @0x%02x stream gate read reg05 failed ret=%d\n",
			 p->enc_addr, ret);
}

static void tc_preset(struct pxw3pe *p)
{
	msleep(10);
	gpio0(p, 1, 1);
	msleep(10);
	gpio0(p, 0, 1);
	msleep(10);
	gpio0(p, 1, 1);
	msleep(10);
}

/* bridge hw_init (cross-validated w/ GPL pxq3pe). */
static void bridge_init(struct pxw3pe *p)
{
	void __iomem *bar = p->bar;

	writeb(readb(bar + REG_GP880) & 0xc0, bar + REG_GP880);
	writel(0x003200c8, bar + REG_CLK904);
	writel(0x90, bar + REG_CLK900);
	usleep_range(2000, 3000);
	writel(0x10000, bar + REG_GP880);
	writel(0x80, bar + 0xa00);		/* TS mode port0 */
	writel(0x80, bar + 0xb40);		/* TS mode port1 */
	writel(0x00, bar + 0x888);
	writel(0xcf, bar + 0x894);
	writel(0x8000, bar + 0x88c);
	writel(0x1004, bar + 0x890);
	writel(0x90, bar + REG_CLK900);
	writel(0x003200c8, bar + REG_CLK904);

	/* SPEC-BRG: GPIO preset before the demod/tuner remap probe. */
	gpio0(p, 8, 0xff);
	gpio1(p, 0, 2);
	gpio1(p, 1, 1);
}

/* tuner/demod power enable = BAR 0x888 bit0 (SmiTunerPowerUp). */
static void power_on(struct pxw3pe *p)
{
	void __iomem *bar = p->bar;
	u32 v = readl(bar + 0x888) & ~1u;

	writel(v, bar + 0x888);
	msleep(20);
	writel(v | 1u, bar + 0x888);
	msleep(20);
}

/* SPEC-PWR: demod/tuner MOS power-up (TC_MOS_POWER): GPIO toggle sequence,
 * then ASIE5606 reg 0x0b = bits 0x46 (mask 0x47), then a T-core demod reg
 * 0x1c pulse (|=0x30 -> delay -> &=~0x10) required to bring up both FC0012.
 */
static void mos_power(struct pxw3pe *p)
{
	static const u8 taddrs[] = { DEMOD_T0, DEMOD_T1 };
	struct device *dev = &p->pdev->dev;
	u8 v;
	int i;

	gpio0(p, 0, 1); msleep(10);
	gpio1(p, 1, 1); msleep(10);
	gpio1(p, 0, 1); msleep(10);
	gpio0(p, 1, 1); msleep(10);
	gpio0(p, 0, 1); msleep(10);
	gpio0(p, 1, 1); msleep(10);
	asie_rmw(p, ASIE_GPIO_REG, 0x46, 0x47); msleep(10);
	asie_rmw(p, ASIE_GPIO_REG, 0x02, 0x02); msleep(10);
	asie_rmw(p, ASIE_GPIO_REG, 0x00, 0x02); msleep(10);
	asie_rmw(p, ASIE_GPIO_REG, 0x02, 0x02); msleep(10);
	asie_rmw(p, ASIE_GPIO_REG, 0x04, 0x04); msleep(10);
	asie_rmw(p, ASIE_GPIO_REG, 0x00, 0x04); msleep(10);
	asie_rmw(p, ASIE_GPIO_REG, 0x04, 0x04); msleep(10);

	if (!asie_rd(p, ASIE_GPIO_REG, &v))
		dev_dbg(dev, "ASIE reg0b after MOS power = 0x%02x\n", v);

	for (i = 0; i < ARRAY_SIZE(taddrs); i++) {
		if (demod_rd(p, taddrs[i], 0x1c, &v))
			continue;
		v |= 0x30;
		demod_wr_reg(p, taddrs[i], 0x1c, v);
		msleep(10);
		v &= ~0x10;
		demod_wr_reg(p, taddrs[i], 0x1c, v);
		msleep(10);
	}
}

/*
 * Warm-reload hardening (R1). The ASV5220 does not self-clear its DMA/IRQ/TS
 * latches, and the demods/tuners/ASV5606 keep running, across an rmmod; a
 * second insmod then inherits that dirty state and only a cold boot recovers
 * (observed: one-core-only TS / mis-tag / AGC drift / stalled DMA). The GPL
 * pxq3pe driver (same bridge) and px4_drv (same TC90522 family, GPL-2.0) both
 * quiesce + sleep + power-down on teardown and re-init from a known state; the
 * three helpers below mirror that so a warm reload converges to cold-boot
 * behaviour. Register-level facts remain SPEC-sourced (SPEC-DMA-REG/IRQ,
 * SPEC-PWR); the sleep/TS-float values follow px4_drv tc90522 sleep and
 * enable_ts_pins helpers.
 */

/* Stop the bridge: disable+ack all stream IRQs, clear each port's DMA arm and
 * TS-output enable. Safe to call before request_irq (plain BAR writes).
 */
static void hw_quiesce(struct pxw3pe *p)
{
	void __iomem *bar = p->bar;
	int port;

	writel(0xffffffff, bar + REG_IRQ_DISABLE);
	writel(readl(bar + REG_IRQ_STAT), bar + REG_IRQ_CLEAR);
	readl(bar + REG_IRQ_FLUSH);
	for (port = 0; port < NR_PORT; port++) {
		u32 ts = port * DMA_OFF_PORT + DMA_TSMODE;

		writel(0, bar + port * DMA_OFF_PORT + DMA_MGMT);
		writeb(readb(bar + ts) & ~0x80, bar + ts);
	}
}

/* Quiesce every demod core: stop acquisition, float the TS-output pins, sleep
 * (px4_drv tc90522_sleep_s/_t + enable_ts_pins_*). Demods must still be powered
 * (call before power_off).
 */
static void demods_sleep(struct pxw3pe *p)
{
	static const u8 saddr[] = { DEMOD_S0, DEMOD_S1 };
	static const u8 taddr[] = { DEMOD_T0, DEMOD_T1 };
	int i;

	for (i = 0; i < ARRAY_SIZE(saddr); i++) {
		demod_wr_reg(p, saddr[i], 0x03, 0x00);	/* stop S acquisition */
		demod_wr_reg(p, saddr[i], 0x1c, 0x80);	/* float TS pins      */
		demod_wr_reg(p, saddr[i], 0x1f, 0x22);
		demod_wr_reg(p, saddr[i], 0x13, 0x80);	/* sleep              */
		demod_wr_reg(p, saddr[i], 0x17, 0xff);
	}
	for (i = 0; i < ARRAY_SIZE(taddr); i++) {
		demod_wr_reg(p, taddr[i], 0x01, 0x00);	/* stop T acquisition */
		demod_wr_reg(p, taddr[i], 0x1d, 0xa8);	/* float TS pin       */
		demod_wr_reg(p, taddr[i], 0x03, 0xf0);	/* sleep              */
	}
}

/* Reverse power_on()/mos_power() and close the ASV5606 TS gate (counterpart of
 * the GPL pxq3pe power(false) path), so the next probe re-powers from clean.
 */
static void power_off(struct pxw3pe *p)
{
	void __iomem *bar = p->bar;

	if (p->enc_present) {
		enc_wr(p, p->enc_addr, 0x05, 0x00);	/* close ASV5606 TS gate */
		enc_gpio_reset(p);			/* pulse ASIE reset      */
	}
	asie_rmw(p, ASIE_GPIO_REG, 0x00, 0x47);		/* drop MOS/demod power   */
	writel(readl(bar + 0x888) & ~1u, bar + 0x888);	/* drop tuner power rail  */
}

/* ====================================================================== */
/* SPEC-DMD: demod init tables + composite-chip initialise order          */
/* ====================================================================== */

/* ISDB-S (8PSK) demod init (reg,val) pairs. */
static const u8 demod_s_init[][2] = {
	{0x01, 0x90}, {0x03, 0x00}, {0x04, 0x02}, {0x06, 0x00}, {0x07, 0x41}, {0x08, 0x00},
	{0x09, 0x00}, {0x0a, 0xff}, {0x0c, 0x59}, {0x0d, 0xf2}, {0x0e, 0xf0}, {0x0f, 0x50},
	{0x10, 0xb2}, {0x11, 0x00}, {0x12, 0x30}, {0x13, 0x80}, {0x14, 0x00}, {0x15, 0x00},
	{0x17, 0x00}, {0x1a, 0x00}, {0x1b, 0x00}, {0x1c, 0x00}, {0x1d, 0x00}, {0x1e, 0x00},
	{0x1f, 0x00}, {0x20, 0x00}, {0x38, 0x40}, {0x39, 0x10}, {0x3b, 0x90}, {0x51, 0xb0},
	{0x52, 0x89}, {0x53, 0xb3}, {0x5a, 0x2d}, {0x5b, 0xd3}, {0x85, 0x69}, {0x87, 0x04},
	{0x8d, 0x00}, {0x8e, 0x00}, {0xa3, 0x11}, {0xa4, 0x00}, {0xa5, 0x40}, {0xa6, 0x04},
};

/* ISDB-T (OFDM) demod init (reg,val) pairs. */
static const u8 demod_t_init[][2] = {
	{0x04, 0x00}, {0x11, 0x1a}, {0x12, 0x04}, {0x13, 0x33}, {0x14, 0x20}, {0x31, 0x00},
	{0x32, 0x00}, {0x38, 0x00}, {0x39, 0xaa}, {0x47, 0x00}, {0x75, 0x02}, {0xb0, 0xa0},
	{0xb2, 0x3d}, {0xb3, 0x25}, {0xb4, 0x8b}, {0xb5, 0x4b}, {0xb6, 0x3f}, {0xb7, 0xff},
	{0xb8, 0xff}, {0x22, 0x8f}, {0x5f, 0x80}, {0xef, 0x01},
};

static void fc0012_init_regs(struct pxw3pe *p, u8 taddr);

static int demod_write_table(struct pxw3pe *p, u8 addr,
			     const u8 tbl[][2], size_t n)
{
	size_t i;
	int ret;

	for (i = 0; i < n; i++) {
		ret = demod_wr_reg(p, addr, tbl[i][0], tbl[i][1]);
		if (ret)
			return ret;
	}
	return 0;
}

/* Composite-chip init order — both terrestrial cores first,
 * then both satellite cores, then S reg0x17=0 and T reg0x0f=0x34. The whole
 * composite chip must be initialised together; per-core init alone leaves the
 * shared 8PSK/OFDM carrier-recovery state unusable.
 */
static int tc905xx_initialise_all(struct pxw3pe *p)
{
	static const u8 taddrs[] = { DEMOD_T0, DEMOD_T1 };
	static const u8 saddrs[] = { DEMOD_S0, DEMOD_S1 };
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(taddrs); i++) {
		ret = demod_write_table(p, taddrs[i], demod_t_init,
					ARRAY_SIZE(demod_t_init));
		if (ret)
			return ret;
		/*
		 * the demod-init routine overrides reg 0x04 to 0x03 for the
		 * odd terrestrial core (idx 1/3 -> addr 0x34). The table value
		 * 0x00 is correct only for the even core (T0/addr 0x30); the
		 * second core selects the alternate TS-output routing via 0x03.
		 */
		if (i & 1) {
			ret = demod_wr_reg(p, taddrs[i], 0x04, 0x03);
			if (ret)
				return ret;
		}
	}
	for (i = 0; i < ARRAY_SIZE(saddrs); i++) {
		ret = demod_write_table(p, saddrs[i], demod_s_init,
					ARRAY_SIZE(demod_s_init));
		if (ret)
			return ret;
	}

	fc0012_init_regs(p, DEMOD_T0);
	fc0012_init_regs(p, DEMOD_T1);

	for (i = 0; i < ARRAY_SIZE(saddrs); i++) {
		ret = demod_wr_reg(p, saddrs[i], 0x17, 0x00);
		if (ret)
			return ret;
	}
	for (i = 0; i < ARRAY_SIZE(taddrs); i++) {
		ret = demod_wr_reg(p, taddrs[i], 0x0f, 0x34);
		if (ret)
			return ret;
	}
	return 0;
}

/* ====================================================================== */
/* SPEC-TNS: ISDB-S raw-PLL tuner (write-only synth @0xc0)                 */
/* ====================================================================== */

/* ISDB-S downlink-kHz -> raw-PLL register bytes.
 *
 * The vendor keeps TWO per-core calibration tables and selects by satellite
 * core: the reference tune sequence programs core 0 (DEMOD_S0 @0x32) via the core-0 PLL writer
 * (the core-0 PLL table) and core 1 (DEMOD_S1 @0x36) via the core-1 PLL writer
 * (the core-1 PLL table). The two tables share identical kHz keys but differ
 * in the tuner PLL fine-divider (mostly pll[1] by one step, pll[2]/[3] on the two
 * range-boundary entries, and a distinct short-form for the band-edge entries on
 * core 0), i.e. a per-tuner trim. Each core MUST be programmed from its own table
 * or it tunes ~1 fine-divider step off (and grossly off at the band edges), which
 * is what intermittently kept DEMOD_S0 from locking.
 *
 * sat_map below is table B (core 1, == the core-1 PLL table); sat_map_s0 is
 * table A (core 0, == the core-0 PLL table). sat_pll_for_khz() picks per core.
 */
struct sat_ent { u32 khz; u8 pll[8]; };
static const struct sat_ent sat_map[] = {
	{0xb2f278, {0x28, 0x2a, 0xe0, 0xd2, 0xe4, 0xf4, 0xd6, 0x48}},
	{0xb38850, {0x24, 0x40, 0xe0, 0xe2, 0xe4, 0xf4, 0xe6, 0x44}},
	{0xb41e28, {0x24, 0x67, 0xe0, 0xe2, 0xe4, 0xf4, 0xe6, 0x44}},
	{0xb4b400, {0x24, 0x8d, 0xe0, 0x20, 0xe4, 0xf4, 0x24, 0x44}},
	{0xb549d8, {0x24, 0xb3, 0xe0, 0x20, 0xe4, 0xf4, 0x24, 0x44}},
	{0xb5dfb0, {0x24, 0xda, 0xe0, 0x20, 0xe4, 0xf4, 0x24, 0x44}},
	{0xb67588, {0x25, 0x01, 0xe0, 0x20, 0xe4, 0xf4, 0x24, 0x45}},
	{0xb70b60, {0x25, 0x27, 0xc4, 0x44, 0xe4, 0xf4, 0x44, 0x45}},
	{0xb7a138, {0x25, 0x4d, 0xe0, 0x40, 0xe4, 0xf4, 0x44, 0x45}},
	{0xb83710, {0x25, 0x75, 0xe0, 0x40, 0xe4, 0xf4, 0x44, 0x45}},
	{0xb8cce8, {0x25, 0x9b, 0xe0, 0x40, 0xe4, 0xf4, 0x44, 0x45}},
	{0xb962c0, {0x25, 0xc0, 0xe0, 0x60, 0xe4, 0xf4, 0x64, 0x45}},
	{0xbb8bb8, {0x26, 0x4e, 0xe0, 0x60, 0xe4, 0xf4, 0x64, 0x46}},
	{0xbc27f8, {0x26, 0x76, 0xe0, 0x80, 0xe4, 0xf4, 0x84, 0x46}},
	{0xbcc438, {0x26, 0x9e, 0xe0, 0x80, 0xe4, 0xf4, 0x84, 0x46}},
	{0xbd6078, {0x26, 0xc6, 0xe0, 0x80, 0xe4, 0xf4, 0x84, 0x46}},
	{0xbdfcb8, {0x26, 0xee, 0xe0, 0x80, 0xe4, 0xf4, 0x84, 0x46}},
	{0xbe98f8, {0x27, 0x16, 0xc4, 0xa4, 0xe4, 0xf4, 0xa4, 0x47}},
	{0xbf3538, {0x27, 0x3e, 0xe0, 0xa0, 0xe4, 0xf4, 0xa4, 0x47}},
	{0xbfd178, {0x27, 0x66, 0xe0, 0xa0, 0xe4, 0xf4, 0xa4, 0x47}},
	{0xc06db8, {0x27, 0x8e, 0xe0, 0xa0, 0xe4, 0xf4, 0xa4, 0x47}},
	{0xc109f8, {0x27, 0xb6, 0xe0, 0xc0, 0xe4, 0xf4, 0xc4, 0x47}},
	{0xc1a638, {0x27, 0xde, 0xe0, 0xc0, 0xe4, 0xf4, 0xc4, 0x47}},
	{0xc24278, {0x28, 0x06, 0xe0, 0xc0, 0xe4, 0xf4, 0xc4, 0x48}},
};

/* Table A: ISDB-S core 0 (DEMOD_S0 @0x32) PLL set. The two band-edge entries (0xb2f278,
 * 0xc24278) use the short 4-byte program form (trailing pll bytes are sentinel
 * zeros); tuner_s_tune() stops after the first transaction for those.
 */
static const struct sat_ent sat_map_s0[] = {
	{0xb2f278, {0x10, 0x63, 0xc5, 0xd6, 0x00, 0x00, 0x00, 0x00}},
	{0xb38850, {0x24, 0x40, 0xe0, 0xe2, 0xe4, 0xf4, 0xe6, 0x44}},
	{0xb41e28, {0x24, 0x66, 0xe0, 0xe2, 0xe4, 0xf4, 0xe6, 0x44}},
	{0xb4b400, {0x24, 0x8d, 0xe0, 0x20, 0xe4, 0xf4, 0x24, 0x44}},
	{0xb549d8, {0x24, 0xb3, 0xe0, 0x20, 0xe4, 0xf4, 0x24, 0x44}},
	{0xb5dfb0, {0x24, 0xd9, 0xe0, 0x20, 0xe4, 0xf4, 0x24, 0x44}},
	{0xb67588, {0x25, 0x00, 0xe0, 0x20, 0xe4, 0xf4, 0x24, 0x45}},
	{0xb70b60, {0x25, 0x26, 0xe0, 0x40, 0xe4, 0xf4, 0x44, 0x45}},
	{0xb7a138, {0x25, 0x4c, 0xe0, 0x40, 0xe4, 0xf4, 0x44, 0x45}},
	{0xb83710, {0x25, 0x73, 0xe0, 0x40, 0xe4, 0xf4, 0x44, 0x45}},
	{0xb8cce8, {0x25, 0x99, 0xe0, 0x40, 0xe4, 0xf4, 0x44, 0x45}},
	{0xb962c0, {0x25, 0xbf, 0xe0, 0x60, 0xe4, 0xf4, 0x64, 0x45}},
	{0xbb8bb8, {0x26, 0x4d, 0xe0, 0x60, 0xe4, 0xf4, 0x64, 0x46}},
	{0xbc27f8, {0x26, 0x75, 0xe0, 0x80, 0xe4, 0xf4, 0x84, 0x46}},
	{0xbcc438, {0x26, 0x9d, 0xe0, 0x80, 0xe4, 0xf4, 0x84, 0x46}},
	{0xbd6078, {0x26, 0xc5, 0xe0, 0x80, 0xe4, 0xf4, 0x84, 0x46}},
	{0xbdfcb8, {0x26, 0xed, 0xe0, 0x80, 0xe4, 0xf4, 0x84, 0x46}},
	{0xbe98f8, {0x27, 0x15, 0xe0, 0xa0, 0xe4, 0xf4, 0xa4, 0x47}},
	{0xbf3538, {0x27, 0x3d, 0xe0, 0xa0, 0xe4, 0xf4, 0xa4, 0x47}},
	{0xbfd178, {0x27, 0x65, 0xe0, 0xa0, 0xe4, 0xf4, 0xa4, 0x47}},
	{0xc06db8, {0x27, 0x8d, 0xe0, 0xa0, 0xe4, 0xf4, 0xa4, 0x47}},
	{0xc109f8, {0x27, 0xb5, 0xe0, 0xc0, 0xe4, 0xf4, 0xc4, 0x47}},
	{0xc1a638, {0x27, 0xdd, 0xe0, 0xc0, 0xe4, 0xf4, 0xc4, 0x47}},
	{0xc24278, {0x10, 0x0a, 0xc5, 0xc4, 0x00, 0x00, 0x00, 0x00}},
};

/* Exact downlink-kHz PLL lookup (kHz key -> 8 PLL bytes) for the given satellite
 * @chip: chip 0 (DEMOD_S0) uses table A, chip 1 (DEMOD_S1) uses table B, matching
 * the per-core PLL writers. Used by the acquisition path for the
 * target and edge-transition intermediate frequencies. The live tune path picks
 * the kHz key via sat_nearest (keys are identical across both tables).
 */
static const u8 *sat_pll_for_khz(u32 khz, int chip)
{
	const struct sat_ent *map = chip ? sat_map : sat_map_s0;
	int i;

	BUILD_BUG_ON(ARRAY_SIZE(sat_map) != ARRAY_SIZE(sat_map_s0));
	for (i = 0; i < ARRAY_SIZE(sat_map); i++)
		if (map[i].khz == khz)
			return map[i].pll;
	return NULL;
}

/*
 * ISDB-S edge-transition kick. Before the target PLL, a specific intermediate
 * downlink is programmed via the full core-1 (table B) PLL writer whenever the
 * previous S downlink and the new target form one of two problematic pairs;
 * without the kick those transitions can fail to (re)lock (table B / core 1
 * only, which is the only mode this driver uses). Returns the intermediate
 * sat_map key to
 * program first, or 0 when no edge kick is needed.
 */
static u32 sat_edge_intermediate(u32 prev_khz, u32 target_khz)
{
	if (prev_khz == 0xc109f8 && target_khz == 0xb67588)
		return 0xc1a638;
	if (prev_khz == 0xb67588 && target_khz == 0xb70b60)
		return 0xb2f278;
	return 0;
}

/* satellite tuner RF/IF init reg table
 * (the S-tuner init table) written via the demod tunnel to tuner @0xc0.
 * Required on this board for the IF to reach the demod.
 */
static const u8 sat_tuner_init[][2] = {
	{0x09, 0x03},
	{0x06, 0x2a}, {0x07, 0xe8}, {0x08, 0x84}, {0x0a, 0x20}, {0x0b, 0x78},
	{0x0c, 0x1e}, {0x0d, 0x0a}, {0x0f, 0x08}, {0x10, 0x0f}, {0x18, 0x40},
};

static void sat_tuner_setup(struct pxw3pe *p, u8 saddr)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sat_tuner_init); i++) {
		u8 b[4] = { 0xfe, 0xc0, sat_tuner_init[i][0], sat_tuner_init[i][1] };

		demod_wr(p, saddr, b, 4);
		if (i == 0)
			msleep(1);
	}
	msleep(5);
}

/* program the raw-PLL synth via the demod tunnel
 * (demod 0xfe <- {0xc0, bytes}). The 8 PLL bytes are written in the official
 * split (4 + 1 + settle + 2 + 1) so the synth latches the divider correctly.
 * The vendor settle differs per core: the core-0 PLL writer (core 0) waits 10 ms,
 * the core-1 PLL writer (core 1) waits 100 ms. The two band-edge entries on
 * core 0 use a short 4-byte program (their trailing PLL bytes are sentinel
 * zeros): the vendor writes only {0xc0,pll0..3} and stops, so do the same.
 */
static int tuner_s_tune(struct pxw3pe *p, u8 saddr, const u8 pll[8])
{
	int chip = chip_of(saddr);
	u8 b[8];
	int ret;

	b[0] = 0xfe; b[1] = 0xc0;
	b[2] = pll[0]; b[3] = pll[1]; b[4] = pll[2]; b[5] = pll[3];
	ret = demod_wr(p, saddr, b, 6);
	if (ret)
		return ret;
	/* Band-edge short-form (core 0 only): no trailing bytes to program. */
	if (!pll[4] && !pll[5] && !pll[6] && !pll[7])
		return 0;
	b[0] = 0xfe; b[1] = 0xc0; b[2] = pll[4];
	ret = demod_wr(p, saddr, b, 3);
	if (ret)
		return ret;
	msleep(chip ? 100 : 10);
	b[0] = 0xfe; b[1] = 0xc0; b[2] = pll[5]; b[3] = pll[6];
	ret = demod_wr(p, saddr, b, 4);
	if (ret)
		return ret;
	b[0] = 0xfe; b[1] = 0xc0; b[2] = pll[7];
	return demod_wr(p, saddr, b, 3);
}

/*
 * ISDB-S TSID prewrite before acquisition (vendor
 * the TSID-write routine, demod reg 0x8F/0x90). The demod must not begin acquisition
 * still filtering on a stale TSID left from the previous channel, or it can lock
 * the carrier yet emit no TS. The reference tune sequence writes 0xFFFF ("accept any") when
 * the target downlink is above 0xbb3d97, otherwise the saved TSID; we map the
 * saved TSID to the userspace absolute stream_id. With no absolute request we
 * prewrite 0xFFFF so the demod accepts any stream and the real TSID is latched
 * by demod_s_select_ts after carrier lock. @target_key is the sat_map downlink
 * key being tuned.
 */
static int demod_s_preselect_ts(struct pxw3pe *p, u8 saddr, u32 stream_id,
				u32 target_key)
{
	u16 tsid = 0xffff;

	if (target_key <= 0xbb3d97 && stream_id != NO_STREAM_ID_FILTER &&
	    stream_id >= 8 && stream_id <= 0xffff)
		tsid = stream_id;
	if (demod_wr_reg(p, saddr, 0x8f, tsid >> 8) ||
	    demod_wr_reg(p, saddr, 0x90, tsid & 0xff))
		return -EIO;
	return 0;
}

/*
 * / / / ISDB-S tune +
 * acquisition, mirroring the reference tune sequence S path in order:
 *   1. hold the demod gate (reg0x25=0, reg0x23=0x4d);
 *   2. on a problematic previous->target downlink pair, program the vendor
 *      edge-transition intermediate first via the full table-B PLL writer;
 *   3. prewrite the TSID filter (reg0x8F/0x90) so acquisition does not start
 *      still latched on a stale TSID from the previous channel;
 *   4. program the target PLL;
 *   5. start acquisition (the re-acquire write = reg0x03=0x01) and release the gate
 *      (reg0x23=0x4c).
 * Without the acquisition kick the S core only locked intermittently (the PLL
 * was programmed but acquisition was never (re)started). The per-chip previous
 * key is updated only on full success, exactly as the vendor stores its
 * prev-freq only when every write in the sequence succeeded.
 */
static int isdbs_acquire(struct pxw3pe *p, u8 saddr, u32 target_key,
			 u32 stream_id)
{
	int chip = chip_of(saddr);
	const u8 *pll = sat_pll_for_khz(target_key, chip);
	u32 inter;
	int ok = 1;	/* mirror the vendor r15 write-success accumulator */
	int ret;

	if (!pll)
		return -EINVAL;

	/*
	 * Gate hold. From here on, mirror the vendor exactly: never bail out
	 * mid-sequence. Each step folds its result into @ok, and the re-acquire write
	 * + gate-release tail always runs, so a transient i2c failure can never
	 * leave the demod stuck in the held (reg0x23=0x4d) state. The per-chip
	 * prev key is stored only when every write in the sequence succeeded,
	 * exactly as the reference tune sequence gates its prev-freq store on r15==1.
	 */
	if (demod_wr_reg(p, saddr, 0x25, 0x00))		/* gate hold */
		ok = 0;
	if (demod_wr_reg(p, saddr, 0x23, 0x4d))
		ok = 0;

	/*
	 * vendor edge-transition kick. The reference tune sequence gates this
	 * on the satellite core index (sil==1), i.e. it only kicks core 1
	 * (DEMOD_S1, table B); core 0 (table A) is never kicked. Mirror that and
	 * program the intermediate from this core's own table.
	 */
	inter = chip ? sat_edge_intermediate(p->s_prev_key[chip], target_key) : 0;
	if (inter) {
		const u8 *ipll = sat_pll_for_khz(inter, chip);

		if (ipll && tuner_s_tune(p, saddr, ipll))
			ok = 0;
	}

	/* clear any stale TSID filter before acquisition. */
	if (demod_s_preselect_ts(p, saddr, stream_id, target_key))
		ok = 0;

	if (tuner_s_tune(p, saddr, pll))		/* target PLL */
		ok = 0;

	ret  = demod_wr_reg(p, saddr, 0x03, 0x01);	/* the re-acquire write */
	ret |= demod_wr_reg(p, saddr, 0x23, 0x4c);	/* gate release (always) */
	if (ret || !ok)
		return -EIO;

	p->s_prev_key[chip] = target_key;		/* store prev on full success */
	return 0;
}

/* Tune an ISDB-S core to one of the mapped transponder frequencies (debug
 * self-test only; the live path is pxw3pe_s_tune via isdbs_acquire).
 */
static int __maybe_unused isdbs_set_frequency(struct pxw3pe *p, u8 saddr, u32 khz)
{
	return isdbs_acquire(p, saddr, khz, NO_STREAM_ID_FILTER);
}

/* ISDB-S lock = reg 0xC3 bit4 clear. */
static int demod_s_locked(struct pxw3pe *p, u8 saddr, u8 *c3)
{
	if (demod_rd(p, saddr, 0xc3, c3))
		return -EIO;
	return ((*c3 >> 4) & 1) ? 0 : 1;
}

/*
 * ISDB-S relative-TS selection. ISDB-S transponders carry up to
 * 8 multiplexed TS streams; the demod outputs a single one only after a TSID
 * is latched. Reg 0xCE holds the 8 available TSIDs (big-endian); pick the one
 * matching the requested stream_id (by TSID value or slot index, or the first
 * valid stream when none was requested) and write it to reg 0x8F/0x90.
 *
 * The vendor TSID latch (the TSID-write routine) writes reg 0x8F/0x90 and trusts the
 * i2c ACK; it does NOT read anything back to confirm. The vendor's active-TSID
 * query (the active-TSID read) reads reg 0x8F (the register just written); this
 * card's vendor driver never touches reg 0xE6. Note 0xE6 is also a real
 * active-TSID register on the TC90522 (mainline tc90522.c and px4_drv both read
 * it), but the asv5220 vendor uses 0x8F, so we follow 0x8F and avoid 0xE6. The
 * previous implementation gated success on a reg-0xE6 read-back equalling the
 * TSID; since the vendor confirms a latch nowhere by readback, a clean carrier
 * lock could still report failure here. Treat the write ACK as the latch,
 * exactly like the vendor, and let the caller's retry loop re-run the select.
 */
static int demod_s_select_ts(struct pxw3pe *p, u8 saddr, u32 stream_id)
{
	u8 tsids[16];
	int i;

	if (demod_rd_buf(p, saddr, 0xce, tsids, sizeof(tsids)))
		return -EIO;

	dev_dbg(&p->pdev->dev,
		"S@0x%02x sid=%u TSIDs %02x%02x %02x%02x %02x%02x %02x%02x\n",
		saddr, stream_id, tsids[0], tsids[1], tsids[2], tsids[3],
		tsids[4], tsids[5], tsids[6], tsids[7]);

	for (i = 0; i < 8; i++) {
		u16 tsid = ((u16)tsids[i * 2] << 8) | tsids[i * 2 + 1];

		if (!tsid || tsid == 0xffff)
			continue;
		if (stream_id != NO_STREAM_ID_FILTER &&
		    stream_id != tsid && stream_id != (u32)i)
			continue;
		if (demod_wr_reg(p, saddr, 0x8f, tsid >> 8) ||
		    demod_wr_reg(p, saddr, 0x90, tsid & 0xff))
			return -EIO;
		return 0;
	}
	return -ENODEV;
}

/* ISDB-S C/N raw register (reg 0xBC:0xBD, 2 bytes). */
static u16 demod_s_cn(struct pxw3pe *p, u8 saddr)
{
	u8 hi = 0, lo = 0;

	demod_rd(p, saddr, 0xbc, &hi);
	demod_rd(p, saddr, 0xbd, &lo);
	return (hi << 8) | lo;
}

/* Vendor ISDB-S AGC: demod reg0xba & 0x7f. */
static u8 demod_s_agc(struct pxw3pe *p, u8 saddr)
{
	u8 v = 0;

	demod_rd(p, saddr, 0xba, &v);
	return v & 0x7f;
}

/* ISDB-S BER: two read-only 3-byte big-endian error counters (reg 0xF0 and reg
 * 0xEB), each scaled by 80 over a fixed 1e8 denominator by the reference design.
 * Expose the reg 0xF0 counter as the DVBv3 BER (raw post-acquisition error
 * count); pure reads, never any register write. */
static u32 demod_s_ber(struct pxw3pe *p, u8 saddr)
{
	u8 b[3] = { 0, 0, 0 };

	demod_rd_buf(p, saddr, 0xf0, b, sizeof(b));
	return ((u32)b[0] << 16) | ((u32)b[1] << 8) | b[2];
}

/* ISDB-T C/N raw register (reg 0x8B, 3 bytes big-endian). */
static u32 demod_t_cn(struct pxw3pe *p, u8 taddr)
{
	u8 b[3] = { 0, 0, 0 };

	demod_rd_buf(p, taddr, 0x8b, b, sizeof(b));
	return ((u32)b[0] << 16) | ((u32)b[1] << 8) | b[2];
}

/*
 * vendor C/N conversion tables (ISDB-S / ISDB-T, 31 entries
 * each). Both are descending register thresholds
 * indexed by C/N in dB: entry [i] is the raw register reading at i dB. The
 * register grows as the signal worsens, so a lower reading maps to a higher
 * C/N. Entries [0]/[1] are unused placeholders (the table starts at 2 dB).
 */
static const u32 isdbs_cn_table[31] = {
	0, 0, 35825, 34437, 32889, 31162, 29249, 27174, 25008, 22846,
	20774, 18842, 17062, 15430, 13934, 12566, 11321, 10198, 9199, 8323,
	7568, 6924, 6379, 5920, 5532, 5204, 4925, 4685, 4479, 4300, 4145,
};
static const u32 isdbt_cn_table[31] = {
	0, 0, 9778432, 5735416, 3903295, 2811328, 2089200, 1583680, 1216799,
	943867, 737184, 578602, 455722, 359802, 284533, 225191, 178317,
	141219, 111834, 88556, 70125, 55546, 44026, 34937, 27773, 22134,
	17696, 14204, 11455, 9287, 7573,
};

/*
 * convert a raw C/N register reading to C/N in 0.01 dB units
 * (max 30.00 dB), faithfully reproducing the vendor C/N conversion. Walk the
 * descending table to bracket @raw, then
 * linearly interpolate between the two surrounding dB steps.
 */
static u32 cn_raw_to_cdb(u32 raw, const u32 *tbl)
{
	int i;

	if (raw > tbl[2])		/* worse than the table floor: no usable C/N */
		return 0;
	for (i = 3; i <= 30; i++) {
		if (raw > tbl[i]) {
			u32 span = tbl[i - 1] - tbl[i];
			u32 frac = span ? (10 * (tbl[i - 1] - raw)) / span : 0;

			return (i - 1) * 100 + frac;
		}
	}
	return 30 * 100;		/* raw <= tbl[30]: clamp to 30.00 dB */
}

/* ISDB-S has an extra clamp: readings <= 3000 are reported as no signal. */
static u32 demod_s_cn_cdb(struct pxw3pe *p, u8 saddr)
{
	u16 raw = demod_s_cn(p, saddr);

	/* vendor floors at raw<=0xbb7 (2999); at exactly 3000 the
	 * old "<= 3000" wrongly returned 0 instead of ~30 dB. The read register
	 * (0xBC:0xBD) and isdbs_cn_table are verified byte-exact against the
	 * vendor firmware, so the table must not be recalibrated from field
	 * strength meter readings.
	 */
	return raw <= 2999 ? 0 : cn_raw_to_cdb(raw, isdbs_cn_table);
}

static u32 demod_t_cn_cdb(struct pxw3pe *p, u8 taddr)
{
	return cn_raw_to_cdb(demod_t_cn(p, taddr), isdbt_cn_table);
}

/*
 * Publish C/N into the DVBv5 statistics cache. @cdb is in 0.01 dB; the DVB
 * core expects FE_SCALE_DECIBEL svalues in 0.001 dB, so scale by 10.
 */
static void cn_set_stat(struct dvb_frontend *fe, u32 cdb)
{
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;

	c->cnr.len = 1;
	c->cnr.stat[0].scale = FE_SCALE_DECIBEL;
	c->cnr.stat[0].svalue = (s64)cdb * 10;
}

static void cn_clear_stat(struct dvb_frontend *fe)
{
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;

	c->cnr.len = 1;
	c->cnr.stat[0].scale = FE_SCALE_NOT_AVAILABLE;
}

/* ====================================================================== */
/* SPEC-TNT: ISDB-T FC0012 tuner (36 MHz xtal, demod 0xfe tunnel @0xc6/0xc7) */
/* ====================================================================== */

static int fc_wr(struct pxw3pe *p, u8 taddr, u8 reg, u8 val)
{
	u8 b[4] = { 0xfe, 0xc6, reg, val };

	return demod_wr(p, taddr, b, 4);
}

static int fc_rd(struct pxw3pe *p, u8 taddr, u8 reg, u8 *val)
{
	u8 setp[3] = { 0xfe, 0xc6, reg };
	u8 rdp[2]  = { 0xfe, 0xc7 };
	int ret;

	mutex_lock(&p->i2c_lock);
	ret = i2c_xfer_wr(p, CTRL_DMOD_WR, taddr, 0, setp, 3);
	if (!ret)
		ret = i2c_xfer_wr(p, CTRL_DMOD_WR, taddr, 0, rdp, 2);
	if (!ret)
		ret = i2c_xfer_rd(p, CTRL_DMOD_RD, taddr, 0, val, 1);
	mutex_unlock(&p->i2c_lock);
	return ret;
}

static void fc_rmw(struct pxw3pe *p, u8 taddr, u8 reg, u8 set, u8 clr)
{
	u8 v;

	if (fc_rd(p, taddr, reg, &v))
		return;
	fc_wr(p, taddr, reg, (v & ~clr) | set);
}

/* FC0012 base register init (mainline fc0012.c init table,
 * regs 0x01..0x15). Mandatory once per tuner — without it the VCO
 * auto-calibration rails and the PLL never locks at low UHF.
 */
static void fc0012_init_regs(struct pxw3pe *p, u8 taddr)
{
	static const u8 regs[] = {
		0x00, 0x05, 0x10, 0x00, 0x00, 0x0f, 0x00, 0x00,
		0xff, 0x6e, 0xb8, 0x82, 0xf8, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x1b, 0x10, 0x00, 0x04,
	};
	int i;

	for (i = 1; i < ARRAY_SIZE(regs); i++)
		fc_wr(p, taddr, i, regs[i]);

	/* Official InitRFDevice toggles FC0012 reg0x10 after the base table. */
	fc_wr(p, taddr, 0x10, 0x00);
	fc_wr(p, taddr, 0x10, 0x10);
	fc_wr(p, taddr, 0x10, 0x00);
}

/* step1: FC0012 RSSI/DC calibration. */
static void fc0012_rssi_cal(struct pxw3pe *p, u8 taddr)
{
	fc_rmw(p, taddr, 0x09, 0x10, 0x00);
	fc_rmw(p, taddr, 0x06, 0x01, 0x00);
	msleep(1);
	fc_rmw(p, taddr, 0x09, 0x00, 0x10);
	fc_rmw(p, taddr, 0x06, 0x00, 0x10);
}

/* FC0012 PLL tune (36 MHz xtal; xtal/2 = 18000 kHz). */
static int fc0012_tune(struct pxw3pe *p, u8 taddr, u32 freq_khz)
{
	static const struct { u32 m; u8 r5, r6; } sel[] = {
		{96, 0x82, 0x00}, {64, 0x82, 0x02}, {48, 0x42, 0x00}, {32, 0x42, 0x02},
		{24, 0x22, 0x00}, {16, 0x22, 0x02}, {12, 0x12, 0x00}, {8, 0x12, 0x02},
		{6, 0x0a, 0x00}, {4, 0x0a, 0x02},
	};
	u32 multi = 4, vco, q, r, n, frac;
	u8 r1, r2, r3, r4, r5 = 0x0a, r6 = 0x02, r6base, e;
	int i, ret;

	fc0012_rssi_cal(p, taddr);

	for (i = 0; i < ARRAY_SIZE(sel); i++)
		if ((u64)freq_khz * sel[i].m <= 0x36523f) {
			multi = sel[i].m; r5 = sel[i].r5; r6 = sel[i].r6;
			break;
		}
	vco = freq_khz * multi;
	if (vco > 0x2eb11f)
		r6 |= 0x08;

	q = (u32)(((u64)vco * 0xe90452d5ULL) >> 46);	/* floor(vco/18000) */
	r = vco - q * 18000;				/* remainder       */
	n = (r <= 8999) ? q : q + 1;			/* round to nearest */
	if ((n & 7) <= 1) {
		r1 = (n & 7) + 8;
		r2 = (n >> 3) - 1;
	} else {
		r1 = n & 7;
		r2 = n >> 3;
	}

	frac = (u32)(((u64)((u32)(u16)r << 15) * 0x7482296bULL) >> 45);
	if ((frac & 0xffff) >= 0x4000)
		frac -= 0x8000;
	r3 = (frac >> 8) & 0xff;
	r4 = frac & 0xff;
	r5 |= 0x07;
	r6 |= 0x80;
	r6base = r6;

	ret  = fc_wr(p, taddr, 0x01, r1);
	ret |= fc_wr(p, taddr, 0x02, r2);
	ret |= fc_wr(p, taddr, 0x03, r3);
	ret |= fc_wr(p, taddr, 0x04, r4);
	ret |= fc_wr(p, taddr, 0x05, r5);
	ret |= fc_wr(p, taddr, 0x06, r6);
	if (ret)
		return -EIO;

	/* VCO auto-calibration (reg 0x0e), one correction pass. */
	fc_wr(p, taddr, 0x0e, 0x80);
	fc_wr(p, taddr, 0x0e, 0x00);
	msleep(1);
	fc_wr(p, taddr, 0x0e, 0x00);
	if (!fc_rd(p, taddr, 0x0e, &e)) {
		e &= 0x3f;
		if (vco > 0x2eb11f) {
			if (e > 0x3c) {
				fc_wr(p, taddr, 0x06, r6base & ~0x08);
				fc_wr(p, taddr, 0x0e, 0x80);
				fc_wr(p, taddr, 0x0e, 0x00);
			}
		} else if (e <= 1) {
			fc_wr(p, taddr, 0x06, r6base | 0x08);
			fc_wr(p, taddr, 0x0e, 0x80);
			fc_wr(p, taddr, 0x0e, 0x00);
		}
	}

	/* step7: demod RF band select (reg 0x1e). */
	{
		u8 v;

		if (!demod_rd(p, taddr, 0x1e, &v)) {
			if (freq_khz <= 261000)
				v = (v & 0xcf) | 0x20;
			else
				v |= 0x30;
			demod_wr_reg(p, taddr, 0x1e, v);
		}
	}
	return 0;
}

/* ISDB-T set-frequency = official demod pre/acquire/finalize
 * wrapped around the FC0012 PLL program.
 */
static int isdbt_set_frequency(struct pxw3pe *p, u8 taddr, u32 freq_khz)
{
	int ret;

	ret  = demod_wr_reg(p, taddr, 0x25, 0x00);
	ret |= demod_wr_reg(p, taddr, 0x23, 0x4d);
	if (ret)
		return -EIO;

	ret = fc0012_tune(p, taddr, freq_khz);
	if (ret)
		return ret;

	ret  = demod_wr_reg(p, taddr, 0x0f, 0x34);
	ret |= demod_wr_reg(p, taddr, 0x01, 0x40);
	ret |= demod_wr_reg(p, taddr, 0x23, 0x4c);
	return ret ? -EIO : 0;
}

/* ISDB-T lock = reg 0xB0 low nibble == 9. */
static int demod_t_locked(struct pxw3pe *p, u8 taddr, u8 *b0)
{
	if (demod_rd(p, taddr, 0xb0, b0))
		return -EIO;
	return ((*b0 & 0x0f) == 9) ? 1 : 0;
}

/* ====================================================================== */
/* Hardware bring-up                                                      */
/* ====================================================================== */

static int demod_scan(struct pxw3pe *p)
{
	struct device *dev = &p->pdev->dev;
	u8 v;
	int i, ack = 0;

	for (i = 0; i < ARRAY_SIZE(demod_addr); i++) {
		if (!demod_rd(p, demod_addr[i], 0x00, &v)) {
			ack++;
			dev_dbg(dev, "demod @0x%02x ACK reg00=0x%02x\n",
				demod_addr[i], v);
		} else {
			dev_warn(dev, "demod @0x%02x no-ack\n", demod_addr[i]);
		}
	}
	dev_info(dev, "%d/%d demods responded\n",
		 ack, (int)ARRAY_SIZE(demod_addr));
	return ack;
}

/* Bring the bridge, control chip, demods and tuners to a ready state.
 * LNB power output is not supported on this card (the onboard LNB regulator
 * does not deliver DC; see git history / re/SEQUENCE_SPEC.md SPEC-PWR-010), so
 * nothing here drives the LNB rail.
 */
static int pxw3pe_hw_init(struct pxw3pe *p)
{
	struct device *dev = &p->pdev->dev;
	int ret;

	hw_quiesce(p);		/* R1: clear residual DMA/IRQ/TS state from a warm reload */
	bridge_init(p);
	tc_preset(p);
	ret = asie_auth_enable(p);
	if (ret)
		return dev_err_probe(dev, ret, "ASIE auth/enable failed\n");
	power_on(p);
	mos_power(p);			/* SPEC-PWR: demod/tuner MOS power */

	if (demod_scan(p) != ARRAY_SIZE(demod_addr))
		dev_warn(dev, "not all demods responded; continuing\n");

	ret = tc905xx_initialise_all(p);
	if (ret)
		return dev_err_probe(dev, ret, "demod init failed\n");

	/* Per-tuner init: FC0012 base regs (ISDB-T) and RF/IF regs (ISDB-S). */
	sat_tuner_setup(p, DEMOD_S0);
	sat_tuner_setup(p, DEMOD_S1);

	/* Official the reference init sequence primes both terrestrial tuners once at 773143 kHz. */
	isdbt_set_frequency(p, DEMOD_T0, 0xbcc17);
	isdbt_set_frequency(p, DEMOD_T1, 0xbcc17);

	enc_probe(p);
	enc_enable_ts_output(p);
	return 0;
}

#ifdef CONFIG_DVB_PXW3PE_DEBUG
/* ====================================================================== */
/* Optional per-core lock self-test (CONFIG_DVB_PXW3PE_DEBUG, selftest=1)  */
/* ====================================================================== */

static void selftest_isdbs(struct pxw3pe *p, int idx, u8 saddr)
{
	/* Transponders that lock cleanly on the official path (DVB-S/8PSK). */
	static const u32 s_khz[] = { 11727480, 12291000, 12731000 };
	struct device *dev = &p->pdev->dev;
	int i, slock = 0;

	for (i = 0; i < ARRAY_SIZE(s_khz); i++) {
		u8 c3 = 0;
		int t, r = 0;

		if (isdbs_set_frequency(p, saddr, s_khz[i]))
			continue;
		for (t = 0; t < 20 && !r; t++) {
			msleep(100);
			r = demod_s_locked(p, saddr, &c3);
		}
		if (r)
			slock++;
		dev_info(dev, "  S%d @0x%02x %u kHz: lock=%d C3=0x%02x CN=0x%04x\n",
			 idx, saddr, s_khz[i], r, c3, demod_s_cn(p, saddr));
	}
	dev_info(dev, "ISDB-S core S%d @0x%02x: %d/%zu locked\n",
		 idx, saddr, slock, ARRAY_SIZE(s_khz));
}

static void selftest_isdbt(struct pxw3pe *p, int idx, u8 taddr)
{
	/* Physical channels confirmed broadcasting on the test feed. */
	static const u32 t_khz[] = { 473143, 503143, 527143 };
	struct device *dev = &p->pdev->dev;
	int i, tlock = 0;

	for (i = 0; i < ARRAY_SIZE(t_khz); i++) {
		u8 b0 = 0;
		int t, r = 0;

		if (isdbt_set_frequency(p, taddr, t_khz[i])) {
			dev_info(dev, "  T%d @0x%02x %u kHz: tune failed\n",
				 idx, taddr, t_khz[i]);
			continue;
		}
		for (t = 0; t < 15 && !r; t++) {
			msleep(100);
			r = demod_t_locked(p, taddr, &b0);
		}
		if (r)
			tlock++;
		dev_info(dev, "  T%d @0x%02x %u kHz: lock=%d B0=0x%02x\n",
			 idx, taddr, t_khz[i], r, b0);
	}
	dev_info(dev, "ISDB-T core T%d @0x%02x: %d/%zu locked\n",
		 idx, taddr, tlock, ARRAY_SIZE(t_khz));
}

static void pxw3pe_selftest(struct pxw3pe *p)
{
	dev_info(&p->pdev->dev, "selftest: per-core lock check\n");

	selftest_isdbs(p, 0, DEMOD_S0);
	selftest_isdbs(p, 1, DEMOD_S1);

	selftest_isdbt(p, 0, DEMOD_T0);
	selftest_isdbt(p, 1, DEMOD_T1);
}
#endif /* CONFIG_DVB_PXW3PE_DEBUG */

/* ====================================================================== */
/* SPEC-DMA: DMA ring, thin ISR, TS kthread, descramble                   */
/* ====================================================================== */

static inline u32 dma_ch_off(int port, int ch)
{
	return port * DMA_OFF_PORT + ch * DMA_OFF_CH + DMA_ADR_LO;
}

static inline u32 dma_mgmt_off(int port)
{
	return port * DMA_OFF_PORT + DMA_MGMT;
}

static inline u32 dma_ts_off(int port)
{
	return port * DMA_OFF_PORT + DMA_TSMODE;
}

static inline dma_addr_t dma_buf_phys(struct pxw3pe *p, int port, int ch,
				      int buf)
{
	return p->dma[port * NR_CH + ch][buf].adr;
}

static inline u8 *dma_buf_virt(struct pxw3pe *p, int port, int ch, int buf)
{
	return (u8 *)p->dma[port * NR_CH + ch][buf].dat;
}

/* start one DMA channel. Returns 0 on success, -EIO if the
 * stream's interrupt did not arm (fail the feed loudly instead of streaming
 * silently with no DMA — the GPL pxq3pe checks IRQ_ACTIVE the same way).
 */
static int dma_chan_start(struct pxw3pe *p, int port, int ch)
{
	void __iomem *bar = p->bar;
	struct device *dev = &p->pdev->dev;
	u32 bit = 1u << (port * NR_CH + ch);
	unsigned long fl;
	u8 v;

	if (p->dma_ch_on[port][ch])
		return 0;

	v = readb(bar + dma_ts_off(port));
	if (!(v & 0x80))
		writeb(v | 0x80, bar + dma_ts_off(port));

	writel(bit, bar + REG_IRQ_ENABLE);

	spin_lock_irqsave(&p->reg_lock, fl);
	{
		void __iomem *cb = bar + dma_ch_off(port, ch);
		u32 mgmt;

		p->dma_cur[port][ch] = 0;
		p->c_full[port][ch] = p->c_skip[port][ch] = 0;
		p->c_tag_sat[port][ch] = p->c_tag_ter[port][ch] = 0;
		mgmt = readl(bar + dma_mgmt_off(port));
		writel(mgmt & ~(0x3u << (ch * 16)), bar + dma_mgmt_off(port));
		writel(dma_buf_phys(p, port, ch, 0), cb);
		writel(0, cb + (DMA_ADR_HI - DMA_ADR_LO));
		writel(p->dma_ctl, cb + (DMA_CTL - DMA_ADR_LO));
		writel(readl(bar + dma_mgmt_off(port)) | (0x3u << (ch * 16)),
		       bar + dma_mgmt_off(port));
		p->dma_ch_on[port][ch] = true;
	}
	spin_unlock_irqrestore(&p->reg_lock, fl);

	msleep(100);
	dev_dbg(dev, "dma P%dC%d start TSMODE=0x%02x MGMT=0x%08x XFR=%u IRQ_ACTIVE=0x%08x\n",
		 port, ch, readb(bar + dma_ts_off(port)),
		 readl(bar + dma_mgmt_off(port)),
		 readl(bar + dma_ch_off(port, ch) + (DMA_XFR_STAT - DMA_ADR_LO)) &
		 DMA_XFR_MASK,
		 readl(bar + REG_IRQ_ACTIVE));

	if (!(readl(bar + REG_IRQ_ACTIVE) & bit)) {
		dev_err(dev, "dma P%dC%d failed to arm (IRQ_ACTIVE=0x%08x)\n",
			port, ch, readl(bar + REG_IRQ_ACTIVE));
		spin_lock_irqsave(&p->reg_lock, fl);
		writel(readl(bar + dma_mgmt_off(port)) & ~(0x3u << (ch * 16)),
		       bar + dma_mgmt_off(port));
		p->dma_ch_on[port][ch] = false;
		spin_unlock_irqrestore(&p->reg_lock, fl);
		writel(bit, bar + REG_IRQ_DISABLE);
		return -EIO;
	}
	return 0;
}

static void dma_chan_stop(struct pxw3pe *p, int port, int ch)
{
	void __iomem *bar = p->bar;
	struct device *dev = &p->pdev->dev;
	unsigned long fl;

	spin_lock_irqsave(&p->reg_lock, fl);
	if (!p->dma_ch_on[port][ch]) {
		spin_unlock_irqrestore(&p->reg_lock, fl);
		return;
	}
	p->dma_ch_on[port][ch] = false;
	writel(readl(bar + dma_mgmt_off(port)) & ~(0x3u << (ch * 16)),
	       bar + dma_mgmt_off(port));
	spin_unlock_irqrestore(&p->reg_lock, fl);
	writel(1u << (port * NR_CH + ch), bar + REG_IRQ_DISABLE);
	dev_dbg(dev,
		 "dma P%dC%d stop MGMT=0x%08x XFR=%u IRQ_STAT=0x%08x IRQ_ACTIVE=0x%08x\n",
		 port, ch, readl(bar + dma_mgmt_off(port)),
		 readl(bar + dma_ch_off(port, ch) + (DMA_XFR_STAT - DMA_ADR_LO)) &
		 DMA_XFR_MASK,
		 readl(bar + REG_IRQ_STAT), readl(bar + REG_IRQ_ACTIVE));
}

static int dma_port_start(struct pxw3pe *p, int port)
{
	bool was_on[NR_CH];
	int ch, ret;

	for (ch = 0; ch < NR_CH; ch++)
		was_on[ch] = p->dma_ch_on[port][ch];

	for (ch = 0; ch < NR_CH; ch++) {
		ret = dma_chan_start(p, port, ch);
		if (ret) {
			while (--ch >= 0)
				if (!was_on[ch])
					dma_chan_stop(p, port, ch);
			return ret;
		}
	}
	return 0;
}

static void dma_port_stop(struct pxw3pe *p, int port)
{
	int ch;

	for (ch = 0; ch < NR_CH; ch++)
		dma_chan_stop(p, port, ch);
}

/* producer — copy a full sub-buffer into the adapter ring. */
static void stream_put(struct pxw3pe_adap *a, const u8 *src, u32 len)
{
	u32 first;

	spin_lock(&a->sbuf_lock);
	if (a->sbuf_cnt + len > SBUF_SIZE) {		/* overflow: drop */
		a->c_drop++;
		spin_unlock(&a->sbuf_lock);
		dev_warn_ratelimited(&a->card->pdev->dev,
				     "adap%u ring overflow, dropping TS (consumer too slow)\n",
				     a->dvb.num);
		return;
	}
	if (a->sbuf_cnt > a->c_dropmax)
		a->c_dropmax = a->sbuf_cnt;
	first = min(len, SBUF_SIZE - a->sbuf_w);
	memcpy(a->sbuf + a->sbuf_w, src, first);
	if (len > first)
		memcpy(a->sbuf, src + first, len - first);
	a->sbuf_w = (a->sbuf_w + len) % SBUF_SIZE;
	a->sbuf_cnt += len;
	spin_unlock(&a->sbuf_lock);
	wake_up(&a->wq);
}

static bool dma_tag_is_sat(u8 tag)
{
	return tag == TS_TAG_SAT;
}

/* pick the adapter a packet belongs to from its source tag.
 * Each DMA port carries one combined stream from its two demod cores; the
 * tag in the sync byte (0x47 = ISDB-S core, 0xC7 = ISDB-T core) is the only
 * reliable source discriminator, so route by tag among the (exactly two)
 * adapters that share this port. Unknown tags return NULL and are dropped.
 */
static struct pxw3pe_adap *adap_by_tag(struct pxw3pe *p, int port, u8 tag)
{
	bool want_sat;
	int i;

	if (dma_tag_is_sat(tag))
		want_sat = true;
	else if (tag == TS_TAG_TER)
		want_sat = false;
	else
		return NULL;
	for (i = 0; i < NR_ADAP; i++)
		if (p->adap[i].port == port && p->adap[i].is_sat == want_sat)
			return &p->adap[i];
	return NULL;
}

/* split one filled DMA buffer to its adapters by per-packet
 * source tag. The DMA channel the packet landed in is not a source indicator
 * (both cores of a port are multiplexed across the port's channels), so the
 * tag alone selects the destination. Packets for a non-streaming adapter and
 * any unrecognized tag are dropped. Contiguous same-destination packets are
 * coalesced into one stream_put so the hardirq does not take the ring lock or
 * wake the consumer once per packet. Source order is preserved because each
 * channel buffer holds a contiguous in-order run of the stream and channels
 * are processed in fill order (lower stream bit first). The sync-byte
 * normalization that erases the tag happens later, in ts_process().
 */
static void dma_dispatch(struct pxw3pe *p, int port, int ch,
			 const u8 *buf, u32 len)
{
	struct pxw3pe_adap *run_a = NULL;
	u32 off, run_off = 0;

	for (off = 0; off + TS_SIZE <= len; off += TS_SIZE) {
		u8 tag = buf[off];
		struct pxw3pe_adap *a = adap_by_tag(p, port, tag);

		if (dma_tag_is_sat(tag))
			p->c_tag_sat[port][ch]++;
		else if (tag == TS_TAG_TER)
			p->c_tag_ter[port][ch]++;
		else
			p->c_unknown++;

		if (a != run_a) {
			if (run_a && run_a->streaming)
				stream_put(run_a, buf + run_off, off - run_off);
			run_a = a;
			run_off = off;
		}
	}
	if (run_a && run_a->streaming)
		stream_put(run_a, buf + run_off, len - run_off);
}

/*
 * Top half: ack the interrupt, re-arm each filled channel's next ping-pong
 * buffer (fast, in hardirq) and queue the just-filled buffer for the threaded
 * bottom half. The bulk per-buffer copy (dma_dispatch -> stream_put memcpy of
 * up to a few MiB) is deliberately kept out of hardirq context.
 */
static irqreturn_t pxw3pe_irq(int irq, void *dev)
{
	struct pxw3pe *p = dev;
	void __iomem *bar = p->bar;
	u32 stat = readl(bar + REG_IRQ_STAT);
	bool wake = false;
	int bit;

	if (!(stat & 0xf))
		return IRQ_NONE;
	writel(stat, bar + REG_IRQ_CLEAR);
	readl(bar + REG_IRQ_FLUSH);	/* posted-write flush */

	p->c_irq++;
	if (hweight32(stat & 0xf) > 1)
		p->c_irq_multi++;

	spin_lock(&p->reg_lock);
	for (bit = 0; bit < NR_ADAP; bit++) {
		int port = bit / NR_CH;
		int ch = bit % NR_CH;
		void __iomem *cb = bar + dma_ch_off(port, ch);
		u32 mgmt;
		int cur, next;
		bool full;

		if (!(stat & (1u << bit)))
			continue;
		if (!p->dma_ch_on[port][ch])
			continue;

		cur = p->dma_cur[port][ch];
		next = (cur + 1) % p->nbuf;
		full = (readl(cb + (DMA_XFR_STAT - DMA_ADR_LO)) &
			DMA_XFR_MASK) == p->pkt_bufsz;

		/*
		 * Ping-pong: hand the engine the next buffer and re-arm. The
		 * channel is known armed here (idle channels were skipped); an
		 * armed sibling channel must keep cycling so the port's combined
		 * stream is captured whole.
		 */
		writel(dma_buf_phys(p, port, ch, next), cb);
		mgmt = readl(bar + dma_mgmt_off(port));
		writel(mgmt | (0x2u << (ch * 16)), bar + dma_mgmt_off(port));
		p->dma_cur[port][ch] = next;

		if (!full) {
			p->c_skip[port][ch]++;
			continue;
		}
		p->c_full[port][ch]++;
		/* Queue the filled buffer for the bottom half (drop if it is not
		 * keeping up — should not happen given the per-buffer fill time).
		 */
		if (p->pend_head - p->pend_tail < PXW3PE_PEND) {
			u32 h = p->pend_head % PXW3PE_PEND;

			p->pend[h].port = port;
			p->pend[h].ch = ch;
			p->pend[h].buf = cur;
			p->pend_head++;
			wake = true;
		} else {
			p->c_pend_drop++;
		}
	}
	spin_unlock(&p->reg_lock);
	return wake ? IRQ_WAKE_THREAD : IRQ_HANDLED;
}

/*
 * Bottom half (threaded IRQ): dispatch + copy each queued filled buffer outside
 * the hardirq and outside reg_lock, so the multi-MiB memcpy does not inflate
 * IRQ-off time or the per-chip register-RMW contention. Each filled buffer stays
 * valid until the engine cycles back to it after (nbuf-1) more fills; that copy
 * window is (nbuf-1) * pkt_bufsz bytes (~1.5 s at the default pkt_num, and kept
 * >= ~0.1 s for small pkt_num by the nbuf bump in pxw3pe_dma_alloc), far longer
 * than this handler takes to run.
 */
static irqreturn_t pxw3pe_irq_thread(int irq, void *dev)
{
	struct pxw3pe *p = dev;
	unsigned long fl;

	for (;;) {
		u8 port, ch, buf;
		u32 t;

		spin_lock_irqsave(&p->reg_lock, fl);
		if (p->pend_tail == p->pend_head) {
			spin_unlock_irqrestore(&p->reg_lock, fl);
			break;
		}
		t = p->pend_tail % PXW3PE_PEND;
		port = p->pend[t].port;
		ch = p->pend[t].ch;
		buf = p->pend[t].buf;
		p->pend_tail++;
		spin_unlock_irqrestore(&p->reg_lock, fl);

		dma_dispatch(p, port, ch, dma_buf_virt(p, port, ch, buf),
			     p->pkt_bufsz);
	}
	return IRQ_HANDLED;
}

/* normalize the per-stream sync tag back to 0x47.
 * SPEC-ENC-DES: ASV5606 transport descramble (pre-XOR + positional DES-ECB).
 *
 * The 184-byte payload is exactly 23 DES blocks; the first 16 (bytes 4..131)
 * use the even key, the last 7 (bytes 132..187) the odd key. The 4-byte TS
 * header is left untouched.
 */
static void ts_process(u8 *buf, u32 len)
{
	bool dec = descramble && des_ready;
	u32 off;
	const int des_start = 4;	/* DES block starts after the 4-byte TS header */

	for (off = 0; off + TS_SIZE <= len; off += TS_SIZE) {
		u8 *pkt = buf + off;
		int b;

		pkt[0] = TS_SYNC;		/* drop the source tag    */
		if (dec) {
			for (b = 0; b < TS_SIZE - 4; b += DES_BLOCK_SIZE) {
				u8 *blk = pkt + des_start + b;
				const struct des_ctx *k;
				int i;

				for (i = 0; i < DES_BLOCK_SIZE; i++)
					blk[i] ^= des_xor_mask[i];
				k = (b < 128) ? &des_sched_even : &des_sched_odd;
				des_decrypt(k, blk, blk);
			}
		}
		pkt[1] &= 0x7f;			/* clear error indicator  */
	}
}

static int pxw3pe_thread(void *data)
{
	struct pxw3pe_adap *a = data;

	set_freezable();
	while (!kthread_should_stop()) {
		unsigned long fl;
		u32 r, span, cnt;

		wait_event_freezable_timeout(a->wq,
			a->sbuf_cnt > 0 || kthread_should_stop(),
			msecs_to_jiffies(50));
		if (kthread_should_stop())
			break;

		spin_lock_irqsave(&a->sbuf_lock, fl);
		cnt = a->sbuf_cnt;
		r = a->sbuf_r;
		spin_unlock_irqrestore(&a->sbuf_lock, fl);
		if (!cnt)
			continue;

		span = min(cnt, SBUF_SIZE - r);		/* contiguous run */
		span -= span % TS_SIZE;
		if (!span)
			continue;

		ts_process(a->sbuf + r, span);
		dvb_dmx_swfilter(&a->demux, a->sbuf + r, span);
		a->c_bytes += span;

		spin_lock_irqsave(&a->sbuf_lock, fl);
		a->sbuf_r = (a->sbuf_r + span) % SBUF_SIZE;
		a->sbuf_cnt -= span;
		spin_unlock_irqrestore(&a->sbuf_lock, fl);
	}
	return 0;
}

/* ====================================================================== */
/* DVB demux feed control + frontend ops                                  */
/* ====================================================================== */

static void pxw3pe_stream_reset_ring(struct pxw3pe_adap *a)
{
	unsigned long fl;

	spin_lock_irqsave(&a->sbuf_lock, fl);
	a->sbuf_w = a->sbuf_r = a->sbuf_cnt = 0;
	spin_unlock_irqrestore(&a->sbuf_lock, fl);
	a->c_drop = a->c_bytes = 0;
	a->c_dropmax = 0;
}

static bool pxw3pe_other_port_adapter_streaming(struct pxw3pe_adap *a)
{
	struct pxw3pe *p = a->card;
	int i;

	for (i = 0; i < NR_ADAP; i++)
		if (&p->adap[i] != a && p->adap[i].port == a->port &&
		    p->adap[i].streaming)
			return true;
	return false;
}

static bool pxw3pe_stream_pause_for_tune(struct pxw3pe_adap *a)
{
	struct pxw3pe *p = a->card;

	if (!a->streaming)
		return false;

	dev_dbg(&p->pdev->dev, "adap%d pause stream for retune\n", a->dvb.num);
	a->streaming = false;
	if (!pxw3pe_other_port_adapter_streaming(a))
		dma_port_stop(p, a->port);
	return true;
}

static int pxw3pe_stream_resume_after_tune(struct pxw3pe_adap *a)
{
	struct pxw3pe *p = a->card;
	int ret;

	if (!a->feeds || !a->thread)
		return 0;

	pxw3pe_stream_reset_ring(a);
	a->streaming = true;
	enc_stream_start(p);
	ret = dma_port_start(p, a->port);
	if (ret) {
		a->streaming = false;
		dev_err(&p->pdev->dev, "adap%d failed to resume stream after retune\n",
			a->dvb.num);
		return ret;
	}
	dev_dbg(&p->pdev->dev, "adap%d resumed stream after retune\n", a->dvb.num);
	return 0;
}

static int pxw3pe_start_feed(struct dvb_demux_feed *feed)
{
	struct pxw3pe_adap *a = feed->demux->priv;
	struct pxw3pe *p = a->card;
	bool card_idle = true;
	int i;

	if (a->feeds++ > 0)
		return 0;

	/*
	 * Reset the ring under its lock: once a->streaming is set below, a
	 * sibling channel's ISR (when an S+T pair shares a port) may route a
	 * tagged packet into this adapter via stream_put(), so the reset must
	 * be ordered before that first producer write.
	 */
	pxw3pe_stream_reset_ring(a);
	/* c_irq/c_irq_multi/c_unknown are card-wide: only zero them when this is
	 * the first adapter to start streaming, so a later feed does not clobber
	 * the running totals of siblings already streaming.
	 */
	for (i = 0; i < NR_ADAP; i++)
		if (&p->adap[i] != a && p->adap[i].streaming)
			card_idle = false;
	if (card_idle)
		p->c_irq = p->c_irq_multi = p->c_unknown = 0;
	a->thread = kthread_run(pxw3pe_thread, a, "pxw3pe-ts/%u",
				a->dvb.num);
	if (IS_ERR(a->thread)) {
		a->thread = NULL;
		a->feeds--;
		return -EFAULT;
	}
	a->streaming = true;
	enc_stream_start(p);
	if (dma_port_start(p, a->port)) {
		a->streaming = false;
		kthread_stop(a->thread);
		a->thread = NULL;
		a->feeds--;
		return -EIO;
	}
	return 0;
}

static int pxw3pe_stop_feed(struct dvb_demux_feed *feed)
{
	struct pxw3pe_adap *a = feed->demux->priv;
	struct pxw3pe *p = a->card;

	if (a->feeds == 0 || --a->feeds > 0)
		return 0;

	a->streaming = false;
	if (a->thread) {
		kthread_stop(a->thread);
		a->thread = NULL;
	}
	dev_dbg(&p->pdev->dev,
		 "adap%d DMA stats: irq=%llu multi=%llu drop=%llu ringmax=%u/%u bytes=%llu(%llupkt) unknown_tag=%llu pend_drop=%llu\n",
		 a->dvb.num, p->c_irq, p->c_irq_multi,
		 a->c_drop, a->c_dropmax, (u32)SBUF_SIZE, a->c_bytes,
		 a->c_bytes / TS_SIZE, p->c_unknown, p->c_pend_drop);
	dev_dbg(&p->pdev->dev,
		 "adap%d port%d tags: C%d full=%llu skip=%llu sat=%llu ter=%llu | C%d full=%llu skip=%llu sat=%llu ter=%llu\n",
		 a->dvb.num, a->port,
		 0, p->c_full[a->port][0], p->c_skip[a->port][0],
		 p->c_tag_sat[a->port][0], p->c_tag_ter[a->port][0],
		 1, p->c_full[a->port][1], p->c_skip[a->port][1],
		 p->c_tag_sat[a->port][1], p->c_tag_ter[a->port][1]);
	if (!pxw3pe_other_port_adapter_streaming(a))
		dma_port_stop(p, a->port);
	return 0;
}

static void pxw3pe_fe_release(struct dvb_frontend *fe)
{
	/* frontend is embedded in the adapter; nothing to free here. */
}

static enum dvbfe_algo pxw3pe_get_algo(struct dvb_frontend *fe)
{
	return DVBFE_ALGO_HW;
}

static int pxw3pe_t_read_status(struct dvb_frontend *fe, enum fe_status *st)
{
	struct pxw3pe_adap *a = container_of(fe, struct pxw3pe_adap, fe);
	u8 b0 = 0;
	int locked;

	*st = 0;
	locked = demod_t_locked(a->card, a->demod, &b0);
	if (locked > 0) {
		*st = FE_HAS_SIGNAL | FE_HAS_CARRIER | FE_HAS_VITERBI |
		      FE_HAS_SYNC | FE_HAS_LOCK;
		cn_set_stat(fe, demod_t_cn_cdb(a->card, a->demod));
	} else {
		cn_clear_stat(fe);
	}
	return 0;
}

/* DVBv3 SNR: C/N in 0.01 dB (0..3000), as reported by the vendor tables. */
static int pxw3pe_t_read_snr(struct dvb_frontend *fe, u16 *snr)
{
	struct pxw3pe_adap *a = container_of(fe, struct pxw3pe_adap, fe);

	*snr = demod_t_cn_cdb(a->card, a->demod);
	return 0;
}

/* HW tune: tune once on retune, then just poll status (no SW zigzag). */
static int pxw3pe_t_tune(struct dvb_frontend *fe, bool retune,
			 unsigned int mode, unsigned int *delay,
			 enum fe_status *status)
{
	struct pxw3pe_adap *a = container_of(fe, struct pxw3pe_adap, fe);
	struct pxw3pe *p = a->card;

	if (retune) {
		int chip = chip_of(a->demod);
		bool restart;
		int w, ret;

		/*
		 * S-before-T ordering: if the sibling ISDB-S core on this chip is
		 * mid-acquisition, let it converge first (its FC0012 RSSI/VCO
		 * recalibration would otherwise swing the shared AGC and break the
		 * 8PSK lock). Bounded yield (~1.5 s) so a T-only setup, where
		 * s_acquiring is never set, is not delayed.
		 */
		restart = pxw3pe_stream_pause_for_tune(a);
		for (w = 0; w < 75 && atomic_read(&p->s_acquiring[chip]); w++)
			msleep(20);

		/*
		 * Serialize the T tune body against the sibling S tune on the same
		 * chip (chip_lock), and hold it for a short settle so the FC0012
		 * RSSI/VCO recalibration and the demod-T AGC mostly converge before
		 * an S tune can grab the chip. T tune is one-time, so the settle is
		 * cheap.
		 */
		mutex_lock(&p->chip_lock[chip]);
		ret = isdbt_set_frequency(p, a->demod,
				fe->dtv_property_cache.frequency / 1000);
		if (!ret)
			msleep(120);
		mutex_unlock(&p->chip_lock[chip]);
		if (restart) {
			int rret = pxw3pe_stream_resume_after_tune(a);

			if (!ret)
				ret = rret;
		}
		if (ret) {
			*status = 0;
			return ret;
		}
	}
	*delay = HZ / 5;
	return pxw3pe_t_read_status(fe, status);
}

static const struct dvb_frontend_ops pxw3pe_isdbt_ops = {
	.delsys = { SYS_ISDBT },
	.info = {
		.name			= "PX-W3PE ISDB-T",
		.frequency_min_hz	= 90000000,
		.frequency_max_hz	= 770000000,
		.frequency_stepsize_hz	= 142857,
		.caps = FE_CAN_INVERSION_AUTO | FE_CAN_FEC_AUTO |
			FE_CAN_QAM_AUTO | FE_CAN_TRANSMISSION_MODE_AUTO |
			FE_CAN_GUARD_INTERVAL_AUTO | FE_CAN_HIERARCHY_AUTO,
	},
	.release		= pxw3pe_fe_release,
	.get_frontend_algo	= pxw3pe_get_algo,
	.tune			= pxw3pe_t_tune,
	.read_status		= pxw3pe_t_read_status,
	.read_snr		= pxw3pe_t_read_snr,
};

/*
 * Japanese BS/CS-110 LNB local oscillator (kHz). The DVB core carries the
 * satellite frequency in kHz and bounds it by frequency_max_hz, so a 12 GHz
 * downlink cannot be expressed in u32. Following the DVB-S convention, the
 * frontend receives the post-LNB IF (L-band, ~1-2 GHz); we add the LO back to
 * recover the downlink that keys sat_map. dvbv5 users configure a matching
 * LNBf (LO 10678 MHz) so the conf still carries the downlink frequency.
 */
#define SAT_LNB_LO_KHZ 10678000u

static const struct sat_ent *sat_nearest(u32 khz)
{
	const struct sat_ent *best = NULL;
	u32 bestd = ~0u;
	int i;

	for (i = 0; i < ARRAY_SIZE(sat_map); i++) {
		u32 d = sat_map[i].khz > khz ?
			sat_map[i].khz - khz : khz - sat_map[i].khz;

		if (d < bestd) {
			bestd = d;
			best = &sat_map[i];
		}
	}
	return best;
}

static int pxw3pe_s_read_status(struct dvb_frontend *fe, enum fe_status *st)
{
	struct pxw3pe_adap *a = container_of(fe, struct pxw3pe_adap, fe);
	u8 c3;

	*st = 0;
	if (demod_s_locked(a->card, a->demod, &c3) <= 0) {
		/*
		 * Carrier dropped. If it had been locked, a same-chip ISDB-T
		 * (re)tune most likely disturbed the shared analog AGC;
		 * re-kick acquisition once and force a fresh TSID latch so the
		 * S core recovers without a userspace retune.
		 * Single i2c write (i2c_lock only) — no chip_lock from the
		 * status-poll path, which runs concurrently with tunes.
		 */
		if (a->s_carrier) {
			demod_wr_reg(a->card, a->demod, 0x03, 0x01);
			a->s_carrier = false;
			a->s_stream_set = false;
		}
		cn_clear_stat(fe);
		return 0;
	}
	a->s_carrier = true;
	if (demod_s_cn(a->card, a->demod) <= 2999) {
		a->s_carrier = false;
		a->s_stream_set = false;
		cn_clear_stat(fe);
		return 0;
	}
	/*
	 * Vendor lock criterion (the reference lock check) is carrier alone: reg 0xC3 bit4
	 * clear. The relative-TS (TSID) latch is independent of lock and the
	 * vendor never gates lock on it, so report FE_HAS_LOCK on carrier + C/N
	 * and treat the stream latch as a best-effort, non-blocking refinement.
	 * (Gating lock on the latch previously stalled userspace whenever the
	 * reg-0xCE TSID list had not yet decoded or no concrete TSID was found.)
	 */
	*st = FE_HAS_SIGNAL | FE_HAS_CARRIER | FE_HAS_VITERBI |
	      FE_HAS_SYNC | FE_HAS_LOCK;
	cn_set_stat(fe, demod_s_cn_cdb(a->card, a->demod));
	if (!a->s_stream_set &&
	    !demod_s_select_ts(a->card, a->demod,
			       fe->dtv_property_cache.stream_id))
		a->s_stream_set = true;
	return 0;
}

/* DVBv3 SNR: C/N in 0.01 dB (0..3000), as reported by the vendor tables. */
static int pxw3pe_s_read_snr(struct dvb_frontend *fe, u16 *snr)
{
	struct pxw3pe_adap *a = container_of(fe, struct pxw3pe_adap, fe);

	*snr = demod_s_cn_cdb(a->card, a->demod);
	return 0;
}

/* DVBv3 BER: vendor ISDB-S error counter (reg 0xF0). Read-only telemetry. */
static int pxw3pe_s_read_ber(struct dvb_frontend *fe, u32 *ber)
{
	struct pxw3pe_adap *a = container_of(fe, struct pxw3pe_adap, fe);

	*ber = demod_s_ber(a->card, a->demod);
	return 0;
}

static int pxw3pe_s_tune(struct dvb_frontend *fe, bool retune,
			 unsigned int mode, unsigned int *delay,
			 enum fe_status *status)
{
	struct pxw3pe_adap *a = container_of(fe, struct pxw3pe_adap, fe);
	struct pxw3pe *p = a->card;

	if (retune) {
		/*
		 * The DVB core delivers the post-LNB IF in kHz; recover the
		 * downlink that keys sat_map. Frequencies already in the
		 * downlink band (e.g. the in-driver self-test) are used as-is.
		 */
		u32 freq = fe->dtv_property_cache.frequency;
		int chip = chip_of(a->demod);
		const struct sat_ent *ent;
		bool restart;
		int attempt, i, retries, ms = 0, locked = 0, ret = 0;
		u32 prev0;
		u8 c3 = 0;

		if (freq < SAT_LNB_LO_KHZ)
			freq += SAT_LNB_LO_KHZ;
		ent = sat_nearest(freq);
		if (!ent) {
			*status = 0;
			return -EINVAL;
		}

		a->s_stream_set = false;
		a->s_carrier = false;
		restart = pxw3pe_stream_pause_for_tune(a);
		retries = max(0, s_acquire_retries);

		/*
		 * Phase 1 (serialized per chip): hold chip_lock across the tuner
		 * PLL program, the ISDB-S acquisition kick (reg0x03=0x01) and the
		 * carrier-convergence window, so a sibling ISDB-T tune on the same
		 * composite chip cannot swing the shared analog AGC while the slow
		 * 8PSK loop is converging (the root cause of the 4ch BS failure).
		 * s_acquiring is raised BEFORE contending for the lock so a
		 * same-chip T tune yields and S converges first even on a cold 4ch
		 * start. Re-kick acquisition every ~600 ms; a cold lock takes a few
		 * hundred ms. Bounded to ~1.2 s, then release BEFORE the long
		 * TSID-latch tail so a same-chip T retune is not stalled for the
		 * whole sequence.
		 */
		atomic_set(&p->s_acquiring[chip], 1);
		mutex_lock(&p->chip_lock[chip]);
		/*
		 * isdbs_acquire() advances s_prev_key to the target
		 * on a successful program, so a bare retry would compute prev==
		 * target and skip the edge-transition kick — exactly for the two
		 * pairs it exists to rescue. Snapshot the entry prev under the lock
		 * and restore it before each retry so every attempt re-runs the
		 * same prev->target edge decision.
		 */
		prev0 = p->s_prev_key[chip];
		for (attempt = 0; attempt <= retries; attempt++) {
			if (attempt) {
				dev_dbg(&p->pdev->dev,
					"S@0x%02x retry acquisition attempt %d\n",
					a->demod, attempt + 1);
				msleep(100);
				ms += 100;
				p->s_prev_key[chip] = prev0;
			}
			if (isdbs_acquire(p, a->demod, ent->khz,
					  fe->dtv_property_cache.stream_id)) {
				ret = -EINVAL;
				break;
			}
			for (i = 0; i < 24; i++) {
				msleep(50);
				ms += 50;
				locked = demod_s_locked(p, a->demod, &c3);
				if (locked > 0 && demod_s_cn(p, a->demod) > 2999)
					break;
				locked = 0;
				if (i % 12 == 11)
					demod_wr_reg(p, a->demod, 0x03, 0x01);
			}
			if (locked > 0)
				break;
		}
		a->s_carrier = locked > 0;
		atomic_set(&p->s_acquiring[chip], 0);
		mutex_unlock(&p->chip_lock[chip]);

		/*
		 * Phase 2 (unlocked): once carrier is up, latch the requested TS
		 * out of the multiplex (reg0xCE list -> 0x8F/0x90). The TSID table
		 * needs time to decode after carrier lock, so retry ~50 ms x26.
		 * This is pure S-core register work and does not perturb the
		 * sibling T core, so it runs without chip_lock. An unlocked or
		 * unlatched return is non-fatal: read_status latches as a fallback.
		 */
		for (i = 0; locked > 0 && i < 26; i++) {
			if (!demod_s_select_ts(p, a->demod,
					       fe->dtv_property_cache.stream_id)) {
				a->s_stream_set = true;
				break;
			}
			msleep(50);
			ms += 50;
		}
		dev_dbg(&p->pdev->dev,
			 "S@0x%02x tune freq=%u carrier=%d tsid=%d c3=0x%02x agc=0x%02x cnraw=%u cn=%u after %dms\n",
			 a->demod, freq, locked > 0, a->s_stream_set, c3,
			 demod_s_agc(p, a->demod), demod_s_cn(p, a->demod),
			 demod_s_cn_cdb(p, a->demod), ms);
		if (restart) {
			int rret = pxw3pe_stream_resume_after_tune(a);

			if (!ret)
				ret = rret;
		}
		if (ret) {
			*status = 0;
			return ret;
		}
	}
	*delay = HZ / 5;
	return pxw3pe_s_read_status(fe, status);
}

static const struct dvb_frontend_ops pxw3pe_isdbs_ops = {
	.delsys = { SYS_ISDBS },
	.info = {
		.name			= "PX-W3PE ISDB-S",
		/* frequency carried in kHz (BS/CS transponder values). */
		.frequency_min_hz	= 1000000,
		.frequency_max_hz	= 2150000000,
		.frequency_stepsize_hz	= 1,
		.caps = FE_CAN_INVERSION_AUTO | FE_CAN_FEC_AUTO | FE_CAN_QAM_AUTO,
	},
	.release		= pxw3pe_fe_release,
	.get_frontend_algo	= pxw3pe_get_algo,
	.tune			= pxw3pe_s_tune,
	.read_status		= pxw3pe_s_read_status,
	.read_snr		= pxw3pe_s_read_snr,
	.read_ber		= pxw3pe_s_read_ber,
};

/* ====================================================================== */
/* DVB adapter registration + DMA/IRQ resources                           */
/* ====================================================================== */

static void pxw3pe_dma_free(struct pxw3pe *p);

static int pxw3pe_dma_alloc(struct pxw3pe *p)
{
	/* Derive the DMA geometry from the (validated) module parameters.
	 * Each ping-pong buffer is allocated separately (pkt_bufsz each) so
	 * none exceeds the buddy allocator's single-allocation ceiling: a
	 * pkt_num up to PKT_NUM_MAX is ~2.9 MiB and fits, whereas one
	 * pkt_bufsz*nbuf block would not.
	 */
	int i, b;

	p->nbuf      = clamp(n_dmabuf, 2, N_DMABUF_MAX);
	p->pkt_bufsz = TS_SIZE * clamp(pkt_num, PKT_NUM_MIN, PKT_NUM_MAX);
	p->dma_ctl   = DMA_CTL_FLAGS | p->pkt_bufsz;

	/*
	 * The threaded IRQ copies a filled buffer out asynchronously; the engine
	 * overwrites it only after cycling through the other (nbuf-1) ping-pong
	 * buffers, i.e. the copy window is (nbuf-1) * pkt_bufsz bytes (~one fill
	 * period per spare buffer). That is ~1.5 s at the default pkt_num but only
	 * a few ms at a small pkt_num, so raise nbuf for small buffers to keep at
	 * least a ~384 KiB (~0.1 s) window before the bottom half must run.
	 */
	while (p->nbuf < N_DMABUF_MAX &&
	       (u32)(p->nbuf - 1) * p->pkt_bufsz < 384u * 1024)
		p->nbuf++;

	for (i = 0; i < NR_ADAP; i++) {
		for (b = 0; b < p->nbuf; b++) {
			p->dma[i][b].dat = dma_alloc_coherent(&p->pdev->dev,
					p->pkt_bufsz, &p->dma[i][b].adr,
					GFP_KERNEL);
			if (!p->dma[i][b].dat)
				goto fail;
		}
	}
	dev_dbg(&p->pdev->dev,
		 "DMA: pkt_bufsz=%u (%d pkt) nbuf=%d per-ch=%u KiB x%d ctl=0x%08x\n",
		 p->pkt_bufsz, p->pkt_bufsz / TS_SIZE, p->nbuf,
		 (p->pkt_bufsz * p->nbuf) >> 10, NR_ADAP, p->dma_ctl);
	return 0;
fail:
	pxw3pe_dma_free(p);
	return -ENOMEM;
}

static void pxw3pe_dma_free(struct pxw3pe *p)
{
	int i, b;

	for (i = 0; i < NR_ADAP; i++) {
		for (b = 0; b < N_DMABUF_MAX; b++) {
			if (p->dma[i][b].dat)
				dma_free_coherent(&p->pdev->dev, p->pkt_bufsz,
						  p->dma[i][b].dat,
						  p->dma[i][b].adr);
			p->dma[i][b].dat = NULL;
		}
	}
}

static void pxw3pe_dvb_exit(struct pxw3pe *p)
{
	int i;

	for (i = NR_ADAP - 1; i >= 0; i--) {
		struct pxw3pe_adap *a = &p->adap[i];

		if (a->dvb_ready) {
			dvb_unregister_frontend(&a->fe);
			dvb_dmxdev_release(&a->dmxdev);
			dvb_dmx_release(&a->demux);
			dvb_unregister_adapter(&a->dvb);
			a->dvb_ready = false;
		}
		if (a->thread) {
			kthread_stop(a->thread);
			a->thread = NULL;
		}
		vfree(a->sbuf);
		a->sbuf = NULL;
	}
}

static int pxw3pe_dvb_init(struct pxw3pe *p)
{
	/*
	 * SPEC-DMA: adapter -> demod-core / DMA-port mapping confirmed against
	 * the official driver. The bridge routes even streams to DMA port B
	 * (TSMODE 0xb40) and odd streams to port A (TSMODE 0xa00); SetTSMode
	 * splits on stream parity exactly this way.
	 */
	static const struct {
		u8 demod;
		bool sat;
	} map[NR_ADAP] = {
		{ DEMOD_S0, true }, { DEMOD_S1, true },
		{ DEMOD_T0, false }, { DEMOD_T1, false },
	};
	int i, ret;

	for (i = 0; i < NR_ADAP; i++) {
		struct pxw3pe_adap *a = &p->adap[i];
		short adapter_nr[] = { -1 };

		a->card    = p;
		a->demod   = map[i].demod;
		a->is_sat  = map[i].sat;
		a->port    = (i & 1) ? 0 : 1;	/* odd=port A(0xa00), even=port B(0xb40) */
		a->ch      = i / 2;
		dev_dbg(&p->pdev->dev,
			 "adapter%d map demod=0x%02x %s dma=P%dC%d\n",
			 i, a->demod, a->is_sat ? "S" : "T",
			 a->port, a->ch);
		spin_lock_init(&a->sbuf_lock);
		init_waitqueue_head(&a->wq);

		a->sbuf = vmalloc(SBUF_SIZE);
		if (!a->sbuf) {
			ret = -ENOMEM;
			goto err;
		}

		ret = dvb_register_adapter(&a->dvb, "PX-W3PE", THIS_MODULE,
					   &p->pdev->dev, adapter_nr);
		if (ret < 0) {
			vfree(a->sbuf);
			a->sbuf = NULL;
			goto err;
		}

		a->demux.dmx.capabilities = DMX_TS_FILTERING |
					    DMX_SECTION_FILTERING;
		a->demux.priv       = a;
		a->demux.filternum  = 256;
		a->demux.feednum    = 256;
		a->demux.start_feed = pxw3pe_start_feed;
		a->demux.stop_feed  = pxw3pe_stop_feed;
		ret = dvb_dmx_init(&a->demux);
		if (ret < 0) {
			dvb_unregister_adapter(&a->dvb);
			vfree(a->sbuf);
			a->sbuf = NULL;
			goto err;
		}

		a->dmxdev.filternum = 256;
		a->dmxdev.demux     = &a->demux.dmx;
		ret = dvb_dmxdev_init(&a->dmxdev, &a->dvb);
		if (ret < 0) {
			dvb_dmx_release(&a->demux);
			dvb_unregister_adapter(&a->dvb);
			vfree(a->sbuf);
			a->sbuf = NULL;
			goto err;
		}

		a->fe.ops = map[i].sat ? pxw3pe_isdbs_ops : pxw3pe_isdbt_ops;
		a->fe.demodulator_priv = a;
		ret = dvb_register_frontend(&a->dvb, &a->fe);
		if (ret < 0) {
			dvb_dmxdev_release(&a->dmxdev);
			dvb_dmx_release(&a->demux);
			dvb_unregister_adapter(&a->dvb);
			vfree(a->sbuf);
			a->sbuf = NULL;
			goto err;
		}
		a->dvb_ready = true;
	}
	return 0;
err:
	pxw3pe_dvb_exit(p);
	return ret;
}

/* ====================================================================== */
/* PCI probe / remove                                                     */
/* ====================================================================== */

static int pxw3pe_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct pxw3pe *p;
	int ret, i;

	p = devm_kzalloc(&pdev->dev, sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	p->pdev = pdev;
	mutex_init(&p->i2c_lock);
	for (i = 0; i < NR_CHIP; i++) {
		mutex_init(&p->chip_lock[i]);
		atomic_set(&p->s_acquiring[i], 0);
	}
	spin_lock_init(&p->reg_lock);
	pci_set_drvdata(pdev, p);

	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;
	pci_set_master(pdev);

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "no 32-bit DMA\n");

	ret = pcim_iomap_regions(pdev, BIT(0), PXW3PE_NAME);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "BAR0 map failed\n");
	p->bar = pcim_iomap_table(pdev)[0];

	dev_info(&pdev->dev,
		 "PX-W3PE found: %04x:%04x subsys %04x:%04x rev %02x bar0=%pR\n",
		 pdev->vendor, pdev->device, pdev->subsystem_vendor,
		 pdev->subsystem_device, pdev->revision, &pdev->resource[0]);

	pxw3pe_load_firmware(p);	/* per-model secrets (ASIE enable + DES keys) */

	ret = pxw3pe_hw_init(p);
	if (ret)
		return ret;

#ifdef CONFIG_DVB_PXW3PE_DEBUG
	if (selftest)
		pxw3pe_selftest(p);
#endif

	ret = pxw3pe_dma_alloc(p);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "DMA alloc failed\n");

	/* Always allocate the IRQ vector (MSI preferred, else legacy) so
	 * pci_irq_vector()/pci_free_irq_vectors() are always paired.
	 */
	ret = pci_alloc_irq_vectors(pdev, 1, 1,
				    use_msi ? (PCI_IRQ_MSI | PCI_IRQ_LEGACY)
					    : PCI_IRQ_LEGACY);
	if (ret < 0) {
		dev_err(&pdev->dev, "alloc_irq_vectors failed: %d\n", ret);
		goto err_dma;
	}
	ret = request_threaded_irq(pci_irq_vector(pdev, 0), pxw3pe_irq,
				   pxw3pe_irq_thread,
				   pci_dev_msi_enabled(pdev) ? 0 : IRQF_SHARED,
				   PXW3PE_NAME, p);
	if (ret) {
		dev_err(&pdev->dev, "request_threaded_irq %d failed: %d\n",
			pci_irq_vector(pdev, 0), ret);
		goto err_vec;
	}
	p->irq_on = true;
	dev_info(&pdev->dev, "IRQ %d mode=%s\n", pci_irq_vector(pdev, 0),
		 pci_dev_msi_enabled(pdev) ? "MSI" : "INTx");

	ret = pxw3pe_dvb_init(p);
	if (ret) {
		dev_err(&pdev->dev, "DVB init failed: %d\n", ret);
		goto err_irq;
	}

	dev_info(&pdev->dev, "registered %d DVB adapters\n", NR_ADAP);
	return 0;

err_irq:
	free_irq(pci_irq_vector(pdev, 0), p);
	p->irq_on = false;
err_vec:
	pci_free_irq_vectors(pdev);
err_dma:
	pxw3pe_dma_free(p);
	return ret;
}

static void pxw3pe_remove(struct pci_dev *pdev)
{
	struct pxw3pe *p = pci_get_drvdata(pdev);
	int port, ch;

	/*
	 * Stop the hardware producer BEFORE tearing down DVB. The ISR's
	 * dma_dispatch()->stream_put() writes into the per-adapter TS rings that
	 * pxw3pe_dvb_exit() frees (vfree), so the DMA engine and IRQ must be
	 * fully quiesced first or a buffer-full interrupt could write into freed
	 * memory. Order: halt DMA channels -> clear DMA/IRQ latches -> free_irq
	 * (synchronizes any in-flight ISR) -> only then dvb_exit frees the rings.
	 */
	for (port = 0; port < NR_PORT; port++)
		for (ch = 0; ch < NR_CH; ch++)
			dma_chan_stop(p, port, ch);
	hw_quiesce(p);			/* disable IRQ + clear DMA/TS latches */
	if (p->irq_on) {
		free_irq(pci_irq_vector(pdev, 0), p);	/* syncs any pending ISR */
		pci_free_irq_vectors(pdev);
		p->irq_on = false;
	}
	pxw3pe_dvb_exit(p);		/* stops consumer kthreads + frees TS rings */
	demods_sleep(p);		/* stop+sleep cores while still powered  */
	power_off(p);			/* drop power rails + ASV5606 gate       */
	pxw3pe_dma_free(p);
}

/* SPEC-META: 0x0B06:0x0001 = PX-W3PE (0x0002 = Q3PE, 0x0003 = W3PE V2). */
static const struct pci_device_id pxw3pe_id[] = {
	{ PCI_DEVICE_SUB(0x188b, 0x5220, 0x0b06, 0x0001) },
	{ }
};
MODULE_DEVICE_TABLE(pci, pxw3pe_id);

static struct pci_driver pxw3pe_driver = {
	.name		= PXW3PE_NAME,
	.id_table	= pxw3pe_id,
	.probe		= pxw3pe_probe,
	.remove		= pxw3pe_remove,
};

module_pci_driver(pxw3pe_driver);

MODULE_DESCRIPTION("PLEX PX-W3PE (ASICEN ASV5220) ISDB-S/T DVB driver (clean-room)");
MODULE_AUTHOR("Inaba <admin@inaba.dev>");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
MODULE_FIRMWARE(PXW3PE_FW_NAME);
