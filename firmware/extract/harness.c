// SPDX-License-Identifier: GPL-2.0
/*
 * harness.c - PX-W3PE (ASV5220/ASIE5606) key-extraction harness.
 *
 * Links the official asv5220_dtv.ko (REL ELF, kernel 2.6.32) into a userspace
 * x86-64 program and runs its key-derivation code (DTV_GenEncSeed +
 * DTV_5606B2_KeyTransfer2) to extract, for entry-0 (the PX-W3PE model key):
 *   - chip seed  (16B) = ctx+0x30da4[0:16]
 *   - DES even key (8B) = ctx+0x8fc98[0:8]   (also captured via des_setkey_dec)
 *   - DES odd  key (8B) = ctx+0x8fca0[0:8]   (also captured via des_setkey_dec)
 *   - xor seed   (4B) = ctx+0x8fca8[0:4]
 *
 * The 4 fields come OUT of the .ko; nothing is hardcoded here except the
 * .ko-derived constants (const70/const80, KEY_C) needed to drive it.
 *
 * Build (objcopy weakens the .ko's des_setkey_dec so our strong one wins,
 * letting us capture the raw DES keys KeyTransfer2 passes in):
 *   objcopy --weaken-symbol=des_setkey_dec asv5220_dtv.ko asv_w.ko
 *   gcc -no-pie -fno-pie -O0 harness.c asv_w.ko -o harness
 *
 * Notes:
 *   - 66 undefined kernel symbols are stubbed (noop / minimal).
 *   - mcount is a naked ret (profiling).
 *   - arch_prctl(ARCH_SET_GS, gsbuf) sets a valid %gs base so the .ko's
 *     "mov rax, gs:0x28" stack-canary loads do not fault.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/syscall.h>
#include <asm/prctl.h>

/* ---- profiling: naked ret ---- */
asm(".global mcount\nmcount:\n  ret\n");

/* ---- stack protector ---- */
void __stack_chk_fail(void) {}

/* ---- allocator stubs (return real memory) ---- */
void *__kmalloc(unsigned long s, unsigned f) { (void)f; return calloc(1, s ? s : 8); }
void *kmem_cache_alloc_notrace(void *c, unsigned f) { (void)c; (void)f; return calloc(1, 256); }
void *vmalloc(unsigned long s) { return calloc(1, s ? s : 8); }
void kfree(const void *p) { (void)p; }
void vfree(const void *p) { (void)p; }
unsigned long slab_buffer_size(void *c) { (void)c; return 0; }

/* ---- libc-backed mem ops the .ko imports ---- */
/* memcpy/memset/sprintf/strncpy resolve from libc; provide only the rest. */

/* ---- printk: route to stderr so it does not pollute the parsable output ---- */
int printk(const char *fmt, ...) { (void)fmt; return 0; }
void warn_slowpath_null(const char *f, int l) { (void)f; (void)l; }
void __udelay(unsigned long u) { (void)u; }
int msleep_interruptible(unsigned int m) { (void)m; return 0; }

/* ---- everything else: noop stubs returning 0 ---- */
long alloc_chrdev_region() { return 0; }
long cdev_add() { return 0; }
long cdev_del() { return 0; }
long cdev_init() { return 0; }
long __class_create() { return 0; }
long class_destroy() { return 0; }
long complete() { return 0; }
long copy_from_user() { return 0; }
long copy_to_user() { return 0; }
long dev_get_drvdata() { return 0; }
long device_create() { return 0; }
long device_destroy() { return 0; }
long dev_set_drvdata() { return 0; }
long down() { return 0; }
long free_irq() { return 0; }
long __init_waitqueue_head() { return 0; }
long kthread_create() { return 0; }
long kthread_should_stop() { return 0; }
long kthread_stop() { return 0; }
long __mutex_init() { return 0; }
long mutex_lock() { return 0; }
long mutex_unlock() { return 0; }
long no_llseek() { return 0; }
long param_get_int() { return 0; }
long param_set_int() { return 0; }
long pci_bus_read_config_word() { return 0; }
long pci_choose_state() { return 0; }
long pci_disable_device() { return 0; }
long pci_enable_device() { return 0; }
long pci_iomap() { return 0; }
long pci_iounmap() { return 0; }
long __pci_register_driver() { return 0; }
long pci_release_regions() { return 0; }
long pci_request_regions() { return 0; }
long pci_restore_state() { return 0; }
long pci_save_state() { return 0; }
long pci_set_dma_mask() { return 0; }
long pci_set_master() { return 0; }
long pci_set_power_state() { return 0; }
long pci_unregister_driver() { return 0; }
long request_threaded_irq() { return 0; }
long unregister_chrdev_region() { return 0; }
long up() { return 0; }
long wait_for_completion() { return 0; }
long wake_up_process() { return 0; }

/* ---- kernel data symbols the .ko references ---- */
void *dma_ops = 0;
void *malloc_sizes = 0;
void *pv_irq_ops = 0;
void *__tracepoint_kmalloc = 0;
void *x86_dma_fallback_dev = 0;

/* ---- .ko symbols we call / read ---- */
extern unsigned char keybox_ASV5606[];
extern unsigned char Key1[];                /* 1024B selector table */
extern unsigned char Key2[];                /* 1024B selector table */
extern long DTV_GenEncSeed(void *ctx, void *V1, long c1, void *V2, long c2);
extern long DTV_5606B2_KeyTransfer2(void *ctx);
extern long FUSBDTV_AddUSBDevice(void *ctx);

/* We define a strong des_setkey_dec; objcopy weakens the .ko's copy so this
 * one wins. KeyTransfer2 calls it twice (even then odd) -> we capture the
 * raw 8-byte DES key it passes in arg2 (rsi). */
static unsigned char g_des_key[2][8];
static int g_des_n = 0;
void des_setkey_dec(void *sched, const unsigned char *key, void *sp)
{
	(void)sched; (void)sp;
	if (g_des_n < 2)
		memcpy(g_des_key[g_des_n], key, 8);
	g_des_n++;
}

/* .ko-derived constants (NOT secret outputs):
 *   const70/const80 are the GenEncSeed input masks; KEY_C is the stage-1
 *   block-3 expansion key from FUSBDTV_AddUSBDevice. */
static const unsigned char const70[16] = {
	0x1f,0xc5,0x62,0xb9,0xb3,0x36,0x4c,0x38,0x86,0xe5,0x21,0x1e,0x94,0x4e,0xce,0x3a };
static const unsigned char const80[16] = {
	0xad,0x1e,0x56,0xa4,0xe8,0xc1,0x4c,0xce,0x90,0xf7,0x33,0x92,0x77,0x14,0xf8,0xb9 };
static const unsigned char KEY_C[8] = {
	0x8a,0x85,0x4f,0x76,0xc0,0xf4,0x2a,0x03 };

static unsigned char *CTX;

static void segv(int sig, siginfo_t *si, void *uc)
{
	ucontext_t *u = uc;
	(void)sig;
	fprintf(stderr, "SIGSEGV rip=%llx addr=%p\n",
		(unsigned long long)u->uc_mcontext.gregs[REG_RIP], si->si_addr);
	_exit(2);
}

static void hex(const char *tag, const unsigned char *p, int n)
{
	int i;
	printf("%s=", tag);
	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf("\n");
}

int main(void)
{
	static unsigned char gsbuf[4096];
	unsigned char V1[16], V2[16];
	struct sigaction sa;
	long r;
	int i;
	const int entry = 0;            /* entry-0 = PX-W3PE model key */

	/* valid %gs base so gs:0x28 canary loads in the .ko do not fault */
	syscall(SYS_arch_prctl, ARCH_SET_GS, (unsigned long)gsbuf);

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &sa, 0);

	CTX = calloc(1, 0x100000);
	*(void **)(CTX + 0x5218) = calloc(1, 0x20000);   /* fake BAR base */
	*(void **)(CTX + 0x1d38) = CTX;                  /* stage-1 buffer ptr */

	/* manual stage-1 block3 (FUSBDTV_AddUSBDevice expansion) -> ctx+0x2b8 */
	for (i = 0; i < 192; i++)
		CTX[0x2b8 + i] = (unsigned char)((keybox_ASV5606[i] - (i % 8)) ^ KEY_C[i % 8]);

	/* GUID (PX-W3PE subsystem 0b06:0001) + flags */
	CTX[0x49d3] = 0x0b; CTX[0x49d4] = 0x06; CTX[0x49d5] = 0x00; CTX[0x49d6] = 0x01;
	CTX[0x49d0] = 1;
	CTX[0x148d] = 0x11;
	CTX[0x30d61] = 1;       /* build gate */
	CTX[0x15d8] = 0;        /* build path selector */

	/* entry-0 selectors: V1[i]=const70[i]^Key1[entry*16+i], V2[i]=const80[i]^Key2[...] */
	for (i = 0; i < 16; i++) {
		V1[i] = const70[i] ^ Key1[entry * 16 + i];
		V2[i] = const80[i] ^ Key2[entry * 16 + i];
	}

	/* lengths MUST be 0x10 for both inputs */
	r = DTV_GenEncSeed(CTX, V1, 0x10, V2, 0x10);
	if (r != 1) {
		fprintf(stderr,
			"harness: DTV_GenEncSeed failed (ret=%ld) - extraction aborted\n",
			r);
		return 3;
	}

	/* KeyTransfer2 -> calls des_setkey_dec twice (even, odd) */
	DTV_5606B2_KeyTransfer2(CTX);
	if (g_des_n < 2) {
		fprintf(stderr,
			"harness: DES key capture incomplete (got %d, need 2) - extraction aborted\n",
			g_des_n);
		return 4;
	}

	/*
	 * Emit the 4 fields in the stable parsable contract. The hard-fails above
	 * guarantee every value below comes from a real extraction, never from the
	 * zeroed ctx (which would otherwise yield a valid-looking but wrong blob).
	 */
	hex("seed", CTX + 0x30da4, 16);
	hex("even", g_des_key[0], 8);
	hex("odd",  g_des_key[1], 8);
	hex("xor",  CTX + 0x8fca8, 4);
	printf("auth=Fuwawa Abyssgard\n");
	return 0;
}
