#ifndef _INCLUDE_ANEMU_PRIVATE_H_
#define _INCLUDE_ANEMU_PRIVATE_H_

#include "anemu.h"
#include <dlfcn.h>              /* dladdr */
#include <errno.h>
#include <fcntl.h>              /* open, close */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>             /* memset */
#include <sys/atomics.h>
#include <sys/mman.h>           /* mprotect */
#include <sys/prctl.h>          /* thread name */
#include <sys/ptrace.h>         /* PSR bit macros */
#include <sys/resource.h>       /* [set,get]rlimit */
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/uio.h>            /* writev */
#include <time.h>
#include <unistd.h>
#ifdef EMU_DEMANGLE
#include <corkscrew/demangle.h> /* demangle C++ */
#include <corkscrew/backtrace.h>
#endif
#ifdef NDK_BUILD
// NDK, unlike AOSP, does not provide ucontext.h and perf_event.h
#include "perf_event.h"
#include "ucontext.h"
#define __read read
#else
#include <linux/perf_event.h>
#endif

#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

// xattr.h from $AOSP/dalvik/libattr/attr/xattr.h
#include "xattr.h"              /* fsetxattr, fgetxattr */

#define atomic_inc __atomic_inc
#define atomic_dec __atomic_dec
#define property_get __system_property_get
#ifdef NDEBUG
#define PROFILE
#else
#define TRACE
#define TRACE_PATH "/sdcard/trace"
#endif

#ifndef NO_TAINT
# define TAINT_PC
# define EMU_MEM_PREAD
#else
# define NO_MPROTECT
#endif

#ifdef ANDROID
#include <android/log.h>
#define LOG_TAG "anemu"
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO,    LOG_TAG, __VA_ARGS__))
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG,   LOG_TAG, __VA_ARGS__))
#define LOGV(...) ((void)__android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR,   LOG_TAG, __VA_ARGS__))
#define LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN,    LOG_TAG, __VA_ARGS__))
#define printf LOGI
#endif

#ifndef PROFILE
// #define emu_log_trace(...) { if (emu.trace_file) { lprintf(emu.trace_file, __VA_ARGS__); fflush(emu.trace_file); }}
#define emu_log_trace emu_log_info
#define emu_log_error(...)  { LOGE(__VA_ARGS__); __log_print(ANDROID_LOG_ERROR,  LOG_TAG, __VA_ARGS__); }
#define emu_log_warn(...)   { LOGW(__VA_ARGS__); __log_print(ANDROID_LOG_WARN,   LOG_TAG, __VA_ARGS__); }
#define emu_log_info(...)   { LOGI(__VA_ARGS__); __log_print(ANDROID_LOG_INFO,   LOG_TAG, __VA_ARGS__); }
#define emu_log_debug(...)  { LOGD(__VA_ARGS__); __log_print(ANDROID_LOG_DEBUG,  LOG_TAG, __VA_ARGS__); }
#else
#define emu_log_trace(...) (void)(NULL)
#define emu_log_error LOGE
#define emu_log_warn  LOGW
#define emu_log_info  LOGI
#define emu_log_debug(...) (void)(NULL)
#endif

#define LOG_BANNER_SIG   "\n### ### ### ### ### ### ### ### ### ### ### ### ### ### ### ###\n"
#define LOG_BANNER_INSTR "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n\n"

/* darm disassembler */
#include <darm.h>

#ifndef NDEBUG
#define assert(x) if (!(x)) { emu_abort("ASSERTION (%s) FAILED file: %s line: %d\n", #x, __FILE__, __LINE__); }
#else
#define assert(x) (void)(NULL)
#endif

#define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))

#define UNUSED __attribute__((unused))

#define SIGNAL SIGTRAP
#define SEGV_FAULT_ADDR (uint32_t *)0xdeadbeef
#define UCONTEXT_REG_OFFSET 3   /* skip first 3 fields (trap_no, error_code, oldmask) of uc_mcontext */

#define CPU(reg) (emu->current.uc_mcontext.arm_##reg)

#define EMU(stmt)                                 \
    emu_log_debug("EMU: %s\n", #stmt);            \
    stmt;                                         \

#define emu_printf(...) { LOGE("%s: ", __func__); LOGE(__VA_ARGS__); }
#define EMU_ENTRY LOGE("%s\n", __func__)

#define emu_abort(...) {                                           \
  UNUSED int __errnum = errno;                                     \
  emu_log_error("\n");                                             \
  emu_log_error("*********************************\n");            \
  emu_log_error("SYSTEM FAILURE! ABORTING!\n");                    \
  emu_log_error( "errno %d %s\n", __errnum, strerror(__errnum));   \
  emu_log_error("%s: ", __func__);                                 \
  emu_log_error(__VA_ARGS__);                                      \
  emu_log_error("instr total: %d\n", emu_global->instr_total);     \
  emu_log_error("line: %d\n", __LINE__);                           \
  emu_log_error("*********************************\n\n");          \
  emu_global->debug = 1;                                           \
  emu_dump_taintmaps();                                            \
  gdb_wait();                                                      \
  signal(SIGSEGV, SIG_DFL);                                        \
  *SEGV_FAULT_ADDR = 0xbadf00d;                                    \
}

#define SWITCH_COMMON                                                  \
    case I_INVLD: {                                                    \
        emu_abort("darm invalid op type\n");                           \
        break;                                                         \
    }                                                                  \
    default:                                                           \
    emu_abort("unhandled instr %s\n", darm_mnemonic_name(d->instr));

/*
CPSR bits
N: Negative result
Z: Zero result
C: Carry from operation
V: oVerflowed operation

I: IRQ
T: Thumb mode
*/

#define CPSR_N ((CPU(cpsr) & PSR_N_BIT) >> 31)
#define CPSR_Z ((CPU(cpsr) & PSR_Z_BIT) >> 30)
#define CPSR_C ((CPU(cpsr) & PSR_C_BIT) >> 29)
#define CPSR_V ((CPU(cpsr) & PSR_V_BIT) >> 28)
#define CPSR_I ((CPU(cpsr) & PSR_I_BIT) >>  7)
#define CPSR_T ((CPU(cpsr) & PSR_T_BIT) >>  5)

#define MAX_MAPS 2048           /* number of memory map entries */
#define MAX_TAINTMAPS 2         /* libs + stack (heap part of libs) */
#define MAX_TAINTPAGES 256      /* number of distinct tainted pages */
#define TAINTMAP_LIB   0        /* taintmap index for libs */
#define TAINTMAP_STACK 1        /* taintmap index for stack */
#define TAINTPAGE_SIZE (PAGE_SIZE >> 2)

typedef struct _map_t {
    uint32_t vm_start;
    uint32_t vm_end;
    uint64_t pgoff;
    uint32_t major, minor;
    char r, w, x, s;
    uint32_t ino;
    char name[128];
    uint32_t pages;
} map_t;

typedef uint16_t taintpage_t;

#define N_REGS 16               /* r0-r15 */
typedef struct _taintmap_t {
    uint32_t *data;             /* mmap-ed data */
    uint32_t  start;            /* address range start */
    uint32_t  end;              /* address range end */
    uint32_t  bytes;            /* (end - start) bytes */
    taintpage_t *pages;         /* taintpages */
} taintmap_t;

/* GLOBAL emu state */
typedef struct _emu_global_t {
    int        initialized;       /* boolean */
    uint16_t   nr_maps;           /* number of process maps available */
    map_t      maps[MAX_MAPS];
    taintmap_t taintmaps[MAX_TAINTMAPS];   /* taint storage for memory */
    int32_t    running;                    /* number of currently emulating threads */
    bool       disabled;                   /* prevent further emulation */
    bool       protect;                    /* dynamic toggle for taint mprotect */
    bool       standalone;        /* standalone or target based emu */
    uint32_t   target;            /* pid targetted for emulation */
    int32_t    instr_total;       /* number of ops seen so far */
    int32_t    trap_bkpt;         /* trap counter */
    int32_t    trap_segv;
    uint32_t   taint_hit;
    uint32_t   taint_hit_stack;
    uint32_t   taint_miss;
    uint32_t   taint_miss_stack;
    uint32_t   taint_mem_read;
    uint32_t   taint_mem_write;
    uint32_t   mem_read;
    uint32_t   mem_write;
    int32_t    trace_fd;          /* trace file descriptor */
    int32_t    mem_fd;            /* memory access via /proc/self/mem */
    int32_t    thread_count;      /* number of threads configured for emu (sigaltstacks) */
    uint32_t   stack_max;         /* RLIMIT_STACK */
    uint32_t   stack_base;        /* stack top - RLIMIT_STACK */
    int32_t    debug;             /* dynamic debug statements */
    int32_t    stop_total;
    int32_t    stop_handler;
    int32_t    debug_offset;
    int32_t    selective;
} emu_global_t;

/* Per-Thread emu state */
typedef struct _emu_thread_t {
    pid_t       tid;              /* system tid */
    ucontext_t  current;          /* present process emulated state */
    ucontext_t  previous;         /* used for diff-ing two contexts */
    ucontext_t  original;         /* process state when trap occured */
    darm_t      darm;             /* darm disassembler */
    uint8_t     branched;         /* branch taken? */
    uint8_t     disasm_bytes;     /* bytes used in last disasm */
    uint32_t   *regs;             /* easy access to ucontext regs */
    uint16_t    nr_maps;          /* number of process maps available */
    uint32_t    taintreg[N_REGS]; /* taint storage for regs */
    int32_t     instr_count;      /* number of ops seen in current trap handler */
    uint64_t    time_start;       /* execution time measurements */
    uint64_t    time_end;
    int32_t     trace_fd;         /* trace file descriptor */
    bool        running;          /* flag to avoid stdio within sig handler */
    bool        stop;             /* emu stop requested */
    uint8_t     skip;             /* special hack to skip certain tricky functions */
    bool        bypass;           /* flag to bypass emulation of trampolines */
    uint8_t     lock_acquired;    /* target program holding a lock */
} emu_thread_t;

/* Synchronization */
// mutex options: PTHREAD_MUTEX_INITIALIZER or PTHREAD_RECURSIVE_MUTEX_INITIALIZER
static pthread_mutex_t emu_lock   = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mmap_lock  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t taint_lock = PTHREAD_MUTEX_INITIALIZER;

static emu_global_t __emu_global = {
#ifndef NDEBUG
    .debug = true,
#endif
    .protect = true,           // default mprotect newly (un)tainted pages
    .trace_fd = STDOUT_FILENO, // stdout = 2
    .target   = 0,
    .disabled = 0,
    .selective = 1
};

static emu_global_t *emu_global = &__emu_global;

/* read/write register by number */
#define RREGN(reg)  emu_read_reg(emu, reg)
#define WREGN(reg) *emu_write_reg(emu, reg)
/* read/write register by darm specifier (e.g. Rd, Rm, Rn, Rt) */
#define RREG(reg)   emu_read_reg(emu, d->reg)
#define WREG(reg)  *emu_write_reg(emu, d->reg)

/* read/write memory */
#define WMEM_DIRECT(addr) *(uint32_t *)(addr)
#define RMEM_DIRECT(addr) WMEM(addr)   /* identical pointer cast */

/* /proc/self/mem interface to memory */
#define WMEM8(addr,  data) mem_write8(addr,  data)
#define WMEM16(addr, data) mem_write16(addr, data)
#define WMEM32(addr, data) mem_write32(addr, data)

#define RMEM8(addr)  mem_read8(addr)
#define RMEM16(addr) mem_read16(addr)
#define RMEM32(addr) mem_read32(addr)

/* taint register by darm specifier */
#define RTREG(reg)       emu_get_taint_reg(emu, d->reg)
#define WTREG(reg, tag)  emu_set_taint_reg(emu, d->reg, tag)
#define RTREGN(reg)      emu_get_taint_reg(emu, reg)
#define WTREGN(reg, tag) emu_set_taint_reg(emu, reg, tag)

#define WTREG1(dest, a)          WTREG(dest, RTREG(a))
#define WTREG2(dest, a, b)       WTREG(dest, RTREG(a) | RTREG(b))
#define WTREG3(dest, a, b, c)    WTREG(dest, RTREG(a) | RTREG(b) | RTREG(c))
#define WTREG4(dest, a, b, c, d) WTREG(dest, RTREG(a) | RTREG(b) | RTREG(c) | RTREG(d))

/* taint memory */
#define RTMEM(addr)      emu_get_taint_mem(addr)
#define WTMEM(addr, tag) emu_set_taint_mem(addr, tag)

/* process two operands according to instr type */
#define OP(a, b) emu_dataop(emu, a, b)
/* shorthand for cleaner arguments */
#define RSHIFT(val) emu_regshift(emu, val)

/*
emulating instr{S} requires saving and restoring CPSR

instructions having S:

ADC, ADD, AND, ASR, BIC, EOR, LSL, LSR, MLA, MOV, MUL, MVN,
ORR, ROR, RRX, RSB, RSC, SBC, SUB,
SMLAL, SMULL, UMLAL, UMULL

formats for S instructions:

<Rd> #<const>
<Rd> <Rm>
<Rd> <Rm> #<shift>
<Rd> <Rm> <type>
<Rd> <Rm>{ <shift>}
<Rd> <Rn> #<const>
<Rd> <Rn> <Rm>
<Rd> <Rn> <Rm> <Ra>
<Rd> <Rn> <Rm> <type>
<Rd> <Rn> <Rm>{ <shift>}
<RdLo> <RdHi> <Rn> <Rm>
*/

/* IS: imm / shift */
#define ASM_RI(instr, R1, IS)                                           \
    asm volatile (#instr "s %[reg1], %[imm]\n"             /* updates flags */ \
                  "mrs %[cpsr], cpsr\n"                    /* save new cpsr */ \
                  : [reg1] "=r" (WREG(R1)), [cpsr] "=r" (CPU(cpsr)) /* output */ \
                  : [imm] "r"   (d->IS)         /* input */             \
                  : "cc"                        /* clobbers condition codes */ \
                  );

#define ASM_RR(instr, R1, R2)                                           \
    asm volatile (#instr "s %[reg1], %[reg2]\n"            /* updates flags */ \
                  "mrs %[cpsr], cpsr\n"                    /* save new cpsr */ \
                  : [reg1] "=r" (WREG(R1)), [cpsr] "=r" (CPU(cpsr)) /* output */ \
                  : [reg2] "r"  (RREG(R2))      /* input */             \
                  : "cc"                        /* clobbers condition codes */ \
                  );

#define ASM_RImm(instr, R1, R2)                                         \
    asm volatile (#instr "s %[reg1], %[reg2]\n"            /* updates flags */ \
                  "mrs %[cpsr], cpsr\n"                    /* save new cpsr */ \
                  : [reg1] "=r" (WREG(R1)), [cpsr] "=r" (CPU(cpsr) /* output */ \
                  : [reg2] "r"  (R2)            /* input */             \
                  : "cc"                        /* clobbers condition codes */ \
                  );

#define ASM_RRR(instr, R1, R2, R3)                                      \
    asm volatile (#instr "s  %[reg1], %[reg2], %[reg3]\n"  /* updates flags */ \
                  "mrs %[cpsr], cpsr\n"                    /* save new cpsr */ \
                  : [reg1] "=r" (WREG(R1)), [cpsr] "=r" (CPU(cpsr)) /* output */ \
                  : [reg2] "r"  (RREG(R2)), [reg3] "r" (RREG(R3))  /* input */ \
                  : "cc"                        /* clobbers condition codes */ \
                  );

#define ASM_RRS(instr, R1, R2, IS)                                      \
    asm volatile ("msr cpsr, %[cpsr]\n"                                 \
                  #instr "s %[reg1], %[reg2], %[imm]\n"    /* updates flags */ \
                  "mrs %[cpsr], cpsr\n"                    /* save new cpsr */ \
                  : [reg1] "=r" (WREG(R1)), [cpsr] "+r" (CPU(cpsr)) /* output */ \
                  : [reg2] "r"  (RREG(R2)), [imm]  "r"  (IS)       /* input */ \
                  : "cc"                        /* clobbers condition codes */ \
                  );

#define ASM_RRI(instr, R1, R2, IS)                                      \
    asm volatile ("msr cpsr, %[cpsr]\n"                                 \
                  #instr "s %[reg1], %[reg2], %[imm]\n"    /* updates flags */ \
                  "mrs %[cpsr], cpsr\n"                    /* save new cpsr */ \
                  : [reg1] "=r" (WREG(R1)), [cpsr] "+r" (CPU(cpsr)) /* output */ \
                  : [reg2] "r"  (RREG(R2)), [imm]  "r"  (d->IS)    /* input */ \
                  : "cc"                        /* clobbers condition codes */ \
                  );

#define ASM_RI_CMP(instr, R1, IS)                                       \
    asm volatile (#instr " %[reg1], %[imm]\n"              /* updates flags */ \
                  "mrs %[cpsr], cpsr\n"                    /* save new cpsr */ \
                  : [cpsr] "=r" (CPU(cpsr))                /* output */ \
                  : [reg1] "r"  (RREG(R1)), [imm] "r"  (d->IS)     /* input */ \
                  : "cc"                        /* clobbers condition codes */ \
                  );                                                    \

#define ASM_RS_CMP(instr, R1, S)                                        \
    asm volatile (#instr " %[reg1], %[imm]\n"              /* updates flags */ \
                  "mrs %[cpsr], cpsr\n"                    /* save new cpsr */ \
                  : [cpsr] "=r" (CPU(cpsr))                /* output */ \
                  : [reg1] "r"  (RREG(R1)), [imm] "r"  (S) /* input */  \
                  : "cc"                        /* clobbers condition codes */ \
                  );

/* switch case helper for ASM */
#define CASE_RR( instr, R1, R2)      case I_##instr: { ASM_RR (instr, R1, R2);      break; }
#define CASE_RRI(instr, R1, R2, imm) case I_##instr: { ASM_RRI(instr, R1, R2, imm); break; }
#define CASE_RRR(instr, R1, R2, R3)  case I_##instr: { ASM_RRR(instr, R1, R2, R3);  break; }
#define CASE_RRS(instr, R1, R2, S)   case I_##instr: { ASM_RRS(instr, R1, R2, S);   break; }
#define CASE_RI_CMP(instr, R1, S)    case I_##instr: { ASM_RI_CMP(instr, R1, S);    break; }
#define CASE_RS_CMP(instr, R1, S)    case I_##instr: { ASM_RS_CMP(instr, R1, S);    break; }

#define BitCount(x)           __builtin_popcount(x)
#define TrailingZerosCount(x) __builtin_ctz(x)
#define LeadingZerosCount(x)  __builtin_clz(x)
#define BitCheck(x, pos)      ((x) & (1 << (pos)))
// lsb, msb
#define BitExtract(x, i, j)   ((((1 << (j+1)) - (1 << i) ) & x) >> i )
#define SignExtend(x) ((int32_t)((int16_t)x))

// NOTE: 4-byte aligned 0x1006 will produce 0x1004 and not 0x1008
// this is be design: we want the word that contains input value
// resulting in 4 bytes [0x1004:0x1007]
#define Align(x,a)            __ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)  ((x)&~(mask))

#define LSL(val, shift) (val << shift)
#define LSR(val, shift) (val >> shift)
#define ASR(val, shift) LSR((int32_t)val, shift)
#define ROR(val, rotate) (((val) >> (rotate)) | ((val) << (32 - (rotate))))

#define ISB(option) asm volatile ("isb " #option : : : "memory")
#define DSB(option) asm volatile ("dsb " #option : : : "memory")
#define DMB(option) asm volatile ("dmb " #option : : : "memory")
// SVC (syscall)
// arguments: r0-r6
// syscall #: r7
// return:  : r0
// NOTE: CPSR offset is the same as (PC+1) in emu regs
#define SVC()       asm volatile("ldr ip, %[emu]\n"     /* base regs */ \
                                 "ldm ip, {r0-r7}\n"                    \
                                 "svc 0\n"                              \
                                 "movs %[ret], r0\n"                    \
                                 "mrs %[cpsr], cpsr\n"                  \
                                 : [ret] "=r" (WREGN(0)), [cpsr] "=r" (emu->regs[PC+1])   /* output */ \
                                 : [emu] "m"  (emu->regs) /* input */      \
                                 : "cc", "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "ip" /* clobbers */ \
                                 );

#define PLD(regname) asm volatile("pld [%[reg]]" :: [reg] "r" (d->regname));

typedef enum _cpumode_t {
    M_ARM, M_THUMB
} cpumode_t;

/*
 * Signal context structure - contains all info to do with the state
 * before the signal handler was invoked.  Note: only add new entries
 * to the end of the structure.
 */
/* 
struct sigcontext {
    unsigned long trap_no;
    unsigned long error_code;
    unsigned long oldmask;
    unsigned long arm_r0;
    unsigned long arm_r1;
    unsigned long arm_r2;
    unsigned long arm_r3;
    unsigned long arm_r4;
    unsigned long arm_r5;
    unsigned long arm_r6;
    unsigned long arm_r7;
    unsigned long arm_r8;
    unsigned long arm_r9;
    unsigned long arm_r10;
    unsigned long arm_fp;
    unsigned long arm_ip;
    unsigned long arm_sp;
    unsigned long arm_lr;
    unsigned long arm_pc;
    unsigned long arm_cpsr;
    unsigned long fault_address;
};
*/

// #include <linux/user.h>         /* user_vfp, user_vfp_exc */
#include "vfp.h"                /* copy of $KERNEL/arch/arm/include/asm/vfp.h */

#ifdef WITH_VFP_D32
#define NUM_VFP_REGS 32         /* VFPv3 ARMv7-A Cortex-A9 */
#else
#define NUM_VFP_REGS 16
#endif

// value from $KERNEL/arch/arm/include/asm/ucontext.h
#define VFP_MAGIC	0x56465001

/*
 * 8 byte for magic and size, 264 byte for ufp, 12 bytes for ufp_exc,
 * 4 bytes padding.
 */
#define VFP_STORAGE_SIZE sizeof(struct vfp_sigframe)

/*
 * User specific VFP registers. If only VFPv2 is present, registers 16 to 31
 * are ignored by the ptrace system call and the signal handler.
 */
struct user_vfp {
	unsigned long long fpregs[32];
	unsigned long fpscr;
};

/*
 * VFP exception registers exposed to user space during signal delivery.
 * Fields not relavant to the current VFP architecture are ignored.
 */
struct user_vfp_exc {
	unsigned long	fpexc;
	unsigned long	fpinst;
	unsigned long	fpinst2;
};

struct vfp_sigframe
{
	unsigned long		magic;
	unsigned long		size;
	struct user_vfp		ufp;
	struct user_vfp_exc	ufp_exc;
} __attribute__((__aligned__(8)));

/*
 * Auxiliary signal frame.  This saves stuff like FP state.
 * The layout of this structure is not part of the user ABI,
 * because the config options aren't.  uc_regspace is really
 * one of these.
 */
struct aux_sigframe {
	struct vfp_sigframe	vfp;
	/* Something that isn't a valid magic number for any coprocessor.  */
	unsigned long		end_magic;
} __attribute__((__aligned__(8)));

// WARNING: this must match pthread state from pthread_internal.h
typedef struct pthread_internal_t
{
    struct pthread_internal_t*  next;
    struct pthread_internal_t** pref;
    pthread_attr_t              attr;
    pid_t                       kernel_id;
    pthread_cond_t              join_cond;
    int                         join_count;
    void*                       return_value;
    int                         intern;
    void*                       altstack;
    size_t                      altstack_size;       /* includes guard size */
    size_t                      altstack_guard_size;
    int                         target;              /* emulation target */
    __pthread_cleanup_t*        cleanup_stack;
    void**                      tls;         /* thread-local storage area */
} pthread_internal_t;

/* stolen from bionic/libc/private/bionic_tls.h */
#define __get_tls() \
    ({ register unsigned int __val asm("r0");              \
       asm ("mrc p15, 0, r0, c13, c0, 3" : "=r"(__val) );  \
       (volatile void*)__val; })

int setcontext(const ucontext_t *ucp);

/* use the next free slot in bionic_tls to stash emu state*/
#define TLS_SLOT_EMU_THREAD 5

/* API */

void
emu_init_handler(int sig,
                 void (*handler)(int, siginfo_t *, void *),
                 void *stack,
                 size_t stack_size);

void emu_handler_trap(int sig, siginfo_t *si, void *uc);
void emu_handler_segv(int sig, siginfo_t *si, void *uc);

static void emu_init();
void emu_ucontext(emu_thread_t *emu, ucontext_t *ucontext);
void emu_start(emu_thread_t *emu);
void emu_stop(emu_thread_t *emu);
uint8_t emu_stop_trigger(emu_thread_t *emu);
bool emu_singlestep(emu_thread_t *emu);

extern const char* emu_disasm_ref(uint32_t pc, uint8_t bits);
uint8_t emu_disasm(emu_thread_t *emu, darm_t *d, uint32_t pc);

void emu_type_arith_shift(emu_thread_t *emu);
void emu_type_arith_imm(emu_thread_t *emu);
void emu_type_branch_syscall(emu_thread_t *emu);
void emu_type_branch_misc(emu_thread_t *emu);
void emu_type_move_imm(emu_thread_t *emu);
void emu_type_cmp_imm(emu_thread_t *emu);
void emu_type_cmp_op(emu_thread_t *emu);
void emu_type_opless(emu_thread_t *emu);
void emu_type_dst_src(emu_thread_t *emu);

void darm_enc(emu_thread_t *emu);

uint32_t emu_dataop(emu_thread_t *emu, const uint32_t a, const uint32_t b);
uint32_t emu_regshift(emu_thread_t *emu, uint32_t val);

/* Debugging / Internal only */

void dbg_dump_ucontext(ucontext_t *uc);
void dbg_dump_ucontext_vfp(ucontext_t *uc);
void emu_dump(emu_thread_t *emu);
void emu_dump_diff(emu_thread_t *emu);
void emu_dump_cpsr(emu_thread_t *emu);
void dump_backtrace(pid_t tid);
#endif
uint32_t emu_read_reg(emu_thread_t *emu, darm_reg_t reg);
uint32_t *emu_write_reg(emu_thread_t *emu, darm_reg_t reg);
uint8_t emu_thumb_mode(emu_thread_t *emu);

/* Memory */
uint8_t mem_read8(uint32_t addr);
uint16_t mem_read16(uint32_t addr);
uint32_t mem_read32(uint32_t addr);

uint8_t mem_write8(uint32_t addr, uint8_t val);
uint16_t mem_write16(uint32_t addr, uint16_t val);
uint32_t mem_write32(uint32_t addr, uint32_t val);

void *emu_alloc(size_t size);
int emu_free(void *addr, size_t size);
static void *mkstack(size_t size, size_t guard_size);

void emu_map_dump(map_t *m);
void emu_parse_maps(emu_global_t *emu_global);
void emu_parse_cmdline(char *cmdline, size_t size);
char* emu_parse_threadname();
const char *get_signame(int sig);
const char *get_sigcode(int signo, int code);
const char *get_ssname(int code);

#ifndef PROFILE
map_t* emu_map_lookup(uint32_t addr);
#else
#define emu_map_lookup(...) (void)(NULL)
#endif

bool emu_advance_pc(emu_thread_t *emu);
#ifndef NO_TAINT
static void emu_set_taint_reg(emu_thread_t *emu, darm_reg_t reg, uint32_t tag);
static uint32_t emu_get_taint_reg(emu_thread_t *emu, darm_reg_t reg);
static void emu_clear_taintregs(emu_thread_t *emu);
static uint8_t emu_regs_tainted(emu_thread_t *emu);
static void emu_init_taintmaps(emu_global_t *emu_global);
static taintmap_t *emu_get_taintmap(uint32_t addr);
uint32_t emu_dump_taintmaps();
uint32_t emu_dump_taintpages();
static uint32_t emu_get_taint_mem(uint32_t addr);
static void emu_set_taint_mem(uint32_t addr, uint32_t tag);
// next two defined in anemu.h already
void emu_set_taint_array(uint32_t addr, uint32_t tag, uint32_t length);
uint32_t emu_get_taint_array(uint32_t addr, uint32_t length);
static taintpage_t* emu_get_taintpage(uint32_t addr);
static void emu_update_taintpage(uint32_t page, int8_t increment);
static ssize_t emu_memcpy(void *dest, const void *src, size_t n);
static void emu_memcpy_safe(void *dest, const void *src, size_t n);
void emu_init_proc_mem();
bool emu_intercept(emu_thread_t *emu, uint32_t addr);
#else  /* NO_TAINT */
#define emu_set_taint_reg(...)    (void)(NULL)
#define emu_get_taint_reg(...)    (void)(NULL)
#define emu_clear_taintregs(...)  (void)(NULL)
#define emu_regs_tainted(...)     (void)(NULL)
#define emu_init_taintmaps(...)   (void)(NULL)
// #define emu_get_taintmap(...)     (void)(NULL)
#define emu_dump_taintmaps(...)   (void)(NULL)
#define emu_dump_taintpages(...)  (void)(NULL)
#define emu_get_taint_mem(...)    (void)(NULL)
#define emu_set_taint_mem(...)    (void)(NULL)
#define emu_get_taintpage(...)    (void)(NULL)
#define emu_update_taintpage(...) (void)(NULL)
#define emu_init_proc_mem(...)    (void)(NULL)
#define emu_intercept(...)        (void)(NULL)
#endif  /* NO_TAINT */

void emu_init_properties();
void emu_init_tracefile();
uint32_t emu_get_taint_file(int fd);
int32_t emu_set_taint_file(int fd, uint32_t tag);
emu_thread_t* emu_tls_get();
void emu_tls_set(emu_thread_t *emu);
bool emu_protect();
bool emu_set_running(bool state);
bool emu_debug();
bool emu_bypass();
bool emu_selective();
bool stack_addr();
uint32_t instr_mask(darm_instr_t instr);

// pthread wrappers with error checking
int mutex_lock(pthread_mutex_t *mutex);
int mutex_unlock(pthread_mutex_t *mutex);

/* Page Protections */

uint32_t getAlignedPage(uint32_t addr);
void emu_handler_segv(int sig, siginfo_t *si, void *ucontext);

#ifndef NO_MPROTECT
static int8_t mprotectPage(uint32_t addr, uint32_t flags);
#else
#define mprotectPage(...) (void)(NULL)
#endif

int emu_mark_page(uint32_t addr);
int emu_unmark_page(uint32_t addr);
void emu_clear_taintpages();

/* ARM manual util functions */
void SelectInstrSet(emu_thread_t *emu, cpumode_t mode);
cpumode_t CurrentInstrSet(emu_thread_t *emu);
cpumode_t TargetInstrSet(emu_thread_t *emu, uint32_t instr);
void BranchWritePC(emu_thread_t *emu, uint32_t addr);
void BXWritePC(emu_thread_t *emu, uint32_t addr);

/* Logging */
static int __log_print(int prio, const char *tag, const char *fmt, ...);

#endif  /* _INCLUDE_ANEMU_PRIVATE_H_ */
