#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
// #include <assert.h>
#include <signal.h>
#include <sys/mman.h>           /* mprotect */
#include <errno.h>
#include <asm/ptrace.h>         /* PSR bit macros */
#include <pthread.h>
#include <time.h>
#include <string.h>             /* memset */
#include <sys/prctl.h>          /* thread name */
#include <sys/uio.h>            /* writev */
#include <fcntl.h>              /* open, close */
#include <dlfcn.h>              /* dladdr */
#include <corkscrew/demangle.h> /* demangle C++ */
#include <corkscrew/backtrace.h>
#include <cutils/atomic.h>
#include <cutils/properties.h>  /* adb setprop, getprop */
#include <sys/xattr.h>          /* fsetxattr, fgetxattr */

#if HAVE_SETRLIMIT
# include <sys/types.h>
# include <sys/time.h>
# include <sys/resource.h>
#endif

#include "anemu-private.h"

#define TAINT_CLEAR 0x0

extern void dlemu_set_tid(pid_t tid);

inline uint8_t emu_regs_tainted(emu_thread_t *emu) {
    int i, tainted;
    tainted = N_REGS;
    for (i = 0; i < N_REGS; i++) {
        if (RTREGN(i) != TAINT_CLEAR) {
            if (i == IP ||
                i == SP ||
                i == LR ||
                i == PC) {
                emu_abort("taint: WARNING special r%d tainted!\n", i);
            }
            emu_log_debug("taint: r%d val: %x tag: %x\n", i, RREGN(i), RTREGN(i));
        } else {
            tainted--;
        }
    }
    return tainted;
}

// debug info to be called from signal handlers
void emu_siginfo(int sig, siginfo_t *si, ucontext_t *uc) {
    emu_log_debug(LOG_BANNER_SIG);

    uint32_t pc = uc->uc_mcontext.arm_pc;
    uint32_t addr_fault = uc->uc_mcontext.fault_address;

    char cmdline[128];
    emu_parse_cmdline(cmdline, sizeof(cmdline));

    emu_log_debug("signal %s (%d) %s (%d) pc: %8x addr: %8x pid: %5d (%s) tid: %5d (%s)\n",
                  get_signame(sig),
                  sig,
                  get_sigcode(sig, si->si_code),
                  si->si_code,
                  pc,
                  addr_fault,
                  getpid(),
                  cmdline,
                  gettid(),
                  emu_parse_threadname());

    // WARNING: a succesful call to execve() will remove any existing alternate signal stack!
    // check to make sure we are running on the alternate stack
    stack_t oss;
    if (sigaltstack(NULL, &oss) == -1) {
        emu_abort("sigaltstack");
    }
    emu_log_debug("sigaltstack sp: %p size: %d flags: %s (%d)\n", oss.ss_sp, oss.ss_size, get_ssname(oss.ss_flags), oss.ss_flags);

    emu_log_debug("emu threads: %d\n", emu_global->thread_count);

    // we only expect two signals in emulation
    assert(sig == SIGTRAP || sig == SIGSEGV);

    dbg_dump_ucontext(uc);
#ifdef WITH_VFP
    dbg_dump_ucontext_vfp(uc);
#endif

    emu_map_lookup(pc);
    emu_map_lookup(addr_fault);

    // paranoid sanity checks follow
    pthread_internal_t *thread = (pthread_internal_t *)pthread_self();
    size_t useable_size = thread->altstack_size - thread->altstack_guard_size;
    uint32_t altstack_base = (uint32_t)thread->altstack + thread->altstack_guard_size;
    assert(oss.ss_sp == (void *)altstack_base && oss.ss_flags == SS_ONSTACK && oss.ss_size == useable_size);
    // make sure segv is not on thread->altstack guard page itself!
    if (addr_fault < altstack_base && addr_fault > (uint32_t)thread->altstack) {
        emu_abort("[-] fault on thread->altstack guard page!\n");
    }

    // assert ((uint32_t)si->si_addr == addr_fault);
    if ((uint32_t)si->si_addr != addr_fault) {
        emu_log_error("si_addr: %x addr: %x", (uint32_t)si->si_addr, addr_fault);
        emu_map_lookup((uint32_t)si->si_addr);
        gdb_wait();
    }
}

/* SIGTRAP handler used for single-stepping */
void emu_handler_trap(int sig, siginfo_t *si, void *ucontext) {
    emu_thread_t emu;
    ucontext_t *uc = (ucontext_t *)ucontext;
    emu_siginfo(sig, si, uc);

    assert(emu_initialized());

    emu_ucontext(&emu, uc);
    emu_start(&emu);
    emu_stop(&emu);
}

inline void emu_ucontext(emu_thread_t *emu, ucontext_t *uc) {
    // emu_log_debug("saving original uc ...\n");
    emu->previous = emu->current = emu->original = *uc;
    emu->regs = (uint32_t *)&emu->current.uc_mcontext.arm_r0;
    emu->branched = 0;
}

inline uint8_t emu_eval_cond(emu_thread_t *emu) {
    emu_dump_cpsr(emu);
    uint32_t cond = emu->darm.cond;

    switch(cond) {
    case C_EQ: return  CPSR_Z;
    case C_NE: return !CPSR_Z;
    case C_CS: return  CPSR_C;
    case C_CC: return !CPSR_C;
    case C_MI: return  CPSR_N;
    case C_PL: return !CPSR_N;
    case C_VS: return  CPSR_V;
    case C_VC: return !CPSR_V;
    case C_HI: return  CPSR_C && !CPSR_Z;
    case C_LS: return !CPSR_C ||  CPSR_Z;
    case C_GE: return  CPSR_N ==  CPSR_V;
    case C_LT: return  CPSR_N !=  CPSR_V;
    case C_GT: return !CPSR_Z && (CPSR_N == CPSR_V);
    case C_LE: return  CPSR_Z || (CPSR_N != CPSR_V);
    case C_AL: return 1;
    case C_UNCOND: return 1;
    default: {
        emu_abort("unknown condition %x\n", cond);
        return 0;
    }
    }
}

// info:
// Arithmetic instructions which take a shift for the second source
//
// encodings:
// ins{S}<c> <Rd>,<Rn>,<Rm>{,<shift>}
// ins{S}<c> <Rd>,<Rn>,<Rm>,<type> <Rs>
//
// affects:
// ADC, ADD, AND, BIC, EOR, ORR, RSB, RSC, SBC, SUB
inline void emu_type_arith_shift(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;
    assert(d->Rd != R_INVLD && d->Rn != R_INVLD && d->Rm != R_INVLD);
    emu_log_debug("Rs: %d shift_type: %d shift: %d\n", d->Rs, d->shift_type, d->shift);
    assert((d->Rs != R_INVLD) || (d->shift_type != S_INVLD) || (d->shift == 0));

    // ins{S}<c> <Rd>,<Rn>,<Rm>,<type> <Rs>
    // ins{S}<c> <Rd>,<Rn>,<Rm>{,<shift>}
    uint32_t imsh = RSHIFT(RREG(Rm));
    emu_log_debug("RSHIFT imm: %x\n", imsh);
    if (d->S == B_SET) {
        switch(d->instr) {
            CASE_RRS(ADC, Rd, Rn, imsh);
            CASE_RRS(ADD, Rd, Rn, imsh);
            CASE_RRS(AND, Rd, Rn, imsh);
            CASE_RRS(BIC, Rd, Rn, imsh);
            CASE_RRS(EOR, Rd, Rn, imsh);
            CASE_RRS(ORR, Rd, Rn, imsh);
            CASE_RRS(RSB, Rd, Rn, imsh);
            CASE_RRS(RSC, Rd, Rn, imsh);
            CASE_RRS(SBC, Rd, Rn, imsh);
            CASE_RRS(SUB, Rd, Rn, imsh);

            SWITCH_COMMON;
        }
    } else {
        /* BIC has no Rs or shift */
        /* FIXME: can we drop this special case? */
        if (d->instr == I_BIC && d->shift == 0) {
            /* shift type 0 is LSL */
            EMU(WREG(Rd) = LSL(RREG(Rn), RREG(Rm)));
        } else {
            EMU(WREG(Rd) = OP(RREG(Rn), imsh));
        }
    }
    WTREG2(Rd, Rn, Rm);
}

// info:
// Arithmetic instructions which take an immediate as second source
//
// encodings:
// ins{S}<c> <Rd>,<Rn>,#<const>
//
// affects:
// ADC, ADD, AND, BIC, EOR, ORR, RSB, RSC, SBC, SUB
inline void emu_type_arith_imm(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;

    if (d->S == B_SET) {
        switch(d->instr) {
            CASE_RRI(ADC, Rd, Rn, imm);
            CASE_RRI(ADD, Rd, Rn, imm);
            CASE_RRI(AND, Rd, Rn, imm);
            CASE_RRI(BIC, Rd, Rn, imm);
            CASE_RRI(EOR, Rd, Rn, imm);
            CASE_RRI(ORR, Rd, Rn, imm);
            CASE_RRI(RSB, Rd, Rn, imm);
            CASE_RRI(RSC, Rd, Rn, imm);
            CASE_RRI(SBC, Rd, Rn, imm);
            CASE_RRI(SUB, Rd, Rn, imm);

            SWITCH_COMMON;
        }
        WTREG1(Rd, Rn);
    } else {
        switch(d->instr) {
        case I_ADC:
        case I_ADD:
        case I_AND:
        case I_BIC:
        case I_EOR:
        case I_ORR:
        case I_RSB:
        case I_RSC:
        case I_SBC:
        case I_SUB: {
            EMU(WREG(Rd) = OP(RREG(Rn), d->imm));
            WTREG1(Rd, Rn);
            break;
        }
        case I_ADR: {
            uint32_t addr = d->U == B_SET ?
                (RREGN(PC) + d->imm) :
                (RREGN(PC) - d->imm);
            if (d->Rd == PC) {
                BXWritePC(emu, addr);
            } else {
                EMU(WREG(Rd) = addr);
                WTREG(Rd, RTMEM(addr));
            }
            break;
        }
            SWITCH_COMMON;
        }
    }
}

inline void emu_type_pusr(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;
    assert(d->S != B_SET);

    switch(d->instr) {
    case I_UXTB: {
        uint32_t rotated = ROR(RREG(Rm), d->rotate);
        WREG(Rd) = rotated & instr_mask(d->instr);
        WTREG1(Rd, Rm);
        break;
    }
    case I_UXTAB: {
        uint32_t rotated = ROR(RREG(Rm), d->rotate);
        WREG(Rd) = RREG(Rn) + (rotated & instr_mask(d->instr));
        WTREG2(Rd, Rn, Rm);
        break;
    }
    case I_UXTH: {
        uint32_t rotated = ROR(RREG(Rm), d->rotate);
        WREG(Rd) = rotated & instr_mask(d->instr);
        WTREG1(Rd, Rm);
        break;
    }
    case I_SXTB: {
        uint32_t rotated = ROR(RREG(Rm), d->rotate);
        WREG(Rd) = SignExtend(rotated & instr_mask(d->instr));
        WTREG1(Rd, Rm);
        break;
    }
    case I_SXTH: {
        uint32_t rotated = ROR(RREG(Rm), d->rotate);
        WREG(Rd) = SignExtend(rotated & instr_mask(d->instr));
        WTREG1(Rd, Rm);
        break;
    }
        SWITCH_COMMON;
    }
}

inline void emu_type_sync(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;

    switch(d->instr) {
    case I_LDREX: {
        emu_log_debug("LDREX before:\n");
        emu_log_debug("Rt: %x Rn: %x MEM Rn: %x\n", RREG(Rt), RREG(Rn), RMEM32(RREG(Rn)));

        emu_log_debug("Checking for special lock aquire case...\n");
        darm_t d2, d3, d4;
        emu_disasm(emu, &d2, CPU(pc) +  4);
        emu_disasm(emu, &d3, CPU(pc) +  8);
        emu_disasm(emu, &d4, CPU(pc) + 12);

        /* pthread_mutex_lock */
        /* __bionic_cmpxchg() */
        if (d2.instr == I_MOV &&
            d3.instr == I_TEQ &&
            d4.instr == I_STREX) {
            emu_log_info("Detecting lock aquire (LDREX/STREX) __bionic_cmpxchg! Executing atomically.\n");

            uint32_t mem_Rn = 0;

            asm volatile ("ldrex %[Rt], [%[Rn]]\n"
                          "mov %[Rd2], #0\n"
                          "teq %[Rt], %[Rm3]\n"
                          "strexeq %[Rd2], %[Rt4], [%[Rn]]"
                          : [Rt] "=&r" (WREGN(d->Rt)), [Rd2] "=&r" (WREGN(d2.Rd)), "+m" (mem_Rn)
                          : [Rn] "r" (RREGN(d->Rn)), [Rm3] "Ir" (RREGN(d3.Rm)), [Rt4] "r" (RREGN(d4.Rt))
                          : "cc"
                          );

            WMEM32(RREG(Rn), mem_Rn);

            emu_log_debug("LDREX after:\n");
            emu_log_debug("Rt: %x Rn: %x MEM Rn: %x\n", RREG(Rt), RREG(Rn), RMEM32(RREG(Rn)));

            WTREG(Rt, RTMEM(RREG(Rn)));
            WTREGN(d2.Rd, TAINT_CLEAR);
            WTREGN(d4.Rt, TAINT_CLEAR); /* status */

            /* updating PC via WREGN is treated as a branch */
            /* which means PC is not advanced a further +2/4 */
            /* thus we have to use CPU(pc) instead of WREGN(pc) */
            CPU(pc) += 3 * 4;
            /* account for extras: mov + teq + strexeq */
            emu->instr_count += 3;

            if (RREGN(d2.Rd) == 0) {    /* 0 if memory was updated  */
                emu_log_debug("Lock aquire (LDREX/STREX) succesfull!\n");
                /* special case to avoid deadlock on malloc! */
                emu->lock_acquired = 1;
                // WTMEM(RREG(Rn), RTREGN(d4.Rt));
            } else {
                emu_abort("STREX failed to update memory\n");
            }
        }
        /* android_atomic_add() */
        else if (d2.instr == I_ADD &&
                 d3.instr == I_STREX) {
            emu_log_info("Detecting lock aquire (LDREX/STREX) android_atomic_add! Executing atomically.\n");

            asm volatile ("ldrex %[Rt], [%[Rn]]\n"
                          "add %[Rd2], %[Rt], #1\n"
                          "strex %[Rd3], %[Rd2], [%[Rn]]"
                          : [Rt] "+r" (WREGN(d->Rt)), [Rd2] "+r" (WREGN(d2.Rd)), [Rd3] "=&r" (WREGN(d3.Rd))
                          : [Rn] "r" (RREGN(d->Rn))
                          : "cc"
                          );

            emu_log_debug("LDREX after:\n");
            emu_log_debug("Rt: %x Rn: %x MEM Rn: %x\n", RREG(Rt), RREG(Rn), RMEM32(RREG(Rn)));

            WTREG(Rt, RTMEM(RREG(Rn)));
            WTREGN(d2.Rd, RTREG(Rt));
            WTMEM(RREG(Rn), RTREGN(d3.Rd));
            WTREGN(d3.Rd, TAINT_CLEAR);

            CPU(pc) += 2 * 4;
            /* account for extras: add + strex */
            emu->instr_count += 2;

            if (RREGN(d3.Rd) == 0) {    /* 0 if memory was updated  */
                emu_log_debug("Lock aquire (LDREX/STREX) succesfull!\n");
                emu->lock_acquired = 0;
                /* FIXME: deadlock on malloc! */
                // WTMEM(RREG(Rn), RTREGN(d4.Rt));
            } else {
                emu_abort("STREX failed to update memory\n");
            }

        }
        /* pthread_mutex_unlock */
        /* __bionic_atomic_dec() */
        else if (d2.instr == I_SUB &&
                 d3.instr == I_STREX) {
            emu_log_info("Detecting lock aquire (LDREX/STREX) __bionic_atomic_dec! Executing atomically.\n");

            asm volatile ("ldrex %[Rt], [%[Rn]]\n"
                          "sub %[Rd2], %[Rt], #1\n"
                          "strex %[Rd3], %[Rd2], [%[Rn]]"
                          : [Rt] "+r" (WREGN(d->Rt)), [Rd2] "+r" (WREGN(d2.Rd)), [Rd3] "=&r" (WREGN(d3.Rd))
                          : [Rn] "r" (RREGN(d->Rn))
                          : "cc"
                          );

            emu_log_debug("LDREX after:\n");
            emu_log_debug("Rt: %x Rn: %x MEM Rn: %x\n", RREG(Rt), RREG(Rn), RMEM32(RREG(Rn)));

            WTREG(Rt, RTMEM(RREG(Rn)));
            WTREGN(d2.Rd, RTREG(Rt));
            WTMEM(RREG(Rn), RTREGN(d3.Rd));
            WTREGN(d3.Rd, TAINT_CLEAR);

            CPU(pc) += 2 * 4;
            /* account for extras: sub + strex */
            emu->instr_count += 2;

            if (RREGN(d3.Rd) == 0) {    /* 0 if memory was updated  */
                emu_log_debug("Lock aquire (LDREX/STREX) succesfull!\n");
                emu->lock_acquired = 0;
                /* FIXME: deadlock on malloc! */
                // WTMEM(RREG(Rn), RTREGN(d4.Rt));
            } else {
                emu_abort("STREX failed to update memory\n");
            }
        }
        /* pthread_mutex_unlock */
        /* int32_t __bionic_swap(int32_t new_value, volatile int32_t* ptr) */
        /* TODO: how about calling the functions directly? */
        else if (d2.instr == I_STREX) {
            emu_log_info("Detecting lock aquire (LDREX/STREX) __bionic_swap! Executing atomically.\n");

            asm volatile ("ldrex %[Rt], [%[Rn]]\n"
                          "strex %[Rd2], %[Rt2], [%[Rn]]"
                          : [Rt] "+r" (WREGN(d->Rt)) /* prev */, [Rd2] "=&r" (WREGN(d2.Rd)) /* status */
                          : [Rn] "r" (RREGN(d->Rn)) /* ptr */, [Rt2] "r" (WREGN(d2.Rt)) /* new_value */
                          : "cc"
                          );

            emu_log_debug("LDREX after:\n");
            emu_log_debug("Rt: %x Rn: %x MEM Rn: %x\n", RREG(Rt), RREG(Rn), RMEM32(RREG(Rn)));

            WTREG(Rt, RTMEM(RREG(Rn)));
            WTMEM(RREG(Rn), RTREGN(d2.Rt));
            WTREGN(d2.Rd, TAINT_CLEAR);

            CPU(pc) += 1 * 4;
            /* account for extras: strex */
            emu->instr_count += 1;

            if (RREGN(d2.Rd) == 0) {    /* 0 if memory was updated  */
                emu_log_debug("Lock aquire (LDREX/STREX) succesfull!\n");
                emu->lock_acquired = 0;
                /* FIXME: deadlock on malloc! */
                // WTMEM(RREG(Rn), RTREGN(d4.Rt));
            } else {
                emu_abort("STREX failed to update memory\n");
            }
        } else {
            emu_abort("Lonely LDREX...\n");
        }

        break;
    }
    case I_STREX: {
        emu_abort("unexpected STREX (should be part of a previous LDREX pattern)\n");
        break;
    }
        SWITCH_COMMON;
    }
}

inline void emu_type_mvcr(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;

    switch(d->instr) {
    case I_MRC: {
        // NOTE: this is the only mrc seen in any libs, hardcoded to avoid complicated template
        // ee1d0f70 mrc 15, 0, r0, cr13, cr0, {3}
        // if (d->w == 0xee1d0f70) {
        if (d->coproc == 15   &&
            d->opc1   == 0    &&
            d->Rt     == r0   &&
            d->CRn    == cr13 &&
            d->CRm    == cr0  &&
            d->opc2   == 3) {
            asm volatile("mrc 15, 0, %[reg], cr13, cr0, 3" : [reg] "=r" CPU(r0));
        } else {
            emu_abort("unhandled encoding\n");
        }
        break;
    }
        SWITCH_COMMON;
    }
}

inline void SelectInstrSet(emu_thread_t *emu, cpumode_t mode) {

    switch(mode) {
    case M_ARM: {
        if (CurrentInstrSet(emu) == M_THUMB) {
            emu_log_debug("Thumb -> ARM switch!\n");
        }
        CPU(cpsr) &= ~PSR_T_BIT;
        break;
    }
    case M_THUMB: {
        if (CurrentInstrSet(emu) == M_ARM) {
            emu_log_debug("ARM -> Thumb switch!\n");
        }
        CPU(cpsr) |=  PSR_T_BIT;
        break;
    }
    default:
        emu_abort("invalid instruction set %d\n", mode);
    }
}

inline cpumode_t CurrentInstrSet(emu_thread_t *emu) {
    return (emu_thumb_mode(emu) ? M_THUMB : M_ARM);
}

inline cpumode_t TargetInstrSet(emu_thread_t *emu, uint32_t instr) {
    if (instr == I_BX || instr == I_BLX) { /* swap mode */
        return (CurrentInstrSet(emu) == M_ARM ? M_THUMB : M_ARM);
    } else {                    /* keep current mode */
        return (CurrentInstrSet(emu));
    }
}

inline void BranchWritePC(emu_thread_t *emu, uint32_t addr) {
    /* EMU_ENTRY; */
    emu_log_debug("RREGN(PC): %x\n", RREGN(PC));
    emu_log_debug("addr: %x\n", addr);
#ifndef PROFILE
    emu_map_lookup(addr);
#endif
    /* TODO: emu.disasm_bytes == 4 instead to account for Thumb2 32? */
    if (CurrentInstrSet(emu) == M_ARM) {
        EMU(WREGN(PC) = addr & ~0b11);
    } else {
        EMU(WREGN(PC) = addr & ~0b1);
    }
}

inline void BXWritePC(emu_thread_t *emu, uint32_t addr) {
    emu_log_debug("RREGN(PC): %x addr: %x\n", RREGN(PC), addr);
#ifndef PROFILE
    emu_map_lookup(addr);
#endif
    if (addr & 1) {
        SelectInstrSet(emu, M_THUMB);
        EMU(WREGN(PC) = addr & ~1);
    } else if (addr & ~0b10) {
        SelectInstrSet(emu, M_ARM);
        EMU(WREGN(PC) = addr);
    } else {
        emu_abort("invalid branch addr: %x", addr);
    }
}

inline void emu_type_branch_syscall(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;

    switch(d->instr) {
    case I_B: {
        BranchWritePC(emu, RREGN(PC) + d->imm);
        break;
    }
    case I_BL:
    case I_BLX: {               /* immediate */
        if (CurrentInstrSet(emu) == M_ARM) {
            EMU(WREGN(LR) = RREGN(PC) - 4);
        } else {
            EMU(WREGN(LR) = RREGN(PC) | 1);
        }
        uint32_t targetAddress;
        cpumode_t targetInstrSet = TargetInstrSet(emu, d->instr);
        if (targetInstrSet == M_ARM) {
            targetAddress = Align(RREGN(PC), 4) + d->imm;
        } else {
            targetAddress = RREGN(PC) + d->imm;
        }
        SelectInstrSet(emu, targetInstrSet);
        BranchWritePC(emu, targetAddress);
        break;
    }
    case I_SVC: {
        /* "svc #0" is the only "svc" instruction in libc.so */
        assert(d->imm == 0);
        SVC();
        break;
    }
        SWITCH_COMMON;
    }
}

inline void emu_type_branch_misc(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;

    switch(d->instr) {
    case I_BX: {
        BXWritePC(emu, RREG(Rm));
        break;
    }
    case I_BLX: {
        if (CurrentInstrSet(emu) == M_ARM) {
            EMU(WREGN(LR) =   RREGN(PC) - 4);
        } else {
            EMU(WREGN(LR) = ((RREGN(PC) - 2) | 1));
        }
        BXWritePC(emu, RREG(Rm));
        break;
    }
        SWITCH_COMMON;
    }
}

inline void emu_type_move_imm(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;
    /* EMU_ENTRY; */

    switch(d->instr) {
    case I_MOV: {
        if (d->S == B_SET) {
            ASM_RI(MOV, Rd, imm);
        } else {
            EMU(WREG(Rd) = d->imm);
        }
        break;
    }
    case I_MOVT: {
        assert(d->S != B_SET);
        EMU(WREG(Rd) = (RREG(Rd) & instr_mask(d->instr)) | (d->imm << 16));
        break;
    }
    case I_MOVW: {
        assert(d->S != B_SET);
        EMU(WREG(Rd) = (RREG(Rd) & instr_mask(d->instr)) | (d->imm));
        break;
    }
    case I_MVN: {
        EMU(WREG(Rd) = ~d->imm);
        break;
    }
        SWITCH_COMMON;
    }
    WTREG(Rd, TAINT_CLEAR);
}

inline void emu_type_misc(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;

    switch(d->instr) {
    case I_MVN: {
        if (d->S == B_SET) {
            ASM_RR(MVN, Rd, Rm);
            break;
        } else {
            EMU(WREG(Rd) = ~RREG(Rm));
            break;
        }
    }
    case I_CLZ: {
        WREG(Rd) = LeadingZerosCount(RREG(Rm));
        break;
    }
        SWITCH_COMMON;
    }
    WTREG1(Rd, Rm);
}

inline void emu_type_cmp_op(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;

    uint32_t shifted = RSHIFT(RREG(Rm));
    switch(d->instr) {
    case I_CMP: {
        ASM_RS_CMP(CMP, Rn, shifted);
        break;
    }
    case I_TEQ: {
        ASM_RS_CMP(TEQ, Rn, shifted);
        break;
    }
    case I_TST: {
        ASM_RS_CMP(TST, Rn, shifted);
        break;
    }
        SWITCH_COMMON;
    }
}

inline void emu_type_cmp_imm(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;
    /* EMU_ENTRY; */

    switch(d->instr) {
    case I_CMP: {
        ASM_RI_CMP(CMP, Rn, imm);
        break;
    }
    case I_CMN: {
        ASM_RI_CMP(CMN, Rn, imm);
        break;
    }
    case I_TST: {
        ASM_RI_CMP(TST, Rn, imm);
        break;
    }
    case I_TEQ: {
        ASM_RI_CMP(TEQ, Rn, imm);
        break;
    }
        SWITCH_COMMON;
    }
}

inline void emu_type_opless(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;
    /* EMU_ENTRY; */

    switch(d->instr) {
    case I_NOP: {
        /* nothing to do */
        break;
    }
        SWITCH_COMMON;
    }
}

inline void emu_type_dst_src(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;
    /* EMU_ENTRY; */

    if (d->instr != I_MOV && d->Rm == R_INVLD) assert(d->shift != 0);
    assert(d->Rm != R_INVLD);

    // ins{S}<c> <Rd>,<Rm>
    // ins{S}<c> <Rd>,<Rm>,#<imm>
    if (d->Rn == R_INVLD && d->Rm != R_INVLD) {
        uint32_t imm = RSHIFT(RREG(Rm));
        // RdImm
        if (d->S == B_SET) {
            emu_log_debug("S flag, we're Screwed!\n");
            switch(d->instr) {
                CASE_RImm(ASR, Rd, imm);
                CASE_RImm(LSL, Rd, imm);
                CASE_RImm(LSR, Rd, imm);
                CASE_RImm(MOV, Rd, imm);
            case I_NOP: {
                /* nothing to do */
                break;
            }
                SWITCH_COMMON;
            }
        } else {
            switch(d->instr) {
            case I_ASR:
            case I_LSL:
            case I_LSR:
            case I_MOV: {
                WREG(Rd) = imm;
                break;
            }
            case I_NOP: {
                /* nothing to do */
                break;
            }
                SWITCH_COMMON;
            }
        }
        /* FIXME: what about NOP? */
        WTREG1(Rd, Rm);
    }
    // ins{S}<c> <Rd>,<Rn>,<Rm>
    else if (d->Rn != R_INVLD && d->Rm != R_INVLD) {
        //RdRnRm
        if (d->S == B_SET) {
            emu_log_debug("S flag, we're Screwed!\n");
            switch(d->instr) {
                CASE_RRR(ASR, Rd, Rn, d->Rm);
                CASE_RRR(LSL, Rd, Rn, d->Rm);
                CASE_RRR(LSR, Rd, Rn, d->Rm);
            case I_NOP: {
                /* nothing to do */
                break;
            }
                SWITCH_COMMON;
            }
        } else {
            switch(d->instr) {
            case I_ASR: WREG(Rd) = ASR(RREG(Rn), RREG(Rm)); break;
            case I_LSL: WREG(Rd) = LSL(RREG(Rn), RREG(Rm)); break;
            case I_LSR: WREG(Rd) = LSR(RREG(Rn), RREG(Rm)); break;
            case I_NOP: /* nothing to do */                 break;
                SWITCH_COMMON;
            }
        }
        /* FIXME: what about NOP? */
        WTREG2(Rd, Rn, Rm);
    } else {
        emu_abort("unexpected format");
    }
}

inline void emu_type_memory(emu_thread_t *emu) {
    /* EMU_ENTRY; */
    const darm_t *d = &emu->darm;

    switch(d->instr) {
    case I_LDR:
    case I_LDRB:
    case I_LDRSB:
    case I_LDRSH:
    case I_LDRH:
    case I_LDRD: {
        assert(d->Rn != R_INVLD);
        assert(d->Rt != R_INVLD);

        uint32_t imm = (d->Rm == R_INVLD) ? d->imm : RSHIFT(RREG(Rm)); /* RREG(Rm) or shift */
        uint32_t offset_addr = d->U == B_SET ?
            (RREG(Rn) + imm) :
            (RREG(Rn) - imm);

        uint32_t addr = d->P == B_SET ?
            offset_addr :
            RREG(Rn);

        if ((d->W == B_SET) || (d->P == B_UNSET)) { /* write-back */
            EMU(WREG(Rn) = offset_addr);
        }

        emu_log_debug("Rt: %x\n", RREG(Rt));
        emu_log_debug("Rn: %x\n", RREG(Rn));
#ifndef PROFILE
        map_t *m = emu_map_lookup(addr);
        if (m) emu_log_debug("addr: %x %s\n", addr, m->name);
#endif
        if (d->instr == I_LDR &&
            CurrentInstrSet(emu) == M_ARM &&
            addr != Align(addr, 4)) { /* unaligned addr */
            emu_log_warn("unaligned address");
        }

        emu_log_debug("RMEM(%x): %x\n", addr, RMEM32(addr));

        uint32_t data;
        /* read 1, 2 or 4 bytes depending on instr type */

        switch(d->instr) {
        case I_LDR:
            data = RMEM32(addr);
            break;
        case I_LDRB:
            data = RMEM8(addr);
            break;
        case I_LDRSB:
            data = RMEM8(addr);
            emu_log_debug("data: %x\n", data);
            data = SignExtend(data); /* 8 bit to 32 bit sign extend */
            emu_log_debug("data extended: %x\n", data);
            break;
        case I_LDRSH:
            data = RMEM16(addr);
            emu_log_debug("data: %x\n", data);
            data = SignExtend(data); /* 16 bit to 32 bit sign extend */
            emu_log_debug("data extended: %x\n", data);
            break;
        case I_LDRH:
            data = RMEM16(addr);
            break;
        case I_LDRD:
            data = RMEM32(addr);
            EMU(WREGN(d->Rt + 1) = RMEM32(addr + 4));
            WTREGN(d->Rt + 1, RTMEM(addr + 4));
            break;
        default: emu_abort("unexpected op");
        }

        if (d->Rt == PC) {
            if ((addr & 0b11) == 0) {
                BXWritePC(emu, data);
            } else {
                emu_abort("unpredictable");
            }
        } else {                /* UnalignedSupport() || address<1:0> == '00' */
            EMU(WREG(Rt) = data);
            WTREG(Rt, RTMEM(addr));
        }

        break;
    }
    case I_STR:
    case I_STRB:
    case I_STRH:
    case I_STRD: {
        uint32_t offset_addr = d->U == B_SET ?
            (RREG(Rn) + d->imm) :
            (RREG(Rn) - d->imm);

        uint32_t addr = d->P == B_SET ?
            offset_addr :
            RREG(Rn);

        if ((d->W == B_SET) || (d->P == B_UNSET)) { /* write-back */
            EMU(WREG(Rn) = offset_addr);
        }

#ifndef PROFILE
        map_t *m = emu_map_lookup(addr);
        if (m) emu_log_debug("addr: %x %s\n", addr, m->name);
#endif
        if (d->instr == I_STR &&
            CurrentInstrSet(emu) == M_ARM &&
            addr != Align(addr, 4)) { /* unaligned addr */
            emu_log_warn("unaligned address");
        }
        emu_log_debug("RMEM before:  %x\n", RMEM32(addr));
        /* depending on instr, 1, 2 or 4 bytes of RREG(Rt) will be used and stored to mem */
        uint32_t data = RREG(Rt) & instr_mask(d->instr);
        switch(d->instr) {
        case I_STR:
            WMEM32(addr, data);
            break;
        case I_STRB:
            WMEM8(addr, (uint8_t)data);
            break;
        case I_STRH:
            WMEM16(addr, (uint16_t)data);
            break;
        case I_STRD:
            WMEM32(addr,     RREGN(d->Rt));
            WMEM32(addr + 4, RREGN(d->Rt + 1));
            /* WTMEM(addr) case handled commonly below */
            WTMEM(addr + 4, RTREGN(d->Rt + 1));
            break;
        default: emu_abort("unexpected op");
        }

        emu_log_debug("RMEM after:   %x\n", RMEM32(addr));
        WTMEM(addr, RTREG(Rt));

        break;
    }
    case I_PUSH:
    case I_STM:
    case I_STMIB: {
        uint16_t reglist       = d->reglist;
        const uint8_t regcount = reglist ? BitCount(reglist) : 1; /* number of bits set to 1 */
        assert(d->Rn != R_INVLD);
        uint32_t addr          = RREG(Rn);
        if (d->instr == I_STMIB) addr += 4;
        if (d->instr == I_PUSH)  {
            assert(d->Rn == SP);
            addr -= 4 * regcount;
        }
        uint8_t reg            = 0;

        if (reglist) {
            while (reglist) {
                reg            = TrailingZerosCount(reglist); /* count trailing zeros */
                reglist       &= ~(1 << reg);                 /* unset this bit */
                emu_log_debug("addr: %x, r%d: %8x\n", addr, reg, RREGN(reg));
                WMEM32(addr, RREGN(reg));
                if (RTMEM(addr) || RTREGN(reg)) WTMEM(addr, RTREGN(reg));
                WTMEM(addr, RTREGN(reg));
                addr          += 4;
            }
        } else {
            WMEM32(addr, RREG(Rt));
        }
        if (d->instr == I_PUSH) {
            EMU(WREG(Rn) = RREG(Rn) - 4 * regcount);
        } else if (d->W == B_SET) { /* writeback */
            EMU(WREG(Rn) = RREG(Rn) + 4 * regcount);
        }
        break;
    }
    case I_POP:
    case I_LDM:
    case I_LDMIB: {
        uint16_t reglist       = d->reglist;
        const uint8_t regcount = reglist ? BitCount(reglist) : 1; /* number of bits set to 1 */
        uint32_t addr          = RREG(Rn);
        if (d->instr == I_LDMIB) addr += 4;
        if (d->instr == I_POP) assert(d->Rn == SP);
        uint8_t reg            = 0;

        if (reglist) {
            while (reglist) {
                reg            = TrailingZerosCount(reglist); /* count trailing zeros */
                reglist       &= ~(1 << reg);                 /* unset this bit */
                emu_log_debug("addr: %x, r%d: %8x\n", addr, reg, RMEM32(addr));
                if (reg == PC) break; /* PC is last reg, handled specially */
                WREGN(reg) = RMEM32(addr);
                if (RTREGN(reg) || RTMEM(addr)) WTREGN(reg, RTMEM(addr));
                addr          += 4;
            }
        } else  {
            WREG(Rt) = RMEM32(addr);
        }
        if (BitCheck(d->reglist, PC)) {
            BXWritePC(emu, RMEM32(addr));
        }
        if (d->W == B_SET || d->instr == I_POP) { /* writeback */
            if (BitCheck(d->reglist, d->Rn) == 0) {
                EMU(WREG(Rn) = RREG(Rn) + 4 * regcount);
            } else {
                emu_abort("unknown Rn %d %x", d->Rn, RREG(Rn));
            }
        }
        break;
    }
        SWITCH_COMMON;
    }
}

inline void emu_type_bits(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;

    switch(d->instr) {
    case I_BFI: {
        uint32_t lsb = d->lsb;
        uint32_t msb = lsb + d->width - 1;
        if (msb >= lsb) {
            /* R[d]<msb:lsb> = R[n]<(msb-lsb):0>; */
            /* 1. clear out        R[d]<msb:lsb>  = 0 */
            uint32_t val = RREG(Rd);
            val &= ~((1<<(msb + 1)) - (1<<lsb));
            emu_log_debug("Rd clear out   : %x\n", val);
            /* 2. extract Rn bits  bits = R[n]<(msb-lsb):0> */
            uint32_t bits = RREG(Rn);
            bits &= ((1<<(d->width)) - 1); /* width = msb - lsb + 1 */
            emu_log_debug("Rn extract bits: %x\n", bits);
            /* 3. set Rd bits      R[d]<msb:lsb> |= bits */
            val |= bits << lsb;
            emu_log_debug("Rd set bits    : %x\n", val);
            WREG(Rd) = val;
        }
        break;
    }
    case I_UBFX: {
        uint32_t lsb = d->lsb;
        uint32_t msb = lsb + d->width - 1;
        WREG(Rd) = BitExtract(RREG(Rn), lsb, msb);
        WTREG1(Rd, Rn);
        break;
    }
    case I_CLZ: {
        WREG(Rd) = LeadingZerosCount(RREG(Rm));
        WTREG1(Rd, Rm);
        break;
    }
        SWITCH_COMMON;
    }
}

inline void emu_type_mul(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;

    switch(d->instr) {
    case I_MUL: {
        /* TODO: move MUL to emu_dataop() and use OP macro instead */
        EMU(WREG(Rd) = RREG(Rn) * RREG(Rm));
        WTREG2(Rd, Rn, Rm);
        break;
    }
    case I_MLA: {
        EMU(WREG(Rd) = RREG(Rn) * RREG(Rm) + RREG(Ra));
        WTREG3(Rd, Rn, Rm, Ra);
        break;
    }
    case I_SMLAL: {
        int64_t acc = ((int64_t)RREG(RdHi)) << 32 | RREG(RdLo);
        int64_t res = (uint64_t)RREG(Rn) * (int64_t)RREG(Rm) + acc;
        WREG(RdLo) = (int32_t)(res & instr_mask(d->instr));
        WREG(RdHi) = (int32_t)(res >> 32);
        WTREG4(RdLo, Rn, Rm, RdLo, RdHi);
        WTREG1(RdHi, RdLo);
        break;
    }
    case I_UMLAL: {
        uint64_t acc = ((uint64_t)RREG(RdHi)) << 32 | RREG(RdLo);
        uint64_t res = (uint32_t)RREG(Rn) * (uint32_t)RREG(Rm) + acc;
        WREG(RdLo) = (uint32_t)(res & instr_mask(d->instr));
        WREG(RdHi) = (uint32_t)(res >> 32);
        WTREG4(RdLo, Rn, Rm, RdLo, RdHi);
        WTREG1(RdHi, RdLo);
        break;
    }
    case I_SMULL: {
        int64_t res = (int32_t)RREG(Rn) * (int32_t)RREG(Rm);
        WREG(RdLo) = (int32_t)(res & instr_mask(d->instr));
        WREG(RdHi) = (int32_t)(res >> 32);
        WTREG2(RdLo, Rn, Rm);
        WTREG1(RdHi, RdLo);
        break;
    }
    case I_UMULL: {
        uint64_t res = (uint32_t)RREG(Rn) * (uint32_t)RREG(Rm);
        WREG(RdLo) = (uint32_t)(res & instr_mask(d->instr));
        WREG(RdHi) = (uint32_t)(res >> 32);
        WTREG2(RdHi, Rn, Rm);
        WTREG1(RdHi, RdLo);
        break;
    }
        SWITCH_COMMON;
    }
}

inline void emu_type_uncond(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;
    switch(d->instr) {
    case I_DMB: {
        /* Options: SY, ST, ISH, ISHST, NSH, NSHST, OSH, OSHST */
        switch(d->option) {
        case O_SY: {
            DMB(SY);
            break;
        }
        case O_ST: {
            DMB(ST);
            break;
        }
        default: {
            emu_abort("unsupported barrier option %d\n", d->option);
        }
        }
        break;
    }
    case I_PLD:
    case I_PLI: {
        emu_log_debug("treating as NOP\n");
        break;
    }
    case I_BL:
    case I_BLX: {
        /* HACK: avoiding duplicate code by re-using BLX defined elsewhere */
        emu_type_branch_syscall(emu);
        break;
    }
        SWITCH_COMMON;
    }
}

inline uint32_t emu_dataop(emu_thread_t *emu, const uint32_t a, const uint32_t b) {
    const darm_t *d = &emu->darm;

    switch(d->instr) {
    case I_CMN :
    case I_ADD : return  a + b;
    case I_ADC : return  a + b  +  CPSR_C;
    case I_CMP :
    case I_SUB : return  a - b;
    case I_SBC : return (a - b) - !CPSR_C;
    case I_RSC : return (b - a) - !CPSR_C;
    case I_RSB : return  b - a;
    case I_TEQ :
    case I_EOR : return  a ^ b;
    case I_TST:
    case I_AND : return  a & b;
    case I_ORR : return  a | b;
    case I_BIC : return  a & ~b;
    case I_MOV : return   b;
    case I_MVN : return  ~b;
    default: emu_abort("unhandled dataop %s\n", darm_mnemonic_name(d->instr));
    }
    return 0xdeadc0de;
}

/* val: Rm or Rn */
inline uint32_t emu_regshift(emu_thread_t *emu, uint32_t val) {
    const darm_t *d = &emu->darm;

    uint32_t amount = d->Rs != R_INVLD ? RREG(Rs) : d->shift; /* shift register value or shift constant */
    emu_log_debug("regshift: amount: %x val: %x\n", amount, val);

    if (amount == 0) return val;

    switch(d->shift_type) {
    case S_LSL: return LSL(val, amount);
    case S_LSR: return LSR(val, amount);
    case S_ASR: return ASR(val, amount);
    case S_ROR: return ROR(val, amount);
    default: emu_abort("invalid shift type %s!\n", darm_shift_type_name(d->shift_type));
    }
    return val;
}

inline bool emu_advance_pc(emu_thread_t *emu) {
    assert(emu->disasm_bytes == 2 || emu->disasm_bytes == 4);
    if (!emu->branched) CPU(pc) += emu->disasm_bytes;
    emu->branched = 0;
    emu->instr_count++;

    android_atomic_inc(&emu_global->instr_total);

#ifndef PROFILE
    emu_log_debug("handled instructions: %d\n", emu_global->instr_total);
    emu_dump_diff(emu);
    dbg_dump_ucontext(&emu->current);

#if 0
    if (!emu->lock_acquired) {
        /* DEBUG: for consistency, we directly call to check the internal state of malloc */
        /* This is for avoiding any memory corruption done by improper EMU of malloc code */
        emu_log_debug("checking malloc state...\n");
        emu_unprotect_mem();
        check_malloc();
        emu_protect_mem();
    }
#endif

        emu_protect_mem();
        emu_stop();             /* will not return */
    if (emu_regs_tainted(emu) == 0) {
        emu_log_debug("taint: no tainted regs remaining, enable protection and leave emu\n");
    }
    emu_log_debug(LOG_BANNER_INSTR);
#endif

    /* number of total instructions to emulate */
    /* read stop value via emu.stop property */
    char prop[PROPERTY_VALUE_MAX]; // max is 92
    property_get("debug.emu.stop_total", prop, "0");
    int32_t stop_total = (int32_t)atoi(prop);
    emu_log_debug("stop_total value: %d\n", stop_total);

    property_get("debug.emu.stop_handler", prop, "0");
    int32_t stop_handler = (int32_t)atoi(prop);
    emu_log_debug("stop_handler value: %d\n", stop_handler);

    if (stop_total && emu_global->instr_total >= stop_total) {
        emu_log_info("SPECIAL: permanently turning off emu after %d instructions.\n", emu_global->instr_total);
        emu_log_debug("disabling emu\n");
        emu_unprotect_mem();
        emu->stop = 1;
        emu_global->disabled = 1;
    } else if (stop_handler && emu->instr_count >= stop_handler) { /* NOTE: we are using a one time count */
        emu_log_info("SPECIAL: stopping current trap  emu after %d instructions.\n", emu->instr_count);
        emu->stop = 1;
    } else if (emu->stop) {
        // emu_stop_trigger() raised flag
    }

    return !emu->stop;
}

inline void emu_set_taint_reg(emu_thread_t *emu, darm_reg_t reg, uint32_t tag) {
    assert(reg >= r0 && reg <= r15);
    if (emu->taintreg[reg] != TAINT_CLEAR && tag == TAINT_CLEAR) {
        emu_log_debug("taint: un-tainting r%d\n", reg);
    } else if (emu->taintreg[reg] == TAINT_CLEAR && tag != TAINT_CLEAR) {
        emu_log_debug("taint: tainting r%d tag: %x\n", reg, tag);
    }
    emu->taintreg[reg] = tag;
}

inline uint32_t emu_get_taint_reg(emu_thread_t *emu, darm_reg_t reg) {
    assert(reg >= r0 && reg <= r15);
    return emu->taintreg[reg];
}

inline void emu_clear_taintregs(emu_thread_t *emu) {
    int i;
    for (i = 0; i < N_REGS; i++) {
        emu->taintreg[i] = TAINT_CLEAR;
    }
}

inline bool emu_singlestep(emu_thread_t *emu) {
    // 1. decode instr
    // emu_disasm_ref(pc, (emu_thumb_mode() ? 16 : 32)); /* rasm2 with libopcodes backend */
    /* static const darm_t *d; */

#if 0
    /* SPECIAL CASES */
    uint32_t op = *(uint32_t *)pc;
    uint8_t regcount;
    emu_log_debug("op: %x\n", op);

    // 0x0d2d0b00, 0x0fbf0f01, "vpush%c %B"
    // ed2d8b02    vpush   {d8}
    // ed2d8b04    vpush   {d8-d9}
    if ((op & 0x0fbf0f01) == 0x0d2d0b00) {
        regcount = (op & 0xff) / 2;
        emu_log_info("SPECIAL: vpush %d\n", regcount);
        WREGN(SP) = RREGN(SP) - 4 * 2 * regcount; /* update SP (64 bit regs) */
        goto next;
    };

    // 0x0cbd0b00, 0x0fbf0f01, "vpop%c %B"
    // ecbd8b02    vpop    {d8}
    // ecbd8b04    vpop    {d8-d9}
    if ((op & 0x0fbf0f01) == 0x0cbd0b00) {
        regcount = (op & 0xff) / 2;
        emu_log_info("SPECIAL: vpop %d\n", regcount);
        WREGN(SP) = RREGN(SP) + 4 * 2 * regcount; /* update SP (64 bit regs) */
        goto next;
    }

    // ed9f9bed    vldr    d9, [pc, #948]
    // f3878e1f    vmov.i8 d8, #255
    if (op == 0xed9f9bed ||
        op == 0xf3878e1f) {
        emu_log_info("SPECIAL skipping %x\n", op);
        goto next;
    }
#endif

    emu_disasm(emu, &emu->darm, CPU(pc));

    if (emu->skip) {
        emu->skip = 0;
        return 0;
    }

    if (emu_stop_trigger(emu)) {
        goto next;
    }

    if (!emu_eval_cond(emu)) {
        emu_log_debug("skipping instruction: condition NOT passed\n");
        goto next;
    }

    const darm_t *d = &emu->darm;
    // 2. emu instr by type
    switch(d->instr_type) {
    case T_ARM_ARITH_SHIFT:
    case T_THUMB_MOD_SP_REG: {
        emu_type_arith_shift(emu);
        break;
    }
    case T_ARM_ARITH_IMM: {
        emu_type_arith_imm(emu);
        break;
    }
    case T_ARM_BRNCHSC:
    case T_THUMB_COND_BRANCH: {
        emu_type_branch_syscall(emu);
        break;
    }
    case T_ARM_BRNCHMISC: {
        emu_type_branch_misc(emu);
        break;
    }
    case T_ARM_MOV_IMM: {
        emu_type_move_imm(emu);
        break;
    }
    case T_ARM_CMP_IMM: {
        emu_type_cmp_imm(emu);
        break;
    }
    case T_ARM_CMP_OP: {
        emu_type_cmp_op(emu);
        break;
    }
    case T_ARM_OPLESS: {
        emu_type_opless(emu);
        break;
    }
    case T_ARM_DST_SRC:
    case T_THUMB_MOV4: {
        emu_type_dst_src(emu);
        break;
    }
    case T_ARM_STACK0:
    case T_ARM_STACK1:
    case T_ARM_STACK2:
    case T_ARM_LDSTREGS:
    case T_THUMB_RW_MEMO:
    case T_THUMB_RW_MEMI:
    case T_THUMB_STACK:
    case T_THUMB_LDR_PC:
    case T_THUMB_PUSHPOP: {
        emu_type_memory(emu);
        break;
    }
    case T_ARM_UNCOND: {
        emu_type_uncond(emu);
        break;
    }
    case T_ARM_PUSR: {
        emu_type_pusr(emu);
        break;
    }
    case T_ARM_SYNC: {
        emu_type_sync(emu);
        break;
    }
    case T_ARM_MVCR: {
        emu_type_mvcr(emu);
        break;
    }
    case T_ARM_BITS:
    case T_ARM_BITREV: {
        emu_type_bits(emu);
        break;
    }
    case T_ARM_MUL: {
        emu_type_mul(emu);
        break;
    }
    case T_ARM_MISC: {
        emu_type_misc(emu);
        break;
    }
        // HACK: temporarily make Thumb16 special cases forward to A32 handlers
    case T_THUMB_3REG:
    case T_THUMB_HAS_IMM8:
    case T_THUMB_MOD_SP_IMM: {
        darm_enc(emu);
        break;
    }
    case T_INVLD: {
        // HACK for Thumb2
        if (emu_thumb_mode(emu)) {
            darm_enc(emu);
        } else {
            emu_abort("darm invalid type (unsupported yet)\n");
        }
        break;
    }
    default:
        emu_abort("unhandled type %s\n", darm_enctype_name(d->instr_type));
    }

 next:
    return emu_advance_pc(emu);
}

uint8_t emu_disabled() {
    return emu_global->disabled || !emu_global->target;
}

// NOTE: caller assumed to hold lock
/* void emu_init(emu_global_t *emu_global) { */
static
void emu_init() {
    if (emu_initialized()) return;

    LOGD("initializing emu state ...\n");

#ifdef TRACE
    /* need to initialize log file before any printfs */
    char traceFilename[256];
    snprintf(traceFilename, sizeof(traceFilename), "%s-%d", TRACE_PATH, getpid());

    emu_global->trace_fd = open(traceFilename, O_WRONLY | O_CREAT | O_SYNC);

    if (!emu_global->trace_fd) {
        emu_abort("Can't open trace file %s!\n", traceFilename);
    }
#endif

    /* process maps */
    emu_parse_maps(emu_global);

#ifndef NO_TAINT
    /* taint tag storage */
    emu_init_taintmaps(emu_global);
    emu_clear_taintpages(emu_global);
#endif

    /* memory access via /proc/self/mem */
    emu_init_proc_mem();

    // __atomic_swap(1, &emu.initialized);
    emu_global->initialized = 1;

    emu_log_info("[+] emu initialized.\n");
}

void emu_start(emu_thread_t *emu) {
    emu_log_info("starting emulation ...\n\n");

    emu->running = 1;
    // wipe register taint
    emu_clear_taintregs(emu);

    emu->time_start = time_ms();

    while(emu_singlestep(emu));
}

/* note: ucontext/setcontext support normally missing in Bionic */
/* unless ported to Bionic, hack it by returning 0 */
/* int setcontext (const ucontext_t *ucp) { return 0; } */

void emu_stop(emu_thread_t *emu) {
    emu_log_debug("stopping emulation\n");

    CPU(pc) |= emu_thumb_mode(emu) ? 1 : 0; /* LSB set for Thumb */

    // WARNING: double conversion will need malloc and can deadlock!
    /*
    emu.time_end = time_ms();
    double delta = emu.time_end - emu.time_start;
    emu_log_info("resuming exec pc old: %0lx new: %0lx time total (ms): %f handled instr: %d time/instr (ns): %f\n",
           emu.original.uc_mcontext.arm_pc,
           emu.current.uc_mcontext.arm_pc,
           delta,
           emu.instr_total,
           (delta * 1e6) / emu.instr_total);
    */
    if (emu_regs_tainted(emu)) {
        emu_log_warn("WARNING: stopping emu with tainted regs!\n");
    }
    dbg_dump_ucontext(&emu->current);
    emu_log_debug(LOG_BANNER_SIG);
    emu->stop = 0;
    emu->running = 0;
    emu_log_info("emulation stopped. total instr: %d\n", emu_global->instr_total);
    /* if we are not in standalone, we need to restore execution context to latest values */
    if (!emu_global->standalone) {
        setcontext((const ucontext_t *)&emu->current); /* never returns */
    }
}

inline uint8_t emu_stop_trigger(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;
    switch(d->instr) {
    case I_BKPT: {
        /* special flags */
        /* entering- JNI: 1337 */
        /* emu_single_step(); */
        if (d->imm == MARKER_START_VAL) {
            emu_log_debug("MARKER: starting emu\n");
            /* advance PC but leave emu enabled */
            return 1;
        } else if (d->imm == MARKER_STOP_VAL) {
            emu_log_debug("MARKER: leaving emu due to JNI re-entry\n");
            emu->stop = 1;
        } else {
            emu_abort("MARKER: unexpected value! %x\n", d->imm);
        }
        break;
    }
    case I_BX: {
        /* special standalone stop case */
        if (RREG(Rm) == MARKER_STOP_VAL) {
            emu_log_debug("MARKER: stopping standalone emu\n");
            emu->stop = 1;
        }
        break;
    }
    default: {
        /* empty: avoids unhandled case warnings */
    }
    }
    return emu->stop;
}

// requires pre-allocated stack of at least MINSTKSZ
void
emu_init_handler(int sig,
                 void (*handler)(int, siginfo_t *, void *),
                 void *stack,
                 size_t stack_size) {
    emu_log_debug("[+] registering %s (%d) handler sigaltstack sp: %p size: %d  threads: %d ...\n", get_signame(sig), sig, stack, stack_size, emu_global->thread_count);
    assert(sig == SIGTRAP || sig == SIGSEGV);
    assert(stack != NULL && stack_size >= MINSIGSTKSZ);

#if HAVE_SETRLIMIT
    /* Be recursion friendly */
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = 0x100000; /* 1 MB */
    setrlimit (RLIMIT_STACK, &rl);
#endif

    /* 1. setup alternate stack for handler */
    if (stack == NULL) {
        emu_abort("unallocated stack");
    }
    stack_t ss, oss;
    ss.ss_sp = stack;
    ss.ss_size = stack_size;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, &oss) == -1) {
        emu_abort("sigaltstack");
    }

    // inspect oldstack and see if we had already setup the thread->altstack
    if (oss.ss_sp != NULL || oss.ss_size != 0 || oss.ss_flags == SA_ONSTACK) {
        pthread_internal_t *thread = (pthread_internal_t *)pthread_self();
        emu_log_warn("[-] sigaltstack previously setup! tid: %d oss ss_sp: %p ss_flags: %d ss_size: %d\n", thread->kernel_id, oss.ss_sp, oss.ss_flags, oss.ss_size);
        dump_backtrace(gettid()); // should be safe to call - we are not in a handler
    }
    // assert(oss.ss_sp == NULL && oss.ss_size == 0 && oss.ss_flags != SA_ONSTACK);

    /* 2. setup signal handler */
    struct sigaction sa;
    // SA_NODEFER to detect traps within the handler itself (bugs)
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    // sigaddset(&sa.sa_mask, SIGQUIT);
    sa.sa_sigaction = handler;
    if (sigaction (sig, &sa, NULL) == -1) {
        emu_abort("sigaction");
    }
}

/* Standalone on-demand emulation */
uint32_t emu_function(void (*fun)()) {
    /* SIGSTKSZ = 8192 */
    void *stack = mkstack(getPageSize() + SIGSTKSZ, getPageSize());
    uint32_t stack_top = (uint32_t)stack + getPageSize() + SIGSTKSZ;

    emu_hook_thread_entry((void *)pthread_self());
    emu_thread_t *emu = emu_tls_get();
    assert(emu);
    emu_set_standalone(true);
    // should already be set prior to calling
    emu_set_target(getpid());

    uint32_t pc = (uint32_t)*fun;
    emu_map_lookup(pc);

    /* create reasonable ucontext to start with */
    CPU(r0) = CPU(r1) = CPU(r2) = CPU(r3) = CPU(r4) = CPU(r5) = 0;
    CPU(r6) = CPU(r7) = CPU(r8) = CPU(r9) = CPU(r10) = 0;
    CPU(fp) = CPU(ip) = 0;
    CPU(lr) = MARKER_STOP_VAL;
    CPU(sp) = stack_top;
    CPU(pc) = pc;
    CPU(cpsr) = 0b10000;         /* User Mode */

    emu_ucontext(emu, &emu->current);
    emu_start(emu);
    emu_stop(emu);
    return emu->instr_count;
}

// diassemble instruction given preallocated darm_t struct
// note that darm_t struct may NOT be the same one inside emu
// this is used in look-ahead diassembly for detecting patterns (e.g. locks)
// returns 0 on failure, 1 for Thumb, 2 for Thumb2, and 2 for ARMv7.
inline uint8_t emu_disasm(emu_thread_t *emu, darm_t *d, uint32_t pc) {
    uint32_t ins = *(uint32_t *)pc;

    uint16_t w     = ins & 0xffff;
    uint16_t w2    = ins >> 16;
    uint32_t addr  = pc | emu_thumb_mode(emu); /* LSB set for Thumb / Thumb2 */
    uint8_t  ret   = darm_disasm(d, w, w2, addr);
    emu_log_debug("emu_disasm : w: %x w2: %x addr: %x T: %d ret: %d\n", w, w2, addr, emu_thumb_mode(emu), ret);
    if (ret) {
#ifdef TRACE
        darm_str_t str;
        darm_str2(d, &str, 1); /* lowercase str */
        map_t *m = emu_map_lookup(pc);

        Dl_info info;
        const char* symbol_name;
        ptrdiff_t function_offset = 0;

        if (dladdr((void *)pc, &info)) {
            /* FIXME: can't use strdup since it uses dlmalloc... */
            /* HACK: temporarily disable dlmalloc marker to allow call  */
            dlemu_set_tid(0);
            dlemu_set_tid(gettid());
            char* demangled = emu->lock_acquired ? "locked" : demangle_symbol_name(info.dli_sname);
            symbol_name = demangled ? demangled : info.dli_sname;
            function_offset = (uintptr_t)info.dli_saddr - (uintptr_t)info.dli_fbase;

            emu_log_trace("TRACE %6d %8x %08x %-32s %-32s %8x %s\n",
                          emu->instr_count + 1, /* we update the count in emu_advance_pc() */
                          pc - m->vm_start,
                          d->w,
                          str.total,
                          m->name,
                          function_offset,
                          symbol_name
                          );

#if 0
            if (symbol_name) {  /* valid symbol */
                if (strcmp(m->name, "/system/lib/libc.so") == 0) {
                    if ((strcmp(symbol_name, "dlmalloc") == 0)) {
                        /* if ((strcmp(symbol_name, "memset") == 0)) { */
                        emu_log_error("SPECIAL avoiding %s %s %x\n", m->name, symbol_name, pc - m->vm_start);
                        emu->skip = 1;
                    }
                }
                if (strcmp(m->name, "/system/lib/libicuuc.so") == 0) {
                    if ((strcmp(symbol_name, "utext_openUChars_48") == 0)) { // works, before memset
                        emu_log_error("SPECIAL avoiding %s %s %x\n", m->name, symbol_name, pc - m->vm_start);
                        emu->skip = 1;
                    }
                }
            }
#endif
            if (!emu->lock_acquired) free(demangled);
        } else {
            emu_abort("dladdr failed");
        }
#endif
        emu->disasm_bytes = ret * 2 /* bytes */;
        emu_log_debug("bytes: %d\n", emu->disasm_bytes);

#ifndef PROFILE
        darm_dump(d, STDOUT_FILENO); /* dump internal darm_t state */
        // darm_dump(d, emu.trace_fd);  /* dump internal darm_t state */
#endif
    } else {
        emu_abort("darm : %x %x %x <invalid instruction>\n", pc, w, w2);
    }
    return emu->disasm_bytes;
}

inline uint8_t emu_thumb_mode(emu_thread_t *emu) {
    return CPSR_T;              /* 0: ARM, 1: Thumb */
}

/* map register number (0-15) to uc reg entry (r0-r10, fp, ip, sp, lr pc) */
inline uint32_t emu_read_reg(emu_thread_t *emu, darm_reg_t reg) {
    assert(reg >= r0 && reg <= r15);
    if (reg == R_INVLD) return R_INVLD;

    switch(reg) {
    case r0  :
    case r1  :
    case r2  :
    case r3  :
    case r4  :
    case r5  :
    case r6  :
    case r7  :
    case r8  :
    case r9  :
    case r10 :
    case FP  :
    case IP  :
    case SP  :
    case LR  : return emu->regs[reg];
    case PC  : return emu->regs[reg] + (emu_thumb_mode(emu) ? 4 : 8); /* A32 +8, Thumb +4 */
    default  : return -1;
    }
    return -1;
}

 inline uint32_t *emu_write_reg(emu_thread_t *emu, darm_reg_t reg) {
    assert(reg >= r0 && reg <= r15);
    if (reg == R_INVLD) return NULL;

    /* if we are explicitly writing the PC, we are branching */
    /* we clear flag in main loop when ready to fetch next op */
    if (reg == PC) emu->branched = 1;
    return &emu->regs[reg];
}

/* Debugging */

inline void dbg_dump_ucontext(ucontext_t *uc) {
    mcontext_t *r = &uc->uc_mcontext;
    emu_log_debug("dump gp regs:\n");
    emu_log_debug("fault addr %8x\n",
                 (uint32_t)r->fault_address);
    emu_log_debug("r0: %8x  r1: %8x  r2: %8x  r3: %8x\n",
                 (uint32_t)r->arm_r0, (uint32_t)r->arm_r1, (uint32_t)r->arm_r2,  (uint32_t)r->arm_r3);
    emu_log_debug("r4: %8x  r5: %8x  r6: %8x  r7: %8x\n",
                 (uint32_t)r->arm_r4, (uint32_t)r->arm_r5, (uint32_t)r->arm_r6,  (uint32_t)r->arm_r7);
    emu_log_debug("r8: %8x  r9: %8x  sl: %8x  fp: %8x\n",
                 (uint32_t)r->arm_r8, (uint32_t)r->arm_r9, (uint32_t)r->arm_r10, (uint32_t)r->arm_fp);
    emu_log_debug("ip: %8x  sp: %8x  lr: %8x  pc: %8x  cpsr: %08x\n",
                 (uint32_t)r->arm_ip, (uint32_t)r->arm_sp, (uint32_t)r->arm_lr,  (uint32_t)r->arm_pc, (uint32_t)r->arm_cpsr);
}

inline void dbg_dump_ucontext_vfp(ucontext_t *uc) {
    emu_log_debug("dump vfp regs:\n");
    /* dump VFP registers from uc_regspace */
    struct aux_sigframe *aux;
    aux = (struct aux_sigframe *) uc->uc_regspace;
    struct vfp_sigframe *vfp = &aux->vfp;

    uint64_t magic = vfp->magic;
    uint64_t size  = vfp->size;
    assert(magic == VFP_MAGIC && size == VFP_STORAGE_SIZE);

    struct user_vfp vfp_regs = vfp->ufp;
    int i;
    for (i = 0; i < NUM_VFP_REGS; i += 2) {
        emu_log_debug("d%-2d: %16llx  d%-2d: %16llx\n",
                      i,   vfp_regs.fpregs[i],
                      i+1, vfp_regs.fpregs[i+1]);
    }
    // Floating-point Status and Control Register
    emu_log_debug("fpscr:   %08lx\n", vfp_regs.fpscr);

    // exception registers
    struct user_vfp_exc vfp_exc = vfp->ufp_exc;
    // Floating-Point Exception Control register
    emu_log_debug("fpexc:   %08lx\n", vfp_exc.fpexc);
    // Floating-Point Instruction Registers
    // FPINST contains the exception-generating instruction
    emu_log_debug("fpinst:  %08lx\n", vfp_exc.fpinst);
    // FPINST2 contains the bypassed instruction
    emu_log_debug("fpinst2: %08lx\n", vfp_exc.fpinst2);

    // sanitise exception registers
    // based on $KERNEL/arch/arm/kernel/signal.c
    // see: int restore_vfp_context(struct vfp_sigframe __user *frame)
    // ensure the VFP is enabled
    assert(vfp_exc.fpexc & FPEXC_EN);
    // ensure FPINST2 is invalid and the exception flag is cleared
    assert(!(vfp_exc.fpexc & (FPEXC_EX | FPEXC_FP2V)));
}

inline void emu_dump(emu_thread_t *emu) {
    dbg_dump_ucontext(&emu->current);
}

/* show register changes since last diff call */
inline void emu_dump_diff(emu_thread_t *emu) {
    static int i;
    for (i = 0; i < SIGCONTEXT_REG_COUNT; i++) {
        uint32_t current  = ((uint32_t *)&emu->current.uc_mcontext)[i];
        uint32_t previous = ((uint32_t *)&emu->previous.uc_mcontext)[i];
        if (current != previous) {
            emu_log_debug("dbg: %-4s: %8x -> %8x\n",
                          sigcontext_names[i],
                          previous, current);
        }
    }
    emu->previous = emu->current;
}

inline void emu_dump_cpsr(emu_thread_t *emu) {
    emu_log_debug("cpsr [%c%c%c%c %c %c]\n",
                  CPSR_N ? 'N' : 'n',
                  CPSR_Z ? 'Z' : 'z',
                  CPSR_C ? 'C' : 'c',
                  CPSR_V ? 'V' : 'v',
                  CPSR_I ? 'I' : 'i',
                  CPSR_T ? 'T' : 't'
                  );
}

inline void emu_map_dump(map_t *m) {
    if (m != NULL) {
        emu_log_debug("%x-%x [%6u pages] %c%c%c%c %8llx %3x:%02x %8u %s\n",
                      m->vm_start,
                      m->vm_end,
                      m->pages,
                      m->r, m->w, m->x, m->s,
                      m->pgoff,
                      m->major, m->minor,
                      m->ino,
                      m->name);
    } else {
        emu_abort("invalid (null) map\n");
    }
}

void emu_parse_maps(emu_global_t *emu_global) {
    emu_log_debug("processing maps...\n");

    char buf[1024];
    emu_global->nr_maps = 0;

    FILE *file = fopen("/proc/self/maps", "r");

    if (!file) {
        emu_abort("open failed\n");
    }

    int32_t page_size = getPageSize();

    while (fgets(buf, sizeof(buf), file) != NULL) {
        if (emu_global->nr_maps >= MAX_MAPS) {
            emu_abort("too many maps\n");
        }
        map_t *m = &emu_global->maps[emu_global->nr_maps++];
        memset(m, 0, sizeof(map_t));

        unsigned int n;
        n = sscanf(buf, "%x-%x %c%c%c%c %llx %x:%x %u %127s\n",
                   &m->vm_start,
                   &m->vm_end,
                   &m->r, &m->w, &m->x, &m->s,
                   &m->pgoff,
                   &m->major, &m->minor,
                   &m->ino,
                   m->name);
        m->pages = (m->vm_end - m->vm_start) / page_size;
#ifndef PROFILE
        // emu_map_dump(m);
#endif
        if (n < 10) {
            emu_log_debug("prev entry:");
            emu_map_dump(m - 1); /* prev entry */
            emu_log_debug("current line: %s",buf);
            emu_log_debug("current entry:");
            emu_map_dump(m);
            emu_abort("unexpected mapping: %d line: %s\n", emu_global->nr_maps, buf);
        }
    }
    fclose(file);
    emu_log_debug("processed maps.\n");
}

/* NOTE: return value only valid until next invocation of function */
void emu_parse_cmdline(char *cmdline, size_t size) {
    // emu_log_debug("processing cmdline...\n");
    char filename[64];
    int bytes = snprintf(filename, sizeof(filename), "/proc/%d/cmdline", (uint32_t)getpid());
    assert(bytes > 0 && (uint32_t)bytes < sizeof(filename));

    /* int file = open("/proc/self/cmdline", O_RDONLY); */
    int file = open(filename, O_RDONLY);

    if (!file) {
        emu_abort("open failed\n");
    }

    int ret = read(file, cmdline, size - 1); // one less to allow space for null terminator
    close(file);
    if (ret == -1) {
        emu_abort("read failed\n");
    }

    // expect we read everything in one shot
    assert(ret > 0 && (uint32_t)ret < size);

    cmdline[ret] = '\0';
    emu_log_debug("cmdline: %s\n", cmdline);
}

// see man(2) prctl, specifically the section about PR_GET_NAME
#define MAX_TASK_NAME_LEN (32)
/* NOTE: return value only valid until next invocation of function */
// WARNING: not thread safe, currently used with emu.lock held so should be fine
char* emu_parse_threadname() {
    static char threadname[MAX_TASK_NAME_LEN + 1]; // one more for termination
    if (prctl(PR_GET_NAME, (unsigned long)threadname, 0, 0, 0) != 0) {
        strcpy(threadname, "<name unknown>");
    } else {
        // short names are null terminated by prctl, but the manpage
        // implies that 16 byte names are not.
        threadname[MAX_TASK_NAME_LEN] = 0;
    }
    return threadname;
}

const char *get_signame(int sig) {
    switch(sig) {
    case SIGSEGV:    return "SIGSEGV";
    case SIGTRAP:    return "SIGTRAP";
    default:         return "?";
    }
}

const char *get_sigcode(int signo, int code) {
    switch (signo) {
    case SIGSEGV:
        switch (code) {
        case SEGV_MAPERR: return "SEGV_MAPERR";
        case SEGV_ACCERR: return "SEGV_ACCERR";
        }
        break;
    case SIGTRAP:
        switch (code) {
        case TRAP_BRKPT:  return "TRAP_BRKPT";
        case TRAP_TRACE:  return "TRAP_TRACE";
#define TRAP_BRANCH 3
        case TRAP_BRANCH: return "TRAP_BRANCH";
#define TRAP_HWBKPT 4
        case TRAP_HWBKPT: return "TRAP_HWBKPT";
        }
        break;
    }
    return "?";
}

const char *get_ssname(int code) {
    switch(code) {
    case SS_DISABLE: return "SS_DISABLE";
    case SS_ONSTACK: return "SS_ONSTACK";
    default:         return "?";
    }
}

map_t* emu_map_lookup(uint32_t addr) {
#ifdef PROFILE
    return NULL;
#endif

    unsigned int i;
    map_t *m;

    if (emu_global->nr_maps == 0) {
        emu_parse_maps(emu_global);
    }

    for (i = 0; i < emu_global->nr_maps; i++) {
        m = &emu_global->maps[i];
        // stricly addr < m->vm_end, because end and start are equal:
        // 5a91f000-5a920000 r--s bb000 103:2 25 /system/app/DownloadProvider.apk [1 pages]
        // 5a920000-5a921000 r--s  7000 103:2 27 /system/app/DrmProvider.apk [1 pages]
        if (addr >= m->vm_start && addr < m->vm_end) {
            emu_log_debug("lib map %8x -> %8x\n", addr, addr - m->vm_start);
            emu_map_dump(m);
            return m;
        }
    }
    // NOTE: since emu only parses maps at init and memory can later change
    // failure to find an addr may or may not be a bug
    emu_log_error("unable to locate addr: %x\n", addr);
    return NULL;
}

/* Page Protection */

int32_t
getPageSize() {
    static int32_t pageSize = 0;

    /* previous invocations will set pageSize */
    if (pageSize) {
        return pageSize;
    }

    /* this code executes once at initialization */
    pageSize = sysconf(_SC_PAGE_SIZE);
    if (pageSize == -1)
        emu_log_error("error: sysconf %d", pageSize);

    emu_log_debug("Page Size = %d bytes\n", pageSize);

    return pageSize;
}

inline uint32_t
getAlignedPage(uint32_t addr) {
    return addr & ~ (getPageSize() - 1);
}

void
emu_handler_segv(int sig, siginfo_t *si, void *ucontext) {
    emu_thread_t *emu = emu_tls_get();
    assert(emu);
    if (emu->running && !emu_global->standalone) {
        emu_abort("re-trap inside emu!\n");
    }
    ucontext_t *uc = (ucontext_t *)ucontext;
    emu_siginfo(sig, si, uc);

    // emu must have been already initialized
    // by previously called set_taint_array which then mprotected memory
    assert(emu_initialized());

    // potential SEGV codes:
    // SEGV_MAPPER: Address not mapped to object
    // SEGV_ACCER: Invalid permissions for mapped object
    // expecting SEGV_ACCER only!
    assert(si->si_code == SEGV_ACCERR);

    emu_ucontext(emu, uc);

    uint32_t addr_fault = uc->uc_mcontext.fault_address;
    if (emu_get_taint_mem(addr_fault) == TAINT_CLEAR) {
        /* false positive, single-step instruction */
        emu_log_info("[-] taint false positive\n");

        // wipe register taint
        emu_clear_taintregs(emu);
        emu->running = 1;

        emu_singlestep(emu);
    } else {
        /* instruction accessing tainted memory */
        emu_log_info("[+] taint trap\n");
        emu_start(emu);
    }
    // emu_stop() will mutex_unlock(&emu.mutex) and not return!
    emu_stop(emu);
}

/* TODO: add length and determine if page boundary crossed */
inline int8_t
mprotectPage(uint32_t addr, uint32_t flags) {
    uint32_t addr_aligned = getAlignedPage(addr); /* align at pageSize */
    emu_log_debug("update protection on page: %x given addr: %x\n", addr_aligned, addr);
    emu_map_lookup(addr);

    emu_log_debug("mprotecting page: %x\n", addr_aligned);
    int8_t ret = mprotect((void *)addr_aligned, getPageSize(), flags);
    if (ret != 0) {
        emu_log_error("error: mprotect ret: %d errno: %d (%s)\n", ret, errno, strerror(errno));
        switch(errno) {
        case EACCES:
            emu_log_error("EACCSS: The memory cannot be given the specified access.\n");
            break;
        case EINVAL:
            emu_log_error("EINVAL: addr is not a valid pointer, or not a multiple of the system page size.\n");
            break;
        case ENOMEM:
            emu_log_error("ENOMEM: Addresses invalid or pages not mapped\n");
            break;
        default:
            emu_log_error("unknown errno %d\n", errno);
        }

        emu_abort("mprotect");
    }
    return ret;
}

void
emu_init_taintmaps(emu_global_t *emu_global) {
    uint32_t start, end, bytes;

    /* lib taintmap */

    start = emu_global->maps[0].vm_start;
    end   = emu_global->maps[emu_global->nr_maps - 3].vm_end;
    bytes = end - start;

    emu_log_debug("mmap lib   range: %x - %x length: %x\n", start, end, bytes);

    taintmap_t *tm;

    tm = &emu_global->taintmaps[TAINTMAP_LIB];
    tm->data  = emu_alloc(bytes);
    tm->start = start;
    tm->end   = end;
    tm->bytes = bytes;

    /* stack taintmap */

    start = emu_global->maps[emu_global->nr_maps - 2].vm_start;
    end   = emu_global->maps[emu_global->nr_maps - 2].vm_end;
    bytes = end - start;

    emu_log_debug("mmap stack range: %x - %x length: %x\n", start, end, bytes);

    tm = &emu_global->taintmaps[TAINTMAP_STACK];
    tm->data  = emu_alloc(bytes);
    tm->start = start;
    tm->end   = end;
    tm->bytes = bytes;

    emu_log_debug("taintmaps initialized\n");
}

inline taintmap_t *
emu_get_taintmap(uint32_t addr) {
    assert(addr > 0);
    taintmap_t *tm;
    addr = Align(addr, 4);      /* word align */

    uint32_t stack_start = emu_global->maps[emu_global->nr_maps - 2].vm_start;
    uint8_t  idx         = (addr > stack_start) ? TAINTMAP_STACK : TAINTMAP_LIB;
    tm = &emu_global->taintmaps[idx];

    if (tm->data == NULL || tm->start == 0) {
        emu_abort("uninitialized taintmap");
    }

    return tm;
}

// WARNING: extremely slow dump (full sweep) - implement bitmap instead
// taintmaps are dumped in ranges for compact output
uint32_t
emu_dump_taintmaps() {
    emu_log_debug("dumping taintmaps...\n");
    uint32_t idx, offset;
    taintmap_t *tm;
    uint32_t ranges = 0;
    for (idx = TAINTMAP_LIB; idx < MAX_TAINTMAPS; idx++) {
        tm = &emu_global->taintmaps[idx];
        if (tm->data == NULL) {
            /* FIXME: this should only occur for the 3rd (heap, idx 2) unused map */
            emu_log_debug("unallocated data for taintmap %d\n", idx);
            continue;
        }
        uint8_t  range_inside = 0;
        uint32_t range_start  = 0;
        uint32_t range_end    = 0;
        uint32_t range_tag    = TAINT_CLEAR;
        for (offset = 0; offset < tm->bytes >> 2; offset++) {
            uint32_t tag = tm->data[offset];
            if (tag != TAINT_CLEAR) {
                if (!range_inside) {
                    range_inside = 1;
                    range_start  = offset;
                    range_tag    = tag;
                }
            } else { // if (tag == TAINT_CLEAR)
                // end range if we were inside a range
                if (range_inside) {
                    assert(offset > 0);
                    range_end = offset;
                    ranges++;

                    // convert ranges offset to original word addresses
                    range_start = tm->start + range_start * sizeof(uint32_t);
                    range_end   = tm->start + range_end   * sizeof(uint32_t);
                    emu_log_debug("taint range %d: %s start: %x end: %x length: %d tag: %x\n",
                                  ranges,
                                  (idx == TAINTMAP_LIB) ? "lib" : "stack",
                                  range_start, range_end, range_end - range_start, range_tag
                                  );

                    range_tag = TAINT_CLEAR;
                    range_inside = range_start = range_end = 0;
                }
            }
        }
    }
    return ranges;
}

inline uint32_t
emu_get_taint_mem(uint32_t addr) {
    addr = Align(addr, 4);      /* word align */
    taintmap_t *taintmap = emu_get_taintmap(addr);

    if (addr < taintmap->start || addr > taintmap->end) {
        emu_abort("out of bounds addr %x\n", addr);
    }
    uint32_t    offset   = (addr - taintmap->start) >> 2;
    uint32_t    tag      = taintmap->data[offset]; /* word (32-bit) based tag storage */
    // emu_log_debug("addr: %x offset: %x tag: %x", addr, offset, tag);
    return tag;
}

// assuming lock is already held when called from emu_set_taint_array
void emu_set_taint_mem(uint32_t addr, uint32_t tag) {
    assert(addr > 0);

    addr = Align(addr, 4);      /* word align */
    taintmap_t *taintmap   = emu_get_taintmap(addr);

    if (addr < taintmap->start || addr > taintmap->end) {
        emu_abort("out of bounds addr %x\n", addr);
    }

    // sanity check offset is valid
    uint32_t    offset     = (addr - taintmap->start) >> 2;

    /* incrementally update tainted page list */
    if (taintmap->data[offset] != TAINT_CLEAR && tag == TAINT_CLEAR) {
        emu_log_debug("taint: un-tainting mem: %x\n", addr);
        emu_unmark_page(addr);
    } else if (taintmap->data[offset] == TAINT_CLEAR && tag != TAINT_CLEAR) {
        emu_log_debug("taint: tainting mem: %x tag: %x\n", addr, tag);
        emu_mark_page(addr);
    }
    emu_log_debug("taint: updating offset: %x tag: %x\n", offset, tag);
    taintmap->data[offset] = tag;  /* word (32-bit) based tag storage */
}

inline void emu_set_taint_array(uint32_t addr, uint32_t tag, uint32_t length) {
    if (emu_disabled()) {
        LOGD("%s: emu disabled\n", __func__);
        return;
    }
    emu_log_info("%s: addr: %x tag: %x length: %d\n", __func__, addr, tag, length);
    assert(addr != 0 && length > 0);

    // Important: must initialize state first - this includes necessary logging and taintmaps
    if (!emu_initialized()) emu_init();

    uint32_t end = addr + length - 1;
    emu_map_lookup(end);

    /* TODO: optimize tainting to be per page when possible */
    /* TODO: aquire lock once per whole array instead of every word */
    mutex_lock(&taint_lock);
    uint32_t x;
    for (x = addr; x <= (end); x += 4) {
        emu_set_taint_mem(x, tag);
    }

#ifndef PROFILE
    // emu_dump_taintmaps();
#endif
    /* TODO: make previous for loop return a list of pages tainted this time */
    /* this avoids protecting ALL pages ever seen so far */
    emu_protect_mem();
    mutex_unlock(&taint_lock);

    emu_log_info("%s: complete.\n", __func__);
}

inline uint32_t emu_get_taint_array(uint32_t addr, uint32_t length) {
    // TODO: aquire lock first before checking flag? extremely unlikely case
    if (emu_disabled() || !emu_initialized()) return TAINT_CLEAR;

    // can't use logging via fprintf since we are getting called from a __swrite()
    // emu_log_info("%s: addr: %x length: %d\n", __func__, addr, length);
    // assert(addr != 0 && length > 0);

    // TODO: get taint tag from taintmap
    uint32_t end = addr + length - 1;
    emu_map_lookup(end);

    /* TODO: optimize tainting to be per page when possible */

    uint32_t ret = TAINT_CLEAR;
    uint32_t x;
    for (x = addr; x <= (end); x += 4) {
        ret |= emu_get_taint_mem(x);
    }

    return ret;
}

inline int emu_mark_page(uint32_t addr) {
    uint32_t page = getAlignedPage(addr);
    uint32_t idx;
    uint8_t found = 0;
    uint8_t added = 0;

    /* 1. look if page has been marked previously marked */
    for (idx = 0; idx < MAX_TAINTPAGES; idx++) {
        /* 0        - un-marked slot */
        /* non-zero - marked plage */
        if (emu_global->taintpages[idx] == page) {
            found = 1;
            return found;
        }
    }

    /* 2. if page not found, add it */
    if (!found) {
        for (idx = 0; idx < MAX_TAINTPAGES; idx++) {
            if (emu_global->taintpages[idx] == 0) {
                emu_global->taintpages[idx] = page;
                added = 1;
                emu_global->nr_taintpages++;
                emu_log_debug("marking addr: %x page: %x\n", addr, page);
                break;
            }
        }
        if (!added) {
            emu_abort("maximum number of protected pages (%d) reached!", MAX_TAINTPAGES);
        }
    }
    return added;
}

inline int emu_unmark_page(uint32_t addr) {
    uint32_t page = getAlignedPage(addr);
    uint32_t idx;
    uint8_t found = 0;

    // assert(emu_global->nr_taintpages > 0);

    /* 1. look if page has been marked previously marked */
    for (idx = 0; idx < MAX_TAINTPAGES; idx++) {
        /* 0        - un-marked slot */
        /* non-zero - marked plage */
        if (emu_global->taintpages[idx] == page) {
            found = 1;
            emu_global->taintpages[idx] = 0;
            emu_global->nr_taintpages--;
            break;
        }
    }
    return found;
}

inline void
emu_clear_taintpages() {
    emu_log_debug("clearing taintpages...\n");
    uint32_t idx;
    for (idx = 0; idx < MAX_TAINTPAGES; idx++) {
        emu_global->taintpages[idx] = 0;
    }
    emu_global->nr_taintpages = 0;
}

inline uint32_t
emu_get_taintpages() {
    return emu_global->nr_taintpages;
}

// caller must hold taint_lock
inline void
emu_protect_mem() {
#ifdef NO_MPROTECT
    return;
#endif

    emu_log_debug("protecting memory...\n");
    uint32_t idx;
    /* protect all pages in unique list */
    static const uint32_t flags = PROT_NONE;
    for (idx = 0; idx < MAX_TAINTPAGES; idx++) {
        uint32_t page = emu_global->taintpages[idx];
        if (page != 0) {
            mprotectPage(page, flags);
        }
    }
    emu_log_debug("protected memory.\n");
}

inline void
emu_unprotect_mem() {
    uint32_t idx;
    static const uint32_t flags = PROT_READ | PROT_WRITE;
    /* un-protect all pages in unique page list */
    for (idx = 0; idx < MAX_TAINTPAGES; idx++) {
        /* 0        - un-marked slot */
        /* non-zero - marked plage */
        uint32_t page = emu_global->taintpages[idx];
        if (page != 0) {
            mprotectPage(page, flags);
        }
    }
}

inline
bool emu_running() {
    if (emu_global->target) {
        emu_thread_t *emu = emu_tls_get();
        assert(emu);
        return emu->running;
    }
    return 0;
}

int
emu_initialized() {
    return emu_global->initialized;
}

inline int32_t
emu_get_trace_fd() {
    return emu_global->trace_fd;
}

inline uint32_t
instr_mask(darm_instr_t instr) {
    switch(instr) {
    case I_LDRSB:
    case I_LDRB:
    case I_UXTB:
    case I_UXTAB:
    case I_SXTB:
    case I_STRB: { return 0xff; }
    case I_LDRSH:
    case I_LDRH:
    case I_UXTH:
    case I_SXTH:
    case I_STRH: { return 0x0000ffff; }
    case I_MOVT: { return 0xffff0000; }
    default:     { return 0xffffffff; }
    }
}

// HACK: Temporarily handle tricky cases for Thumb. This will be revised
// once we finish out disassembler rewrite with better Thumb

inline void darm_enc(emu_thread_t *emu) {
    const darm_t *d = &emu->darm;

    switch(d->instr_type) {
        /* Rd Imm */
    case T_THUMB_HAS_IMM8: {
        switch (d->instr) {
        case I_ADD:
        case I_ADR:
        case I_SUB: {
            emu_type_arith_imm(emu);
            break;
        }
        case I_CMP: {
            emu_type_cmp_imm(emu);
            break;
        }
        case I_MOV: {
            emu_type_move_imm(emu);
            break;
        }
            SWITCH_COMMON;
        }
        break;                  /* inner switch break to outer switch */
    }
    case T_THUMB_MOD_SP_IMM: {
        emu_type_arith_imm(emu);
        break;
    }
    case T_THUMB_3REG: {
        WREG(Rd) = OP(RREG(Rn), RREG(Rm));
        WTREG2(Rd, Rn, Rm);
        break;
    }
    case T_INVLD: {
        switch(d->instr) {
        case I_LDR:
        case I_LDRD:
        case I_STR:
        case I_STRD:
        case I_PUSH: {
            emu_type_memory(emu);
            break;
        }
        case I_BL:
        case I_BLX: {
            emu_type_uncond(emu);
            break;
        }
            SWITCH_COMMON;
        }
        break;                  /* inner switch break to outer switch */
    }
    default:
        emu_abort("unhandled type %s\n", darm_enctype_name(d->instr_type));
    }
}
inline double time_ms(void) {
    struct timespec res;
    clock_gettime(CLOCK_MONOTONIC, &res);
    double result = 1000.0 * res.tv_sec + (double) res.tv_nsec / 1e6;
    return result;
}

/*
 * Dump the native stack for the specified thread.
 * Taken from: dvmDumpNativeStack in dalvik/vm/interp/Stack.cpp
 */
void dump_backtrace(pid_t tid)
{
    const size_t MAX_DEPTH = 64;
    backtrace_frame_t backtrace[MAX_DEPTH];
    ssize_t frames = unwind_backtrace_thread(tid, backtrace, 0, MAX_DEPTH);
    if (frames > 0) {
        backtrace_symbol_t backtrace_symbols[MAX_DEPTH];
        get_backtrace_symbols(backtrace, frames, backtrace_symbols);

        ssize_t i;
        for (i = 0; i < frames; i++) {
            char line[MAX_BACKTRACE_LINE_LENGTH];
            format_backtrace_line(i, &backtrace[i], &backtrace_symbols[i],
                                  line, MAX_BACKTRACE_LINE_LENGTH);
            emu_log_info("  %s\n", line);
        }

        free_backtrace_symbols(backtrace_symbols, frames);
    }
}

// mutex wrappers with error checking
inline int mutex_lock(pthread_mutex_t *mutex) {
    emu_log_debug("mutex   lock try\n");
    int ret = pthread_mutex_lock(mutex);
    if (ret != 0) {
        switch(ret) {
        case EINVAL:
            emu_abort("EINVAL\n");
            break;
        case EDEADLK:
            emu_abort("EDEADLK\n");
            break;
        default:
            emu_abort("unknown ret %d\n", ret);
            break;
        }
    }
    emu_log_debug("mutex   lock success\n");
    return ret;
}

inline int mutex_unlock(pthread_mutex_t *mutex) {
    emu_log_debug("mutex unlock try\n");
    int ret = pthread_mutex_unlock(mutex);
    if (ret != 0) {
        switch(ret) {
        case EINVAL:
            emu_abort("EINVAL\n");
            break;
        case EPERM:
            emu_abort("EPERM\n");
            break;
        default:
            emu_abort("unknown ret %d\n", ret);
            break;
        }
    }
    emu_log_debug("mutex unlock success\n");
    return ret;
}

// wait for gdb to attach to process
// when attached, to continue: set var c = 1
// ignored if called again when already attached
inline
void gdb_wait() {
    static int attached = 0;
    if (attached) {
        emu_log_debug("already attached!\n");
        return;
    }
    emu_log_error(LOG_BANNER_SIG);
    emu_log_error("waiting for gdb to attach pid: %d tid: %d ...\n", getpid(), gettid());
    volatile int c = 0;
    while(!attached && c == 0) {
        *(int volatile *)&c;
    }
    attached = 1;
}

inline
uint32_t emu_target() {
    return emu_global->target;
}

inline
void emu_set_target(pid_t pid) {
    emu_global->target = pid;
}

inline
void emu_set_standalone(bool state) {
    emu_init();
    emu_global->standalone = state;
}

// copied over from libc/bionic/pthread.c
static
void *mkstack(size_t size, size_t guard_size) {
    void *stack;

    // NOTE: don't think we need a lock for mmap?
    pthread_mutex_lock(&mmap_lock);

    stack = emu_alloc(size);

    if(mprotect(stack, guard_size, PROT_NONE)){
        emu_free(stack, size);
        stack = NULL;
    }

    pthread_mutex_unlock(&mmap_lock);
    return stack;
}

int32_t emu_thread_count_up() {
    return android_atomic_inc(&emu_global->thread_count);
}

int32_t emu_thread_count_down() {
    return android_atomic_dec(&emu_global->thread_count);
}

void emu_hook_thread_entry(void *arg) {
    pthread_internal_t *thread = (pthread_internal_t *)arg;
    assert(thread == pthread_self());
    thread->target = emu_target();
    if (thread->target) {
        // atomic increment a emu->thread_count and decrement it in __pthread_internal_free()
        // which would provide a live thread count equal to total running threads for target pid
        // can then match it against /proc/self/task
        emu_thread_count_up();

        size_t guard_size = getPageSize(); /* PAGE_SIZE */
        size_t altstack_size = guard_size + 1 * SIGSTKSZ; /* ensures useable altstack is SIGSTKSZ */

        if (!thread->altstack) {
            thread->altstack = mkstack(altstack_size, guard_size);
            if (thread->altstack == NULL) {
                // kill thread/process
                emu_abort("mkstack failed alstack_size: %d guard_size: %d\n", altstack_size, guard_size);
            }
            thread->altstack_size = altstack_size;
            thread->altstack_guard_size = guard_size;
            // emu_log_debug("altstack alloc: %p\n", thread->altstack);
        } else {
            emu_abort("altstack already exists: %p\n", thread->altstack);
        }
        // allocated PAGE_SIZE for guard + SIGSTKSZ thread->altstack
        // handler must use only the SIGSTKSZ portion
        size_t useable_size = altstack_size - guard_size;
        uint32_t altstack_base = (uint32_t)thread->altstack + guard_size;

        emu_init_handler(SIGSEGV, emu_handler_segv, (void *)altstack_base, useable_size);
        if (emu_global->standalone) {
            // NOTE! for standalone emu, we use START and STOP markers
            // we purposely want the same handler for SIGTRAP as SIGSEGV to simplify matters
            emu_init_handler(SIGTRAP, emu_handler_segv, (void *)altstack_base, useable_size);
        } else {
            emu_init_handler(SIGTRAP, emu_handler_trap, (void *)altstack_base, useable_size);
        }

        // FIXME: delay this until trap time? not all threads will emu
        emu_log_debug("init TLS emu thread ...\n");
        emu_thread_t *emu = emu_alloc(sizeof(emu_thread_t));
        emu->tid = gettid();
        assert(emu->tid == thread->kernel_id);
        emu_tls_set(emu);
    }
}

void emu_hook_pthread_internal_free(void *arg) {
    pthread_internal_t *thread = (pthread_internal_t *)arg;
    if (thread->altstack) {
        assert(thread->target);
        emu_log_debug("altstack free: %p\n", thread->altstack);
        emu_free(thread->altstack, thread->altstack_size);
        // check error
        emu_thread_t *emu = emu_tls_get();
        if (emu) {
            emu_log_debug("emu free: %p", emu);
            emu_free(emu, sizeof(emu_thread_t));
            emu_tls_set(NULL);
        }
        emu_thread_count_down();
    }
}

void emu_hook_bionic_clone_entry() {
    dump_backtrace(gettid());
    emu_thread_count_up();

    emu_abort("not implemented yet");
}

void emu_hook_exit_thread(int ret) {
    emu_log_debug("exit_thread: %d %s\n", ret, ret ? "EXIT_FAILURE" : "EXIT_SUCCESS");
    emu_thread_count_down();
}

void emu_hook_bionic_atfork_run_child(void *arg) {
    UNUSED pthread_internal_t *thread = (pthread_internal_t *)arg;

    // emu_log_debug("fork:\n");
    char name[16];
    int ret = prctl(PR_GET_NAME, (unsigned long) name, 0, 0, 0);
    if (ret != 0) {
        emu_log_debug("fork prctl name: %s\n", name);
    }
    // NOTE: if target check is done after work, we'll be with a new pid so can't ever be target?
    // move hook to right before the kernel adjusts id __pthread_settid(pthread_self(), gettid());
    if (emu_target()) gdb_wait();
}

void emu_hook_Zygote_forkAndSpecializeCommon(void *arg) {
    pid_t pid = (pid_t)arg;
    assert(!emu_global->target);
    emu_global->target = pid;

    char name[16];
    int ret = prctl(PR_GET_NAME, (unsigned long) name, 0, 0, 0);
    if (ret != 0) {
        emu_log_debug("prctl name: %s\n", name);
    }

    // reuse handler setup code
    emu_hook_thread_entry((void *)pthread_self());
}

uint32_t emu_get_taint_file(int fd) {
#ifdef DEBUG_FILE_TAINT
    int skip = 1;
    char path[1024];
    char result[1024];

    sprintf(path, "/proc/self/fd/%d", fd);
    memset(result, 0, sizeof(result));
    readlink(path, result, sizeof(result)-1);
    // TODO: ignore /proc reads (strcmp)
    if (strstr(result, "/proc/") == NULL) { /* does NOT contain special case */
        skip = 0;
#endif
        int xbuf;
        int xtag = TAINT_CLEAR;
        int xret;
#define TAINT_XATTR_NAME "user.taint"
        xret = fgetxattr(fd, TAINT_XATTR_NAME, &xbuf, sizeof(xbuf));

        if (xret > 0) {
            xtag = xbuf;
            emu_log_debug("%s : read(%d) taint tag: 0x%x\n", __func__, fd, xtag);
        } else {
#define ENOATTR ENODATA
            if (errno == ENOATTR) {
                // emu_log_error("fgetxattr(%s): no taint tag\n", result);
            } else if (errno == ERANGE) {
                emu_log_debug("TaintLog: fgetxattr(%d) contents to large\n", fd);
            } else if (errno == ENOTSUP) {
                /* XATTRs are not supported. No need to spam the logs */
            } else if (errno == EPERM) {
                /* Strange interaction with /dev/log/main. Suppress the log */
            } else {
                emu_log_error("TaintLog: fgetxattr(%d): unknown error code %d\n", fd, errno);
            }
        }
#ifdef DEBUG_FILE_TAINT
    }
#endif

    return xtag;
}

int32_t emu_set_taint_file(int fd, uint32_t tag)
{
    int32_t ret;

    ret = fsetxattr(fd, TAINT_XATTR_NAME, &tag, sizeof(tag), 0);

    if (ret < 0) {
        if (errno == ENOSPC || errno == EDQUOT) {
            emu_log_error("TaintLog: fsetxattr(%d): not enough room to set xattr", fd);
        } else if (errno == ENOTSUP) {
            /* XATTRs are not supported. No need to spam the logs */
        } else if (errno == EPERM) {
            /* Strange interaction with /dev/log/main. Suppress the log */
        } else {
            emu_log_error("TaintLog: fsetxattr(%d): unknown error code %d", fd, errno);
        }
    }

    return ret;
}

/* syscalls used by trampolines */
extern ssize_t __read(int, void *, size_t);
extern ssize_t __write(int, void *, size_t);

ssize_t check_read(int fd, void *buf, size_t count) {
    ssize_t ret = __read(fd, buf, count);
    if (ret == -1) {
        if (errno != ENOENT) {
            emu_log_error("read(%d, %p, %d) failed with ret: %ld and errno: %d\n", fd, buf, count, ret, errno);
        }
        // this should never happen outside emu
        assert(errno != EFAULT);
    }
    return ret;
}

ssize_t check_write(int fd, void *buf, size_t count) {
    ssize_t ret = __write(fd, buf, count);
    if (ret == -1) {
        emu_log_error("write(%d, %p, %d) failed with ret: %ld and errno: %d\n", fd, buf, count, ret, errno);
        // this should never happen outside emu
        assert(errno != EFAULT);
    }
    return ret;
}

int emu_trampoline_read(int fd, void *buf, size_t count) {
    ssize_t ret;
    // TODO: add TLS flag to avoid checking taint for emu internal calls
    if (unlikely(emu_target())) {
        uint32_t taint_file = emu_get_taint_file(fd);
        uint32_t taint_buf  = emu_get_taint_array((uint32_t)buf, count);

        if (!taint_file && !taint_buf ) { goto no_taint; }

        if (taint_buf) {
            // need temp buffer to avoid EFAULT
            emu_log_debug("read(%d, %p, %d) tainted buf - sneaking data...\n", fd, buf, count);
            void *tmp = emu_alloc(count);
            ret = check_read(fd, tmp, count);
            if (ret) {
                emu_memcpy(buf, tmp, ret);
            }
            emu_free(tmp, count);
        } else {
            // can perform read directly
            ret = check_read(fd, buf, count);
        }
        if (ret && taint_file) {
            emu_log_debug("read(%d, %p, %d) tainted ret: %ld\n", fd, buf, count, ret);
            emu_set_taint_array((uint32_t)buf, taint_file, ret);
        }
        return ret;
    }

no_taint:
    /* common case (no taint) */
    ret = check_read(fd, buf, count);
    return ret;
}

int emu_trampoline_write(int fd, void *buf, size_t count) {
    ssize_t ret;
    if (unlikely(emu_target())) {
        // if (fd == emu_get_trace_fd()) continue;
        uint32_t taint_file = emu_get_taint_file(fd);
        uint32_t taint_buf  = emu_get_taint_array((uint32_t)buf, count);

        if (!taint_file && !taint_buf ) { goto no_taint; }

        if (taint_file && !taint_buf) {
            // let write go through - this must be Dalvik setting taint
            emu_log_debug("write(%d, %p, %d) taint from Dalvik...\n", fd, buf, count);
            // goto no_taint;
        } else if (!taint_file && taint_buf) {
            emu_log_debug("write(%d, %p, %d) tainted - sneaking data...\n", fd, buf, count);
            // TODO taint
            gdb_wait();

            void *tmp = emu_alloc(count);
            emu_memcpy(tmp, buf, count);
            ret = check_write(fd, tmp, count);
            emu_free(tmp, count);
            return ret;
        }
    }

 no_taint:
    /* common case (no taint) */
    ret = __write(fd, buf, count);
    if (ret == -1) {
        if (errno != 2) {
            emu_log_error("write(%d, %p, %d) failed with ret: %ld and errno: %d\n", fd, buf, count, ret, errno);
            // dump_backtrace(gettid());
        }
        // this should never happen outside emu
        assert(errno != EFAULT);
    }
    return ret;
}

/*
// thread kill (send signal to a thread)
int tgkill(int tgid, int tid, int sig) {
    int ret;
    emu_log_debug("tgkill tgid: %d tid: %d sig: %d\n", tgid, tid, sig);
    ret = syscall(__NR_tgkill, tgid, tid, sig);
    if (ret != 0) {
        switch(ret) {
        case EINVAL: emu_abort("EINVAL: An invalid thread ID, thread group ID, or signal was specified."); break;
        case EPERM:  emu_abort("EPERM  Permission denied."); break;
        case ESRCH:  emu_abort("ESRCH  No process with the specified thread ID (and thread group ID) exists.");
        default:     emu_abort("Unknown errno %d", ret);
        }
    }
    return ret;
}
*/

#if 1
inline
emu_thread_t* emu_tls_get() {
    void**  tls = (void**)__get_tls();
    return tls[TLS_SLOT_EMU_THREAD];
}

inline
void emu_tls_set(emu_thread_t *emu) {
    void**  tls = (void**)__get_tls();
    tls[TLS_SLOT_EMU_THREAD] = emu;
}
void emu_init_proc_mem() {
    emu_global->mem_fd = open("/proc/self/mem", O_RDWR);

    if (!emu_global->mem_fd) {
        emu_abort("Can't open /proc/self/mem\n");
    }
}

#ifdef NO_TAINT
inline
uint8_t mem_read8(uint32_t addr) {
    return *(uint8_t*)addr;
}

inline
uint16_t mem_read16(uint32_t addr) {
    return *(uint16_t*)addr;
}

inline
uint32_t mem_read32(uint32_t addr) {
    return *(uint32_t*)addr;
}

inline
uint8_t mem_write8(uint32_t addr, uint8_t val) {
    return *(uint8_t*)addr = val;
}

inline
uint16_t mem_write16(uint32_t addr, uint16_t val) {
    return *(uint16_t*)addr = val;
}

inline
uint32_t mem_write32(uint32_t addr, uint32_t val) {
    return *(uint32_t*)addr = val;
}
#else
/* READ */
inline
uint8_t mem_read8(uint32_t addr) {
    uint8_t val = 0;
    int32_t fd = emu_global->mem_fd;
    assert(fd);
    ssize_t bytes;
#ifdef EMU_MEM_PREAD
    bytes = pread(fd, &val, sizeof(val), addr);
#else
    off_t off;
    off = lseek(fd, addr, SEEK_SET);
    assert(off == (off_t)addr);
    bytes = read(fd, &val, sizeof(val));
#endif
    assert(bytes == sizeof(val));
    return val;
}

inline
uint16_t mem_read16(uint32_t addr) {
    uint16_t val = 0;
    int32_t fd = emu_global->mem_fd;
    assert(fd);
    ssize_t bytes;
#ifdef EMU_MEM_PREAD
    bytes = pread(fd, &val, sizeof(val), addr);
#else
    off_t off;
    off = lseek(fd, addr, SEEK_SET);
    assert(off == (off_t)addr);
    bytes = read(fd, &val, sizeof(val));
#endif
    assert(bytes == sizeof(val));
    return val;
}

inline
uint32_t mem_read32(uint32_t addr) {
    uint32_t val = 0;
    int32_t fd = emu_global->mem_fd;
    assert(fd);
    ssize_t bytes;
#ifdef EMU_MEM_PREAD
    bytes = pread(fd, &val, sizeof(val), addr);
#else
    off_t off;
    off = lseek(fd, addr, SEEK_SET);
    assert(off == (off_t)addr);
    bytes = read(fd, &val, sizeof(val));
#endif
    assert(bytes == sizeof(val));
    return val;
}

/* WRITE */
inline
uint8_t mem_write8(uint32_t addr, uint8_t val) {
    int32_t fd = emu_global->mem_fd;
    assert(fd);
    ssize_t bytes;
#ifdef EMU_MEM_PREAD
    bytes = pwrite(fd, &val, sizeof(val), addr);
#else
    off_t off;
    off = lseek(fd, addr, SEEK_SET);
    assert(off == (off_t)addr);
    bytes = write(fd, &val, sizeof(val));
#endif
    assert(bytes == sizeof(val));
    return val;
}

inline
uint16_t mem_write16(uint32_t addr, uint16_t val) {
    int32_t fd = emu_global->mem_fd;
    assert(fd);
    ssize_t bytes;
#ifdef EMU_MEM_PREAD
    bytes = pwrite(fd, &val, sizeof(val), addr);
#else
    off_t off;
    off = lseek(fd, addr, SEEK_SET);
    assert(off == (off_t)addr);
    bytes = write(fd, &val, sizeof(val));
#endif
    assert(bytes == sizeof(val));
    return val;
}

inline
uint32_t mem_write32(uint32_t addr, uint32_t val) {
    int32_t fd = emu_global->mem_fd;
    assert(fd);
    ssize_t bytes;
#ifdef EMU_MEM_PREAD
    bytes = pwrite(fd, &val, sizeof(val), addr);
#else
    off_t off;
    off = lseek(fd, addr, SEEK_SET);
    assert(off == (off_t)addr);
    bytes = write(fd, &val, sizeof(val));
#endif
    assert(bytes == sizeof(val));
    return val;
}
#endif  /* NO_TAINT */

void *emu_alloc(size_t size) {
    assert(size > 0);
    void *ret = mmap(NULL, size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                     -1, 0);
    if (ret == MAP_FAILED) {
        emu_abort("mmap");
    }

    emu_log_debug("%s: %x - %x length: %5d\n", __func__, (intptr_t)ret, (intptr_t)ret + size, size);
    return ret;
}

int emu_free(void *addr, size_t size) {
    assert(addr && size > 0);
    int ret = munmap(addr, size);
    if (ret) {
        emu_abort("munmap");
    }
    emu_log_debug("%s: %x - %x length: %5d\n", __func__, (intptr_t)addr, (intptr_t)addr + size, size);
    return ret;
}

static
ssize_t emu_memcpy(void *dst, const void *src, size_t n) {
    assert(emu_global->mem_fd);
    assert(n > 0);

    emu_log_debug("%s: dst: %p src: %p n: %d\n", __func__, dst, src, n);

    // pwrite() writes up to count bytes from the buffer starting at buf to the
    // file descriptor fd at offset offset. The file offset is not changed.
    ssize_t ret = pwrite(emu_global->mem_fd, src, n, (off_t)dst);
    if (ret != -1 && (size_t)ret != n) {
        emu_abort("pwrite");
    }
    return ret;
}

// taint-aware memcpy, defaults to vanilla memcpy when no taint
void emu_memcpy_safe(void *dst, const void *src, size_t n) {
    if (!emu_running()) {
        uint32_t taint_dst = emu_get_taint_array((uint32_t)dst, n);
        uint32_t taint_src = emu_get_taint_array((uint32_t)src, n);
        uint32_t tag = taint_dst | taint_src;
        if (tag) {
            (void)emu_memcpy(dst, src, n);
            emu_set_taint_array((uint32_t)dst, tag, n);
        } else {
            (void)memcpy(dst, src, n);
        }
    } else {
        (void)memcpy(dst, src, n);
    }
}
/* copied from system/core/liblog/logprint.c */
char filterPriToChar(android_LogPriority pri)
{
    switch (pri) {
        case ANDROID_LOG_VERBOSE:       return 'V';
        case ANDROID_LOG_DEBUG:         return 'D';
        case ANDROID_LOG_INFO:          return 'I';
        case ANDROID_LOG_WARN:          return 'W';
        case ANDROID_LOG_ERROR:         return 'E';
        case ANDROID_LOG_FATAL:         return 'F';
        case ANDROID_LOG_SILENT:        return 'S';

        case ANDROID_LOG_DEFAULT:
        case ANDROID_LOG_UNKNOWN:
        default:                        return '?';
    }
}

#define LOG_BUF_SIZE 256
#define LOG_HEADER_SIZE 24
static
int __log_print(int prio, const char *tag, const char *fmt, ...) {
    va_list ap;
    char buf[LOG_BUF_SIZE];

    va_start(ap, fmt);
    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);

    char msg[LOG_HEADER_SIZE];
    snprintf(msg, LOG_HEADER_SIZE, "%d %d %c ", getpid(), gettid(), filterPriToChar(prio));

    int fd = emu_global->trace_fd;

    const int iovcnt = 2;
    struct iovec vec[iovcnt];

    vec[0].iov_base   = (void *) msg;
    vec[0].iov_len    = strlen(msg);
    vec[1].iov_base   = (void *) buf;
    vec[1].iov_len    = strlen(buf);

    ssize_t ret;

    do {
        ret = writev(fd, vec, iovcnt);
    } while (ret < 0 && errno == EINTR);

    assert(ret == (ssize_t)(vec[0].iov_len + vec[1].iov_len));

    return ret;
}
