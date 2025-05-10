/* Copyright (C) 2024-2025 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#include <stddef.h>

#include "types.h"
#include "utils.h"

struct kexec_args {
    u64 entry;
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    u64 arg5;
};

void do_patch(void);
void restore(struct kexec_args *uap);

__attribute__((section (".text.start")))
int kpatch(void *td, struct kexec_args *uap) {
    do_patch();
    restore(uap);
    return 0;
}

void restore(struct kexec_args *uap) {
    u8 *pipe = uap->arg1;
    u8 *pipebuf = uap->arg2;
    for (size_t i = 0; i < 0x18; i++) {
        pipe[i] = pipebuf[i];
    }
    u64 *pktinfo_field = uap->arg3;
    *pktinfo_field = 0;
    u64 *pktinfo_field2 = uap->arg4;
    *pktinfo_field2 = 0;
}

void do_patch(void) {
       const size_t off_fast_syscall = 0x1d0;
    void * const kbase = (void *)rdmsr(0xc0000082) - off_fast_syscall;

    disable_cr0_wp();

    ////////////////////////////////////////////////////////
    // Patch critiche per 9.00
    ////////////////////////////////////////////////////////

    // 1. Disabilita verifica firme kernel (SceVeriPatch)
    write16(kbase, 0x626874, 0x9090); // NOP; NOP

    // 2. Patch syscall handler per bypassare controlli
    write32(kbase, 0x390, 0);         // is_invalid_syscall = 0
    write16(kbase, 0x4b5, 0x9090);    // NOP check 1
    write16(kbase, 0x4b9, 0x9090);    // NOP check 2
    write8(kbase, 0x4c2, 0xeb);       // JMP do_syscall

    // 3. Abilita mappature RWX in sys_mmap/sys_mprotect
    write8(kbase, 0x16632A, 0x37);    // max_protection = RWX
    write8(kbase, 0x16632D, 0x37);
    write32(kbase, 0x80B8B, 0);       // Disabilita controllo vm_map_protect

    // 4. Dynlib: permette dlsym ovunque
    write8(kbase, 0x23B67F, 0xeb);    // JMP dopo cmp eax, 0x4000000
    write32(kbase, 0x221b40, 0xC3C03148); // xor eax, eax; ret

    // 5. Bypassa controllo UID in sys_setuid
    write8(kbase, 0x1A06, 0xeb);      // JMP dopo priv_check_cred

    ////////////////////////////////////////////////////////
    // Syscall 11 personalizzata (kexec)
    ////////////////////////////////////////////////////////
    
    // Syscall table entry per 9.00 (sysent[11])
    const size_t offset_sysent_11 = 0x1100520;
    
    // .sy_narg = 6
    write32(kbase, offset_sysent_11, 6);
    
    // .sy_call = gadget "jmp [rsi]" (confermato per 9.00)
    write64(kbase, offset_sysent_11 + 8, kbase + 0xE629C);
    
    // .sy_thrcnt = SY_THR_STATIC
    write32(kbase, offset_sysent_11 + 0x2c, 1);

    enable_cr0_wp();
}

