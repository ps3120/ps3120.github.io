/* Copyright (C) 2025 anonymous

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

// 11.02

export const pthread_offsets = new Map(
  Object.entries({
    pthread_create: 0x20ac0,
    pthread_join: 0x8cf0,
    pthread_barrier_init: 0x26250,
    pthread_barrier_wait: 0x1e610,
    pthread_barrier_destroy: 0x1fd0,
    pthread_exit: 0x193f0,
  }),
);

export const off_kstr = 0x7FC22F;
export const off_cpuid_to_pcpu = 0x212c840; 

export const off_sysent_661 = 0x1109350;
export const jmp_rsi = 0x71A21;

export const patch_elf_loc = "./kpatch/1102.bin"; // Relative to `../../lapse.mjs`
