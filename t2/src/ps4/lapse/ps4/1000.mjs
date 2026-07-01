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

// 10.00, 10.01

export const pthread_offsets = new Map(
  Object.entries({
    pthread_create: 0x29680,
    pthread_join: 0xb820,
    pthread_barrier_init: 0x26f40,
    pthread_barrier_wait: 0x16b30,
    pthread_barrier_destroy: 0xd700,
    pthread_exit: 0x7950,
  }),
);

export const off_kstr = 0x7B5133;
export const off_cpuid_to_pcpu = 0x21e47f0;

export const off_sysent_661 = 0x110A980;
export const jmp_rsi = 0x68B1;

export const patch_elf_loc = "./kpatch/1000.bin"; // Relative to `../../lapse.mjs`
