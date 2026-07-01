import { version } from "../utils.mjs";

const offset_map = {
  9: {
    0: {
      wk_CSSFontFace_sizeof: 0xb8,
      wk_CSSFontFace_m_families: 0x10,
      wk_CSSFontFace_m_featureSettings_m_buffer: 0x28,
      wk_CSSFontFace_m_featureSettings_m_size: 0x30,
      wk_CSSFontFace_m_featureSettings_m_capacity: 0x34,
      wk_CSSFontFace_m_clients: 0x60,
      wk_CSSFontFace_m_wrapper: 0x68,
      wk_CSSFontFace_m_status: 0x82,
      wk_CSSFontFace_m_thread: 0xa8, 
      wk_FontFace_m_backing: 0x28,
      wk_TypedArray_flags: 0x1c,
      wk_ArrayBuffer_m_contents_m_sizeInBytes: 0x24,
      wk_RET: 0x2bf0769n,
      wk_LEAVE_RET: 0x220a168n,
      wk_POP_R8_RET: 0x1e262f8n,
      wk_POP_R9_RET: 0x12a7b96n,
      wk_POP_R10_RET: 0x125abffn,
      wk_POP_R11_RET: 0x1c33581n,
      wk_POP_R12_RET: 0x17c39e1n,
      wk_POP_R13_RET: 0x202adebn,
      wk_POP_R14_RET: 0x2105ec1n,
      wk_POP_R15_RET: 0x1c24b31n,
      wk_POP_RAX_RET: 0x1e67954n,
      wk_POP_RBP_RET: 0x685e6en,
      wk_POP_RBX_RET: 0x4d6758n,
      wk_POP_RCX_RET: 0x2c09fcdn,
      wk_POP_RDI_RET: 0x13c9c15n,
      wk_POP_RDX_RET: 0x155683bn,
      wk_POP_RSI_RET: 0x2bf0851n,
      wk_POP_RSP_RET: 0x685d81n,
      wk_MOV_RAX_RCX_RET: 0x2008fa0n,
      wk_MOV_QWORD_PTR_RDI_RAX_RET: 0x1eb1f1bn,
      wk_MOV_RAX_QWORD_PTR_RDI_RET: 0x16ba6f0n,
      wk_PUSH_RAX_POP_RBP_RET: 0x16d5cccn,
      wk_PUSH_RAX_PUSH_RBP_RET: 0x29ced40n,
      wk_PUSH_RBP_POP_RAX_RET: 0xb3b5d5n, // push rbp; rol ch, 0xfb; pop rax; ret;
      wk_POP_RAX_MOV_RAX_QWORD_PTR_RDI_JMP_QWORD_PTR_RAX_8: 0x143a842n,
      wk_PUSH_RBP_MOV_RBP_RSP_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_20: 0x141d420n,
      wk_MOV_RSI_QWORD_PTR_RAX_10_CALL_QWORD_PTR_RAX_18: 0x1f0d7e0n,
      wk_PUSH_RSI_JMP_QWORD_PTR_RAX: 0x294c0e2n,
      wk_MOV_RDI_RSI_30_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_38: 0xf33be4n,
      wk_expm1_builtin: 0x1d23560n,
      wk___imp___error: 0x2f4a4d0,
      wk___imp_strerror: 0x2f4a520,
      k__error: 0xcb80n,
      c_strerror: 0x394f0n,
    },
    0x50: {
      wk_expm1_builtin: 0xd05b0n,
      wk___imp___error: 0x2f91ce0,
      wk___imp_strerror: 0x2f91d00,
      k__error: 0xbb60n,
      c_strerror: 0x357d0n,
    }
  },
  10: {
    0: {
      wk_CSSFontFace_m_clients: 0x58,
      wk_CSSFontFace_m_wrapper: 0x60,
      wk_CSSFontFace_m_status: 0x7a,
      wk_FontFace_m_backing: 0x30,
      wk_TypedArray_flags: 0x20,
      wk_ArrayBuffer_m_contents_m_sizeInBytes: 0x28,
      wk_expm1_builtin: 0x218bb70n,
      wk___imp___error: 0x36d1bf0,
      wk___imp_strerror: 0x36d1c20,
      k__error: 0x14f40n,
      c_strerror: 0x10d00n,
    },
    0x50: {
      wk_expm1_builtin: 0x218dcd0n,
      wk___imp___error: 0x36d5be8,
      wk___imp_strerror: 0x36d5c18,
      k__error: 0x1470n,
    }
  },
  11: {
    0: {
      wk_expm1_builtin: 0x2193f30n,
      wk___imp___error: 0x36e1c68,
      wk___imp_strerror: 0x36e1c98,
      k__error: 0x3370n,
    },
    2: {
      wk_expm1_builtin: 0x2193f40n,
    }
  }
}

export const offsets = new Proxy(offset_map, {
  get(target, prop) {
    for (let major = version.major; major >= 0; major--) {
      if (major in target) {
        for (let minor = major === version.major ? version.minor : 0xFF; minor >= 0; minor--) {
          if (minor in target[major] && prop in target[major][minor]) {
            const value = target[major][minor][prop];
            if (value === null) {
              throw new Error(`${prop} offset is not supported for ${version}`);
            }

            return value;
          }
        }
      }
    }

    throw new Error(`${version} has no ${prop} !!`);
  }
});