import { version } from "../utils.mjs";

export class Offsets {
  static get current() {
    if (Offsets._current === undefined) {
      let matched = false;
      for (const type of Offsets.types) {
        if (type.version === version.toString()) {
          matched = true;
          Offsets._current = new type();
          break;
        }
      }

      if (!matched) {
        throw new Error(`Unable to find impl for ${version} !!`);
      }
    }

    return Offsets._current;
  }
}

//added only necessary gadgets
class V800 extends Offsets {
  static get version() { return "8.00"; }
  get wk_CSSFontFace_sizeof() { return 0xb8; }                                  
  get wk_CSSFontFace_m_families() { return 0x10; }                              
  get wk_CSSFontFace_m_featureSettings_m_buffer() { return 0x28; }               
  get wk_CSSFontFace_m_featureSettings_m_size() { return 0x30; }                 
  get wk_CSSFontFace_m_featureSettings_m_capacity() { return 0x34; }             
  get wk_CSSFontFace_m_clients() { return 0x58; }                                
  get wk_CSSFontFace_m_wrapper() { return 0x60; }                               
  get wk_CSSFontFace_m_status() { return 0x7a; }                                
  get wk_CSSFontFace_m_thread() { return 0xa8; }
	
}


class V801 extends V800 {
	static get version() { return "8.01" }
}


class V803 extends V800 {
	static get version() { return "8.03" }
}



//added only necessary gadgets
class V850 extends Offsets {
  static get version() { return "8.50"; }
  get wk_CSSFontFace_sizeof() { return 0xb8; }                                  
  get wk_CSSFontFace_m_families() { return 0x10; }                               
  get wk_CSSFontFace_m_featureSettings_m_buffer() { return 0x28; }              
  get wk_CSSFontFace_m_featureSettings_m_size() { return 0x30; }                
  get wk_CSSFontFace_m_featureSettings_m_capacity() { return 0x34; }             
  get wk_CSSFontFace_m_clients() { return 0x58; }                               
  get wk_CSSFontFace_m_wrapper() { return 0x60; }                                
  get wk_CSSFontFace_m_status() { return 0x7a; }                                
  get wk_CSSFontFace_m_thread() { return 0xa8; }                              
}


class V900 extends Offsets {
  static get version() { return "9.00"; }
  get wk_CSSFontFace_sizeof() { return 0xb8; }
  get wk_CSSFontFace_m_families() { return 0x10; }
  get wk_CSSFontFace_m_featureSettings_m_buffer() { return 0x28; }
  get wk_CSSFontFace_m_featureSettings_m_size() { return 0x30; }
  get wk_CSSFontFace_m_featureSettings_m_capacity() { return 0x34; }
  get wk_CSSFontFace_m_clients() { return 0x60; }
  get wk_CSSFontFace_m_wrapper() { return 0x68; }
  get wk_CSSFontFace_m_status() { return 0x82; }
  get wk_CSSFontFace_m_thread() { return 0xa8; }

}

class V903 extends V900 {
  static get version() { return "9.03" }
}

class V904 extends V900 {
  static get version() { return "9.04" }
}

class V950 extends Offsets {
  static get version() { return "9.50"; }
  get wk_CSSFontFace_sizeof() { return 0xb8; }
  get wk_CSSFontFace_m_families() { return 0x10; }
  get wk_CSSFontFace_m_featureSettings_m_buffer() { return 0x28; }
  get wk_CSSFontFace_m_featureSettings_m_size() { return 0x30; }
  get wk_CSSFontFace_m_featureSettings_m_capacity() { return 0x34; }
  get wk_CSSFontFace_m_clients() { return 0x60; }
  get wk_CSSFontFace_m_wrapper() { return 0x68; }
  get wk_CSSFontFace_m_status() { return 0x82; }
  get wk_CSSFontFace_m_thread() { return 0xa8; }
  get wk_RET() { return 0x11d0746n; }
  get wk_LEAVE_RET() { return 0x147d37n; }
  get wk_POP_R8_RET() { return 0x1e49663n; }
  get wk_POP_R9_RET() { return 0xaaad51n; }
  get wk_POP_R11_RET() { return 0x520109n; }
  get wk_POP_R12_RET() { return 0x1648e45n; }
  get wk_POP_R13_RET() { return 0x18fc4c1n; }
  get wk_POP_R14_RET() { return 0x28c900n; }
  get wk_POP_R15_RET() { return 0x1619dbn; }
  get wk_POP_RAX_RET() { return 0x1314102n; }
  get wk_POP_RBP_RET() { return 0x1b8da18n; }
  get wk_POP_RBX_RET() { return 0x13730n; }
  get wk_POP_RCX_RET() { return 0x12b4c45n; }
  get wk_POP_RDI_RET() { return 0xbff06dn; }
  get wk_POP_RDX_RET() { return 0x11f95e1n; }
  get wk_POP_RSI_RET() { return 0x111f543n; }
  get wk_POP_RSP_RET() { return 0xa3f6e0n; }
  get wk_MOV_RAX_RCX_RET() { return 0x2810fn; }
  get wk_MOV_QWORD_PTR_RDI_RAX_RET() { return 0x191a08en; }
  get wk_MOV_RAX_QWORD_PTR_RDI_RET() { return 0x1e84910n; }
  get wk_PUSH_RAX_POP_RBP_RET() { return 0x1d3677bn; }
  get wk_PUSH_RAX_PUSH_RBP_RET() { return 0x2c7bd07n; }
  get wk_POP_RAX_MOV_RAX_QWORD_PTR_RDI_JMP_QWORD_PTR_RAX_8() { return 0x16a4e82n; }
  get wk_PUSH_RBP_MOV_RBP_RSP_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_20() { return 0x1e41210n; }
  get wk_MOV_RSI_QWORD_PTR_RAX_10_CALL_QWORD_PTR_RAX_18() { return 0x1f02710n; }
  get wk_PUSH_RSI_JMP_QWORD_PTR_RAX() { return 0x2c06ef1n; }
  get wk_MOV_RDI_RSI_30_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_38() { return 0xedf8b4n; }
  get wk_expm1_builtin() { return 0x0n; }// todo
  get wk___imp___error() { return 0x2F91CE0; }
  get wk___imp_strerror() { return 0x2F91D00; }
  get k__error() { return 0xBB60n; }
  get c_strerror() { return 0x397D0n; }
}

class V951 extends V950 {
  static get version() { return "9.51" }
}

class V960 extends V950 {
  static get version() { return "9.60"; }
}

class V1000 extends Offsets {
  static get version() { return "10.00"; }
  get wk_CSSFontFace_sizeof() { return 0xb8; }
  get wk_CSSFontFace_m_families() { return 0x10; }
  get wk_CSSFontFace_m_featureSettings_m_buffer() { return 0x28; }
  get wk_CSSFontFace_m_featureSettings_m_size() { return 0x30; }
  get wk_CSSFontFace_m_featureSettings_m_capacity() { return 0x34; }
  get wk_CSSFontFace_m_clients() { return 0x58; }
  get wk_CSSFontFace_m_wrapper() { return 0x60; }
  get wk_CSSFontFace_m_status() { return 0x7a; }
  get wk_CSSFontFace_m_thread() { return 0xa8; }
  get wk_RET() { return 0x25da7c1n; }
  get wk_LEAVE_RET() { return 0x2e4ce35n; }
  get wk_POP_R8_RET() { return 0x202b671n; }
  get wk_POP_R9_RET() { return 0x14420c6n; }
  get wk_POP_R10_RET() { return 0n; } // todo
  get wk_POP_R11_RET() { return 0n; } // todo
  get wk_POP_R12_RET() { return 0x1d83283n; }
  get wk_POP_R13_RET() { return 0x1bfaa4fn; }
  get wk_POP_R14_RET() { return 0x2563be3n; }
  get wk_POP_R15_RET() { return 0x220eea8n; }
  get wk_POP_RAX_RET() { return 0x23eba7en; }
  get wk_POP_RBP_RET() { return 0x66e6cfn; }
  get wk_POP_RBX_RET() { return 0x13035d7n; }
  get wk_POP_RCX_RET() { return 0x741bf6n; }
  get wk_POP_RDI_RET() { return 0x3306ffdn; }
  get wk_POP_RDX_RET() { return 0x3334535n; }
  get wk_POP_RSI_RET() { return 0x2348ben; }
  get wk_POP_RSP_RET() { return 0x1454677n; }
  get wk_MOV_RAX_RSI_RET() { return 0x2210490n; }
  get wk_MOV_QWORD_PTR_RDI_RAX_RET() { return 0x2082567n; }
  get wk_MOV_RAX_QWORD_PTR_RDI_RET() { return 0x1fea957n; }
  get wk_PUSH_RAX_POP_RBP_RET() { return 0x1fbba1en; }
  get wk_PUSH_RAX_PUSH_RBP_RET() { return 0x146c55cn; }
  get wk_PUSH_RBP_POP_RSI_RET() { return 0x222997n; }
  get wk_POP_RAX_MOV_RAX_QWORD_PTR_RDI_JMP_QWORD_PTR_RAX_40() { return 0x8e3ad3n; }
  get wk_PUSH_RBP_MOV_RBP_RSP_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_28() { return 0x179d190n; }
  get wk_MOV_RSI_QWORD_PTR_RAX_10_CALL_QWORD_PTR_RAX_18() { return 0x20e21f0n; }
  get wk_PUSH_RSI_JMP_QWORD_PTR_RAX() { return 0x29787c2n; }
  get wk_MOV_RDI_RSI_30_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_38() { return 0x124c8d4n; }
  get wk_expm1_builtin() { return 0x218bb70n; }
  get wk___imp___error() { return 0x36d1bf0; }
  get wk___imp_strerror() { return 0x36d1c20; }
  get k__error() { return 0x14f40n; }
  get c_strerror() { return 0x10d00n; }
}

class V1001 extends V1000 {
  static get version() { return "10.01" }
}

class V1050 extends Offsets {
  static get version() { return "10.50"; }
  get wk_CSSFontFace_sizeof() { return 0xb8; }
  get wk_CSSFontFace_m_families() { return 0x10; }
  get wk_CSSFontFace_m_featureSettings_m_buffer() { return 0x28; }
  get wk_CSSFontFace_m_featureSettings_m_size() { return 0x30; }
  get wk_CSSFontFace_m_featureSettings_m_capacity() { return 0x34; }
  get wk_CSSFontFace_m_clients() { return 0x58; }
  get wk_CSSFontFace_m_wrapper() { return 0x60; }
  get wk_CSSFontFace_m_status() { return 0x7a; }
  get wk_CSSFontFace_m_thread() { return 0xa8; }
  get wk_RET() { return 0x134bd80n; }
  get wk_LEAVE_RET() { return 0x190dd93n; }
  get wk_POP_R8_RET() { return 0x199b7a2n; }
  get wk_POP_R9_RET() { return 0x1e35046n; }
  get wk_POP_R10_RET() { return 0x0n; } // todo
  get wk_POP_R11_RET() { return 0x9d6a43n; }
  get wk_POP_R12_RET() { return 0x1ab3587n; }
  get wk_POP_R13_RET() { return 0x1057705n; }
  get wk_POP_R14_RET() { return 0x188196en; }
  get wk_POP_R15_RET() { return 0x129fa31n; }
  get wk_POP_RAX_RET() { return 0x25bc260n; }
  get wk_POP_RBP_RET() { return 0x257514cn; }
  get wk_POP_RBX_RET() { return 0x1fe45ban; }
  get wk_POP_RCX_RET() { return 0x25b439bn; }
  get wk_POP_RDI_RET() { return 0x1a33793n; }
  get wk_POP_RDX_RET() { return 0x1d3d41bn; }
  get wk_POP_RSI_RET() { return 0x289fa09n; }
  get wk_POP_RSP_RET() { return 0x206309dn; }
  get wk_MOV_RAX_RCX_RET() { return 0x15f2c66n; }
  get wk_MOV_QWORD_PTR_RDI_RAX_RET() { return 0x1d300ebn; }
  get wk_MOV_RAX_QWORD_PTR_RDI_RET() { return 0x9f0f27n; }
  get wk_PUSH_RAX_POP_RBP_RET() { return 0x1ffc6cfn; }
  get wk_PUSH_RAX_PUSH_RBP_RET() { return 0x0n; } // todo
  get wk_PUSH_RBP_POP_RAX_RET() { return 0xb3b5d5n; } // push rbp; rol ch, 0xfb; pop rax; ret; todo
  get wk_POP_RAX_MOV_RAX_QWORD_PTR_RDI_JMP_QWORD_PTR_RAX_8() { return 0x0n; } // todo (no [rax + 8])
  get wk_PUSH_RBP_MOV_RBP_RSP_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_20() { return 0x0n; } //todo maybe 0x1602391?
  get wk_MOV_RSI_QWORD_PTR_RAX_10_CALL_QWORD_PTR_RAX_18() { return 0x20e4350n; }
  get wk_PUSH_RSI_JMP_QWORD_PTR_RAX() { return 0x299224en; }
  get wk_MOV_RDI_RSI_30_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_38() { return 0x1368714n; }
  get wk_expm1_builtin() { return 0x0n; }// todo
  get wk___imp___error() { return 0x36d5be8; }
  get wk___imp_strerror() { return 0x36D5C18; }
  get k__error() { return 0x14F40n; }
  get c_strerror() { return 0x10d00n; }

}

class V1070 extends V1050 {
  static get version() { return "10.70"; }
}

class V1071 extends V1070 {
  static get version() { return "10.71" }
}

class V1100 extends Offsets {
  static get version() { return "11.00"; }
  get wk_CSSFontFace_sizeof() { return 0xb8; }
  get wk_CSSFontFace_m_families() { return 0x10; }
  get wk_CSSFontFace_m_featureSettings_m_buffer() { return 0x28; }
  get wk_CSSFontFace_m_featureSettings_m_size() { return 0x30; }
  get wk_CSSFontFace_m_featureSettings_m_capacity() { return 0x34; }
  get wk_CSSFontFace_m_clients() { return 0x58; }
  get wk_CSSFontFace_m_wrapper() { return 0x60; }
  get wk_CSSFontFace_m_status() { return 0x7a; }
  get wk_CSSFontFace_m_thread() { return 0xa0; }
  get wk_RET() { return 0x147aac6n; }
  get wk_LEAVE_RET() { return 0x13c37a2n; }
  get wk_POP_R8_RET() { return 0x1fb5f32n; }
  get wk_POP_R9_RET() { return 0x1868f26n; }
  get wk_POP_R10_RET() { return 0x0n; }// todo
  get wk_POP_R11_RET() { return 0x0n; } // todo
  get wk_POP_R12_RET() { return 0x90d803n; }
  get wk_POP_R13_RET() { return 0x1ccd8bfn; }
  get wk_POP_R14_RET() { return 0x22189c2n; }
  get wk_POP_R15_RET() { return 0x1c502f4n; }
  get wk_POP_RAX_RET() { return 0x63c928n; }
  get wk_POP_RBP_RET() { return 0x25ea572n; }
  get wk_POP_RBX_RET() { return 0x862407n; }
  get wk_POP_RCX_RET() { return 0xb68425n; }
  get wk_POP_RDI_RET() { return 0x1b1b60an; }
  get wk_POP_RDX_RET() { return 0x1eb8b52n; }
  get wk_POP_RSI_RET() { return 0x1f15bfdn; }
  get wk_POP_RSP_RET() { return 0x2b42fd4n; }
  get wk_MOV_RAX_RCX_RET() { return 0x1c9bea6n; }
  get wk_MOV_QWORD_PTR_RDI_RAX_RET() { return 0x1b890afn; }
  get wk_MOV_RAX_QWORD_PTR_RDI_RET() { return 0x1183340n; }
  get wk_PUSH_RAX_POP_RBP_RET() { return 0x1fe83a9n; }
  get wk_PUSH_RAX_PUSH_RBP_RET() { return 0x0n; } // todo
  get wk_PUSH_RBP_POP_RAX_RET() { return 0x0n; } // push rbp; rol ch, 0xfb; pop rax; ret; todo
  get wk_POP_RAX_MOV_RAX_QWORD_PTR_RDI_JMP_QWORD_PTR_RAX_8() { return 0x0n; } //todo, no 8. but 10 at 0x70c693
  get wk_PUSH_RBP_MOV_RBP_RSP_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_20() { return 0x0n; }// todo
  get wk_MOV_RSI_QWORD_PTR_RAX_10_CALL_QWORD_PTR_RAX_18() { return 0x20ea440n; }//
  get wk_PUSH_RSI_JMP_QWORD_PTR_RAX() { return 0x0n; } // todo
  get wk_MOV_RDI_RSI_30_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_38() { return 0x1c60dc4n; }
  get wk_expm1_builtin() { return 0x0n; }// todo
  get wk___imp___error() { return 0x36e1c68; }
  get wk___imp_strerror() { return 0x36e1c98; }
  get k__error() { return 0x3370n; }
  get c_strerror() { return 0x10d00n; }
}

class V1102 extends Offsets {
  static get version() { return "11.02"; }
  get wk_CSSFontFace_sizeof() { return 0xb8; }
  get wk_CSSFontFace_m_families() { return 0x10; }
  get wk_CSSFontFace_m_featureSettings_m_buffer() { return 0x28; }
  get wk_CSSFontFace_m_featureSettings_m_size() { return 0x30; }
  get wk_CSSFontFace_m_featureSettings_m_capacity() { return 0x34; }
  get wk_CSSFontFace_m_clients() { return 0x40; }
  get wk_CSSFontFace_m_wrapper() { return 0x68; }
  get wk_CSSFontFace_m_status() { return 0x7a; }
  get wk_CSSFontFace_m_thread() { return 0xa0; }
  get wk_RET() { return 0x147aac6n; }
  get wk_LEAVE_RET() { return 0x13c37a2n; }
  get wk_POP_R8_RET() { return 0x01fb5f42n; }
  get wk_POP_R9_RET() { return 0x1868f26n; }
  get wk_POP_R10_RET() { return 0x0n; }// todo
  get wk_POP_R11_RET() { return 0x0n; } // todo
  get wk_POP_R12_RET() { return 0x90d813n; }
  get wk_POP_R13_RET() { return 0x1ccd8bfn; }
  get wk_POP_R14_RET() { return 0x15ed130n; }
  get wk_POP_R15_RET() { return 0x1c502f4n; }
  get wk_POP_RAX_RET() { return 0x2c4899dn; }
  get wk_POP_RBP_RET() { return 0x2429641n; }
  get wk_POP_RBX_RET() { return 0x1ec394en; }
  get wk_POP_RCX_RET() { return 0xb68425n; }
  get wk_POP_RDI_RET() { return 0x1b1b60an; }
  get wk_POP_RDX_RET() { return 0x1eb8b52n; }
  get wk_POP_RSI_RET() { return 0x1e9024en; }
  get wk_POP_RSP_RET() { return 0x32b2e15n; }
  get wk_MOV_RAX_RCX_RET() { return 0x1c9bea6n; }
  get wk_MOV_QWORD_PTR_RDI_RAX_RET() { return 0x1b890afn; }
  get wk_MOV_RAX_QWORD_PTR_RDI_RET() { return 0x01183340n; }
  get wk_PUSH_RAX_POP_RBP_RET() { return 0x1fe83b9n; }
  get wk_PUSH_RAX_PUSH_RBP_RET() { return 0x0n; } // todo
  get wk_PUSH_RBP_POP_RAX_RET() { return 0x0n; } // push rbp; rol ch, 0xfb; pop rax; ret; todo
  get wk_POP_RAX_MOV_RAX_QWORD_PTR_RDI_JMP_QWORD_PTR_RAX_8() { return 0x0n; } //todo, no 8. but 10 at 0x70c693
  get wk_PUSH_RBP_MOV_RBP_RSP_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_20() { return 0x0n; }// todo
  get wk_MOV_RSI_QWORD_PTR_RAX_10_CALL_QWORD_PTR_RAX_18() { return 0x20ea450n; }
  get wk_PUSH_RSI_JMP_QWORD_PTR_RAX() { return 0x0n; } // todo
  get wk_MOV_RDI_RSI_30_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_38() { return 0x192f124n; }
  get wk_expm1_builtin() { return 0x0n; }// todo
  get wk___imp___error() { return 0x36e1c68; }
  get wk___imp_strerror() { return 0x36e1c98; }
  get k__error() { return 0x3370n; }
  get c_strerror() { return 0x10d00n; }
}

class V1150 extends Offsets {
  static get version() { return "11.50"; }
  get wk_CSSFontFace_sizeof() { return 0xb8; }
  get wk_CSSFontFace_m_families() { return 0x10; }
  get wk_CSSFontFace_m_featureSettings_m_buffer() { return 0x28; }
  get wk_CSSFontFace_m_featureSettings_m_size() { return 0x30; }
  get wk_CSSFontFace_m_featureSettings_m_capacity() { return 0x34; }
  get wk_CSSFontFace_m_clients() { return 0x50; }
  get wk_CSSFontFace_m_wrapper() { return 0x0; }// todo
  get wk_CSSFontFace_m_status() { return 0x48; }
  get wk_CSSFontFace_m_thread() { return 0x60; }
  get wk_RET() { return 0xe67c21n; }
  get wk_LEAVE_RET() { return 0x1f1b53bn; }
  get wk_POP_R8_RET() { return 0x23bb4bdn; }
  get wk_POP_R9_RET() { return 0x1c2cda1n; }
  get wk_POP_R10_RET() { return 0x1d09d1bn; }
  get wk_POP_R11_RET() { return 0x12a4041n; }
  get wk_POP_R12_RET() { return 0x222ef3bn; }
  get wk_POP_R13_RET() { return 0x1ef72ban; }
  get wk_POP_R14_RET() { return 0x1d5eab8n; }
  get wk_POP_R15_RET() { return 0x16595a1n; }
  get wk_POP_RAX_RET() { return 0x440ee5n; }
  get wk_POP_RBP_RET() { return 0x29db5cdn; }
  get wk_POP_RBX_RET() { return 0x23428ban; }
  get wk_POP_RCX_RET() { return 0x22d097bn; }
  get wk_POP_RDI_RET() { return 0x1f5a605n; }
  get wk_POP_RDX_RET() { return 0x184fd97n; }
  get wk_POP_RSI_RET() { return 0x265be3fn; }
  get wk_POP_RSP_RET() { return 0x2ac57dfn; }
  get wk_MOV_RAX_RCX_RET() { return 0x140fd86n; }
  get wk_MOV_QWORD_PTR_RDI_RAX_RET() { return 0x211774en; }
  get wk_MOV_RAX_QWORD_PTR_RDI_RET() { return 0x161e168n; }
  get wk_PUSH_RAX_POP_RBP_RET() { return 0x1284321; }
  get wk_PUSH_RAX_PUSH_RBP_RET() { return 0x0n; } // todo
  get wk_PUSH_RBP_POP_RAX_RET() { return 0x0n; } // push rbp; rol ch, 0xfb; pop rax; ret; todo
  get wk_POP_RAX_MOV_RAX_QWORD_PTR_RDI_JMP_QWORD_PTR_RAX_8() { return 0x0n; } //todo, no 8. but 10 at 0x70c693
  get wk_PUSH_RBP_MOV_RBP_RSP_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_20() { return 0xd406f0n; }
  get wk_MOV_RSI_QWORD_PTR_RAX_10_CALL_QWORD_PTR_RAX_18() { return 0x24bc149n; }
  get wk_PUSH_RSI_JMP_QWORD_PTR_RAX() { return 0x0325291an; }
  get wk_MOV_RDI_RSI_30_MOV_RAX_QWORD_PTR_RDI_CALL_QWORD_PTR_RAX_38() { return 0x384434n; }
  get wk_expm1_builtin() { return 0x0n; }// todo
  get wk___imp___error() { return 0x3CBCC98; }
  get wk___imp_strerror() { return 0x3CBCCA8; }
  get k__error() { return 0x183C0n; }
  get c_strerror() { return 0x10d00n; }

}


Offsets._current = Offsets._current || undefined;
Offsets.types = [V800,V801,V803,V850,V900, V903, V904, V950, V951, V960, V1000, V1001, V1050, V1070, V1071, V1100, V1102, V1150];