// Utility function to mimic Python's struct.unpack
function unpack(buffer, format, offset) {
    const view = new DataView(buffer);
    let pos = offset || 0;
    const result = [];

    for (let i = 0; i < format.length; i++) {
        switch (format[i]) {
            case '<': break; // Little-endian, handled by DataView
            case '4s':
                result.push(String.fromCharCode(view.getUint8(pos), view.getUint8(pos + 1), view.getUint8(pos + 2), view.getUint8(pos + 3)));
                pos += 4;
                break;
            case 'B':
                result.push(view.getUint8(pos));
                pos += 1;
                break;
            case 'H':
                result.push(view.getUint16(pos, true));
                pos += 2;
                break;
            case 'I':
                result.push(view.getUint32(pos, true));
                pos += 4;
                break;
            case 'Q':
                result.push(Number(view.getBigUint64(pos, true))); // Convert BigInt to Number for simplicity
                pos += 8;
                break;
            case '2x': pos += 2; break;
            case '4x': pos += 4; break;
            case '8x': pos += 8; break;
            case '32s':
                let bytes = [];
                for (let j = 0; j < 32; j++) {
                    bytes.push(view.getUint8(pos + j).toString(16).padStart(2, '0'));
                }
                result.push(bytes.join('').toUpperCase());
                pos += 32;
                break;
        }
    }
    return result;
}

// Convert number to hex string
function toHex(num) {
    return '0x' + num.toString(16).toUpperCase();
}

// SELF Header Parser
function selfHeader(buffer, output) {
    const [MAGIC, VERSION, MODE, ENDIAN, ATTRIBUTES] = unpack(buffer, '<4s4B', 0);
    output.innerHTML += '\n[SELF Header]\n';
    output.innerHTML += `Magic: ${toHex(MAGIC.charCodeAt(0))}${toHex(MAGIC.charCodeAt(1))}${toHex(MAGIC.charCodeAt(2))}${toHex(MAGIC.charCodeAt(3))}\n`;
    output.innerHTML += `Version: ${VERSION}\n`;
    output.innerHTML += `Mode: ${toHex(MODE)}\n`;
    output.innerHTML += `Endian: ${ENDIAN} (${ENDIAN === 1 ? 'Little Endian' : 'Unknown'})\n`;
    output.innerHTML += `Attributes: ${toHex(ATTRIBUTES)}\n`;

    const [CONTENT_TYPE, KEY_TYPE, , HEADER_SIZE, META_SIZE, FILE_SIZE, ENTRY_COUNT, FLAG] = unpack(buffer, '<2B2x2HQ2H4x', 16);
    output.innerHTML += '\n[SELF Extended Header]\n';
    output.innerHTML += `Content Type: ${toHex(CONTENT_TYPE)}\n`;
    output.innerHTML += `Key Type: ${toHex(KEY_TYPE)}\n`;
    output.innerHTML += `Header Size: ${toHex(HEADER_SIZE)}\n`;
    output.innerHTML += `Meta Size: ${META_SIZE} Bytes\n`;
    output.innerHTML += `File Size: ${FILE_SIZE} Bytes\n`;
    output.innerHTML += `Entry Count: ${ENTRY_COUNT}\n`;
    output.innerHTML += `Flag: ${toHex(FLAG)}\n`;

    return ENTRY_COUNT;
}

// SELF Entry Parser
function selfEntry(entry, buffer, pos, entries, output) {
    const [PROPS, FILE_OFFSET, FILE_SIZE, MEMORY_SIZE] = unpack(buffer, '<4Q', pos);
    output.innerHTML += `\n[SELF Entry #${entry}]\n`;
    output.innerHTML += `Properties: ${toHex(PROPS)}\n`;

    const PROPERTIES = [
        ['Order', 0, 0x1], ['Encrypted', 1, 0x1], ['Signed', 2, 0x1], ['Compressed', 3, 0x1],
        ['Window Bits', 8, 0x7], ['Has Block', 11, 0x1], ['Block Size', 12, 0xF],
        ['Has Digest', 16, 0x1], ['Has Extent', 17, 0x1], ['Has Meta', 20, 0x1],
        ['Segment Index', 20, 0xFFFF]
    ];

    for (const [name, shift, mask] of PROPERTIES) {
        if (name === 'Block Size') {
            const size = ((PROPS >> shift) & mask) !== 0 ? (1 << (12 + ((PROPS >> shift) & mask))) : 0x1000;
            output.innerHTML += `    ${name}: ${toHex(size)}\n`;
        } else {
            output.innerHTML += `    ${name}: ${(PROPS >> shift) & mask}\n`;
        }
    }

    output.innerHTML += `File Offset: ${toHex(FILE_OFFSET)}\n`;
    output.innerHTML += `File Size: ${FILE_SIZE} Bytes\n`;
    output.innerHTML += `Memory Size: ${MEMORY_SIZE} Bytes\n`;

    const entryData = buffer.slice(FILE_OFFSET, FILE_OFFSET + FILE_SIZE);
    entries.push(entryData);

    return FILE_OFFSET + FILE_SIZE;
}

// ELF Header Parser
function elfHeader(buffer, pos, outputBlob, output) {
    const [MAGIC, ARCHITECTURE, ENDIAN, VERSION, OS_ABI, ABI_VERSION, EID_SIZE] = unpack(buffer, '<4s5B6xB', pos);
    output.innerHTML += '\n[ELF Header]\n';
    output.innerHTML += `Magic: ${toHex(MAGIC.charCodeAt(0))}${toHex(MAGIC.charCodeAt(1))}${toHex(MAGIC.charCodeAt(2))}${toHex(MAGIC.charCodeAt(3))}\n`;
    output.innerHTML += `Architecture: ${ARCHITECTURE} (${ARCHITECTURE === 2 ? 'ELF64' : 'Unknown'})\n`;
    output.innerHTML += `Endian: ${ENDIAN} (${ENDIAN === 1 ? 'Little Endian' : 'Unknown'})\n`;
    output.innerHTML += `Version: ${VERSION} (${VERSION === 1 ? 'Current' : 'None'})\n`;
    output.innerHTML += `OS/ABI: ${OS_ABI} (${OS_ABI === 9 ? 'FreeBSD' : 'Unknown'})\n`;
    output.innerHTML += `ABI Version: ${ABI_VERSION}\n`;
    output.innerHTML += `Size: ${EID_SIZE}\n`;

    const elfHeader = new Uint8Array(buffer.slice(pos, pos + 16));
    outputBlob.push(elfHeader);

    const [TYPE, MACHINE, VERSION_EX, ENTRY_POINT_ADDRESS, PROGRAM_HEADER_OFFSET, SECTION_HEADER_OFFSET, FLAG, HEADER_SIZE, PROGRAM_HEADER_SIZE, PROGRAM_HEADER_COUNT, SECTION_HEADER_SIZE, SECTION_HEADER_COUNT, SECTION_HEADER_STRING_INDEX] = unpack(buffer, '<2HI3QI6H', pos + 16);
    output.innerHTML += '\n[ELF Extension Header]\n';
    const TYPES = { 0x0: 'ET_NONE', 0x1: 'ET_REL', 0x2: 'ET_EXEC', 0x3: 'ET_DYN', 0x4: 'ET_CORE', 0xFE00: 'ET_SCE_EXEC', 0xFE0C: 'ET_SCE_STUBLIB', 0xFE10: 'ET_SCE_DYNEXEC', 0xFE18: 'ET_SCE_DYNAMIC' };
    output.innerHTML += `Type: ${toHex(TYPE)} (${TYPES[TYPE] || 'Unknown'})\n`;
    output.innerHTML += `Machine: ${toHex(MACHINE)} (${MACHINE === 0x3E ? 'AMD_X86_64' : 'Unknown'})\n`;
    output.innerHTML += `Version: ${VERSION_EX}\n`;
    output.innerHTML += `Entry Point Address: ${toHex(ENTRY_POINT_ADDRESS)}\n`;
    output.innerHTML += `Program Header Offset: ${toHex(PROGRAM_HEADER_OFFSET)}\n`;
    output.innerHTML += `Section Header Offset: ${toHex(SECTION_HEADER_OFFSET)}\n`;
    output.innerHTML += `Flag: ${toHex(FLAG)}\n`;
    output.innerHTML += `Header Size: ${HEADER_SIZE} Bytes\n`;
    output.innerHTML += `Program Header Size: ${PROGRAM_HEADER_SIZE} Bytes\n`;
    output.innerHTML += `Program Header Count: ${PROGRAM_HEADER_COUNT}\n`;
    output.innerHTML += `Section Header Size: ${SECTION_HEADER_SIZE} Bytes\n`;
    output.innerHTML += `Section Header Count: ${SECTION_HEADER_COUNT}\n`;
    output.innerHTML += `Section Header String Index: ${toHex(SECTION_HEADER_STRING_INDEX)}\n`;

    const elfExtHeader = new Uint8Array(buffer.slice(pos + 16, pos + 16 + 36));
    outputBlob.push(elfExtHeader);

    return [PROGRAM_HEADER_COUNT, SECTION_HEADER_COUNT, pos + 52];
}

// ELF Program Header Parser
function elfProgramHeader(program, buffer, pos, outputBlob, entries, output) {
    const [TYPE, FLAG, OFFSET, VIRTUAL_ADDRESS, PHYSICAL_ADDRESS, FILE_SIZE, MEMORY_SIZE, ALIGNMENT] = unpack(buffer, '<2I6Q', pos);
    const TYPES = { 0x0: 'PT_NULL', 0x1: 'PT_LOAD', 0x2: 'PT_DYNAMIC', 0x3: 'PT_INTERP', 0x4: 'PT_NOTE', 0x5: 'PT_SHLIB', 0x6: 'PT_PHDR', 0x7: 'PT_TLS', 0x6474E550: 'PT_GNU_EH_FRAME', 0x6474E551: 'PT_GNU_STACK', 0x6474E552: 'PT_GNU_RELRO', 0x60000000: 'PT_SCE_RELA', 0x61000000: 'PT_SCE_DYNLIBDATA', 0x61000001: 'PT_SCE_PROCPARAM', 0x61000002: 'PT_SCE_MODULE_PARAM', 0x61000010: 'PT_SCE_RELRO', 0x6FFFFF00: 'PT_SCE_COMMENT', 0x6FFFFF01: 'PT_SCE_LIBVERSION' };
    const FLAGS = { 0x0: 'None', 0x1: 'Execute', 0x2: 'Write', 0x4: 'Read', 0x5: 'Read, Execute', 0x6: 'Read, Write', 0x7: 'Read, Write, Execute' };
    output.innerHTML += `\n[ELF Program Header #${program}]\n`;
    output.innerHTML += `Type: ${toHex(TYPE)} (${TYPES[TYPE] || 'Unknown'})\n`;
    output.innerHTML += `Flag: ${toHex(FLAG)} (${FLAGS[FLAG] || 'Unknown'})\n`;
    output.innerHTML += `Offset: ${toHex(OFFSET)}\n`;
    output.innerHTML += `Virtual Address: ${toHex(VIRTUAL_ADDRESS)}\n`;
    output.innerHTML += `Physical Address: ${toHex(PHYSICAL_ADDRESS)}\n`;
    output.innerHTML += `File Size: ${toHex(FILE_SIZE)}\n`;
    output.innerHTML += `Memory Size: ${toHex(MEMORY_SIZE)}\n`;
    output.innerHTML += `Alignment: ${toHex(ALIGNMENT)}\n`;

    const programHeader = new Uint8Array(buffer.slice(pos, pos + 56));
    outputBlob.push(programHeader);

    for (let i = 0; i < entries.length; i++) {
        if (entries[i].byteLength === FILE_SIZE) {
            outputBlob.push(new Uint8Array(entries[i]));
            entries.splice(i, 1);
            break;
        }
    }

    if (TYPE === 0x6FFFFF01) {
        output.innerHTML += `\n[SELF Version]\n`;
        output.innerHTML += `Version: ${FILE_SIZE}\n`;
    }

    return pos + 56;
}

// ELF Section Header Parser
function elfSectionHeader(section, buffer, pos, output) {
    const [NAME, TYPE, FLAG, ADDRESS, OFFSET, SIZE, LINK, INFORMATION, ALIGNMENT, ENTRY_SIZE] = unpack(buffer, '<2I4Q2I2Q', pos);
    const TYPES = { 0x0: 'SHT_NULL', 0x1: 'SHT_PROGBITS', 0x2: 'SHT_SYMTAB', 0x3: 'SHT_STRTAB', 0x4: 'SHT_RELA', 0x5: 'SHT_HASH', 0x6: 'SHT_DYNAMIC', 0x7: 'SHT_NOTE', 0x8: 'SHT_NOBITS', 0x9: 'SHT_REL', 0xA: 'SHT_SHLIB', 0xB: 'SHT_DYNSYM', 0xE: 'SHT_INIT_ARRAY', 0xF: 'SHT_FINI_ARRAY', 0x10: 'SHT_PREINIT_ARRAY', 0x11: 'SHT_GROUP', 0x12: 'SHT_SYMTAB_SHNDX', 0x61000001: 'SHT_SCE_NID' };
    const FLAGS = { 0x1: 'SHF_WRITE', 0x2: 'SHF_ALLOC', 0x4: 'SHF_EXECINSTR', 0x10: 'SHF_MERGE', 0x20: 'SHF_STRINGS', 0x40: 'SHF_INFO_LINK', 0x80: 'SHF_LINK_ORDER', 0x100: 'SHF_OS_NONCONFORMING', 0x200: 'SHF_GROUP', 0x400: 'SHF_TLS' };
    output.innerHTML += `\n[ELF Section Header #${section}]\n`;
    output.innerHTML += `Name: ${NAME}\n`;
    output.innerHTML += `Type: ${toHex(TYPE)} (${TYPES[TYPE] || 'Unknown'})\n`;
    output.innerHTML += `Flag: ${toHex(FLAG)} (${FLAGS[FLAG] || 'Unknown'})\n`;
    output.innerHTML += `Address: ${toHex(ADDRESS)}\n`;
    output.innerHTML += `Offset: ${toHex(OFFSET)}\n`;
    output.innerHTML += `Size: ${SIZE} Bytes\n`;
    output.innerHTML += `Link: ${LINK}\n`;
    output.innerHTML += `Information: ${INFORMATION}\n`;
    output.innerHTML += `Alignment: ${toHex(ALIGNMENT)}\n`;
    output.innerHTML += `Entry Size: ${ENTRY_SIZE} Bytes\n`;

    return pos + 64;
}

// SELF Extended Information Parser
function selfExtendedInformation(buffer, pos, output) {
    const [AUTHENTICATION_ID, TYPE, APPLICATION_VERSION, FIRMWARE_VERSION, DIGEST] = unpack(buffer, '<8x4Q32s', pos);
    const AUTHS = { 0x3C00000000000001: 'HOST_KERNEL', 0x3E00000000000003: 'PUP_MGR', 0x3E00000000000004: 'MEME_MGR', 0x3E00000000000005: 'AUTH_MGR', 0x3E00000000000006: 'IDATA_MGR', 0x3E00000000000007: 'MANUMODE_MGR', 0x3E00000000000008: 'KEY_MGR', 0x3E00000000000009: 'SM_MGR', 0x3F00000000000001: 'SECURE_KERNEL' };
    const TYPES = { 0x1: 'PT_FAKE', 0x4: 'PT_NPDRM_EXEC', 0x5: 'PT_NPDRM_DYNLIB', 0x8: 'PT_SYSTEM_EXEC', 0x9: 'PT_SYSTEM_DYNLIB', 0xC: 'PT_HOST_KERNEL', 0xE: 'PT_SECURE_MODULE', 0xF: 'PT_SECURE_KERNEL' };
    output.innerHTML += '\n[SELF Extended Information]\n';
    output.innerHTML += `Authentication ID: ${toHex(AUTHENTICATION_ID)} (${AUTHS[AUTHENTICATION_ID] || 'Unknown'})\n`;
    output.innerHTML += `Type: ${toHex(TYPE)} (${TYPES[TYPE] || 'Unknown'})\n`;
    output.innerHTML += `Application Version: ${toHex(APPLICATION_VERSION)}\n`;
    output.innerHTML += `Firmware Version: ${toHex(FIRMWARE_VERSION)}\n`;
    output.innerHTML += `Digest: ${DIGEST}\n`;

    return TYPE === 0x4 || TYPE === 0x5;
}

// Main parsing function
function parseSELF() {
    const fileInput = document.getElementById('selfFile');
    const output = document.getElementById('output');
    output.innerHTML = '';

    if (!fileInput.files.length) {
        output.innerHTML = 'Please select a SELF file.';
        return;
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = function(event) {
        const arrayBuffer = event.target.result;
        output.innerHTML = 'Parsing PS4 SELF Header...\n';
        const entryCount = selfHeader(arrayBuffer, output);

        let pos = 32; // After SELF header
        const entries = [];
        if (entryCount > 0) {
            output.innerHTML += '\nParsing PS4 SELF Entries...\n';
            for (let entry = 0; entry < entryCount; entry++) {
                pos = selfEntry(entry, arrayBuffer, pos, entries, output);
            }
        }

        const originalPos = pos;
        output.innerHTML += '\nParsing SCE Version Information...\n';
        entries.push(arrayBuffer.slice(pos)); // Simplified version info

        pos = originalPos;
        output.innerHTML += '\nParsing PS4 ELF Header...\n';
        const outputBlob = [];
        const [programHeaderCount, sectionHeaderCount, newPos] = elfHeader(arrayBuffer, pos, outputBlob, output);
        pos = newPos;

        if (programHeaderCount > 0) {
            output.innerHTML += '\nParsing PS4 ELF Program Headers...\n';
            for (let program = 0; program < programHeaderCount; program++) {
                pos = elfProgramHeader(program, arrayBuffer, pos, outputBlob, entries, output);
            }
        }

        if (sectionHeaderCount > 0) {
            output.innerHTML += '\nParsing PS4 ELF Section Headers...\n';
            for (let section = 0; section < sectionHeaderCount; section++) {
                pos = elfSectionHeader(section, arrayBuffer, pos, output);
            }
        }

        output.innerHTML += '\nParsing PS4 SELF Extended Information...\n';
        const hasNPDRM = selfExtendedInformation(arrayBuffer, pos, output);

        output.innerHTML += '\nDone!\n';

        // Generate and download ELF file
        const blob = new Blob(outputBlob, { type: 'application/octet-stream' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = file.name.split('.')[0] + '.elf';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    reader.onerror = function() {
        output.innerHTML = 'Error: Unable to Parse PS4 SELF File!!!';
    };

    reader.readAsArrayBuffer(file);
}
