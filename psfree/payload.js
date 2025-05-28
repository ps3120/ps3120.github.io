fetch('./payload.bin').then(res => {
    res.arrayBuffer().then(arr => {


          const byteLen = arr.byteLength;

        const padLength = (4 - (byteLen % 4)) % 4;
    const padding = new Uint8Array(padLength); 

        const alignedBuf = new ArrayBuffer(byteLen + padLength);
    const tmp8 = new Uint8Array(alignedBuf);
            tmp8.set(new Uint8Array(arr), 0);

            window.pld = new Uint32Array(alignedBuf);

       // window.pld = new Uint32Array(arr);

    })
})
