function int64(low, hi) {
    this.low = (low >>> 0);
    this.hi = (hi >>> 0);

    this.add32inplace = function (val) {
        var new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
        var new_hi = (this.hi >>> 0);

        if (new_lo < this.low) {
            new_hi++;
        }

        this.hi = new_hi;
        this.low = new_lo;
    }
    this.byteAt = function(i) {
    
    if (i < 4) {
        return (this.low >>> (i * 8)) & 0xff;
    } else {
        return (this.hi  >>> ((i - 4) * 8)) & 0xff;
    }
}
    this.add=function(other) {
   
    if (!(other instanceof int64)) {
        other = new int64(other.low >>> 0, other.hi >>> 0);
    }
    let carry = 0;
    const res = new Array(8);
    for (let j = 0; j < 8; j++) {
        const sum = this.byteAt(j) + other.byteAt(j) + carry;
        res[j]   = sum & 0xff;
        carry    = sum >>> 8;
    }
   
    const new_low = (res[0]       )
                  | (res[1] << 8  )
                  | (res[2] << 16 )
                  | (res[3] << 24 );
    const new_hi  = (res[4]       )
                  | (res[5] << 8  )
                  | (res[6] << 16 )
                  | (res[7] << 24 );
    return new int64(new_low >>> 0, new_hi >>> 0);
}

    this.add32 = function (val) {
        var new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
        var new_hi = (this.hi >>> 0);

        if (new_lo < this.low) {
            new_hi++;
        }

        return new int64(new_lo, new_hi);
    }

    this.sub32 = function (val) {
        var new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
        var new_hi = (this.hi >>> 0);

        if (new_lo > (this.low) & 0xFFFFFFFF) {
            new_hi--;
        }

        return new int64(new_lo, new_hi);
    }

    this.sub32inplace = function (val) {
        var new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
        var new_hi = (this.hi >>> 0);

        if (new_lo > (this.low) & 0xFFFFFFFF) {
            new_hi--;
        }

        this.hi = new_hi;
        this.low = new_lo;
    }

    this.and32 = function (val) {
        var new_lo = this.low & val;
        var new_hi = this.hi;
        return new int64(new_lo, new_hi);
    }

    this.and64 = function (vallo, valhi) {
        var new_lo = this.low & vallo;
        var new_hi = this.hi & valhi;
        return new int64(new_lo, new_hi);
    }

    this.toString = function (val) {
        val = 16;
        var lo_str = (this.low >>> 0).toString(val);
        var hi_str = (this.hi >>> 0).toString(val);

        if (this.hi == 0)
            return lo_str;
        else
            lo_str = zeroFill(lo_str, 8)

        return hi_str + lo_str;
    }

    return this;
}

function zeroFill(number, width) {
    width -= number.toString().length;

    if (width > 0) {
        return new Array(width + (/\./.test(number) ? 2 : 1)).join('0') + number;
    }

    return number + ""; // always return a string
}

function zeroFill(number, width) {
    width -= number.toString().length;

    if (width > 0) {
        return new Array(width + (/\./.test(number) ? 2 : 1)).join('0') + number;
    }

    return number + ""; // always return a string
}
