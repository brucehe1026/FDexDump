rpc.exports = {
    memorydump: function memorydump(address, size) {
        return new NativePointer(address).readByteArray(size);
    },
    scandex: function scandex() {
        var result = [];
        // range base size
        Process.enumerateRanges('r--').forEach(function (range) {
            //console.log(range.base, range.size)
            try {
                // loading Memory
                // 64 65 78 0a 30 ?? ?? 00 dex header 
                Memory.scanSync(range.base, range.size, "64 65 78 0a 30 ?? ?? 00").forEach(function (match) {

                    // ex sytem dex file
                    if (range.file && range.file.path
                        && (range.file.path.startsWith("/data/dalvik-cache/") ||
                            range.file.path.startsWith("/system/"))) {
                        return;
                    }

                    if (verify(match.address, range)) {
                        var dex_size = dex_ptr.add(0x20).readUInt();
                        //var dex_size = get_dex_real_size(match.address, range.base, range.base.add(range.size));
                        result.push({
                            "addr": match.address,
                            "size": dex_size
                        });
                    }

                });

            } catch {

            }
        });
        return result;
    }
}

function verify_dex(dex_ptr, range) {
    if (range != null) {
        var range_end = range.base.add(range.size);
        // verify header_size
        if (dex_ptr.add(0x70) > range_end) {
            return false;
        }
        return dex_ptr.add(0x3C).readUInt() === 0x70;
    }
    return false;
}



function get_dex_real_size(dexptr, range_base, range_end) {
    var dex_size = dexptr.add(0x20).readUInt();

    var maps_address = get_maps_address(dexptr, range_base, range_end);
    if (!maps_address) {
        return dex_size;
    }

    var maps_end = get_maps_end(maps_address, range_base, range_end);
    if (!maps_end) {
        return dex_size;
    }

    return maps_end - dexptr
}

function get_maps_address(dexptr, range_base, range_end) {
    var maps_offset = dexptr.add(0x34).readUInt();
    if (maps_offset === 0) {
        return null;
    }

    var maps_address = dexptr.add(maps_offset);
    if (maps_address < range_base || maps_address > range_end) {
        return null;
    }

    return maps_address;
}
