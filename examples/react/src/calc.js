var global =  window;
var root = typeof window === 'undefined' ? '../' : '';

export function calcWasm(args) {
    calcBinaryen(args, 'native-wasm');
}

function loadScript(src, onload, onerror) {
    var el = document.createElement('script');
    el.src = src;
    el.onload = onload;
    el.onerror = onerror;
    document.body.appendChild(el);
}

function calcBinaryen(args, method) {

    if (!global.WebAssembly) {
        console.log(
            "Your browser doesn't support WebAssembly, please try it in Chrome Canary or Firefox Nightly with WASM flag enabled"
        );
        return;
    }
    console.log(args);
    const mem = args.mem;

    console.log('Testing Argon2 using Binaryen ' + method);
    if (
        global.Module &&
        global.Module.wasmJSMethod === method &&
        global.Module._argon2_hash_ext
    ) {
        console.log('Calculating hash...');
        setTimeout(() => calcHash(args), 10);
        return;
    }

    const KB = 1024 * 1024;
    const MB = 1024 * KB;
    const GB = 1024 * MB;
    const WASM_PAGE_SIZE = 64 * 1024;

    const totalMemory = (2 * GB - 64 * KB) / 1024 / WASM_PAGE_SIZE;
    const initialMemory = Math.min(
        Math.max(Math.ceil((mem * 1024) / WASM_PAGE_SIZE), 256) + 256,
        totalMemory
    );
    console.log(
        'Memory: ' +
            initialMemory +
            ' pages (' +
            Math.round(initialMemory * 64) +
            ' KB)',
        totalMemory
    );
    const wasmMemory = new WebAssembly.Memory({
        initial: initialMemory,
        maximum: totalMemory,
    });

    global.Module = {
        print: console.log,
        printErr: console.log,
        setStatus: console.log,
        wasmBinary: null,
        wasmJSMethod: method,
        wasmMemory: wasmMemory,
        buffer: wasmMemory.buffer,
        TOTAL_MEMORY: initialMemory * WASM_PAGE_SIZE,
    };

    var wasmFileName = 'argon2.wasm';

    console.log('Loading wasm...');
    var xhr = new XMLHttpRequest();
    xhr.open('GET', root + wasmFileName, true);
    xhr.responseType = 'arraybuffer';
    xhr.onload = function () {
        global.Module.wasmBinary = xhr.response;
        global.Module.postRun = () => calcHash(args);
        var ts = now();
        console.log('Wasm loaded, loading script...');
        loadScript(
            root + 'argon2.js',
            function () {
                console.log('Script loaded in ' + Math.round(now() - ts) + 'ms');
                console.log('Calculating hash...');
            },
            function () {
                console.log('Error loading script');
            }
        );
    };
    xhr.onerror = function () {
        console.log('Error loading wasm');
    };
    xhr.send(null);
}

function calcHash(arg) {
    console.log(arg);
    if (!global.Module._argon2_hash_ext) {
        return console.log('Error');
    }
    console.log(
        'Params: ' +
            Object.keys(arg)
                .map(function (key) {
                    return key + '=' + arg[key];
                })
                .join(', ')
    );
    var dt = now();
    var t_cost = (arg && arg.time) || 10;
    var m_cost = (arg && arg.mem) || 1024;
    var parallelism = (arg && arg.parallelism) || 1;
    var passEncoded = encodeUtf8(arg.pass || 'password');
    var pwd = allocateArray(passEncoded);
    var pwdlen = passEncoded.length;
    var saltEncoded = encodeUtf8(arg.salt || 'somesalt');
    var argon2_type = (arg && arg.type) || 0;
    var salt = allocateArray(saltEncoded);
    var saltlen = saltEncoded.length;
    var hash = global.Module.allocate(
        new Array((arg && arg.hashLen) || 32),
        'i8',
        global.Module.ALLOC_NORMAL
    );
    var hashlen = (arg && arg.hashLen) || 32;
    var encodedlen = global.Module._argon2_encodedlen(
        t_cost,
        m_cost,
        parallelism,
        saltlen,
        hashlen,
        argon2_type
    );
    var encoded = global.Module.allocate(
        new Array(encodedlen + 1),
        'i8',
        global.Module.ALLOC_NORMAL
    );
    var secret = 0;
    var secretlen = 0;
    var ad = 0;
    var adlen = 0;
    var version = 0x13;
    var err;
    try {
        var res = global.Module._argon2_hash_ext(
            t_cost,
            m_cost,
            parallelism,
            pwd,
            pwdlen,
            salt,
            saltlen,
            hash,
            hashlen,
            encoded,
            encodedlen,
            argon2_type,
            secret,
            secretlen,
            ad,
            adlen,
            version
        );
    } catch (e) {
        err = e;
    }
    var elapsed = now() - dt;
    if (res === 0 && !err) {
        var hashArr = [];
        for (var i = hash; i < hash + hashlen; i++) {
            hashArr.push(global.Module.HEAP8[i]);
        }
        console.log('Encoded: ' + global.Module.UTF8ToString(encoded));
        console.log(
            'Hash: ' +
                hashArr
                    .map(function (b) {
                        return ('0' + (0xff & b).toString(16)).slice(-2);
                    })
                    .join('')
        );
        console.log('Elapsed: ' + Math.round(elapsed) + 'ms');
    } else {
        try {
            if (!err) {
                err = global.Module.UTF8ToString(global.Module._argon2_error_message(res));
            }
        } catch (e) {}
        console.log('Error: ' + res + (err ? ': ' + err : ''));
    }
    try {
        global.Module._free(pwd);
        global.Module._free(salt);
        global.Module._free(hash);
        global.Module._free(encoded);
    } catch (e) {}
}

function encodeUtf8(str) {
    return new TextEncoder().encode(str);
}

function allocateArray(arr) {
    return global.Module.allocate(arr, 'i8', global.Module.ALLOC_NORMAL);
}

function now() {
    return global.performance ? performance.now() : Date.now();
}
