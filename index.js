
import crypto from 'crypto'
import net from 'net'
import dns from 'dns'
import ip from 'ip'

let ALL_NODES = new Set()
let USED_NODES = new Set()
export async function getDnsSeedNode() {
    const DNS_SEEDS = [ // https://github.com/bitcoin/bitcoin/blob/623745ca74cf3f54b474dac106f5802b7929503f/src/chainparams.cpp#L121
        'seed.bitcoin.sipa.be',
        'dnsseed.bluematt.me',
        'dnsseed.bitcoin.dashjr.org',
        'seed.bitcoinstats.com',
        'seed.bitcoin.jonasschnelli.ch',
        'seed.btc.petertodd.org',
        'seed.bitcoin.sprovoost.nl',
        'dnsseed.emzy.de',
        'seed.bitcoin.wiz.biz',
    ]
    async function fillNodesList() {
        return new Promise((resolve, reject) => {
            let resolved = 0
            DNS_SEEDS.forEach(seed => dns.resolve(seed, (error, nodes) => {
                nodes?.forEach(node => !USED_NODES.has(node) && ALL_NODES.add(node))
                if (ALL_NODES.size > 0) { resolve(); return }
                if (++resolved === DNS_SEEDS.length - 1) { reject() }
            }))
        })
    }
    if (ALL_NODES.size === 0) {
        await fillNodesList()
    }
    let nodes = Array.from(ALL_NODES)
    const node = nodes[Math.floor(Math.random() * nodes.length)]
    USED_NODES.add(node)
    return node
}

export async function connect(onTransaction, { minNodes=6 }={}) {
    let nodes = []
    const seenBlocks = new Set()
    Array(minNodes).fill(0).forEach(addNode)

    async function addNode() {
        const addr = await getDnsSeedNode()
        const node = connectNode(addr, ({ command, data }) => {
            if (command === 'verack') { console.log('🌐', addr) }
            if (command === 'inv') {
                readInvVect(data).forEach(({ hash, type }) => {
                    if (type === 2 && !seenBlocks.has(Buffer.from(hash).reverse().toString('hex'))) {
                        node.getInvData({ hash, type })
                    }
                })
            }
            if (command === 'block') {
                const hash = sha256(sha256(data.payload.subarray(data.offset, data.offset+80))).reverse().toString('hex')
                if (!seenBlocks.has(hash)) {
                    readBlock(data, onTransaction)
                    console.log(`⛓️  ${hash}`)
                }
            }
        })
        node.socket.once('close', async () => {
            console.log('❌', addr)
            nodes = nodes.filter(n => node !== n)
            addNode()
        })
        nodes.push(node)
    }
}

function connectNode(addr, onCommand) {
    let socket = net.connect(8333, addr)
    socket.once('connect', sendVersionPacket)
    socket.once('close', () => pings !== null && clearInterval(pings))
    socket.on('error', (err) => {/* fixes unhandled exception */})

    let pings = null
    let socketBuffer = Buffer.alloc(0)
    socket.on('data', function onData(chunk) {
        if (chunk) {
            socketBuffer = Buffer.concat([socketBuffer, chunk])
        }
        if (socketBuffer.length < 24) { return }
        const messageHeader = socketBuffer.subarray(0, 24)
        const size = messageHeader.readUInt32LE(16)
        if (socketBuffer.length < 24 + size) { return }
        
        const command = messageHeader.subarray(4, 16).toString('ascii').replace(/\0/g, '')
        const payload = socketBuffer.subarray(24, 24 + size)
        socketBuffer = socketBuffer.subarray(24 + size)
        const data = { payload, offset: 0 }
        onCommand({ command, messageHeader, data })
        // TODO checksum test

        if (command === 'version') { socket.write(getMessageHeader('verack')) }
        if (command === 'verack') {
            sendPing()
            pings = setInterval(sendPing, 20 * 1000)
        }
        if (command === 'ping') { sendPong(data) }

        if (socketBuffer.length >= 24) {
            onData()
        }
    })

    function getMessageHeader(command, payload) {
        const header = Buffer.alloc(24)
        header.writeUint32LE(0xd9b4bef9, 0)
        header.write(command, 4)
        header.writeUint32LE(payload?.length || 0, 16)
        const checksum = sha256(sha256(payload || Buffer.alloc(0))).toString('hex').slice(0, 8)
        header.write(checksum, 20, 'hex')
        return header
    }

    function sendPong(data) {
        const payload = data.payload.subarray(0, 8)
        socket.write(getMessageHeader('pong', payload))
        socket.write(payload)
    }

    function sendPing() {
        const payload = crypto.pseudoRandomBytes(8)
        socket.write(getMessageHeader('ping', payload))
        socket.write(payload)
    }

    function getInvData({ type, hash }) {
        const payload = Buffer.alloc(1 + 36)
        let lastByte = 0
        payload.writeUint8(1, lastByte); lastByte += 1
        payload.writeUint32LE(type, lastByte); lastByte += 4
        payload.write(hash.toString('hex'), lastByte, 'hex'); lastByte += 32

        socket.write(getMessageHeader('getdata', payload))
        socket.write(payload)
    }

    function sendVersionPacket() {
        const PROTOCOL_VERSION = 70012
        const USER_AGENT = '/btc-watcher:0.2/'

        let lastByte = 0
        const payloadConstruct = Buffer.alloc(86 + USER_AGENT.length)
        payloadConstruct.writeUint32LE(PROTOCOL_VERSION, lastByte); lastByte += 4
        payloadConstruct.write('0800000000000000', lastByte, 'hex'); lastByte += 8
        payloadConstruct.writeBigUint64LE(BigInt(Math.round(Date.now() / 1000)), lastByte); lastByte += 8
        payloadConstruct.write('0100000000000000', lastByte, 'hex'); lastByte += 8
        payloadConstruct.write('00000000000000000000ffff', lastByte, 'hex'); lastByte += 12
        ip.toBuffer(socket.remoteAddress || '0.0.0.0', payloadConstruct, lastByte); lastByte += 4
        payloadConstruct.writeUInt16BE(socket.remotePort, lastByte); lastByte += 2
        payloadConstruct.write('0800000000000000', lastByte, 'hex'); lastByte += 8
        payloadConstruct.write('00000000000000000000ffff', lastByte, 'hex'); lastByte += 12
        ip.toBuffer('0.0.0.0', payloadConstruct, lastByte); lastByte += 4
        payloadConstruct.writeUInt16BE(socket.localPort, lastByte); lastByte += 2
        payloadConstruct.write(crypto.pseudoRandomBytes(8).toString('hex'), lastByte, 'hex'); lastByte += 8
        payloadConstruct.writeUint8(USER_AGENT.length, lastByte); lastByte += 1
        payloadConstruct.write(USER_AGENT, lastByte, 'ascii'); lastByte += USER_AGENT.length
        payloadConstruct.writeUint32LE(0, lastByte); lastByte += 4
        payloadConstruct.writeUint8(0, lastByte); lastByte += 1

        socket.write(getMessageHeader('version', payloadConstruct))
        socket.write(payloadConstruct)
    }
    return { addr, socket, getInvData }
}

function readUInt16(data) { return data.payload.readUInt16LE((data.offset += 2) - 2) }
function readUInt32(data) { return data.payload.readUInt32LE((data.offset += 4) - 4) }
function readInt32(data) { return data.payload.readInt32LE((data.offset += 4) - 4) }
function readInt64(data) { return data.payload.readBigInt64LE((data.offset += 8) - 8) }
function readHex(data, len) { return Buffer.from(data.payload.subarray(data.offset, data.offset += len)) }
function readVarInt(data) {
    let first = data.payload.readUint8((data.offset += 1) - 1)
    if (first < 0xfd) {
        return first
    } else if (first === 0xfd) {
        return data.payload.readUInt16LE((data.offset += 2) - 2)
    } else if (first === 0xfe) {
        return data.payload.readUInt32LE((data.offset += 4) - 4)
    } else {
        return data.payload.readBigUInt64LE((data.offset += 8) - 8)
    }
}
function readInvVect(data) {
    const count = readVarInt(data)
    const vectList = []
    for (let i = 0; i < count; i++) {
        let type = readUInt32(data)
        let hash = readHex(data, 32)
        vectList.push({ type, hash })
    }
    return vectList
}
function readTransaction(data, onOutAddress) {
    const offsetStart = data.offset
    const version = readUInt32(data)
    const hasWitness = data.payload[data.offset] === 0
    const flag = hasWitness ? readUInt16(data) : 0
    const tx_in_count = readVarInt(data)
    const tx_in = Array(tx_in_count).fill(0).forEach(readTXinput)
    const tx_out_count = readVarInt(data)
    const tx_out = Array(tx_out_count).fill(0).map(readTXoutput)
    const tx_witnesses = hasWitness ? Array(tx_in_count).fill(0).map(readTXWitness) : []
    const lock_time = hasWitness ? 0 : readUInt32(data)
    const tx_hash = sha256(sha256(data.payload.subarray(offsetStart, data.offset))).reverse().toString('hex')
    if (onOutAddress) {
        tx_out.forEach(({ addr, value, script }) => onOutAddress({ addr, value, script, tx_hash }))
    }

    function readTXinput() {
        const previous_output_hash = readHex(data, 32)
        const previous_output_index = readUInt32(data)
        const script_length = readVarInt(data)
        const signature_script = readHex(data, script_length)
        const sequence = readUInt32(data)
        return { previous_output_hash, previous_output_index, signature_script, sequence }
    }
    function readTXoutput() {
        const value = Number(readInt64(data)) / 100_000_000
        const pk_script_length = readVarInt(data)
        const script = readHex(data, pk_script_length)
        const addr = scriptToAddr(script)
        return { value, addr, script }
    }
    function readTXWitness() {
        const data_components_count = readVarInt(data)
        const data_components = Array(data_components_count).fill(0).map(readTXWitnessComponent)
        function readTXWitnessComponent() {
            const component_size = readVarInt(data)
            return readHex(data, component_size)
        }
        return data_components
    }
    return { tx_hash, version, flag, tx_in, tx_out, tx_witnesses, lock_time }
}
export function readBlockHeader(data) {
    const hash = sha256(sha256(data.payload.subarray(data.offset, data.offset+80))).reverse().toString('hex')
    const version = readInt32(data)
    const prev_block = readHex(data, 32)
    const merkle_root = readHex(data, 32)
    const timestamp = new Date(readUInt32(data) * 1000)
    const bits = readUInt32(data)
    const nonce = readUInt32(data)

    return { hash, version, prev_block, merkle_root, timestamp, bits, nonce }
}
export function readBlock(data, onOutAddress) {
    const header = readBlockHeader(data)
    const txCount = readVarInt(data)
    Array(txCount).fill(0).forEach(() => readTransaction(data, onOutAddress))
    return { header }
}

function sha256(data) {
    return crypto.createHash('sha256').update(data).digest()
}

const ALPHABET_BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const BASE_MAP = new Uint8Array(256)
for (let j = 0; j < BASE_MAP.length; j++) {
  BASE_MAP[j] = 255
}
for (let i = 0; i < ALPHABET_BASE58.length; i++) {
  const x = ALPHABET_BASE58.charAt(i)
  const xc = x.charCodeAt(0)
  BASE_MAP[xc] = i
}
const BASE = ALPHABET_BASE58.length
const LEADER = ALPHABET_BASE58.charAt(0)
const iFACTOR = Math.log(256) / Math.log(BASE) // log(256) / log(BASE), rounded up
function base58(data) {
    if (data instanceof Uint8Array) { } else if (ArrayBuffer.isView(data)) {
    data = new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    } else if (Array.isArray(data)) {
    data = Uint8Array.from(data)
    }
    if (!(data instanceof Uint8Array)) { throw new TypeError('Expected Uint8Array') }
    if (data.length === 0) { return '' }
    let zeroes = 0
    let length = 0
    let pbegin = 0
    const pend = data.length
    while (pbegin !== pend && data[pbegin] === 0) {
    pbegin++
    zeroes++
    }
    const size = ((pend - pbegin) * iFACTOR + 1) >>> 0
    const b58 = new Uint8Array(size)
    while (pbegin !== pend) {
    let carry = data[pbegin]
    let i = 0
    for (let it1 = size - 1; (carry !== 0 || i < length) && (it1 !== -1); it1--, i++) {
        carry += (256 * b58[it1]) >>> 0
        b58[it1] = (carry % BASE) >>> 0
        carry = (carry / BASE) >>> 0
    }
    if (carry !== 0) { throw new Error('Non-zero carry') }
    length = i
    pbegin++
    }
    let it2 = size - length
    while (it2 !== size && b58[it2] === 0) {
    it2++
    }
    let str = LEADER.repeat(zeroes)
    for (; it2 < size; ++it2) { str += ALPHABET_BASE58.charAt(b58[it2]) }
    return str
}

const ALPHABET_BECH32  = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function encodeBech32(data, taproot=false) {
    let dataAlign = BigInt((5 - (data.length * 8) % 5) % 5)
    const base32 = (BigInt(`0x${data.toString('hex')}`) << dataAlign).toString(32)
    let words = []
    for (let i = 0; i < base32.length; i++) {
        let code = base32.charCodeAt(i) - 48
        words.push(code > 32 ? code - 39 : code)
    }
    let chk = 1
    let result = ''
    const prefix = [0b00011, 0b00011, 0b00000, 0b00010, 0b00011, taproot ? 0b00001 : 0b00000]
    const words_ext = prefix.concat(words).concat([0, 0, 0, 0, 0, 0])
    for (let i = 0; i < words_ext.length; ++i) {
        const x = words_ext[i];
        const b = chk >> 25;
        chk = (((chk & 0x1ffffff) << 5) ^
            (-((b >> 0) & 1) & 0x3b6a57b2) ^
            (-((b >> 1) & 1) & 0x26508e6d) ^
            (-((b >> 2) & 1) & 0x1ea119fa) ^
            (-((b >> 3) & 1) & 0x3d4233dd) ^
            (-((b >> 4) & 1) & 0x2a1462b3)
        ) ^ x
        if (i < 6 || i >= words_ext.length - 6) { continue }
        result += ALPHABET_BECH32.charAt(x)
    }
    chk ^= taproot ? 0x2bc830a3 : 1
    for (let i = 0; i < 6; ++i) {
        result += ALPHABET_BECH32.charAt((chk >> ((5 - i) * 5)) & 0x1f)
    }
    return result;
}
export function scriptToAddr(script) {
    if (script.length === 25 && script[0] === 0x76 && script[1] === 0xa9 && script[2] === 0x14 && script[23] === 0x88 && script[24] === 0xac) {
        const addr = Buffer.alloc(25)
        script.copy(addr, 1, 3, 23)
        const checksum = sha256(sha256(addr.subarray(0, 21)))
        checksum.copy(addr, 21, 0, 4)
        return base58(addr) // P2PKH
    }
    if (script.length === 23 && script[0] === 0xa9 && script[1] === 0x14 && script[22] === 0x87) {
        const addr = Buffer.alloc(25)
        addr[0] = 0x5
        script.copy(addr, 1, 2, 22)
        const checksum = sha256(sha256(addr.subarray(0, 21)))
        checksum.copy(addr, 21, 0, 4)
        return base58(addr) // P2SH
    }
    const isWitness = script.length >= 4 && script.length <= 42 &&
        (script[0] === 0 || (script[0] >= 0x51 && script[1] <= 0x60)) &&
        script[1]+2 === script.length
    if (isWitness) {
        const version = script[0]
        const addr = script.subarray(2)
        if (version === 0 && addr.length === 20) {
            return 'bc1q' + encodeBech32(addr) // P2WPKH
        }
        if (version === 0 && addr.length === 32) {
            return 'bc1q' + encodeBech32(addr) // P2WSH
        }
    }
    if (script[0] === 0x6a) {
        return null // OP_RETURN, Arbitrary string in transaction
    }
    if (script[0] === 0x51 && script[1] === 0x20) {
        const addr = script.subarray(2, 34)
        return 'bc1p' + encodeBech32(addr, true) // P2TR
    }
}
