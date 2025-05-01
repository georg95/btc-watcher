## btc-watcher
Observe incoming bitcoin transactions.

Zero dependecies, zero 3rd-party services, raw native bitcoin blockchain connection.

## usage
`npm i georg95/btc-watcher`

```javascript
import { connect } from 'btc-watcher'

const addrSet = new Set([
    '1GrwDkr33gT6LuumniYjKEGjTLhsL5kmqC',
    'bc1qhuv3dhpnm0wktasd3v0kt6e4aqfqsd0uhfdu7d',
    '37jdMXYbvg3dKzJ4pGSYiABiXoBy4putZq',
    'bc1qprdf80adfz7aekh5nejjfrp3jksc8r929svpxk',
    'bc1quhruqrghgcca950rvhtrg7cpd7u8k6svpzgzmrjy8xyukacl5lkq0r8l2d',
])

connect(({ addr, script, value, tx_hash }) => {
    if (addrSet.has(addr)) {
        console.log(`💸 ${value} ₿ ${addr}`)
        console.log(`🔗 https://mempool.space/tx/${tx_hash}`)
    }
})
```
