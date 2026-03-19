const express = require('express')
const crypto  = require('crypto')
const https   = require('https')
const app = express()
app.use(express.json())

// ─── Config ──────────────────────────────────────────────────────────────────

const TIMEOUT_MS   = 8000    // 8 seconds — fast now we have the right domain
const MAX_RETRIES  = 1       // one attempt per host
const RETRY_DELAY  = 0
const HOSTS = ['openapi-sg.iotbing.com']  // Tuya Singapore — confirmed from API Explorer

// ─── HTTPS helper with retry + host fallback ─────────────────────────────────

function sleep(ms) { return new Promise(r => setTimeout(r, ms)) }

function singleRequest(hostname, options, body) {
  return new Promise((resolve, reject) => {
    const opts = { ...options, hostname }
    const req = https.request(opts, (res) => {
      let data = ''
      res.on('data', chunk => data += chunk)
      res.on('end', () => {
        console.log('[proxy]', res.statusCode, opts.method, hostname + opts.path)
        try { resolve(JSON.parse(data)) }
        catch (e) { resolve({ raw: data, http_status: res.statusCode }) }
      })
    })
    req.on('error', reject)
    req.setTimeout(TIMEOUT_MS, () => {
      req.destroy()
      reject(new Error(`Timeout ${TIMEOUT_MS}ms → ${hostname}${opts.path}`))
    })
    if (body) req.write(body)
    req.end()
  })
}

async function makeRequest(options, body, hosts) {
  const hostList = hosts || HOSTS
  let lastError

  for (const host of hostList) {
    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        console.log(`[proxy] ${host} attempt ${attempt}/${MAX_RETRIES}`)
        return await singleRequest(host, options, body)
      } catch (err) {
        lastError = err
        console.error(`[proxy] ${host} attempt ${attempt} failed: ${err.message}`)
        if (attempt < MAX_RETRIES) await sleep(RETRY_DELAY)
      }
    }
    console.log(`[proxy] ${host} exhausted ${MAX_RETRIES} retries, trying next host...`)
  }

  throw lastError || new Error('All hosts and retries exhausted')
}

// ─── Signature ───────────────────────────────────────────────────────────────

function sha256(content) {
  return crypto.createHash('sha256').update(content).digest('hex')
}

function hmacSha256(str, secret) {
  return crypto.createHmac('sha256', secret).update(str).digest('hex').toUpperCase()
}

function buildSign(clientId, token, clientSecret, method, path, body) {
  const t     = Date.now().toString()
  const nonce = crypto.randomUUID()
  const stringToSign = method + '\n' + sha256(body || '') + '\n\n' + path
  const signStr = clientId + (token || '') + t + nonce + stringToSign
  const sign = hmacSha256(signStr, clientSecret)
  return { t, nonce, sign }
}

// ─── Tuya calls ──────────────────────────────────────────────────────────────

async function getTuyaToken(clientId, clientSecret) {
  const path = '/v1.0/token?grant_type=1'
  const { t, nonce, sign } = buildSign(clientId, '', clientSecret, 'GET', path, '')

  console.log('[proxy] === GET TOKEN ===')
  const data = await makeRequest({
    path,
    method: 'GET',
    headers: {
      'client_id': clientId,
      'sign': sign,
      't': t,
      'nonce': nonce,
      'sign_method': 'HMAC-SHA256',
    },
  })

  console.log('[proxy] token success:', data.success, '| msg:', data.msg || 'ok')
  if (!data.success) throw new Error('Token failed: ' + JSON.stringify(data))
  return { token: data.result.access_token, host: 'resolved' }
}

async function callEndpoint(clientId, clientSecret, token, method, path, body) {
  const { t, nonce, sign } = buildSign(clientId, token, clientSecret, method, path, body || '')

  return makeRequest({
    path,
    method,
    headers: {
      'client_id':    clientId,
      'access_token': token,
      'sign':         sign,
      't':            t,
      'nonce':        nonce,
      'sign_method':  'HMAC-SHA256',
      'Content-Type': 'application/json',
    },
  }, body)
}

// ─── DP extraction ───────────────────────────────────────────────────────────

function extractDps(data) {
  if (Array.isArray(data.result) && data.result.length > 0 && data.result[0].code) {
    return data.result
  }
  // Base64 fallback
  if (typeof data.result === 'string') {
    try {
      const buf = Buffer.from(data.result, 'base64')
      const results = []
      let offset = 0
      const DP_MAP = { 12: 'prepayment_switch', 13: 'balance_energy', 18: 'meter_id', 37: 'balance' }
      while (offset + 4 <= buf.length) {
        const id = buf[offset], type = buf[offset+1], len = buf.readUInt16BE(offset+2)
        if (offset + 4 + len > buf.length) break
        const raw = buf.slice(offset+4, offset+4+len)
        let value
        if (type === 1) value = raw[0] === 1
        else if (type === 2) value = raw.readInt32BE(0)
        else value = raw.toString()
        results.push({ code: DP_MAP[id] || ('dp_' + id), value })
        offset += 4 + len
      }
      if (results.length > 0) return results
    } catch (e) { /* ignore */ }
  }
  return []
}

// ─── Routes ──────────────────────────────────────────────────────────────────

app.post('/webhook/tuya-proxy', async (req, res) => {
  const { action, deviceId, clientId, clientSecret, kwhAmount } = req.body

  console.log('\n[proxy] ========== ' + action + ' | device: ' + deviceId + ' ==========')

  try {
    if (action === 'getDeviceStatus') {
      const { token } = await getTuyaToken(clientId, clientSecret)

      // v2.0 shadow (works for app-linked devices, avoids 1106 permission error)
      // then v1.0 iot-03, then legacy v1.0
      const pathsToTry = [
        { path: '/v2.0/cloud/thing/' + deviceId + '/shadow/properties', label: 'v2_shadow' },
        { path: '/v1.0/iot-03/devices/' + deviceId + '/status',         label: 'v1_iot03'  },
        { path: '/v1.0/devices/' + deviceId + '/status',                label: 'v1_legacy' },
      ]

      let dps = []
      const endpointResults = {}

      for (const { path, label } of pathsToTry) {
        try {
          const data = await callEndpoint(clientId, clientSecret, token, 'GET', path)
          console.log('[proxy]', label, path, '→ success:', data.success, 'code:', data.code, '| result:', JSON.stringify(data.result).slice(0, 300))
          endpointResults[label] = { success: data.success, code: data.code, msg: data.msg }
          if (data.success) {
            // v2.0 returns { result: { properties: [{code, value}] } }
            if (label === 'v2_shadow' && data.result && data.result.properties) {
              dps = data.result.properties.map(p => ({ code: p.code, value: p.value }))
            } else {
              dps = extractDps(data)
            }
            if (dps.length > 0) { console.log('[proxy] Got DPs from', label); break }
          }
        } catch (e) {
          endpointResults[label] = { error: e.message }
          console.log('[proxy]', label, '→ error:', e.message)
        }
      }

      // Device online status
      let is_online = dps.length > 0
      try {
        const info = await callEndpoint(clientId, clientSecret, token, 'GET', '/v1.0/devices/' + deviceId)
        if (info.success && info.result) {
          is_online = info.result.online ?? is_online
        }
      } catch (e) { /* non-critical */ }

      console.log('[proxy] DPs found:', dps.length, '→', JSON.stringify(dps))

      // ── DP extraction — confirmed from Tuya product definition ──────────
      // DP 13: balance_energy  — Remaining Energy, Scale 2 (value/100 = kWh)
      // DP 37: balance         — Balance, Scale 2 (fallback)
      // DP 12: prepayment_switch — Bool
      const balanceDp  = dps.find(dp => dp.code === 'balance_energy')  // DP 13 (primary)
      const balance2Dp = dps.find(dp => dp.code === 'balance')          // DP 37 (fallback)
      const prepayDp   = dps.find(dp => dp.code === 'prepayment_switch')// DP 12
      const powerDp    = dps.find(dp => ['cur_power','power','active_power'].includes(dp.code))

      const balance_kwh = balanceDp  ? balanceDp.value  / 100
                        : balance2Dp ? balance2Dp.value / 100
                        : 0

      console.log('[proxy] balance_energy(DP13)=' + (balanceDp?.value ?? 'N/A') +
                  ' balance(DP37)=' + (balance2Dp?.value ?? 'N/A') +
                  ' → balance_kwh=' + balance_kwh + ' | online=' + is_online)

      return res.json({
        success:       true,
        balance_kwh,
        power_w:       powerDp  ? powerDp.value  / 10 : null,
        is_online,
        is_on:         true,
        is_prepayment: prepayDp ? prepayDp.value  : false,
        raw_dps:       dps,
        endpoints:     endpointResults,
      })
    }

    if (action === 'topupDevice') {
      const { token } = await getTuyaToken(clientId, clientSecret)
      // DP 37 'balance' is the Send+Report DP for topping up (Scale 2 → value * 100)
      const deviceValue = Math.round(kwhAmount * 100)
      const body = JSON.stringify({ commands: [{ code: 'balance', value: deviceValue }] })
      console.log('[proxy] topup kWh:', kwhAmount, '→ raw value:', deviceValue)
      const result = await callEndpoint(clientId, clientSecret, token, 'POST', '/v1.0/iot-03/devices/' + deviceId + '/commands', body)
      console.log('[proxy] topup result:', JSON.stringify(result))
      return res.json({ success: result.success ?? false, result })
    }

    res.status(400).json({ success: false, error: 'Unknown action' })

  } catch (err) {
    console.error('[proxy] FATAL:', err.message)
    res.status(500).json({ success: false, error: err.message })
  }
})

app.get('/health', (req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }))

const PORT = process.env.PORT || 3001
app.listen(PORT, () => console.log('[tuya-proxy] port', PORT, '| timeout:', TIMEOUT_MS + 'ms | retries:', MAX_RETRIES, '| hosts:', HOSTS.join(', ')))
