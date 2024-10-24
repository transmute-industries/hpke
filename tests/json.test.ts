import moment from 'moment'
import * as jose from 'jose'
import { jose as hpke  } from '../src'

const claims = { 'urn:example:claim': true }

it('JSON serialized Compact JWT', async () => {
  const privateKey = await hpke.jwk.generate('HPKE-P256-SHA256-A128GCM')
  const publicKey = await hpke.jwk.publicFromPrivate(privateKey)
  const iat = moment().unix()
  const exp = moment().add(2, 'hours').unix()
  const pskid = new TextEncoder().encode("our-pre-shared-key-id")
  // a PSK MUST have at least 32 bytes.
  const psk = new TextEncoder().encode("jugemujugemugokounosurikirekaija")
  const jwe = await hpke.jwt.encryptJWT({
    ...claims,
    iss: 'urn:example:issuer',
    aud: 'urn:example:audience',
    iat,
    exp,
  }, 
  {
    type: `application/foo+jwt`,
    senderPrivateKey:  privateKey, 
    recipientPublicKey:  publicKey, 
    keyManagementParameters: {
      psk: {
        id: pskid,
        key: psk,
      }
    }
  })
  const jweJsonSerialized = hpke.jwe.compact.toJsonSerialization(jwe)
  // // For example:
  // console.log(jwe)
  // console.log(JSON.stringify(jweJsonSerialized, null, 2))
  expect(jweJsonSerialized.protected).toBeDefined()
  expect(jweJsonSerialized.encrypted_key).toBeDefined()
  expect(jweJsonSerialized.ciphertext).toBeDefined()
  const jweCompactSerialized = hpke.jwe.json.toCompactSerialization(jweJsonSerialized)
  expect(jweCompactSerialized).toBe(jwe)
})

const formatCryptoKey = async (k: any, alg: string)=>{
  const jwk = await jose.exportJWK(k) as any
  const kid = await jose.calculateJwkThumbprintUri(jwk)
  const { kty, crv, x, y, d } = jwk
  return JSON.parse(JSON.stringify({
    kid,
    alg,
    kty,
    crv,
    x,
    y,
    d
  }))
}

it('JSON serialized HPKE JWE', async () => {
  const key1 = await jose.generateKeyPair('ECDH-ES+A128KW', { crv: 'P-256', extractable: true })
  const privateKey1 = await formatCryptoKey(key1.privateKey, 'ECDH-ES+A128KW')
  const publicKey1 = await formatCryptoKey(key1.publicKey, 'ECDH-ES+A128KW')
  const privateKey2 = {
    "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:S6AXfdU_6Yfzvu0KDDJb0sFuwnIWPk6LMTErYhPb32s",
    "alg": "HPKE-P256-SHA256-A128GCM",
    "kty": "EC",
    "crv": "P-256",
    "x": "wt36K06T4T4APWfGtioqDBXCvRN9evqkZjNydib9MaM",
    "y": "eupgedeE_HAmVJ62kpSt2_EOoXb6e0y2YF1JPlfr1-I",
    "d": "O3KznUTAxw-ov-9ZokwNaJ289RgP9VxQc7GJthaXzWY"
  }

  const psk_jwk = {
    "kty": "oct",
    "kid": "our-pre-shared-key-id",
    "k": "anVnZW11anVnZW11Z29rb3Vub3N1cmlraXJla2FpamE"
  }

  const publicKey2 = await hpke.jwk.publicFromPrivate(privateKey2)
  const recipients = {
    keys: [
      publicKey1,
      publicKey2
    ]
  }
  const psk = jose.base64url.decode(psk_jwk.k)
  const pskid = new TextEncoder().encode(psk_jwk.kid)
  const message = "🎵 My lungs taste the air of Time Blown past falling sands 🎵"
  const plaintext = new TextEncoder().encode(message)
  const senderOptions = {
    algorithm: 'A128GCM' as 'A128GCM',
    additionalAuthenticatedData: new TextEncoder().encode('paul atreides'),
    senderPrivateKey:  privateKey2, 
    recipientPublicKey:  publicKey2, 
    keyManagementParameters: {
      psk: {
        id: pskid,
        key: psk,
      }
    }
  }
  const jwe = await hpke.jwe.json.encrypt(plaintext, recipients, senderOptions)

  expect(jwe.aad).toBe('cGF1bCBhdHJlaWRlcw')
  expect(jwe.recipients.length).toBe(2)
  // console.log(JSON.stringify(jwe, null, 2))
  // proof of interop with ECDH-ES+A128KW
  const decrypted1 =  await jose.generalDecrypt(jwe, key1.privateKey) as any
  expect(decrypted1.protectedHeader.enc).toBe('A128GCM')
  expect(decrypted1.unprotectedHeader.kid).toBeDefined()
  expect(decrypted1.unprotectedHeader.alg).toBeDefined()
  expect(decrypted1.unprotectedHeader.epk).toBeDefined()
  expect(new TextDecoder().decode(decrypted1.additionalAuthenticatedData)).toBe('paul atreides')
  expect(new TextDecoder().decode(decrypted1.plaintext)).toBe(message)
  const recipientOptions = {
    senderPublicKey: publicKey2,
    recipientPrivateKey: privateKey2,
    keyManagementParameters: {
      psk: {
        id: pskid,
        key: psk,
      }
    }
  }
  const decrypted2 = await hpke.jwe.json.decrypt(jwe, {
    keys: [
      privateKey2
    ],
  },
  recipientOptions)
  decrypted2.additionalAuthenticatedData = new TextDecoder().decode(decrypted2.additionalAuthenticatedData)
  decrypted2.plaintext = new TextDecoder().decode(decrypted2.plaintext)
  // console.log(JSON.stringify(decrypted2, null, 2))
  expect(decrypted2.additionalAuthenticatedData).toBe('paul atreides')
  expect(decrypted2.plaintext).toBe(message)
  expect(decrypted2.protectedHeader.enc).toBe('A128GCM')
  expect(decrypted2.unprotectedHeader.kid).toBeDefined()
  expect(decrypted2.unprotectedHeader.alg).toBeDefined()
  expect(decrypted2.unprotectedHeader.ek).toBeDefined()
  expect(decrypted2.unprotectedHeader.psk_id).toBeDefined()
  expect(decrypted2.unprotectedHeader.auth_kid).toBeDefined()
})


it('JSON serialized HPKE JWE to Compact', async () => {
  const privateKey2 = await hpke.jwk.generate('HPKE-P256-SHA256-A128GCM')
  const publicKey2 = await hpke.jwk.publicFromPrivate(privateKey2)
  const recipients = {
    keys: [
      publicKey2
    ]
  }
  const psk = new TextEncoder().encode("jugemujugemugokounosurikirekaija")
  const pskid = new TextEncoder().encode("our-pre-shared-key-id")
  const message = "⌛ My lungs taste the air of Time Blown past falling sands ⌛"
  const plaintext = new TextEncoder().encode(message)
  const senderOptions = {
    algorithm: 'A128GCM' as 'A128GCM',
    // additionalAuthenticatedData: new TextEncoder().encode('paul atreides'), // not supported in compact
    senderPrivateKey:  privateKey2, 
    recipientPublicKey:  publicKey2, 
    keyManagementParameters: {
      psk: {
        id: pskid,
        key: psk,
      }
    }
  }
  const jwe = await hpke.jwe.json.encrypt(plaintext, recipients, senderOptions)
  const jwt = hpke.jwe.json.toCompactSerialization(jwe)
  // console.log(jwt)
  // console.log(JSON.stringify(jwe, null, 2))
  expect(jwt.split(".").length).toBe(5) // unprotected headers destroyed in the process
})