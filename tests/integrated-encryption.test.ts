import { base64url } from 'jose'
import { jose as hpke  } from '../src'
// import * as jose from 'jose'

it('HPKE Integrated Encryption, Auth Mode, PSK and AAD', async () => {
  const privateKey = {
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

  const publicKey = await hpke.jwk.publicFromPrivate(privateKey)
  const pskid = new TextEncoder().encode(psk_jwk.kid)
  const psk = base64url.decode(psk_jwk.k)
  const plaintext = new TextEncoder().encode(`🖤 this plaintext!`)
  const additionalAuthenticatedData = new TextEncoder().encode('🏴‍☠️ beware the aad!')
  const commonOptions = {
    keyManagementParameters: {
      psk: {
        id: pskid,
        key: psk,
      }
    }
  }
  const encryptOptions = {
    additionalAuthenticatedData,
    senderPrivateKey:  privateKey, 
    recipientPublicKey:  publicKey, 
    ...commonOptions
  }
  const encrypted = await hpke.modes.integrated.encrypt(plaintext, publicKey, encryptOptions)
  const decryptOptions = {
    senderPublicKey: publicKey,
    recipientPrivateKey: privateKey,
    ...commonOptions
  }
  // console.log(JSON.stringify(encrypted, null, 2))
  const decrypted = await hpke.modes.integrated.decrypt(encrypted, privateKey, decryptOptions)
  decrypted.plaintext = new TextDecoder().decode(decrypted.plaintext)
  decrypted.additionalAuthenticatedData = new TextDecoder().decode(decrypted.additionalAuthenticatedData)
  // console.log(JSON.stringify(decrypted, null, 2))
  expect(decrypted.plaintext).toBe('🖤 this plaintext!')
  expect(decrypted.additionalAuthenticatedData).toBe('🏴‍☠️ beware the aad!')
  expect(decrypted.protectedHeader).toBeDefined()

  // console.log(JSON.stringify({
  //   "kty":"oct",
  //   "kid": "our-pre-shared-key-id",
  //   k: jose.base64url.encode(psk)
  // }, null, 2))
  // console.log(JSON.stringify(encrypted, null, 2))
})