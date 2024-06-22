import moment from 'moment'
import * as jose from 'jose'

import { jose as hpke  } from '../src'

const claims = { 'urn:example:claim': true }

it('Encrypted JWT with ECDH-ES+A128KW and A128GCM', async () => {
  const keys = await jose.generateKeyPair('ECDH-ES+A128KW', { extractable: true })
  const jwt = await new jose.EncryptJWT(claims)
  .setProtectedHeader({ alg: 'ECDH-ES+A128KW', enc: 'A128GCM' })
  .setIssuedAt()
  .setIssuer('urn:example:issuer')
  .setAudience('urn:example:audience')
  .setExpirationTime('2h')
  .encrypt(keys.privateKey)
  // protected.encrypted_key.iv.ciphertext.tag
  const result = await jose.jwtDecrypt(jwt, keys.privateKey)
  expect(result.payload['urn:example:claim']).toBe(true)
  expect(result.payload['iss']).toBe('urn:example:issuer')
  expect(result.payload['aud']).toBe('urn:example:audience')
  expect(result.payload.iat).toBeDefined()
  expect(result.payload.exp).toBeDefined()
  expect(result.protectedHeader['alg']).toBe('ECDH-ES+A128KW')
  expect(result.protectedHeader['enc']).toBe('A128GCM')
  expect(result.protectedHeader.epk).toBeDefined()
})

it('Encrypted JWT with HPKE-Base-P256-SHA256-A128GCM', async () => {
  const privateKey = await hpke.jwk.generate('HPKE-Base-P256-SHA256-A128GCM')
  const publicKey = await hpke.jwk.publicFromPrivate(privateKey)
  const iat = moment().unix()
  const exp = moment().add(2, 'hours').unix()
  const jwe = await hpke.jwt.encryptJWT({
    ...claims,
    iss: 'urn:example:issuer',
    aud: 'urn:example:audience',
    iat,
    exp,
  }, publicKey)
  // protected.encapsulated_key.<no iv>.ciphertext.<no tag>
  const result = await hpke.jwt.decryptJWT(jwe, privateKey)
  expect(result.payload['urn:example:claim']).toBe(true)
  expect(result.payload['iss']).toBe('urn:example:issuer')
  expect(result.payload['aud']).toBe('urn:example:audience')
  expect(result.payload.iat).toBeDefined()
  expect(result.payload.exp).toBeDefined()
  expect(result.protectedHeader['alg']).toBe('HPKE-Base-P256-SHA256-A128GCM')
  expect(result.protectedHeader['enc']).toBe('A128GCM')
  // protected header does not contain epk
  expect(result.protectedHeader.epk).toBeUndefined() 
  // encapsulated key is transported through "encrypted_key"
})

it('Encrypted JWT with ECDH-ES+A128KW and A128GCM, and party info', async () => {
  const keys = await jose.generateKeyPair('ECDH-ES+A128KW', { extractable: true })
  const jwt = await new jose.EncryptJWT(claims)
  .setKeyManagementParameters({
    "apu": jose.base64url.decode("QWxpY2U"),
    "apv": jose.base64url.decode("Qm9i"),
  })
  .setProtectedHeader({ 
    alg: 'ECDH-ES+A128KW', 
    enc: 'A128GCM'
   })
  .setIssuedAt()
  .setIssuer('urn:example:issuer')
  .setAudience('urn:example:audience')
  .setExpirationTime('2h')
  .encrypt(keys.privateKey)
  // protected.encrypted_key.iv.ciphertext.tag
  const result = await jose.jwtDecrypt(jwt, keys.privateKey)
  expect(result.payload['urn:example:claim']).toBe(true)
  expect(result.payload['iss']).toBe('urn:example:issuer')
  expect(result.payload['aud']).toBe('urn:example:audience')
  expect(result.payload.iat).toBeDefined()
  expect(result.payload.exp).toBeDefined()
  expect(result.protectedHeader['alg']).toBe('ECDH-ES+A128KW')
  expect(result.protectedHeader['enc']).toBe('A128GCM')
  expect(result.protectedHeader.epk).toBeDefined()
  expect(result.protectedHeader.apu).toBe("QWxpY2U")
  expect(result.protectedHeader.apv).toBe("Qm9i")
})

it('Encrypted JWT with HPKE-Base-P256-SHA256-A128GCM, and party info ', async () => {
  const privateKey = await hpke.jwk.generate('HPKE-Base-P256-SHA256-A128GCM')
  const publicKey = await hpke.jwk.publicFromPrivate(privateKey)
  const iat = moment().unix()
  const exp = moment().add(2, 'hours').unix()
  const jwe = await hpke.jwt.encryptJWT({
    ...claims,
    iss: 'urn:example:issuer',
    aud: 'urn:example:audience',
    iat,
    exp,
  }, 
  publicKey, 
  {
    keyManagementParameters: {
      "apu": jose.base64url.decode("QWxpY2U"),
      "apv": jose.base64url.decode("Qm9i"),
    }
  })
  // protected.encapsulated_key.<no iv>.ciphertext.<no tag>
  const result = await hpke.jwt.decryptJWT(jwe, privateKey)
  expect(result.payload['urn:example:claim']).toBe(true)
  expect(result.payload['iss']).toBe('urn:example:issuer')
  expect(result.payload['aud']).toBe('urn:example:audience')
  expect(result.payload.iat).toBeDefined()
  expect(result.payload.exp).toBeDefined()
  expect(result.protectedHeader['alg']).toBe('HPKE-Base-P256-SHA256-A128GCM')
  expect(result.protectedHeader['enc']).toBe('A128GCM')
  expect(result.protectedHeader.apu).toBe("QWxpY2U")
  expect(result.protectedHeader.apv).toBe("Qm9i")
})