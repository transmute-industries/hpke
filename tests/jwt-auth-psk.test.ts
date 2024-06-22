import moment from 'moment'

import { jose as hpke  } from '../src'

const claims = { 'urn:example:claim': true }

it('Encrypted JWT with HPKE-Base-P256-SHA256-A128GCM, and pre shared key', async () => {
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
  {
    senderPrivateKey:  privateKey, 
    recipientPublicKey:  publicKey, 
    keyManagementParameters: {
      id: new TextEncoder().encode("our-pre-shared-key-id"),
      // a PSK MUST have at least 32 bytes.
      key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
    }
  })
  // protected.encapsulated_key.<no iv>.ciphertext.<no tag>
  const result = await hpke.jwt.decryptJWT(jwe, {
    senderPublicKey: publicKey,
    recipientPrivateKey: privateKey
  })
  expect(result.payload['urn:example:claim']).toBe(true)
  expect(result.payload['iss']).toBe('urn:example:issuer')
  expect(result.payload['aud']).toBe('urn:example:audience')
  expect(result.payload.iat).toBeDefined()
  expect(result.payload.exp).toBeDefined()
  expect(result.protectedHeader['alg']).toBe('HPKE-Base-P256-SHA256-A128GCM')
  expect(result.protectedHeader['enc']).toBe('A128GCM')

})