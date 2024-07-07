import moment from 'moment'

import { jose as hpke  } from '../src'

const claims = { 'urn:example:claim': true }

it('Encrypted JWT with HPKE-P256-SHA256-A128GCM (auth and psk)', async () => {
  const privateKey = {
    "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:S6AXfdU_6Yfzvu0KDDJb0sFuwnIWPk6LMTErYhPb32s",
    "alg": "HPKE-P256-SHA256-A128GCM",
    "kty": "EC",
    "crv": "P-256",
    "x": "wt36K06T4T4APWfGtioqDBXCvRN9evqkZjNydib9MaM",
    "y": "eupgedeE_HAmVJ62kpSt2_EOoXb6e0y2YF1JPlfr1-I",
    "d": "O3KznUTAxw-ov-9ZokwNaJ289RgP9VxQc7GJthaXzWY"
  }
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
    senderPrivateKey:  privateKey, 
    recipientPublicKey:  publicKey, 
    keyManagementParameters: {
      psk: {
        id: pskid,
        key: psk,
      }
    }
  })
  // protected.encapsulated_key.<no iv>.ciphertext.<no tag>
  const result = await hpke.jwt.decryptJWT(jwe, {
    senderPublicKey: publicKey,
    recipientPrivateKey: privateKey,
    keyManagementParameters: {
      psk: {
        id: pskid,
        key: psk,
      }
    }
  })
  expect(result.payload['urn:example:claim']).toBe(true)
  expect(result.payload['iss']).toBe('urn:example:issuer')
  expect(result.payload['aud']).toBe('urn:example:audience')
  expect(result.payload.iat).toBeDefined()
  expect(result.payload.exp).toBeDefined()
  expect(result.protectedHeader['alg']).toBe('HPKE-P256-SHA256-A128GCM')
  expect(result.protectedHeader['enc']).toBe('A128GCM')
  expect(result.protectedHeader['psk_id']).toBe('our-pre-shared-key-id')
  expect(result.protectedHeader['auth_kid']).toBe('urn:ietf:params:oauth:jwk-thumbprint:sha-256:S6AXfdU_6Yfzvu0KDDJb0sFuwnIWPk6LMTErYhPb32s')
})