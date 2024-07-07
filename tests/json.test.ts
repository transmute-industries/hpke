import moment from 'moment'

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
})