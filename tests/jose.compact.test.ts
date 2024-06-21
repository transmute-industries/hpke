import { jose  } from '../src'

it('Encrypted JWT', async () => {
  const privateKey = await jose.jwk.generate('HPKE-Base-P256-SHA256-A128GCM')
  // {
  //   "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:rLf589p6ciQuNovRRgw7QenhIkRlCYvbEvjrR6H0cXE",
  //   "alg": "HPKE-Base-P256-SHA256-A128GCM",
  //   "kty": "EC",
  //   "crv": "P-256",
  //   "x": "Za60d_DGbWcgLMVbSy3tVK04fzLRsUeQyHajk_nQymg",
  //   "y": "ZcHHk4fwfb-KvVyL8mJh4DZrnOlbxU38BIsI9X-JWPI",
  //   "d": "Y5TVtePtdR9rQv4SUwFl5X8QsUEBuV7xb4CQ64LwR-0"
  // }
  const publicKey = await jose.jwk.publicFromPrivate(privateKey)
  // {
  //   "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:UpCljbgoIeH6NQ9u0GYnF_p72OxPxcVUumnOMduiqwI",
  //   "alg": "HPKE-Base-P256-SHA256-A128GCM",
  //   "kty": "EC",
  //   "crv": "P-256",
  //   "x": "U9_XoUs-DoxwpY0tkRWR1T4AnaUNojkc90tPLTQsE0U",
  //   "y": "lWLt3R4GVs_WF6UbOaPBBTjPe3tE_M1_8EDC4KNDBxE"
  // }
  const claims = new TextEncoder().encode(JSON.stringify({
    iss: `issuer.example`,
    sub: `subject.example`,
    aud: `verifier.example`,
    // other claims
  }))
  const jwe = await jose.jwe.compact.encrypt(claims, publicKey)
  // protected.encrypted_key..ciphertext.
  const plaintext = await jose.jwe.compact.decrypt(jwe, privateKey)
  expect(plaintext).toBeDefined()
})
