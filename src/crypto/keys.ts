import subtle from "./subtle";

import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { XWing } from "@hpke/hybridkem-x-wing";
import { base64url } from "jose";

export const publicKeyFromJwk = async (publicKeyJwk: any) => {
  if (publicKeyJwk.alg === 'HPKE-X-Wing-SHA256-A128GCM'){
    const suite = new CipherSuite({
      kem: new XWing(),
      kdf: new HkdfSha256(),
      aead: new Aes128Gcm(),
    });
    return suite.kem.importKey('jwk', {...publicKeyJwk, alg: 'X-Wing'}, true)
  }
  const api = (await subtle())
  const publicKey = await api.importKey(
    'jwk',
    publicKeyJwk,
    {
      name: 'ECDH',
      namedCurve: publicKeyJwk.crv,
    },
    true,
    [],
  )
  return publicKey;
}

export const privateKeyFromJwk = async (privateKeyJwk: any) => {
  if (privateKeyJwk.alg === 'HPKE-X-Wing-SHA256-A128GCM'){
    const suite = new CipherSuite({
      kem: new XWing(),
      kdf: new HkdfSha256(),
      aead: new Aes128Gcm(),
    });
    return suite.kem.importKey('jwk', {...privateKeyJwk, alg: 'X-Wing'}, false)
  }
  const api = (await subtle())
  const privateKey = await api.importKey(
    'jwk',
    privateKeyJwk,
    {
      name: 'ECDH',
      namedCurve: privateKeyJwk.crv,
    },
    true,
    ['deriveBits', 'deriveKey'],
  )
  return privateKey
}