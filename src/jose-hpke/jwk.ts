
import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { XWing } from "@hpke/hybridkem-x-wing";

import { generateKeyPair, exportJWK, calculateJwkThumbprintUri, base64url } from "jose"

export const isKeyAlgorithmSupported = (recipient: Record<string, any>) => {
  return ['HPKE-P256-SHA256-A128GCM', 'HPKE-P256-SHA256-A128GCM'].includes(recipient.alg)
}

export const formatJWK = (jwk: any) => {
  const { kid, alg, kty, crv, x, y, d, pub, priv } = jwk
  return JSON.parse(JSON.stringify({
    kid, alg, kty, crv, x, y, d, pub, priv
  }))
}

export const publicFromPrivate = (privateKeyJwk: any) => { 
  const { kid, alg, kty, crv, x, y, pub, ...rest } = privateKeyJwk
  return formatJWK({
    kid, alg, kty, crv, x, y, pub
  })
}

export const generate = async (alg: 'HPKE-P256-SHA256-A128GCM' | 'HPKE-P256-SHA256-A128GCM' | `HPKE-X-Wing-SHA256-A128GCM`) => {
  let kp;
  if (alg.includes('P256')){
    kp = await generateKeyPair('ECDH-ES+A256KW', { crv: 'P-256', extractable: true })
  } else if (alg.includes('P384')){
    kp = await generateKeyPair('ECDH-ES+A256KW', { crv: 'P-384', extractable: true })
  } else if (alg.includes('X-Wing')){
    const suite = new CipherSuite({
      kem: new XWing(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm(),
    });
    const rkp:any = await suite.kem.generateKeyPair()
    return {
      'kty': 'AKP',
      'alg': 'HPKE-X-Wing-SHA256-A128GCM',
      'pub': base64url.encode(rkp.publicKey.key),
      'priv': base64url.encode(rkp.privateKey.key),
    }
  } else {
    throw new Error('Could not generate private key for ' + alg)
  }
  const privateKeyJwk = await exportJWK(kp.privateKey);
  privateKeyJwk.kid = await calculateJwkThumbprintUri(privateKeyJwk)
  privateKeyJwk.alg = alg;
  return formatJWK(privateKeyJwk)
}