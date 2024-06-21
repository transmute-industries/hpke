
import { generateKeyPair, exportJWK, calculateJwkThumbprintUri } from "jose"

import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

export type JOSE_HPKE_ALG = `HPKE-Base-P256-SHA256-A128GCM` | `HPKE-Base-P384-SHA256-AES128GCM`

export type JWK = {
  kid?:string
  alg?: string
  kty: string
  crv: string
}

export type JWKS = {
  keys: JWK[]
}

export type HPKERecipient = {
  encrypted_key: string
  header: {
    kid?: string
    alg?: string
    epk?: JWK
    encapsulated_key: string,
  }
}

export const suites = {
  ['HPKE-Base-P256-SHA256-A128GCM']: new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  }),
  ['HPKE-Base-P384-SHA256-AES128GCM']: new CipherSuite({
    kem: KemId.DhkemP384HkdfSha384,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  })
} as Record<any, CipherSuite>

export const isKeyAlgorithmSupported = (recipient: JWK) => {
  const supported_alg = Object.keys(suites) as string []
  return supported_alg.includes(`${recipient.alg}`)
}

export const formatJWK = (jwk: any) => {
  const { kid, alg, kty, crv, x, y, d } = jwk
  return JSON.parse(JSON.stringify({
    kid, alg, kty, crv, x, y, d
  }))
}

export const publicFromPrivate = (privateKeyJwk: any) => { 
  const { kid, alg, kty, crv, x, y, ...rest } = privateKeyJwk
  return {
    kid, alg, kty, crv, x, y
  }
}

export const generate = async (alg: JOSE_HPKE_ALG) => {
  if (!suites[alg]){
    throw new Error('Algorithm not supported')
  }
  let kp;
  if (alg.includes('P256')){
    kp = await generateKeyPair('ECDH-ES+A256KW', { crv: 'P-256', extractable: true })
  } else if (alg.includes('P384')){
    kp = await generateKeyPair('ECDH-ES+A256KW', { crv: 'P-384', extractable: true })
  } else {
    throw new Error('Could not generate private key for ' + alg)
  }
  const privateKeyJwk = await exportJWK(kp.privateKey);
  privateKeyJwk.kid = await calculateJwkThumbprintUri(privateKeyJwk)
  privateKeyJwk.alg = alg;
  return formatJWK(privateKeyJwk)
}