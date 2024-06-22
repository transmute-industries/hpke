
import { generateKeyPair, exportJWK, calculateJwkThumbprintUri } from "jose"

export const isKeyAlgorithmSupported = (recipient: Record<string, any>) => {
  return ['HPKE-Base-P256-SHA256-A128GCM', 'HPKE-AuthPSK-P256-SHA256-A128GCM'].includes(recipient.alg)
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

export const generate = async (alg: 'HPKE-Base-P256-SHA256-A128GCM' | 'HPKE-AuthPSK-P256-SHA256-A128GCM') => {
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