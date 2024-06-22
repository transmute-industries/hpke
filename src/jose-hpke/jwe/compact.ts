import { base64url } from "jose";

import { privateKeyFromJwk, publicKeyFromJwk  } from "../../crypto/keys";
import { isKeyAlgorithmSupported, suites  } from "../jwk";


import { HPKE_JWT_OPTIONS  } from '../types'

export const encrypt = async (plaintext: Uint8Array, publicKeyJwk: any, options?: HPKE_JWT_OPTIONS): Promise<string> => {
  if (!isKeyAlgorithmSupported(publicKeyJwk)) {
    throw new Error('Public key algorithm is not supported')
  }
  const suite = suites[publicKeyJwk.alg]
  const sender = await suite.createSenderContext({
    recipientPublicKey: await publicKeyFromJwk(publicKeyJwk),
  });
  const encodedEncapsulatedKey = base64url.encode(new Uint8Array(sender.enc))
  const headerParams = {
    alg: publicKeyJwk.alg,
    enc: publicKeyJwk.alg.split('-').pop() // HPKE algorithms always end in an AEAD.
  } as Record<string, any>
  if (options?.keyManagementParameters.apu){
    headerParams.apu = base64url.encode(options?.keyManagementParameters.apu)
  }
  if (options?.keyManagementParameters.apv){
    headerParams.apv = base64url.encode(options?.keyManagementParameters.apv)
  }
  const protectedHeader = base64url.encode(JSON.stringify(headerParams))
  const aad = new TextEncoder().encode(protectedHeader)
  // apu / apv are protected by aad, not as part of kdf
  const ciphertext = base64url.encode(new Uint8Array(await sender.seal(plaintext, aad)));
  const encrypted_key = encodedEncapsulatedKey
  const iv = ``
  const tag = ``
  // https://datatracker.ietf.org/doc/html/rfc7516#section-3.1
  const jwe = `${protectedHeader}.${encrypted_key}.${iv}.${ciphertext}.${tag}`
  return jwe
}

export const decrypt = async (compact: string, privateKeyJwk: any): Promise<Uint8Array> => {
  if (!isKeyAlgorithmSupported(privateKeyJwk)) {
    throw new Error('Public key algorithm is not supported')
  }
  const suite = suites[privateKeyJwk.alg]
  const [protectedHeader, encrypted_key, iv, ciphertext, tag] = compact.split('.');
  const recipient = await suite.createRecipientContext({
    recipientKey: await privateKeyFromJwk(privateKeyJwk),
    enc: base64url.decode(encrypted_key)
  })
  const aad = new TextEncoder().encode(protectedHeader)
  const plaintext = await recipient.open(base64url.decode(ciphertext), aad)
  return new Uint8Array(plaintext)
}