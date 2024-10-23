import { base64url } from "jose";

import { privateKeyFromJwk, publicKeyFromJwk  } from "../../crypto/keys";
import { isKeyAlgorithmSupported  } from "../jwk";

import { AeadId, CipherSuite, KdfId, KemId, RecipientContextParams, SenderContextParams } from "hpke-js";

import { HPKE_JWT_DECRYPT_OPTIONS, HPKE_JWT_ENCRYPT_OPTIONS  } from '../types'
import { modes } from "..";

export const encrypt = async (plaintext: Uint8Array, publicKeyJwk: any, options?: HPKE_JWT_ENCRYPT_OPTIONS): Promise<string> => {
  if (!isKeyAlgorithmSupported(publicKeyJwk)) {
    throw new Error('Public key algorithm is not supported')
  }
  if (options?.additionalAuthenticatedData) {
    throw new Error('AdditionalAuthenticatedData is not supported in compact mode')
  }
  const encrypted = await modes.integrated.encrypt(plaintext, publicKeyJwk, options as any)
  // https://datatracker.ietf.org/doc/html/rfc7516#section-3.1
  const jwe = `${encrypted.protected}.${encrypted.encrypted_key}.${encrypted.iv || ''}.${encrypted.ciphertext}.${encrypted.tag || ''}`
  return jwe
}

export const decrypt = async (compact: string, options: HPKE_JWT_DECRYPT_OPTIONS): Promise<Uint8Array> => {
  if (!isKeyAlgorithmSupported(options.recipientPrivateKey)) {
    throw new Error('Public key algorithm is not supported')
  }
  const [protectedHeader, encrypted_key, iv, ciphertext, tag] = compact.split('.');
  const encapsulated_key = base64url.decode(encrypted_key)

  const recipientParams = {
    recipientKey: await privateKeyFromJwk(options.recipientPrivateKey),
    enc: encapsulated_key,
    info: options.hpke_info
  } as RecipientContextParams

  if (options.keyManagementParameters){
    const { keyManagementParameters } = options
    if (keyManagementParameters.psk){
      recipientParams.psk = {
        id: keyManagementParameters.psk.id as any, 
        key: keyManagementParameters.psk.key as any
      }
    }
  }

  if (options.senderPublicKey){
    recipientParams.senderPublicKey = await publicKeyFromJwk(options.senderPublicKey)
  }

  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  })


  const recipient = await suite.createRecipientContext(recipientParams)
  const aad = new TextEncoder().encode(protectedHeader)
  const plaintext = await recipient.open(base64url.decode(ciphertext), aad)
  return new Uint8Array(plaintext)
}


// https://datatracker.ietf.org/doc/html/rfc7516#section-3.2
// "protected", with the value BASE64URL(UTF8(JWE Protected Header))
// "unprotected", with the value JWE Shared Unprotected Header
// "header", with the value JWE Per-Recipient Unprotected Header
// "encrypted_key", with the value BASE64URL(JWE Encrypted Key)
// "iv", with the value BASE64URL(JWE Initialization Vector)
// "ciphertext", with the value BASE64URL(JWE Ciphertext)
// "tag", with the value BASE64URL(JWE Authentication Tag)
// "aad", with the value BASE64URL(JWE AAD)

export const toJsonSerialization = (jwe: string) =>{
  const [protectedHeader, encrypted_key, iv, ciphertext, tag] = jwe.split('.');
  return JSON.parse(JSON.stringify({
    protected: protectedHeader, 
    encrypted_key,
    iv: iv.length ? iv : undefined,
    ciphertext,
    tag: tag.length ? tag : undefined,
  }))
}