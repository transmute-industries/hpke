import { base64url } from "jose";

import { privateKeyFromJwk, publicKeyFromJwk  } from "../../crypto/keys";
import { isKeyAlgorithmSupported  } from "../jwk";

import { AeadId, CipherSuite, KdfId, KemId, RecipientContextParams, SenderContextParams } from "hpke-js";

import { HPKE_JWT_DECRYPT_OPTIONS, HPKE_JWT_ENCRYPT_OPTIONS  } from '../types'

const decoder = new TextDecoder()

export const encrypt = async (plaintext: Uint8Array, publicKeyJwk: any, options?: HPKE_JWT_ENCRYPT_OPTIONS): Promise<string> => {
  if (!isKeyAlgorithmSupported(publicKeyJwk)) {
    throw new Error('Public key algorithm is not supported')
  }

  const senderParams = {
    recipientPublicKey: await publicKeyFromJwk(publicKeyJwk),
  } as SenderContextParams

  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  })
  
  const headerParams = {
    alg: publicKeyJwk.alg,
    enc: publicKeyJwk.alg.split('-').pop() // HPKE algorithms always end in an AEAD.
  } as Record<string, any>

  if (options?.keyManagementParameters){
    const { keyManagementParameters } = options
    if (keyManagementParameters.apu){
      headerParams.apu = base64url.encode(keyManagementParameters.apu)
    }
    if (keyManagementParameters.apv){
      headerParams.apv = base64url.encode(keyManagementParameters.apv)
    }
    if (keyManagementParameters.psk){
      // in JOSE kid is known to be a string
      headerParams.psk_id = decoder.decode(keyManagementParameters.psk.id) 
      if (!keyManagementParameters.psk.key){
        throw new Error('psk key required when id present.')
      }
      senderParams.psk = {
        id: keyManagementParameters.psk.id,
        key: keyManagementParameters.psk.key
      }
    }
  }

  // auth mode
  if (options?.senderPrivateKey){
    headerParams.auth_kid = options.senderPrivateKey.kid
    senderParams.senderKey = await privateKeyFromJwk(options.senderPrivateKey)
  }

  const sender = await suite.createSenderContext(senderParams);
  const encodedEncapsulatedKey = base64url.encode(new Uint8Array(sender.enc))
 
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

export const decrypt = async (compact: string, options: HPKE_JWT_DECRYPT_OPTIONS): Promise<Uint8Array> => {
  if (!isKeyAlgorithmSupported(options.recipientPrivateKey)) {
    throw new Error('Public key algorithm is not supported')
  }
  const [protectedHeader, encrypted_key, iv, ciphertext, tag] = compact.split('.');
  const encapsulated_key = base64url.decode(encrypted_key)

  const recipientParams = {
    recipientKey: await privateKeyFromJwk(options.recipientPrivateKey),
    enc: encapsulated_key
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