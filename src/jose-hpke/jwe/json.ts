
import * as jose from "jose";
import { HPKE_JWT_DECRYPT_OPTIONS, HPKE_JWT_ENCRYPT_OPTIONS } from '../types'
import { wrapForRecipient } from '../wrapForRecipient'
import * as aead from './aead'


import { prepareRecipientContext } from "../prepareRecipientContext";

export const encrypt = async (plaintext: Uint8Array, recipients: any, options: HPKE_JWT_ENCRYPT_OPTIONS): Promise<any> => {
  if (options.algorithm !== 'A128GCM') {
    throw new Error('Only A128GCM is supported')
  }
  // generate a content encryption key for a content encryption algorithm
  const cek = await aead.generateKey(options.algorithm);
  // generate an initialization vector for use with the content encryption key
  const ivForCek = crypto.getRandomValues(new Uint8Array(12)); // possibly wrong
  // create the protected header
  // top level protected header only has "enc"
  const protectedHeader = jose.base64url.encode(JSON.stringify({
    enc: 'A128GCM'
  }))
  // encrypt the plaintext with the content encryption algorithm
  const encodedAad = options.additionalAuthenticatedData ? jose.base64url.encode(options.additionalAuthenticatedData) : undefined
  const aad = aead.prepareJweAad(protectedHeader, encodedAad)
  const { iv, ciphertext, tag } = await aead.encrypt(plaintext, cek, ivForCek, aad)
  // prepare the encrypted content for all recipients
  let jwe = {
    protected: protectedHeader,
    iv,
    ciphertext,
    tag,
    aad: encodedAad,
    recipients: [] as any[]
  };
 
  // for each recipient public key, encrypt the content encryption key to the recipient public key
  // and add the result to the unprotected header recipients property
  for (const recipient of recipients.keys) {
    if (recipient.alg === 'HPKE-P256-SHA256-A128GCM') {
      const wrappedWithHPKE = await wrapForRecipient(cek, recipient, options) // psk / auth mode
      jwe.recipients.push(wrappedWithHPKE)
    } else if (recipient.alg === 'ECDH-ES+A128KW') {
      const wrappedWithECDH = await aead.wrapForRecipient(cek, recipient)
      jwe.recipients.push(wrappedWithECDH)
    } else {
      throw new Error('Public key algorithm not supported: ' + recipient.alg)
    }
  }
  return jwe
}
export const decrypt = async (jwe: any, recipients: any, options: HPKE_JWT_DECRYPT_OPTIONS) => {

  // for testing purposes assume the caller knows which key to use:
  const recipientPrivateKeyJwk = recipients.keys[0]
  const privateKeyId = recipientPrivateKeyJwk.kid
  // find the recipient
  const recipient = jwe.recipients.find((r:any)=>{
    return r.header.kid === privateKeyId
  })
  // setup hpke
  const context = await prepareRecipientContext(recipientPrivateKeyJwk, recipient.header, options)
  // const aad = new TextEncoder().encode(protectedHeader)
  const encryptedContentEncryptionKey = jose.base64url.decode(recipient.encrypted_key)
  // decrypt cek
  // no aad here means no recipient identity binding (apu / apv) via HPKE info, or aad
  const decryptedContentEncryptionKey = new Uint8Array(await context.open(encryptedContentEncryptionKey)) 
  const encryptedContent = jose.base64url.decode(jwe.ciphertext)
  const iv = jose.base64url.decode(jwe.iv)
  const tag = jose.base64url.decode(jwe.tag)
  const aad = aead.prepareJweAad(jwe.protected, jwe.aad && jwe.aad.length ? jwe.aad : undefined)
  // decrypt ct
  const plaintext = aead.decrypt(encryptedContent, decryptedContentEncryptionKey, iv, tag, aad)
  const decryption =  {
    plaintext,
    protectedHeader: JSON.parse(new TextDecoder().decode(jose.base64url.decode(jwe.protected)) ),
    unprotectedHeader: recipient.header,
  } as any
  if (jwe.aad){
    decryption.additionalAuthenticatedData = jose.base64url.decode(jwe.aad)
  }
  return decryption
}

// https://datatracker.ietf.org/doc/html/rfc7516#section-3.1
// BASE64URL(UTF8(JWE Protected Header)) || '.' ||
// BASE64URL(JWE Encrypted Key) || '.' ||
// BASE64URL(JWE Initialization Vector) || '.' ||
// BASE64URL(JWE Ciphertext) || '.' ||
// BASE64URL(JWE Authentication Tag)

export const toCompactSerialization = (jwe: any) => {
  if (jwe.recipients && jwe.recipients.length !== 1){
    throw new Error('Compact serialization does not support multiple recipients')
  }
  if (jwe.aad && jwe.aad.length){
    throw new Error('Compact serialization does not support additional authenticated data')
  }
  const { iv, ciphertext, tag, aad } = jwe;
  if (jwe.encrypted_key){
    return `${jwe.protected}.${jwe.encrypted_key}.${iv || ''}.${ciphertext}.${tag || ''}`
  }
  // we loose unprotected headers here....
  return `${jwe.protected}.${jwe.recipients[0].encrypted_key}.${iv}.${ciphertext}.${tag}`
}