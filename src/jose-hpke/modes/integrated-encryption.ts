import * as jose from "jose";

import { prepareSenderContext } from "../prepareSenderContext";
import { prepareRecipientHeader } from "../prepareRecipientHeader";

import * as aead from '../jwe/aead'

import { prepareRecipientContext } from '../prepareRecipientContext'

export const encrypt = async (plaintext: Uint8Array, publicKeyJwk: any, options?: any): Promise<any> => {
  const sender = await prepareSenderContext(publicKeyJwk, options)
  const header = await prepareRecipientHeader(publicKeyJwk, options)
  header.enc = "dir"; // 
  const encrypted_key = jose.base64url.encode(new Uint8Array(sender.enc))
  const protectedHeader = jose.base64url.encode(JSON.stringify(header))
  const encodedAad = options.additionalAuthenticatedData ? jose.base64url.encode(options.additionalAuthenticatedData) : undefined
  const aad = aead.prepareJweAad(protectedHeader, encodedAad)
  const ciphertext = jose.base64url.encode(new Uint8Array(await sender.seal(plaintext, aad)));
  const encrypted = {
    protected: protectedHeader,
    encrypted_key,
    ciphertext,
  } as any
  if (options.additionalAuthenticatedData){
    encrypted.aad = encodedAad
  }
  return encrypted
}


export const decrypt = async (encrypted: any, privateKeyJwk: any, options?: any): Promise<any> => {
  const header = JSON.parse(new TextDecoder().decode(jose.base64url.decode(encrypted.protected)))
  const ek = jose.base64url.decode(encrypted.encrypted_key)
  const context = await prepareRecipientContext(privateKeyJwk, ek, options)
  const aad = aead.prepareJweAad(encrypted.protected, encrypted.aad)
  const plaintext = await context.open(jose.base64url.decode(encrypted.ciphertext), aad)
  return {
    protectedHeader: header,
    plaintext: new Uint8Array(plaintext),
    additionalAuthenticatedData: jose.base64url.decode(encrypted.aad)
  }
}