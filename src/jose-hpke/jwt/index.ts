import { base64url } from 'jose'

import { HPKE_JWT_ENCRYPT_OPTIONS, HPKE_JWT_DECRYPT_OPTIONS  } from '../types'

import * as jwe from '../jwe'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

export const encryptJWT = async (claims: Record<string, any>, options?: HPKE_JWT_ENCRYPT_OPTIONS) => {
  const plaintext = encoder.encode(JSON.stringify(claims))
  return jwe.compact.encrypt(plaintext, options?.recipientPublicKey, options)
}

export const decryptJWT = async (jwt: string, options?: HPKE_JWT_DECRYPT_OPTIONS) => {
  const plaintext = await jwe.compact.decrypt(jwt, options?.recipientPrivateKey)
  const [protectedHeader] = jwt.split('.')
  return {
    protectedHeader: JSON.parse(decoder.decode(base64url.decode(protectedHeader))),
    payload: JSON.parse(decoder.decode(plaintext))
  }
}