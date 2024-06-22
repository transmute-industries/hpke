import { base64url } from 'jose'

import { HPKE_JWT_OPTIONS  } from '../types'

import * as jwe from '../jwe'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

export const encryptJWT = async (claims: Record<string, any>, publicKey: Record<string, any>, options?: HPKE_JWT_OPTIONS) => {
  const plaintext = encoder.encode(JSON.stringify(claims))
  return jwe.compact.encrypt(plaintext, publicKey, options)
}

export const decryptJWT = async (jwt: string, privateKey: Record<string, any>) => {
  const plaintext = await jwe.compact.decrypt(jwt, privateKey)
  const [protectedHeader] = jwt.split('.')
  return {
    protectedHeader: JSON.parse(decoder.decode(base64url.decode(protectedHeader))),
    payload: JSON.parse(decoder.decode(plaintext))
  }
}