
import * as jwe from '../jwe'

import { base64url } from 'jose'


const encoder = new TextEncoder()
const decoder = new TextDecoder()

export const encryptJWT = async (claims: Record<string, any>, publicKey: Record<string, any>) => {
  const plaintext = encoder.encode(JSON.stringify(claims))
  return jwe.compact.encrypt(plaintext, publicKey)
}

export const decryptJWT = async (jwt: string, privateKey: Record<string, any>) => {
  const plaintext = await jwe.compact.decrypt(jwt, privateKey)
  const [protectedHeader] = jwt.split('.')
  return {
    protectedHeader: JSON.parse(decoder.decode(base64url.decode(protectedHeader))),
    payload: JSON.parse(decoder.decode(plaintext))
  }
}