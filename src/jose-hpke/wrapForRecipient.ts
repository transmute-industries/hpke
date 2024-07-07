
import * as jose from 'jose'

import { prepareSenderContext } from "./prepareSenderContext";
import { prepareRecipientHeader } from "./prepareRecipientHeader";

export const wrapForRecipient = async (cek: Uint8Array, recipientPublicKey: any, options: any): Promise<any> => {
  const sender = await prepareSenderContext(recipientPublicKey, options)
  const header = await prepareRecipientHeader(recipientPublicKey, options)
  // BEFORE encrypting the cek
  // Add the ek to the header.
  // This ensured the entire header is protected as aad.
  const encodedEncapsulatedKey = jose.base64url.encode(new Uint8Array(sender.enc))
  header.ek = encodedEncapsulatedKey
  // No way to use apu / apv here... 
  const ciphertext = jose.base64url.encode(new Uint8Array(await sender.seal(cek)));
  return {
    encrypted_key: ciphertext,
    header
  }
}