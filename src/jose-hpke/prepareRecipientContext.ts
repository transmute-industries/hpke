
import { AeadId, CipherSuite, KdfId, KemId, RecipientContextParams } from "hpke-js";
import { publicKeyFromJwk, privateKeyFromJwk } from '../crypto/keys'

import * as jose from 'jose'

export const prepareRecipientContext = async (recipientPrivateKey: any, recipientHeader: any, options: any)=>{

  const recipientParams = {
    recipientKey: await privateKeyFromJwk(recipientPrivateKey),
    enc: jose.base64url.decode(recipientHeader.ek)
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


  return  suite.createRecipientContext(recipientParams)

}