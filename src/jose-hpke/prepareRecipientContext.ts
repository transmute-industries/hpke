
import { RecipientContextParams } from "hpke-js";
import { publicKeyFromJwk, privateKeyFromJwk } from '../crypto/keys'
import { XWing } from "@hpke/hybridkem-x-wing";


import { Aes128Gcm, CipherSuite, HkdfSha256, DhkemP256HkdfSha256,} from "@hpke/core";


export const prepareRecipientContext = async (recipientPrivateKey: any, encapsulatedKey: any, options: any)=>{
  let suite: any
  let recipientParams = {} as any
  if (recipientPrivateKey.alg === 'HPKE-X-Wing-SHA256-A128GCM'){
    suite = new CipherSuite({
      kem: new XWing(),
      kdf: new HkdfSha256(),
      aead: new Aes128Gcm(),
    });
   recipientParams = {
      recipientKey: await privateKeyFromJwk(recipientPrivateKey) ,
      enc: encapsulatedKey
    } as RecipientContextParams
   await suite.kem.importKey('jwk', { ...recipientPrivateKey, alg:'X-Wing' }, false)
  } else {
    suite = new CipherSuite({
      kem: new DhkemP256HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes128Gcm(),
    });
    recipientParams = {
      recipientKey: await privateKeyFromJwk(recipientPrivateKey),
      enc: encapsulatedKey
    } as RecipientContextParams
  }

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

  return  suite.createRecipientContext(recipientParams)

}