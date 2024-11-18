
import { SenderContextParams } from "hpke-js";

import { Aes128Gcm, CipherSuite, HkdfSha256,
  
  DhkemP256HkdfSha256,
   } from "@hpke/core";

import { XWing } from "@hpke/hybridkem-x-wing";


import { publicKeyFromJwk, privateKeyFromJwk } from '../crypto/keys'
export const prepareSenderContext = async (recipientPublicKey: any, options: any) =>{
  const senderParams = {
    recipientPublicKey: await publicKeyFromJwk(recipientPublicKey),
  } as SenderContextParams
  let suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
  if (recipientPublicKey.alg === 'HPKE-X-Wing-SHA256-A128GCM'){
    suite = new CipherSuite({
      kem: new XWing(),
      kdf: new HkdfSha256(),
      aead: new Aes128Gcm(),
    });
   await suite.kem.importKey('jwk', {...recipientPublicKey, alg:'X-Wing' }, true)
  }
  if (options?.keyManagementParameters){
    const { keyManagementParameters } = options
    if (keyManagementParameters.psk){
      // in JOSE kid is known to be a string
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
    senderParams.senderKey = await privateKeyFromJwk(options.senderPrivateKey)
  }
  const sender = await suite.createSenderContext(senderParams);
  return sender
}