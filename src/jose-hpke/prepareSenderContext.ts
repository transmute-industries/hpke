
import { AeadId, CipherSuite, KdfId, KemId, SenderContextParams } from "hpke-js";
import { publicKeyFromJwk, privateKeyFromJwk } from '../crypto/keys'
export const prepareSenderContext = async (recipientPublicKey: any, options: any) =>{
  const senderParams = {
    recipientPublicKey: await publicKeyFromJwk(recipientPublicKey),
  } as SenderContextParams
  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  })
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