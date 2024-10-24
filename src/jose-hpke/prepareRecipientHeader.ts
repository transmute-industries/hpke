import * as jose from 'jose'

const decoder = new TextDecoder()

export const prepareRecipientHeader = async (recipientPublicKey: any, options: any) =>{
  const headerParams = {
    alg: recipientPublicKey.alg,
    enc: "dir"
  } as Record<string, any>
  if (recipientPublicKey.kid){
    headerParams.kid = recipientPublicKey.kid
  }
  if (options?.type){
    headerParams.typ = options?.type
  }
  if (options?.keyManagementParameters){
    const { keyManagementParameters } = options
    if (keyManagementParameters.apu){
      headerParams.apu = jose.base64url.encode(keyManagementParameters.apu)
    }
    if (keyManagementParameters.apv){
      headerParams.apv = jose.base64url.encode(keyManagementParameters.apv)
    }
    if (keyManagementParameters.psk){
      // in JOSE kid is known to be a string
      headerParams.psk_id = decoder.decode(keyManagementParameters.psk.id) 
      if (!keyManagementParameters.psk.key){
        throw new Error('psk key required when id present.')
      }
    }
  }
  // auth mode
  if (options?.senderPrivateKey){
    headerParams.auth_kid = options.senderPrivateKey.kid
  }
  return headerParams
}