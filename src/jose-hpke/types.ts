
export type HPKE_JWT_ENCRYPT_OPTIONS = {
  senderPrivateKey?: Record<string, any>, 
  recipientPublicKey?: Record<string, any>, 
  keyManagementParameters?: {
    apu?: Uint8Array,
    apv?: Uint8Array

    psk?: {
      id: Uint8Array,
      key: Uint8Array
    }
  }
}

export type HPKE_JWT_DECRYPT_OPTIONS = {
  senderPublicKey?: Record<string, any>,
  recipientPrivateKey: Record<string, any>,
  keyManagementParameters?: {
    psk?: {
      id: Uint8Array,
      key: Uint8Array
    }
  }
}

