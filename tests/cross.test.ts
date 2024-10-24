const private_key = {
  "kid": "TcFvrer05N5M2gFYzoY5KATir43bC2Qo0oSpim8xLTQ=",
  "kty": "EC",
  "crv": "P-256",
  "alg": "HPKE-P256-SHA256-A128GCM",
  "x": "RIjTekw094uGwk2BrEPfRSJD9v0zwFEWnj0u7aYQ-gc",
  "y": "cUPnPCPxvWxlctBAUyx3lln7H_bDyz9zeR4uQVbhCkg",
  "d": "IBYVjH1w0q64ySr5KjX2w1mEib2uk_gFSn4EHRjisgw"
}

import { jose as hpke } from '../src'
// import * as jose from 'jose'

const token = `ewogICJlbmMiIDogImRpciIsCiAgImFsZyIgOiAiSFBLRS1QMjU2LVNIQTI1Ni1BMTI4R0NNIgp9.BJyCM45zphHr9aIc7aZx3ug0RQY10fuvS8fYZxXG1_JUEArboE9QDwHYS_sPlF_67z_OsPpCA3iM7Iu0zaSNq08..Ju7xVmgyk77bmbRfJtr7diBfexyp4rqO09Rpo0Vn2xxxfGqlYsiMhUPd3gyetXI6qsrfPnbUU8M0eJVVMMWmRo9VWtyoPbGtCEZDK4GZI2GTDP7D-U0ah_espkW2hsVJZbLwOYsaU_DRQFJyDRi31p6NGS3GZMdAVrLXESk0k4AZ6BaEEVz1.`

it('decrypt', async () => {
  const result = await hpke.jwt.decryptJWT(
    token,
    {
      recipientPrivateKey: private_key,
      hpke_info: new TextEncoder().encode('B97CF7BF-3F35-4367-A898-D537B7A26F51')
    })
  expect(result.protectedHeader.alg).toBe('HPKE-P256-SHA256-A128GCM')
  expect(result.protectedHeader.enc).toBe('dir')
})