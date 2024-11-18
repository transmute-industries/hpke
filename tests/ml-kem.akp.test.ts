import moment from 'moment'
import { jose as hpke } from '../src'


import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { XWing } from "@hpke/hybridkem-x-wing";

it('X-Wing Sanity', async () => {
    const suite = new CipherSuite({
      kem: new XWing(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm(),
    });
    // NOTE: The following support for JWKs with the AKP key type is experimental.
    // Please be aware that the specifications are subject to change without notice.
    const jwkPub = {
      kty: "AKP",
      kid: "01",
      alg: "X-Wing",
      pub:
        "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
      key_ops: [],
    };
    const pk = await suite.kem.importKey("jwk", jwkPub, true);
    // In addition to importing keys from external sources, you can also generate keys as follows:
    //   const rkp = await suite.kem.generateKeyPair();
    //   const rkp = await suite.kem.deriveKeyPair(random32bytesValue);
    const sender = await suite.createSenderContext({ recipientPublicKey: pk });
    const jwkPriv = {
      kty: "AKP",
      kid: "01",
      alg: "X-Wing",
      priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
      key_ops: ["deriveBits"],
    };
    const sk = await suite.kem.importKey("jwk", jwkPriv, false);
    const recipient = await suite.createRecipientContext({
      recipientKey: sk,
      enc: sender.enc,
    });
    const encrypted = await sender.seal(
      new TextEncoder().encode("Hello World"),
    );
    const pt = await recipient.open(encrypted);
    expect(new TextDecoder().decode(pt)).toBe('Hello World')
})

it('X-Wing JWE', async () => {
  // const privateKey = await hpke.jwk.generate('HPKE-X-Wing-SHA256-A128GCM')
  const privateKey = {
    "kty": "AKP",
    "alg": "HPKE-X-Wing-SHA256-A128GCM",
    "pub": "afBkNtMvxVd_goqlJZAP_cNJAOJ7V7BvIVF5IkQx4SBwbGvEk_wDnSXKpIUSFoEBVsV8fwlga9w-0cFUpHN9U6E66hCwxFeFcRMsLClplNRT_1gVs-h2mignEQC6RwNZzUNYqiuagMeb3oPP1Ra3AAWgr8nKMTWdxFaZvwNYuKlkTVkd5CgkLsAUk7wyzRe-5pglFdfIO-AydYy9a3iKLzDOSdsIqCyAQJtivOYcMMnPFpuTUUbAkBUllJIzIXY0G0xwOcw4gNJHvnCG_5xr78oAReuSBjaY7WMYYmYXAK2zNls6FhYNtlaf2dSJEgku8KG7q4ANcwIbl0krjrB6MLPISEOMfrkbBgmeiyQfSEC1WVSd_1DGROynxLt19nw6ZZgX9ZluFkAjoJjLXHvOP6hNvimPCmW5cEGhClNZhAdrsboz8CUV0BMrACFLEqdkkxUqcoyouxyMUiIV5MuQnBG5f4JLUhQtP6OufRhq-Pe6iWdPCNapuTtofSepGBO3eDxd5JtV-uVuG0lEoXUYxFaPM0mgW2kP3Lwl_PfFZ-A7_QOiT4tZBhZ_IipE3padOJG_P6qEgYmMmNN4vRzBTcKHGxOuAtcYANNBxKCvCzl6hOUwLiwFC2AsyeMTkIfHOQcSGhJtMguxgty0Hcqu4CWfTfW5vqOCbbyGzyFCU1Cp-0SYdvrFKnOcsjrCnJZhZdilXqxcmumyS8O6rhmaM2E6BZJs4mW0PtTGo6iRletEOQtm0gwcrMESWcaX_JiDsti42QGlD9ZVzBktDvOZfTYUGFnMCPmLpih1n5ew-9hoojM3AelfAgcAVqOvEOJjSzVNk4IpM3wQy4szODrIU-sCBMCKjmJKRrhfJAavBvShgZlNXTSZfcVz1nwcPiYvDIhb-YHBCFqt_zUmGyy5FTWO3TgTGuTDZmzBKGOgNMk9r-smuobKHbWguscR0mEMo5B6VUxqOecYNTsfiTkcXqxkv4Ifemhl8LgptGKsoNsJm9MQHBSW21YCwFxbG4KCCwRDjMctbcMOR-xFFPSbwAGnKyBm-eVhF5ywdGBQ3ONhIYlOJHcJMymRNVQJZ2iWRgvLunEC73qO1eYa1Bah0ncXPWI79iCQXDRsrPJF3RQMEAgA6aErotJ29FCWn9ZhkzdspKBWnOK7zYVsrFgQkQrFlrmpzIYVXfm7sGqZwGucXhu-2HHBBIQ9iHp7MiS3MucHG-Gb1VdI0lRYbPGZJ5M2RBZALrCqgHh0Gwss20MNonaqnglKPytOvne0bsOjgpaOfJYr5AC5uXtmyOx6e6qzv1BIyiNvCbEwTcS64IQ7CEai5dd9x1lh4ioZhFKjgdqEW_BmT-UNiiyxkhKOJ5pVmZVns3CRORwmfTigWfxsEArNQcy1EoN2-pOJMseTQXIfZlq7i5OidSplvCvM7BSsVExJM4qOa7akZiMLtUKte6CFtGl51DQizeBnxJUn70E3VZxVwOgwsmNlJTFnW1pcOubGEIh-vjEAtXNrnXsAGvxSRwgzRVUoJ5TFhzUpTyt2he48W9M8uuIb1AsBx8R9mJCQ3r31wyobDKSWNm8CMmbchd3JU_RKCZA4K6Y-W6OwD-U0OvzZ4vLjRLVOaQ",
    "priv": "FmI_sPWh20npiIGtApYwZ50DiTOE6bAKGd7SFU_b4yM"
  }
  // const publicKey = await hpke.jwk.publicFromPrivate(privateKey)
  const { priv, ...publicKey} = privateKey
  const plaintext = new TextEncoder().encode(`🖤 this plaintext!`)
  const additionalAuthenticatedData = new TextEncoder().encode('🏴‍☠️ beware the aad!')
  const encrypted = await hpke.modes.integrated.encrypt(plaintext, publicKey, {
    additionalAuthenticatedData,
    recipientPublicKey:  publicKey, 
  })
  const decrypted = await hpke.modes.integrated.decrypt(encrypted, privateKey, {
    recipientPrivateKey: privateKey,
  })
  expect(decrypted.protectedHeader.alg).toBe('HPKE-X-Wing-SHA256-A128GCM')
  expect(decrypted.protectedHeader.enc).toBe('dir')
  expect(new TextDecoder().decode(decrypted.plaintext)).toBe(`🖤 this plaintext!`)
  expect(new TextDecoder().decode(decrypted.additionalAuthenticatedData)).toBe('🏴‍☠️ beware the aad!')
})

