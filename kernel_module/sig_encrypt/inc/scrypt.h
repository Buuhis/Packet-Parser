#ifndef __SCRYPT__
#define __SCRYPT__

#include "types.h"

SCRYPT_API int scrypt_Init();
SCRYPT_API int scrypt_Cleanup();
SCRYPT_API const char* scrypt_ErrorString(int err);

SCRYPT_API int scrypt_RandomBytes(byte* out, word32 outLen);

SCRYPT_API SCryptCipherCtx* scrypt_CipherCtxNew();
SCRYPT_API void scrypt_CipherCtxFree(SCryptCipherCtx* ctx);

SCRYPT_API int scrypt_CipherInit(SCryptCipherCtx* ctx, SCryptCipherType type, const byte* key,
                                 word32 keySz, const byte* iv, word32 ivSz, int enc);
SCRYPT_API int scrypt_CipherUpdate(SCryptCipherCtx* ctx, const byte* input, word32 inputLen, byte* output,
                                   word32* outLen);
SCRYPT_API int scrypt_CipherFinal(SCryptCipherCtx* ctx, byte* output, word32* outLen);

SCRYPT_API int scrypt_CipherUpdateAAD(SCryptCipherCtx* ctx, const byte* aad, word32 aadLen);
SCRYPT_API int scrypt_CipherSetTagSize(SCryptCipherCtx* ctx, word32 sz);
SCRYPT_API int scrypt_CipherGetTag(SCryptCipherCtx* ctx, byte* tag, word32* tagLen);
SCRYPT_API int scrypt_CipherSetTag(SCryptCipherCtx* ctx, const byte* tag, word32 tagLen);

SCRYPT_API SCryptDigestCtx* scrypt_DigestCtxNew();
SCRYPT_API void scrypt_DigestCtxFree(SCryptDigestCtx* ctx);
SCRYPT_API int scrypt_DigestInit(SCryptDigestCtx* ctx, SCryptDigestType type, word32 digestSize);
SCRYPT_API int scrypt_DigestUpdate(SCryptDigestCtx* ctx, const byte* input, word32 inputLen);
SCRYPT_API int scrypt_DigestFinal(SCryptDigestCtx* ctx, byte* digest);
SCRYPT_API int scrypt_GetDigestSize(SCryptDigestCtx* ctx);

SCRYPT_API SCryptHmacCtx* scrypt_HmacCtxNew();
SCRYPT_API void scrypt_HmacCtxFree(SCryptHmacCtx* ctx);
SCRYPT_API int scrypt_HmacInit(SCryptHmacCtx* ctx, const byte* key, word32 keyLen, SCryptDigestType hash);
SCRYPT_API int scrypt_HmacUpdate(SCryptHmacCtx* ctx, const byte* in, word32 inLen);
SCRYPT_API int scrypt_HmacFinal(SCryptHmacCtx* ctx, byte* out, word32 outLen);
SCRYPT_API int scrypt_HmacGetTagSize(SCryptHmacCtx* ctx);

SCRYPT_API int scrypt_HKDF(SCryptDigestType hash, const byte* key, word32 keySz, const byte* salt,
                           word32 saltSz, const byte* info, word32 infoSz, byte* out, word32 outSz);
SCRYPT_API int scrypt_HKDF_Extract(SCryptDigestType hash, const byte* inKey, word32 inKeySz,
                                   const byte* salt, word32 saltSz, byte* out, word32 outSz);
SCRYPT_API int scrypt_HKDF_Expand(SCryptDigestType hash, const byte* inKey, word32 inKeySz,
                                  const byte* info, word32 infoSz, byte* out, word32 outSz);

SCRYPT_API SCryptMlKemKey* scrypt_MlKemKeyNew();
SCRYPT_API void scrypt_MlKemKeyFree(SCryptMlKemKey* mlkey);
SCRYPT_API int scrypt_MlKemKeyGen(SCryptMlKemKey* mlkey, SCryptMlKemLevel level);
SCRYPT_API int scrypt_MlKemGetKeyLevel(SCryptMlKemKey* mlkey);

SCRYPT_API int scrypt_MlKemExportPublicKey(SCryptMlKemKey* mlkey, byte* out, word32 size);
SCRYPT_API int scrypt_MlKemExportPrivateKey(SCryptMlKemKey* mlkey, byte* out, word32 size);
SCRYPT_API int scrypt_MlKemImportPublicKey(SCryptMlKemKey* mlkey, const byte* in, word32 size, SCryptMlKemLevel level);
SCRYPT_API int scrypt_MlKemImportPrivateKey(SCryptMlKemKey* mlkey, const byte* in, word32 size, SCryptMlKemLevel level);
SCRYPT_API int scrypt_MlKemPublicKeySize(SCryptMlKemKey* mlkey);
SCRYPT_API int scrypt_MlKemPrivateKeySize(SCryptMlKemKey* mlkey);

SCRYPT_API int scrypt_MlKemEncapsulate(SCryptMlKemKey* mlkey, byte* ct, word32 ctSz, byte* ss, word32 ssSz);
SCRYPT_API int scrypt_MlKemDecapsulate(SCryptMlKemKey* mlkey, byte* ss, word32 ssSz, const byte* ct, word32 ctSz);
SCRYPT_API int scrypt_MlKemCipherTextSize(SCryptMlKemKey* mlkey);
SCRYPT_API int scrypt_MlKemShareSecretSize(SCryptMlKemKey* mlkey);

SCRYPT_API SCryptMlDsaKey* scrypt_MlDsaKeyNew();
SCRYPT_API void scrypt_MlDsaKeyFree(SCryptMlDsaKey* mlkey);
SCRYPT_API int scrypt_MlDsaKeyGen(SCryptMlDsaKey* mlkey, SCryptMlDsaLevel level);
SCRYPT_API int scrypt_MlDsaGetKeyLevel(SCryptMlDsaKey* mlkey);

SCRYPT_API int scrypt_MlDsaExportPublicKey(SCryptMlDsaKey* mlkey, byte* out, word32 size);
SCRYPT_API int scrypt_MlDsaExportPrivateKey(SCryptMlDsaKey* mlkey, byte* out, word32 size);
SCRYPT_API int scrypt_MlDsaImportPublicKey(SCryptMlDsaKey* mlkey, const byte* in, word32 size, SCryptMlDsaLevel level);
SCRYPT_API int scrypt_MlDsaImportPrivateKey(SCryptMlDsaKey* mlkey, const byte* in, word32 size, SCryptMlDsaLevel level);
SCRYPT_API int scrypt_MlDsaPublicKeySize(SCryptMlDsaKey* mlkey);
SCRYPT_API int scrypt_MlDsaPrivateKeySize(SCryptMlDsaKey* mlkey);

SCRYPT_API int scrypt_MlDsaSign(SCryptMlDsaKey* mlkey, const byte* msg, word32 msgSz, byte* sig, word32 sigSz);
SCRYPT_API int scrypt_MlDsaVerify(SCryptMlDsaKey* mlkey, const byte* msg, word32 msgSz, const byte* sig, word32 sigSz);
SCRYPT_API int scrypt_MlDsaSignatureSize(SCryptMlDsaKey* mlkey);

#endif
