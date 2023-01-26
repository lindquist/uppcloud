#include "EVP.h"

using namespace Upp;

namespace UppCloud {

EVPCipher::EVPCipher()
{
   ctx = EVP_CIPHER_CTX_new();
   ASSERT(ctx);
}

EVPCipher::~EVPCipher()
{
   EVP_CIPHER_CTX_free(ctx);
}

void EVPCipher::Reset()
{
    EVP_CIPHER_CTX_free(ctx);
    ctx = EVP_CIPHER_CTX_new();
    ASSERT(ctx);
    buffer.Clear();
}

bool EVPCipher::BeginEncrypt(const EVP_CIPHER* cipher, const String& key, const String& iv)
{
   if (EVP_EncryptInit_ex(ctx, cipher, nullptr, (const byte*)~key, (const byte*)~iv) <= 0)
      return false;
   return true;
}


bool EVPCipher::DoEncrypt(const String& data)
{
	int outlen = data.GetCount() + EVP_MAX_BLOCK_LENGTH;
   Buffer<byte> out(outlen);
   if (EVP_EncryptUpdate(ctx, ~out, &outlen, (const byte*)~data, data.GetLength()) <= 0)
      return false;
   if (outlen > 0)
      buffer.Cat((char*)~out, outlen);
   return true;
}

String EVPCipher::FinishEncrypt()
{
   int outlen = EVP_MAX_BLOCK_LENGTH;
   byte out[EVP_MAX_BLOCK_LENGTH];
   if (EVP_EncryptFinal_ex(ctx, out, &outlen) <= 0)
      return String::GetVoid();
   if (outlen > 0)
      buffer.Cat((char*)out, outlen);
   return pick(buffer);
}

bool EVPCipher::BeginDecrypt(const EVP_CIPHER* cipher, const String& key, const String& iv)
{
   if (EVP_DecryptInit_ex(ctx, cipher, nullptr, (const byte*)~key, (const byte*)~iv) <= 0)
      return false;
   return true;
}

bool EVPCipher::DoDecrypt(const String& data)
{
	int outlen = data.GetCount() + EVP_MAX_BLOCK_LENGTH;
   Buffer<byte> out(outlen);
   if (EVP_DecryptUpdate(ctx, ~out, &outlen, (const byte*)~data, data.GetLength()) <= 0)
      return false;
   if (outlen > 0)
      buffer.Cat((char*)~out, outlen);
   return true;
}

String EVPCipher::FinishDecrypt()
{
   int outlen = EVP_MAX_BLOCK_LENGTH;
   byte out[EVP_MAX_BLOCK_LENGTH];
   if (EVP_DecryptFinal_ex(ctx, out, &outlen) <= 0)
      return String::GetVoid();
    if (outlen > 0)
        buffer.Cat((char*)out, outlen);
   return pick(buffer);

}

int EVPCipher::GetBlockSize() const
{
	return EVP_CIPHER_CTX_block_size(ctx);
}

int EVPCipher::GetCipherBlockSize(const EVP_CIPHER *cipher)
{
	return EVP_CIPHER_block_size(cipher);
}

String EVPCipher::Encrypt(const EVP_CIPHER* cipher, const String& key, const String& iv, const String& message)
{
   if (!BeginEncrypt(cipher, key, iv))
      return String::GetVoid();
   if (!DoEncrypt(message))
      return String::GetVoid();
   return FinishEncrypt();
}

String EVPCipher::Decrypt(const EVP_CIPHER* cipher, const String& key, const String& iv, const String& message)
{
   if (!BeginDecrypt(cipher, key, iv))
      return String::GetVoid();
   if (!DoDecrypt(message))
      return String::GetVoid();
   return FinishDecrypt();
}

} // UppCloud
