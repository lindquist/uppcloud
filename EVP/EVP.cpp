#include "EVP.h"

using namespace Upp;

namespace UppCloud {

// ---------------------------------------------------------------------------

// according to the notes here:
// https://www.openssl.org/docs/man1.1.1/man3/PEM_read_bio_RSAPrivateKey.html
// all new code should use the PEM_write_bio_PKCS8PrivateKey, and PEM_write_PKCS8PrivateKey
// "The PrivateKey read routines can be used in all applications because they handle all formats transparently."
// 
// starting point:
// https://www.openssl.org/docs/man1.1.1/man7/evp.html
//
// not written against 3.x at this time, but 1.1.1

struct iBIO
{
	BIO* bio;

	iBIO() : bio(BIO_new(BIO_s_mem())) {}
	iBIO(const String& string)
		: bio(BIO_new_mem_buf((void *)~string, string.GetCount())) {};
	~iBIO() { BIO_free(bio); }
	operator BIO*() const { return bio; }
	operator bool() const { return bio != nullptr; }
};

//--------------------------------------------------------------------------

EVPKey::EVPKey()
{
   ctx = nullptr;
}

EVPKey::~EVPKey()
{
   EVP_PKEY_CTX_free(ctx);
}

bool EVPKey::LoadPrivate(const String& string_key)
{
   iBIO bio(string_key);
   if (!bio)
      return false;

   auto evp = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
   if (!evp)
      return false;
   if (ctx)
       EVP_PKEY_CTX_free(ctx);
   ctx = EVP_PKEY_CTX_new(evp, nullptr);
   if (!ctx)
      return false;
   EVP_PKEY_free(evp); // _new increments the ref count

   return true;
}

bool EVPKey::LoadPublic(const String& string_key)
{
   iBIO bio(string_key);
   if (!bio)
      return false;

   auto evp = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
   if (!evp)
      return false;
   if (ctx)
       EVP_PKEY_CTX_free(ctx);
   ctx = EVP_PKEY_CTX_new(evp, nullptr);
   if (!ctx)
      return false;
   EVP_PKEY_free(evp); // _new increments the ref count

   return true;
}

String EVPKey::SavePrivatePKCS8() const
{
   iBIO bio;
   String key = String::GetVoid();
   if (!bio || !ctx)
      return key;

   auto evp = EVP_PKEY_CTX_get0_pkey(ctx); // does not increment the ref count
   if (!evp)
      return key;
   if (PEM_write_bio_PKCS8PrivateKey(bio, evp, nullptr, nullptr, 0, nullptr, nullptr) <= 0)
      return key;

   char* ptr = nullptr;
   auto len = BIO_get_mem_data(bio, &ptr);
   if (len > 0) {
      ASSERT(ptr != nullptr);
      key = String(ptr, len); // copy
   }

   return key;
}

String EVPKey::SavePrivate() const
{
   iBIO bio;
   String key = String::GetVoid();
   if (!bio || !ctx)
      return key;

   auto evp = EVP_PKEY_CTX_get0_pkey(ctx); // does not increment the ref count
   if (!evp)
      return key;
   if (PEM_write_bio_PrivateKey(bio, evp, nullptr, nullptr, 0, nullptr, nullptr) <= 0)
      return key;

   char* ptr = nullptr;
   auto len = BIO_get_mem_data(bio, &ptr);
   if (len > 0) {
      ASSERT(ptr != nullptr);
      key = String(ptr, len); // copy
   }
   return key;
}

String EVPKey::SavePublic() const
{
   iBIO bio;
   String key = String::GetVoid();
   if (!bio || !ctx)
      return key;

   auto evp = EVP_PKEY_CTX_get0_pkey(ctx); // does not increment the ref count
   if (!evp)
      return key;
   if (PEM_write_bio_PUBKEY(bio, evp) <= 0)
      return key;

   char* ptr = nullptr;
   auto len = BIO_get_mem_data(bio, &ptr);
   if (len > 0) {
      ASSERT(ptr != nullptr);
      key = String(ptr, len); // copy
   }
   return key;
}

bool EVPKey::Generate(int id)
{
   if (ctx)
      EVP_PKEY_CTX_free(ctx);
   ctx = EVP_PKEY_CTX_new_id(id, nullptr);
   if (!ctx)
      return false;
   if (EVP_PKEY_keygen_init(ctx) <= 0)
      return false;
   EVP_PKEY* evp = nullptr;
   if (EVP_PKEY_keygen(ctx, &evp) <= 0) // the returned key is not part of this context
      return false;
   if (!evp)
       return false;
   EVP_PKEY_CTX_free(ctx);
   ctx = EVP_PKEY_CTX_new(evp, nullptr);
   EVP_PKEY_free(evp); // _new increments the ref count
   return true;
}

int EVPKey::GetId() const
{
   auto evp = EVP_PKEY_CTX_get0_pkey(ctx); // does not increment the ref count
   ASSERT(evp != nullptr);
   return EVP_PKEY_id(evp);
}

String EVPKey::Sign(const String& data) const
{
   const String svoid = String::GetVoid();
   if (!ctx)
      return svoid;
   if (EVP_PKEY_sign_init(ctx) <= 0)
      return svoid;
   size_t sigLen;
   if (EVP_PKEY_sign(ctx, nullptr, &sigLen, (const byte*)~data, (size_t)data.GetCount()) <= 0)
      return svoid;
   ASSERT(sigLen > 0);
   Buffer<byte> sigBuf(sigLen);
   if (EVP_PKEY_sign(ctx, ~sigBuf, &sigLen, (const byte*)~data, data.GetCount()) <= 0)
      return svoid;

   return String((const char *)~sigBuf, sigLen); // copy
}

bool EVPKey::Verify(const String& data, const String& signature) const
{
   if (!ctx)
      return false;
   if (EVP_PKEY_verify_init(ctx) <= 0)
      return false;
   if (EVP_PKEY_verify(ctx, (const byte*)~signature, (size_t)signature.GetCount(), (const byte*)~data, (size_t)data.GetCount()) > 0)
      return true;
   return false;
}

} // UppCloud
