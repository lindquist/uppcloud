#ifndef _EVP_EVP_h
#define _EVP_EVP_h

#include <Core/SSL/SSL.h>

namespace UppCloud {

struct EVPKey : Upp::Moveable<EVPKey>
{
	// formerly-NID ids (not entirely suggested by very convenient)
	enum {
		NONE = EVP_PKEY_NONE,
		RSA = EVP_PKEY_RSA,
		RSA2 = EVP_PKEY_RSA2,
		RSA_PSS = EVP_PKEY_RSA_PSS,
		DSA = EVP_PKEY_DSA,
		DSA1 = EVP_PKEY_DSA1,
		DSA2 = EVP_PKEY_DSA2,
		DSA3 = EVP_PKEY_DSA3,
		DSA4 = EVP_PKEY_DSA4,
		DH = EVP_PKEY_DH,
		DHX = EVP_PKEY_DHX,
		EC = EVP_PKEY_EC,
		SM2 = EVP_PKEY_SM2,
		HMAC = EVP_PKEY_HMAC,
		CMAC = EVP_PKEY_CMAC,
		SCRYPT = EVP_PKEY_SCRYPT,
		TLS1_PRF = EVP_PKEY_TLS1_PRF,
		HKDF = EVP_PKEY_HKDF,
		POLY1305 = EVP_PKEY_POLY1305,
		SIPHASH = EVP_PKEY_SIPHASH,
		X25519 = EVP_PKEY_X25519,
		ED25519 = EVP_PKEY_ED25519,
		X448 = EVP_PKEY_X448,
		ED448 = EVP_PKEY_ED448,
	};

   EVP_PKEY_CTX *ctx;

	EVPKey();
	~EVPKey();

   bool LoadPrivate(const Upp::String& string_key);
	bool LoadPublic(const Upp::String& string_key);
   Upp::String SavePrivatePKCS8() const;
	Upp::String SavePrivate() const;
	Upp::String SavePublic() const;
   bool Generate(int type);
	int GetId() const;

   Upp::String Sign(const Upp::String& message) const;
   bool Verify(const Upp::String& message, const Upp::String& signature) const;

};

struct EVPCipher : Upp::Moveable<EVPCipher>
{
	EVP_CIPHER_CTX *ctx;

	EVPCipher();
	~EVPCipher();

	void Reset();

	bool BeginEncrypt(const EVP_CIPHER* cipher, const Upp::String& key, const Upp::String& iv);
	bool DoEncrypt(const Upp::String& data);
	Upp::String FinishEncrypt();
	
	bool BeginDecrypt(const EVP_CIPHER* cipher, const Upp::String& key, const Upp::String& iv);
	bool DoDecrypt(const Upp::String& data);
	Upp::String FinishDecrypt();
	
	Upp::String Encrypt(const EVP_CIPHER* cipher, const Upp::String& key, const Upp::String& iv, const Upp::String& message);
	Upp::String Decrypt(const EVP_CIPHER* cipher, const Upp::String& key, const Upp::String& iv, const Upp::String& message);
	
	int GetBlockSize() const;
	static int GetCipherBlockSize(const EVP_CIPHER* cipher);

private:
	Upp::String buffer;
};

} // UppCloud

#endif
