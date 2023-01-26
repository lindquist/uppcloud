#ifndef _RSA_RSA_h
#define _RSA_RSA_h

#include <Core/SSL/SSL.h>

namespace UppCloud {

struct RSAPrivateKey : Upp::Moveable<RSAPrivateKey>
{
	RSA* priv = nullptr;
	
	RSAPrivateKey()			{}
	RSAPrivateKey(const Upp::String& pem_string)
							{ SetKey(pem_string); }
	~RSAPrivateKey();
	
	operator RSA*() const	{ return priv; }
	operator bool() const	{ return priv != nullptr; }
	
	bool SetKey(const Upp::String& pem_string);
	Upp::String GetKey() const;
	bool Generate(int bits, BN_ULONG e = RSA_F4);
	RSA* GetPublicKey() const;

	Upp::String SignRS256(const Upp::String& text) const;
};

struct RSAPublicKey : Upp::Moveable<RSAPublicKey>
{
	RSA *pub = nullptr;
	
	RSAPublicKey()		{}
	RSAPublicKey(const Upp::String& pem_string)
							{ SetKey(pem_string); }
	RSAPublicKey(RSA* pubkey)
							{ pub = pubkey; }
	~RSAPublicKey();
	
	operator RSA*() const	{ return pub; }
	operator bool() const	{ return pub != nullptr; }
	
	bool SetKey(const Upp::String& pem);
	Upp::String GetKey() const;
	
	bool VerifyRS256(const Upp::String& text, const Upp::String& signature) const;
};

} // UppCloud

#endif
