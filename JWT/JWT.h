#ifndef _JWT_JWT_h
#define _JWT_JWT_h

#include <RSA/RSA.h>

// based on https://datatracker.ietf.org/doc/html/rfc7519

namespace UppCloud {

using namespace Upp;

// the key type really should be generalized for this

struct JWT : Moveable<JWT>
{
    JWT();
	JWT(const String& token);
    JWT(Value header, Value payload);
	
    bool Parse(const String& token);
    String Sign(const RSAPrivateKey& priv);
    bool Verify(const RSAPublicKey& pub);
    
    ValueMap& SetHeader()		{ header.Clear(); return header; }
    ValueMap& SetPayload()		{ payload.Clear(); return payload; }
    
    const String& Get() const	{ return token; }
    operator String() const		{ return token; }
    operator bool() const		{ return valid; }
    
    // make private maybe?
    ValueMap header;
    ValueMap payload;
    String signature;
    
    String token; // if seen
    bool valid; // if verified
};

} // UppCloud

#endif
