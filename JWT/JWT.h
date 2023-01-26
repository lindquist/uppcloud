#ifndef _JWT_JWT_h
#define _JWT_JWT_h

#include <RSA/RSA.h>

// based on https://datatracker.ietf.org/doc/html/rfc7519

namespace UppCloud {

// the key type really should be generalized for this

struct JWT : Upp::Moveable<JWT>
{
    JWT();
	JWT(const Upp::String& token);
    JWT(Upp::Value header, Upp::Value payload);
	
    bool Parse(const Upp::String& token);
    Upp::String Sign(const RSAPrivateKey& priv);
    bool Verify(const RSAPublicKey& pub);
    
    Upp::ValueMap& SetHeader()      { header.Clear(); return header; }
    Upp::ValueMap& SetPayload()     { payload.Clear(); return payload; }
    
    const Upp::String& Get() const  { return token; }
    operator Upp::String() const    { return token; }
    operator bool() const           { return valid; }
    
    // make private maybe?
    Upp::ValueMap header;
    Upp::ValueMap payload;
    Upp::String signature;
    
    Upp::String token; // if seen
    bool valid; // if verified
};

} // UppCloud

#endif
