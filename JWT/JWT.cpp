#include "JWT.h"

namespace UppCloud {

JWT::JWT()
{
	header("typ", "JWT");
	header("alg", "RS256");
	valid = false;
}

JWT::JWT(const String& token)
{
	Parse(token);
	valid = false; // signature not verified
}

JWT::JWT(Value header, Value payload)
{
	this->header = header;
	this->payload = payload;
	valid = false;
}

bool JWT::Parse(const String& tok)
{
	token = tok;

	auto parts = Split(~tok, '.', false);
	int N = parts.GetCount();
	if (N != 3)
		return false;
	
	auto hdr = Base64Decode(parts[0]);
	if (hdr.IsEmpty())
		return false;
	header = ParseJSON(hdr);
	if (IsError(header))
		return false;
	if (header["typ"] != "JWT")
		return false;
	if (header["alg"] != "RS256")
		return false;
	
	auto data = Base64Decode(parts[1]);
	if (data.IsEmpty())
		return false;
	payload = ParseJSON(data);
	if (IsError(payload))
		return false;

	signature = Base64Decode(parts[2]);
	if (signature.IsEmpty())
		return false; // fixme check spec

	return true;
}

String JWT::Sign(const RSAPrivateKey& priv)
{
	signature = String::GetVoid();
	
	auto& alg = header["alg"];
	if (IsError(alg) || alg != "RS256" || !priv)
		return signature;
	
	String tok;
	tok << Base64Encode(AsJSON(header)) << "." << Base64Encode(AsJSON(payload));
	
	signature = priv.SignRS256(tok);
	if (signature.IsVoid())
		return signature;
	
	// append signature
	tok << "." << Base64Encode(signature);
	valid = true;
	
	return token = pick(tok);
}

bool JWT::Verify(const RSAPublicKey& pub)
{
	if (token.IsEmpty() || signature.IsEmpty())
		return false;
	
	auto parts = Split(~token, '.', false);
	if (parts.GetCount() != 3)
		return false;
	
	String tok;
	tok << parts[0] << "." << parts[1]; // already b64
	return valid = pub.VerifyRS256(tok, signature);
}

} // UppCloud
