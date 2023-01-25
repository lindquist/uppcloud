#include <JWT/JWT.h>

using namespace Upp;
using namespace UppCloud;

CONSOLE_APP_MAIN
{
	StdLogSetup(LOG_COUT);
	
	RSAPrivateKey priv;
	auto keyok = priv.Generate(2048);
	ASSERT(keyok);
	
	RSAPublicKey pub = priv.GetPublicKey();
	ASSERT(pub);
	
	JWT jwt;
	jwt.SetHeader()
		("alg", "RS256")
		("typ", "JWT");
	jwt.SetPayload()
		("sub", "1234567890")
		("name", "John Doe")
		("admin", true)
		("iat", 1516239022);
	
	ASSERT(!jwt);
	String tok = jwt.Sign(priv);
	ASSERT(!tok.IsVoid());
	ASSERT(jwt);
	
	auto split = Split(tok, ".", false);
	ASSERT(split.GetCount() == 3);
	
	String retok;
	retok << Base64Encode(AsJSON(jwt.header)) << "." << Base64Encode(AsJSON(jwt.payload));
	ASSERT(retok == (String() << split[0] << "." << split[1]));
	auto sig = priv.SignRS256(retok);
	ASSERT(!sig.IsVoid());
	ASSERT(sig == jwt.signature);
	
	Cout() << GetExeTitle() << ": all ok\n";
}



















