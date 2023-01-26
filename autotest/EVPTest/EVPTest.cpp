#include <Core/Core.h>
#include <EVP/EVP.h>

using namespace Upp;
using namespace UppCloud;

#define PASS(x) do{ if (!(x)){ DUMP(SslGetLastError()); ASSERT(0); } }while(0);
#define FAIL(x) do{ if   (x) { DUMP(SslGetLastError()); ASSERT(0); } }while(0);

static void GenerateSave()
{
	EVPKey key;
	PASS(key.Generate(EVPKey::RSA));
	String s = key.SavePrivate();
	ASSERT(!s.IsVoid());
	ASSERT(s.Find("BEGIN PRIVATE KEY") > 0);
}

static void GenerateSaveLoad()
{
	EVPKey key;
	PASS(key.Generate(EVPKey::RSA));
	String s = key.SavePrivate();
	ASSERT(!s.IsVoid());
	ASSERT(s.Find("BEGIN PRIVATE KEY") > 0);
	
	EVPKey key2;
	PASS(key2.LoadPrivate(s));
	String s2 = key2.SavePrivate();
	
	ASSERT(s == s2);
}

static void GenerateSavePubLoad()
{
	EVPKey key;
	PASS(key.Generate(EVPKey::RSA));
	String s = key.SavePublic();
	ASSERT(!s.IsVoid());
	ASSERT(s.Find("BEGIN PUBLIC KEY") > 0);
	
	EVPKey key2;
	PASS(key2.LoadPublic(s));
	String s2 = key2.SavePublic();
	ASSERT(!s2.IsVoid());
	ASSERT(s2.Find("BEGIN PUBLIC KEY") > 0);
	ASSERT(s == s2);
	
	String s3 = key2.SavePrivate(); // actually returns key - hm
	ASSERT(s3.Find("BEGIN PRIVATE KEY") > 0);
}

static void GenerateSignVerify()
{
	EVPKey key;
	PASS(key.Generate(EVPKey::RSA));
	
	String message = "this is a secret message";
	PASS(key.InitSign());
	String signature = key.Sign(message);
	ASSERT(signature.GetCount() > 0);
	
	String pubstring = key.SavePublic();
	ASSERT(!pubstring.IsVoid());

	EVPKey pub;
	PASS(pub.LoadPublic(pubstring));
	PASS(pub.InitVerify());
	PASS(pub.Verify(message, signature));
}

static void GenerateSignVerifyMd()
{
	EVPKey key;
	PASS(key.Generate(EVPKey::RSA));
	
	String message = "this is a secret message";
	PASS(key.InitSign());
	PASS(key.SetSignatureDigest(EVP_sha512()));
	
	EVPDigest dig(EVP_sha512());
	String digest = dig.Digest(message);
	String signature = key.Sign(digest);
	
	String pubstring = key.SavePublic();
	ASSERT(pubstring.Find("PUBLIC") > 0);
	ASSERT(!pubstring.IsVoid());

	EVPKey pub;
	PASS(pub.LoadPublic(pubstring));
	PASS(pub.InitVerify());
	PASS(pub.SetSignatureDigest(EVP_sha384()));
	FAIL(pub.Verify(digest, signature));
	
	PASS(pub.InitVerify());
	PASS(pub.SetSignatureDigest(EVP_sha512()));
	PASS(pub.Verify(digest, signature));
}

CONSOLE_APP_MAIN
{
	StdLogSetup(LOG_COUT);
	
	GenerateSave();
	GenerateSaveLoad();
	GenerateSavePubLoad();
	GenerateSignVerify();
	GenerateSignVerifyMd();
	
	Cout() << GetExeTitle() << ": all ok\n";
}
