#include <Core/Core.h>
#include <EVP/EVP.h>

using namespace Upp;
using namespace UppCloud;

static void GenerateSave()
{
	EVPKey key;
	ASSERT(key.Generate(EVPKey::RSA));
	String s = key.SavePrivate();
	ASSERT(!s.IsVoid());
	ASSERT(s.Find("BEGIN PRIVATE KEY") > 0);
}

static void GenerateSaveLoad()
{
	EVPKey key;
	ASSERT(key.Generate(EVPKey::RSA));
	String s = key.SavePrivate();
	ASSERT(!s.IsVoid());
	ASSERT(s.Find("BEGIN PRIVATE KEY") > 0);
	
	EVPKey key2;
	ASSERT(key2.LoadPrivate(s));
	String s2 = key2.SavePrivate();
	
	ASSERT(s == s2);
}

static void GenerateSavePubLoad()
{
	EVPKey key;
	ASSERT(key.Generate(EVPKey::RSA));
	String s = key.SavePublic();
	ASSERT(!s.IsVoid());
	ASSERT(s.Find("BEGIN PUBLIC KEY") > 0);
	
	EVPKey key2;
	ASSERT(key2.LoadPublic(s));
	String s2 = key2.SavePublic();
	ASSERT(!s2.IsVoid());
	ASSERT(s2.Find("BEGIN PUBLIC KEY") > 0);
	ASSERT(s == s2);
	
	String s3 = key2.SavePrivate(); // actually returns key - hm
	ASSERT(s3.Find("BEGIN PRIVATE KEY") > 0);
}

CONSOLE_APP_MAIN
{
	GenerateSave();
	GenerateSaveLoad();
	GenerateSavePubLoad();
	
	Cout() << GetExeTitle() << ": all ok\n";
}
