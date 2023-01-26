#include <Core/Core.h>
#include <EVP/EVP.h>

using namespace Upp;
using namespace UppCloud;

static void EncryptDecrypt()
{
	auto algo = EVP_aes_128_cbc();
	
	EVPCipher cipher;
	String message = "hello world this message will be encrypted then decrypted";
	
	// from example: https://www.openssl.org/docs/man1.1.1/man3/EVP_EncryptInit.html
	String key = "0123456789abcdeF";
	String iv = "1234567887654321";
	ASSERT(cipher.BeginEncrypt(algo, key, iv));
	ASSERT(cipher.DoEncrypt(message));
	String secret = cipher.FinishEncrypt();
	ASSERT(secret != message);
	
	ASSERT(cipher.BeginDecrypt(algo, key, iv));
	ASSERT(cipher.DoDecrypt(secret));
	String message2 = cipher.FinishDecrypt();
	ASSERT(secret != message2);
	ASSERT(message == message2);
};

CONSOLE_APP_MAIN
{
	EncryptDecrypt();
	
	Cout() << GetExeTitle() << ": all ok\n";
}
