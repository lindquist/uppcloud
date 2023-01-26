#include "EVP.h"

using namespace Upp;

namespace UppCloud {

EVPDigest::EVPDigest()
{
    mdctx = EVP_MD_CTX_new();
    ASSERT(mdctx != nullptr);
    md = nullptr;
}

EVPDigest::EVPDigest(const EVP_MD *md_)
{
    md = md_;
    mdctx = EVP_MD_CTX_new();
    ASSERT(mdctx != nullptr);
}

EVPDigest::~EVPDigest()
{
    EVP_MD_CTX_free(mdctx);
}

bool EVPDigest::SetDigest(const EVP_MD *md)
{
    return md && EVP_DigestInit_ex(mdctx, md, nullptr) > 0;
}

String EVPDigest::Digest(const String& data) const
{
    if (md && Init() && Update(data))
        return Final();
    return String::GetVoid();
}

bool EVPDigest::Init() const
{
    return md && EVP_DigestInit_ex(mdctx, md, nullptr) > 0;
}

bool EVPDigest::Update(const String& data) const
{
    return EVP_DigestUpdate(mdctx, ~data, data.GetLength()) > 0;
}

String EVPDigest::Final() const
{
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) <= 0)
        return String::GetVoid();
    
    return String((const char*)md_value, md_len);
}

} // UppCloud
