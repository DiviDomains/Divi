// Copyright (c) 2026 The Divi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypter_pq.h"
#include "MasterKey.h"
#include "PqBlockSigning.h"
#include "pqcrypto/divi_pqcrypto.h"
#include "script/PqStakingVaultScript.h"
#include "spork_pq.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#ifndef DIVI_PQ_STANDALONE_TEST
#include "ForkActivation.h"
#include <boost/test/unit_test.hpp>
#endif

namespace
{

static uint8_t HexNibble(char c)
{
    if (c >= '0' && c <= '9') {
        return static_cast<uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<uint8_t>(10 + (c - 'a'));
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<uint8_t>(10 + (c - 'A'));
    }
    std::fprintf(stderr, "Invalid hex character: %c\n", c);
    std::abort();
}

static std::vector<uint8_t> DecodeHex(const char* hexStr)
{
    const size_t len = std::strlen(hexStr);
    if ((len & 1U) != 0U) {
        std::fprintf(stderr, "Odd hex string length: %zu\n", len);
        std::abort();
    }
    std::vector<uint8_t> out(len / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>((HexNibble(hexStr[2 * i]) << 4) | HexNibble(hexStr[2 * i + 1]));
    }
    return out;
}

static std::string EncodeHex(const uint8_t* data, size_t len)
{
    static const char HEX_DIGITS[17] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[2 * i] = HEX_DIGITS[(data[i] >> 4) & 0x0fU];
        out[2 * i + 1] = HEX_DIGITS[data[i] & 0x0fU];
    }
    return out;
}

static std::string EncodeHex(const std::vector<uint8_t>& data)
{
    return EncodeHex(data.empty() ? nullptr : data.data(), data.size());
}

static void WriteBe32(uint8_t* dst, uint32_t val)
{
    dst[0] = static_cast<uint8_t>((val >> 24) & 0xffU);
    dst[1] = static_cast<uint8_t>((val >> 16) & 0xffU);
    dst[2] = static_cast<uint8_t>((val >> 8) & 0xffU);
    dst[3] = static_cast<uint8_t>(val & 0xffU);
}

#ifdef DIVI_PQ_STANDALONE_TEST
#define PQ_CHECK(cond)                                                                     \
    do {                                                                                   \
        if (!(cond)) {                                                                     \
            std::fprintf(stderr, "PQ_CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            std::abort();                                                                  \
        }                                                                                  \
    } while (0)

#define PQ_CHECK_EQ(a, b)                                                                  \
    do {                                                                                   \
        if (!((a) == (b))) {                                                               \
            std::cerr << "PQ_CHECK_EQ failed at " << __FILE__ << ":" << __LINE__ << ": "   \
                      << #a << " != " << #b << "\n";                                       \
            std::abort();                                                                  \
        }                                                                                  \
    } while (0)
#else
#define PQ_CHECK(cond) BOOST_CHECK(cond)
#define PQ_CHECK_EQ(a, b) BOOST_CHECK((a) == (b))
#endif

// ============================================================================
// Helper: Canonical FN-DSA-512 (897 B pk, 666 B sig) & ML-DSA-44 (1312 B pk, 2420 B sig)
// ============================================================================

static std::vector<uint8_t> BuildSampleFnDsa512Pubkey(uint8_t tag)
{
    std::vector<uint8_t> pk;
    pk.reserve(897);
    pk.push_back(0x09U);
    uint32_t acc = 0;
    unsigned int accBits = 0;
    for (uint32_t i = 0; i < 512U; ++i) {
        uint32_t coeff = (i + static_cast<uint32_t>(tag)) % 1024U;
        acc = (acc << 14) | coeff;
        accBits += 14U;
        while (accBits >= 8U) {
            accBits -= 8U;
            pk.push_back(static_cast<uint8_t>((acc >> accBits) & 0xffU));
        }
    }
    PQ_CHECK_EQ(pk.size(), static_cast<size_t>(897));
    PQ_CHECK_EQ(
        divi_pq_validate_pubkey_encoding(DIVI_PQ_SCHEME_FNDSA512, pk.data(), pk.size()),
        DIVI_PQ_OK);
    return pk;
}

static std::vector<uint8_t> BuildSampleFnDsa512Signature(uint8_t nonceByte)
{
    std::vector<uint8_t> sig(666, 0);
    sig[0] = 0x39U;
    for (size_t i = 1; i < 41; ++i) {
        sig[i] = nonceByte;
    }
    uint8_t* payload = sig.data() + 41;
    for (size_t coeffIdx = 0; coeffIdx < 512; ++coeffIdx) {
        size_t bitPos = coeffIdx * 9 + 8;
        size_t byteIdx = bitPos >> 3;
        unsigned int bitShift = static_cast<unsigned int>(7U - (bitPos & 7U));
        payload[byteIdx] |= static_cast<uint8_t>(1U << bitShift);
    }
    PQ_CHECK_EQ(
        divi_pq_validate_sig_encoding(DIVI_PQ_SCHEME_FNDSA512, sig.data(), sig.size()),
        DIVI_PQ_OK);
    return sig;
}

static std::vector<uint8_t> BuildSampleMlDsa44Pubkey(uint8_t tag)
{
    std::vector<uint8_t> pk(1312, 0);
    for (size_t i = 0; i < pk.size(); ++i) {
        pk[i] = static_cast<uint8_t>(static_cast<uint8_t>(i) + tag);
    }
    PQ_CHECK_EQ(
        divi_pq_validate_pubkey_encoding(DIVI_PQ_SCHEME_MLDSA44, pk.data(), pk.size()),
        DIVI_PQ_OK);
    return pk;
}

static std::vector<uint8_t> BuildSampleMlDsa44Signature(uint8_t cTildeByte)
{
    std::vector<uint8_t> sig(2420, 0);
    for (size_t i = 0; i < 32; ++i) {
        sig[i] = cTildeByte;
    }
    static const uint8_t ZERO_Z_CHUNK[9] = {0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x20, 0x00, 0x80};
    for (size_t offset = 32; offset < 2336; offset += 9) {
        std::memcpy(sig.data() + offset, ZERO_Z_CHUNK, 9);
    }
    PQ_CHECK_EQ(
        divi_pq_validate_sig_encoding(DIVI_PQ_SCHEME_MLDSA44, sig.data(), sig.size()),
        DIVI_PQ_OK);
    return sig;
}

// ============================================================================
// 1. DIP-PQ-1 Canonical Vectors & 17 Negative Vectors (pq_dip_pq_1.json)
// ============================================================================

static void RunDipPq1KeyHashVectorsTest()
{
    struct KeyHashVec {
        uint8_t schemeId;
        size_t pubkeyLen;
        const char* pubkeyHex;
        const char* keyHashHex;
        const char* addrKeyHashHex;
    };

    static const char MLDSA44_PK_HEX[] =
        "205ea462c081255c0000093ca36c98f7bd5172db7b2ef329804bdf3990d9e3bf"
        "b48b95b3d61278da0c95f4e8e6a3f74d6fd58542092bf595e7d6a640e43f6908"
        "e3fbad735d900d1e832a0d7097cfd8435ae4e530404aee235b3a3cb2de048747"
        "b930a8542aefd81935d2f1caefbb04a759367e187fff2624ceabf0dedf3fd3ab"
        "a8001c0c218f0053a596181316f23eff525a0e6b98e496af5c0ca37200a83ca7"
        "9634d0f909b17c18ac769bdc516dae116a397a53823338a28a3f37b1e9540478"
        "e890f825626aa5860d5322a42eb2b2b1ddea94fd317a49359c63d9d1956b54fa"
        "0406ec192f328bb05dc8cd6ffe83c491217da25570df9fb964f9309394e1b507"
        "b9970b4bf01cfb0a74f7f306bc73bede715622bc162777107f8e779d23c01121"
        "b6d9e6e783acb84486e9d2408a4e0e448a54bb5386cec357a16f786afccbcc94"
        "77ba0f8500d5f76d9292ea22af01be99f0ea855fed5141cc75a3698fb013fbea"
        "aeb50c6210cb9d8feb453e420ba762538d6a121b227a31837c2e7f87abe0d4ad"
        "4f239b9018074d88fa8d6894d77716d34c6acbb289fb4b7a0e5e9c6a115bca71"
        "080698801b39a5cbba762c191e1df94cd405e132f446651ad6375366e1607a77"
        "0ad2480430a7251737c4c756d055a9b8ec38306baa9eaa3bcff027f83ea9f21b"
        "5b681db39cbb8672184c305e69ca3e160ab6a898025560fac77f5b8e2b256322"
        "f57a2d63a4a3528cde7f223289b52e91e2e665e94b59ec9c17bd2bcc5ebbc881"
        "f5f601e7f6e13af435a019cf5d4c405708505a923980fcc02cc8bceba6c29a9a"
        "369fd6bc89859d4ee3d148e747e825fad0c42a656c9f26152a449091095a4fb1"
        "e0765011d9944ccc9d970f202b60a4d2d42be469abe681414b2d638cd4e9b4fe"
        "f487c3bb4d105b29abd045fe54c1df0cfa64c8c59bd90ad7813b9abbc1368362"
        "11564ff84d143c82308658e0d2927ef18002541f9406db3ff82818387ae54485"
        "d94aec4905fce82a4699d23e8825ddb0eacedd2d41971884f54ceecb28757194"
        "6115dcc32dad56015ef098160dc0cf736d47264b34674ec557d52b3423eafbf5"
        "b436ed3ed792dd7b2b6f1457a84fbf37f3619af7d191d15f0d6eb4e03045a9c8"
        "207c42d1fff3f918c1215288f22d9610f5af62061eade59462ec19c804ea9bab"
        "b9a7e8ed593ef56c72872410b3b31996c802caf107723d43c184e14e40dbb524"
        "b24176758c72fd2766bb29430674c4e77f66c16b1eaa731bf2ce1a8909ff7ada"
        "dc52bc17cbb2b7bcc484f94f0ccb974ae00a50d94a1c08fe3d35aa919a0c675d"
        "97adf7a752d67aef45b99d1f648522ac9d93557bda44cff4f5688f53a28ff057"
        "a96be77eb683ab016f4e3f59aecdbc75ea82283b0d14a9e54a3d819bd157c5e0"
        "f70c068e7b5478ff29359209d875a2b179d216939be424f13c8711608a92d305"
        "a0a2b15c8840f5a3d9a2412ffce095030f23df4bae2d52c55961b2e2204aab8d"
        "67626894ddad1640c248107592710f97779b77cb79d58d181945726aeb5e20da"
        "551db8c1f32fdc420196986733a778fb9f1f633d65d5d03a6d8e7764b754234e"
        "533da32a897550c25daa31fa57ae4cf59f988e2ab588a456b1a65e264bcf014e"
        "8d47cb90911c07ac4c9388f16dd9d870126985d1ab676097643c27d22b4b807d"
        "02d49ed7f900d62211ded143ff6953d11ed8b9deed4e8ee632801f30af02b406"
        "4182497cc486976270d35d99b85f45c11452b5d120eaeaab1c26798c208df91c"
        "cf6fdcc8acea2d794dc55cf206cda92503a54e081c03a444c99884ebc9e80cf8"
        "f521ab7738e43c12c00fd3a768b3789abdac8cf651b6fb65bedf0e8efd5b2cee";

    std::vector<uint8_t> fnPk(897, 0);
    fnPk[0] = 0x09U;

    const KeyHashVec vecs[3] = {
        {
            DIVI_PQ_SCHEME_MLDSA44,
            1312,
            MLDSA44_PK_HEX,
            "8151eb8bee64a21b7de032cf5704b15702e20854ab6c0f661d5a9e522c57e41d",
            "6b6789d1ccdfe2ca5c3a0b772e490985a302ed5a67cffad7ace50eacd86f4976"
        },
        {
            DIVI_PQ_SCHEME_SLHDSA128S,
            32,
            "f11b6af4d424344c4522942c3123320a174afcfa7a602f825d51ca7307d9b273",
            "5a3f4e05d0763eba15ad8219d4792605ecaaed7f1b19148368c894bb30f91944",
            "53e3862c0bae770a8cf1c3ecf2a728c7ebb91d8073f32e9586f66a3d2f7d0c49"
        },
        {
            DIVI_PQ_SCHEME_LMS_SHA256_M32_H10,
            60,
            "0000000600000003bf2fd2b1a59e04f9b9da4243bb4b78d6a2cccf5a07cc294fd61b762122616dc1884927cfeb3f340e5a6949502bd4a60100000000",
            "03bfb33bb7ba3eaba95c8ac9abf5c55bb5c6030f1dd28879d2c70f804826cc02",
            "42d30d5f77c2435ce1888d77fc87f9cfdfbdd82e0eff2e12f4bc46a10697f81c"
        }
    };

    for (size_t i = 0; i < 3; ++i) {
        std::vector<uint8_t> pk = DecodeHex(vecs[i].pubkeyHex);
        PQ_CHECK_EQ(pk.size(), vecs[i].pubkeyLen);
        uint8_t kh[32];
        uint8_t akh[32];
        divi_pq_key_hash_256(vecs[i].schemeId, pk.data(), pk.size(), kh);
        divi_pq_address_key_hash_256(vecs[i].schemeId, pk.data(), pk.size(), akh);
        PQ_CHECK_EQ(EncodeHex(kh, 32), std::string(vecs[i].keyHashHex));
        PQ_CHECK_EQ(EncodeHex(akh, 32), std::string(vecs[i].addrKeyHashHex));
    }

    // FN-DSA-512 vector 2
    uint8_t fnKh[32];
    uint8_t fnAkh[32];
    divi_pq_key_hash_256(DIVI_PQ_SCHEME_FNDSA512, fnPk.data(), fnPk.size(), fnKh);
    divi_pq_address_key_hash_256(DIVI_PQ_SCHEME_FNDSA512, fnPk.data(), fnPk.size(), fnAkh);
    PQ_CHECK_EQ(
        EncodeHex(fnKh, 32),
        std::string("be06745554b3a4b99a7c18b6162d2621e230e304e2fec37364f59e361a4ddd55"));
    PQ_CHECK_EQ(
        EncodeHex(fnAkh, 32),
        std::string("1f087e7f8ac41a72c4976c01f764f68c57948b631301f5b251bf541328d374ae"));
}

static void RunDipPq1HdDerivationVectorsTest()
{
    const std::vector<uint8_t> bip39Seed = DecodeHex(
        "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70"
        "5489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840");
    PQ_CHECK_EQ(bip39Seed.size(), static_cast<size_t>(64));

    uint8_t masterK[32];
    uint8_t masterC[32];
    PQ_CHECK_EQ(divi_pq_derive_master(bip39Seed.data(), masterK, masterC), DIVI_PQ_OK);
    PQ_CHECK_EQ(
        EncodeHex(masterK, 32),
        std::string("47cd0fc16effbec1c630f59b2f3aae6924a13d6058d7fab33395829e21fe7a37"));
    PQ_CHECK_EQ(
        EncodeHex(masterC, 32),
        std::string("80b033237fd0594e16a0b3afaa608abbdf86f03cff7bf4c2ca248fbf95f9a77a"));

    struct LeafVec {
        uint32_t coinType;
        uint32_t account;
        uint8_t schemeId;
        uint32_t index;
        size_t seedLen;
        const char* kLeafHex;
        const char* cLeafHex;
        const char* algSeedHex;
        const char* stream64Hex;
    };

    static const LeafVec LEAVES[10] = {
        {
            301, 0, DIVI_PQ_SCHEME_MLDSA44, 0, 32,
            "eb2660d9798dde6a7dfd99da787fdcc470b3a19270fa04a708986c282904b8a8",
            "abce2677b924f115d859de017055629b07357fcd1d6772e4dc7dd6bddf3e1e9e",
            "5453ad6e329dfd732cffdd3f9adaa808682f8c6597100bb7912b03116c26f38a",
            "5453ad6e329dfd732cffdd3f9adaa808682f8c6597100bb7912b03116c26f38a20a2a8f18860a1ae440eae38b21af9a36ae65680f430fe5b4684a4e68a9ef9a1"
        },
        {
            301, 0, DIVI_PQ_SCHEME_FNDSA512, 0, 64,
            "59d356d84afc5b11ec409c8485c8c4cc63f85e7035a25d36fcf19cbec285f8f2",
            "951f0c084b45664df19555b13fbbc391f0af07fb27d403db2a2b65de85d3dd97",
            "61644f3db169e2dd7a7750f58c032b525fdf6d8afbc0a3243ac01606ace6d5ae2d2865aba8d5f1cf73d359389b5a28a92e279794c3bcad50405d743b7a83ee67",
            "61644f3db169e2dd7a7750f58c032b525fdf6d8afbc0a3243ac01606ace6d5ae2d2865aba8d5f1cf73d359389b5a28a92e279794c3bcad50405d743b7a83ee67"
        },
        {
            301, 0, DIVI_PQ_SCHEME_SLHDSA128S, 0, 48,
            "6ef5a0ac7cf91103ade416d58fa8c26887bd0c489757aeb3cff9e40acd8af5af",
            "18c4307336d7e9cad796e51355c38692fca7a4cc7bd8d230fd2b032f28ed34b3",
            "1c9107b4294ea04d121061281585ea22b78f0dddc6c4dc588448f2eee2287c70f11b6af4d424344c4522942c3123320a",
            "1c9107b4294ea04d121061281585ea22b78f0dddc6c4dc588448f2eee2287c70f11b6af4d424344c4522942c3123320afcc6388d5fd34044be7de4b27ebae070"
        },
        {
            301, 0, DIVI_PQ_SCHEME_LMS_SHA256_M32_H10, 0, 48,
            "40454acf8491c7e178e9417993e1b48fc1b9cbe703569c9515cf783d4e57721c",
            "0c175a7c66ac8f3d6bd514f4eef0daa0f70b59aab0ce8ee599c8f67b7923b3c9",
            "bf2fd2b1a59e04f9b9da4243bb4b78d64d4fc0255e0916ff0fc4e1ebcf26d65b45cc4c47717afc7cecb68799b5c3d981",
            "bf2fd2b1a59e04f9b9da4243bb4b78d64d4fc0255e0916ff0fc4e1ebcf26d65b45cc4c47717afc7cecb68799b5c3d981fb006f81a30900b4aad420f844dbe611"
        },
        {
            1, 0, DIVI_PQ_SCHEME_MLDSA44, 0, 32,
            "279ea392e7ca0264cfcc9e78568e9cfaaa8e402ae0b42151bbd1a659105ea819",
            "92a323683917ed6642ed3398404b179e69e239d28287b81617d17406db588b71",
            "866b3335fad05491e55b4c8b95dc87a249d01beb8d6d6bd190eb6e2836d1def2",
            "866b3335fad05491e55b4c8b95dc87a249d01beb8d6d6bd190eb6e2836d1def249947bdd026fc9a652ec8a0598b361d155d8c91dee8af79a4381733c17fb7afb"
        },
        {
            1, 0, DIVI_PQ_SCHEME_FNDSA512, 0, 64,
            "7ff90f6fce9a57374b2710535ad02b6488920672660b6724d8243703048b3129",
            "5aea993007c60acd66214359a79585fabec67d68e3a2e652e8bc41e2a85e9a3c",
            "50445157b207c1bfaab9424832fd7c6150fccf5c1a47a794e9e67b17cd028e12f9705b5085a0ffa39cad73069f38de124dfde5618dd2c3119f9ffdb4566662bf",
            "50445157b207c1bfaab9424832fd7c6150fccf5c1a47a794e9e67b17cd028e12f9705b5085a0ffa39cad73069f38de124dfde5618dd2c3119f9ffdb4566662bf"
        },
        {
            1, 0, DIVI_PQ_SCHEME_SLHDSA128S, 0, 48,
            "4992d2229534627c91f76ac109b8184be9f3f14d00b88661493d5bbe464e3381",
            "7efd83729b322fe65296b93135753c1268f64a69e982f0d33fe49df766b0d0ac",
            "b95d1de8bf60554c4aacfde74b089df9a9f864ead8aeb1b414c588eb30938ebf75d4265cb0232d4407ea48a4eb007410",
            "b95d1de8bf60554c4aacfde74b089df9a9f864ead8aeb1b414c588eb30938ebf75d4265cb0232d4407ea48a4eb007410fa06c49ecd14e307f1d25e00134f063b"
        },
        {
            801, 0, DIVI_PQ_SCHEME_MLDSA44, 0, 32,
            "1d61da22286da2de751a8e2bc126a3bc79606a194e68ac23507814d95888760d",
            "69966d43af748806b5dfe98a925dbf06562d9a8dec2f44be446493ce4994eb7a",
            "a1eba3460aeb33c7c46ebf4957cab8761fd8e5f305141d1e8617657655ad9206",
            "a1eba3460aeb33c7c46ebf4957cab8761fd8e5f305141d1e8617657655ad92068a88cfc5974164fb68905c7943f491a7929c0328e304f4da784837dd72450c42"
        },
        {
            801, 0, DIVI_PQ_SCHEME_FNDSA512, 0, 64,
            "e65d154600b909d212bb021bbddbcc9735c873fd6fff15f5016babd8eb34ac44",
            "5d98e512dab6a10e894227ac5d0ef0d9707272c0e1d5dc30cab26408310178f9",
            "dce9645ea47022a68e272ced7fd5fb13bc85469a160c4708075c3871d56ec37ccac0b82553b86f81dccb635fa5f26e2d0f1524f0bcf318ca203dfe715e3ee658",
            "dce9645ea47022a68e272ced7fd5fb13bc85469a160c4708075c3871d56ec37ccac0b82553b86f81dccb635fa5f26e2d0f1524f0bcf318ca203dfe715e3ee658"
        },
        {
            801, 0, DIVI_PQ_SCHEME_SLHDSA128S, 0, 48,
            "1e32c077f1d7c8e349f0bac9e3ea309eb0e7691f0f84bbac34e5ece18413c3ec",
            "014f0802e64e72ab72d9bdc84137fd02a465f08b9546a3c21900de305175baee",
            "a43ff3bedb8c7680e5593915ca4d1dd64d63e436e196a611461dead2840e63bb58dae11e2f98c854bb6b3da355a11add",
            "a43ff3bedb8c7680e5593915ca4d1dd64d63e436e196a611461dead2840e63bb58dae11e2f98c854bb6b3da355a11add4b36d0bbc4a2a714aad1a25483a49ae2"
        }
    };

    for (size_t i = 0; i < 10; ++i) {
        uint8_t kLeaf[32];
        uint8_t cLeaf[32];
        uint8_t stream64[64];
        PQ_CHECK_EQ(
            divi_pq_derive_leaf(
                bip39Seed.data(),
                LEAVES[i].coinType,
                LEAVES[i].account,
                LEAVES[i].schemeId,
                LEAVES[i].index,
                kLeaf,
                cLeaf,
                stream64,
                64),
            DIVI_PQ_OK);
        const size_t algSeedLen = divi_pq_scheme_seed_len(LEAVES[i].schemeId);
        PQ_CHECK_EQ(algSeedLen, LEAVES[i].seedLen);
        PQ_CHECK_EQ(EncodeHex(kLeaf, 32), std::string(LEAVES[i].kLeafHex));
        PQ_CHECK_EQ(EncodeHex(cLeaf, 32), std::string(LEAVES[i].cLeafHex));
        PQ_CHECK_EQ(EncodeHex(stream64, algSeedLen), std::string(LEAVES[i].algSeedHex));
        PQ_CHECK_EQ(EncodeHex(stream64, 64), std::string(LEAVES[i].stream64Hex));
    }
}

static void RunDipPq1SigningPrehashVectorsTest()
{
    struct PrehashVec {
        const char* domainTag;
        const char* magicHex;
        uint8_t schemeId;
        const char* pkHashHex;
        const char* payloadHex;
        const char* expectedPrehashHex;
    };

    static const PrehashVec VECS[5] = {
        {
            "Divi-PQ-TxSig-v1",
            "dff0c8f3",
            DIVI_PQ_SCHEME_MLDSA44,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "35a53a5300c86e71a0ca916cbbb5000fa2f06dca1b6bd6938a0945c92d00c9dcef28976fbd763b535da1683a0ca12e0cf65592666751bb2eb4bf97bf1201132f"
        },
        {
            "Divi-PQ-TxSig-v1",
            "dff0c8f3",
            DIVI_PQ_SCHEME_FNDSA512,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "715b0f9f72cb7031723ccdb38633a48fedd9b7f6e44a4043461d727546028509b94300a802c24d5c736b6f1cbb524d23e0e8eb6aabf849e3ac73378a2e94a1af"
        },
        {
            "Divi-PQ-BlockSig-v1",
            "dff0c8f3",
            DIVI_PQ_SCHEME_FNDSA512,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "c87bc21802e2ceaba45c471cf9d4911b808223789d053b77e096378e6d2b85483af8e1b04a9022e10f336ab571205852de60ac31f965af19c52312380ec8ab9c"
        },
        {
            "Divi-PQ-Spork-v1",
            "dff0c8f3",
            DIVI_PQ_SCHEME_LMS_SHA256_M32_H10,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1c2700008023a5f20000000000f1536500000000",
            "fc80064a5487fc3a9f9152ff6002fca7b6f14f159f4b67be058b3df72e78982018b4bd345b0b77bc89e42db3a9817c6f75cd28b6caf877f963fc2bc7d0bd2783"
        },
        {
            "Divi-PQ-TxSig-v1",
            "b7dc624e",
            DIVI_PQ_SCHEME_MLDSA44,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "2ecf58a20b5288ec72b82e19a64517167bd6d6f8c8d50b91d89025b3afe37352ac95683e3dbe3f0281a78359809da62cd7e43bd14864419a0a63e637ff7ac275"
        }
    };

    for (size_t i = 0; i < 5; ++i) {
        std::vector<uint8_t> magic = DecodeHex(VECS[i].magicHex);
        std::vector<uint8_t> pkHash = DecodeHex(VECS[i].pkHashHex);
        std::vector<uint8_t> payload = DecodeHex(VECS[i].payloadHex);
        uint8_t outPrehash[64];
        divi_pq_signing_prehash_var(
            VECS[i].domainTag,
            std::strlen(VECS[i].domainTag),
            magic.data(),
            VECS[i].schemeId,
            pkHash.data(),
            payload.data(),
            payload.size(),
            outPrehash);
        PQ_CHECK_EQ(EncodeHex(outPrehash, 64), std::string(VECS[i].expectedPrehashHex));
    }
}

static void RunDipPq1LmsPositiveAnd17NegativeVectorsTest()
{
    const std::vector<uint8_t> lmsPk = DecodeHex(
        "0000000600000003bf2fd2b1a59e04f9b9da4243bb4b78d6"
        "a2cccf5a07cc294fd61b762122616dc1884927cfeb3f340e5a6949502bd4a60100000000");
    PQ_CHECK_EQ(lmsPk.size(), static_cast<size_t>(60));

    const std::vector<uint8_t> networkMagic = DecodeHex("dff0c8f3");
    const std::vector<uint8_t> sporkPayload = DecodeHex("1c2700008023a5f20000000000f1536500000000");
    const std::vector<uint8_t> expectedPrehash = DecodeHex(
        "e067c584d789507d56132a2e42d1fa487a20bd2fb92a8308c7634e8dba1e74cf"
        "be1d87e8e80c31b5a758522aee02b610aa09e385b493dfc58607efe356fd6e90");

    uint8_t lmsPkHash[32];
    divi_pq_key_hash_256(DIVI_PQ_SCHEME_LMS_SHA256_M32_H10, lmsPk.data(), lmsPk.size(), lmsPkHash);

    uint8_t computedPrehash[64];
    divi_pq_signing_prehash_var(
        "Divi-PQ-Spork-v1",
        16,
        networkMagic.data(),
        DIVI_PQ_SCHEME_LMS_SHA256_M32_H10,
        lmsPkHash,
        sporkPayload.data(),
        sporkPayload.size(),
        computedPrehash);
    PQ_CHECK(std::memcmp(computedPrehash, expectedPrehash.data(), 64) == 0);

    static const char SIG_Q0_HEX[] =
        "0000000000000003fc3b4d2cd996e12410ef99e49bef25bde718689049d623ef"
        "8bbd9e8ed52e2cc2ed4f2f6517bc7c7a9a6ca9c9a7e1b62e106c3f100c849638"
        "0f634fce5910480f9df01e78edc187820cb22f64af5baeff1d0c5c0ce939aca3"
        "527efa399348f6335e468be20f675bbd09607350a6068c4d666e5027a815971f"
        "4916a629728b5cee9553c0b7441f4460dc6d71b5f6f863a437b0ef0d387d1d61"
        "723581ac2f5506206904bbba567b417134ebd297dc811eeabadab623dd06e7ec"
        "533600332e9f4d20c3eb20391edd869e3496cbda8435e34d0260d1096138e37b"
        "e6d76b77adc1bf33a01d2c05588c8890694a0847f8f69cb57cf03c920c4f375d"
        "1e944512c670b58684e1c53d0eebe322b87d60b260c693704d36875cd78c351c"
        "8324980116729cc33f04d455d7c52cd3590844333759ced63ae8c3de4d86a164"
        "9c4c05bc8ee2a1769dcbf18d9c3e2893e2890c269bf6298f26c9105d113b35dd"
        "1b9bf6f6b9773cef97a507ea39d4627553079316786bfed9fd696a99449ebe55"
        "dbf3dd0c3dad74a295d6a58b449c3633e9da49b809506778e4b44a3cf7e1a06d"
        "e48564cdbce6e9bec01dc3fc28c6322bd756171507b7565c2b31004208a83393"
        "98f72ce1c23679250c878f8ee0f21b95c531739a7d2f8c0c73c48524b50747ab"
        "b00eda3f96822249c1734d0ccc84fb161c3490dfb980d5fdf9e5adb3d35477d4"
        "30092923b99243f32a89f210b468ff28061ad395290bebab8e3b4546f84ea9a7"
        "957248d5e2179340322570934769945705fbfa5d7ac714a861c4f9e5068c4886"
        "477a5ee1003507ab12060f9f323c00e454c94ade72234b1fc5bd530d175a261a"
        "5a83c9168cba270113f5b1f486461195098327de769092b88cc2db2dbbee387f"
        "122a69cd70d25845549eeabf3410e166fced2f88fb1600c7dde0961b14e8653d"
        "889b7ad4609307612ff8a3913155459fd44f0e000071c0eb4a089b06382cd0c1"
        "e375de975b9f40688a09c1791226859d64734b7c39b08b56f83bd920c158b2bd"
        "f1a5b5064d0b35f9cc56d85a9abe82e13ad04fb02f499184de79eb2fbdb0719f"
        "a354b9d3580d32161ebee1c65726096382e1956cb045fa24a8bc74445f9ad4c4"
        "a4f53a2bd189034daa6ba64934bf48563ea31cad703dcfc3d42604ea94bb9492"
        "7b74455b59b3af14fdfc2ce0254a64d994d8b354f8c1b4eab22bed15eccf6520"
        "aa2221bb15b92311706668281cae32591e09728d52e667a4e064afb377d049f9"
        "d0194fa851d63a075c82d35e635327657ea9333cdcba8d11a142d5f052f77eea"
        "0b355ad77e98ee62e530264f853d600c80cf184e8b43076fed39355623c2b3a7"
        "cfa540406f542c33248601fabf798a5ba9f3681967f6af0cf529de6a9eeefbc0"
        "08f648d54b44bb2b581c13112e80c46227b86a97f3333c3385b8feb7848c0049"
        "5e6096deb733d3c9cd1d6c3409b0b8bdf4fba16b586c447c1b8608b29488b7c5"
        "41cde710388474060796f904af28c8cbddcf790d193212e2d976e7b6b0de941e"
        "5d54e646e12ee41792104469ee722c0918b3b4263edb326a0cdb94e4a3c7ccbf"
        "e81c86f7b17b9141fdf4e8d92eb6e0ec51b891a01beeb7655091a4142e8c7e56"
        "5578e9a1d23d1e74e23468844410a0cbd96a770f9b506904aa238655f504862d"
        "5d3af50a54f79130328f9449416fbf409c8dc511bf7f5865984b3e1d8e0daa38"
        "1e617b1b0072d07f3a3dc08da51e670109d69a96b9561575141f66b2354b057e"
        "641f06257c8361a0cd5177f81f944871d56dceb7f29667548001277894f555b1"
        "cc81e16c8160368e4e6d519b82de47c1f99ff51a26c2ca1d0e6bbc22f3e23a79"
        "88444877380425a939c2b0a9c5ecc7c32a4c39874d6cf7faf7b31ae21fe30c7c"
        "3c14262f933b21dabe9b70328fc14ff29891ae53fc9d77211305883ca48e2225"
        "b8c6e5c403c003159b53b3f4080687c430ec570e1bfc87a8e5f0725236c2fbdc"
        "bea1f10f5cb1abb370e3af6360f7a563d666d6d5bbcdd0f15a9c995b2a97c833"
        "097fdf0febaf572462e579ed7d3888fee33ea01157199b2edfceff8f41a5c2de"
        "d713990f71e579c2b47bf11e6880100495a3d8b2a369d85c1024ab59fc7db1c8"
        "f5e4bf2f441e3294408536f7c27d3fe2e98d0e86f38879e1732338038f424060"
        "873c3e3b2a2f71be6fc4d2008581b6de45ca6579b7e11d17070579b452a00bf7"
        "ce2330181d008b55882c362984af365d24ca7547a77e432a653fc2efade8becf"
        "77555005d0d30b2eeafc106156c46fd8bfd033a6dcb58658818da389895bf0ef"
        "bd85c0d903d22ddec0d054e50e9450cc9f600f774ceaf32b979a78398b58a05f"
        "d5631a0c9d5c3936d36ddfc3a8057b0717ead705af2e5a5cd46b070065f0886c"
        "45d03df80307a20910ba8f79bd34a5630bcebaabaa8a1aca67c3e5ea24beb816"
        "f90216ccac744990953ee0027dc8fc8466053048ea2e63c82271b1693723a03e"
        "7eaee89a373deafef0e1b991e894a529a16bd938624dd26e456c7daf8ff88f84"
        "2803983ba850138a56e1b3656a2267d0b93a4cec8987bb4ed69b65609ab4fc2b"
        "49760e5e914400b958a1f559161b28910aef710cded7effc5c189123b389d60d"
        "35e788fe099638b09ca403c53fdc62261f14194922dc055f5779a2b3040ec769"
        "4bee0b7310a1b7d82bd63a80a192fac0a38a77eb3a13899cc5a5ae24f236e1be"
        "21672a7cf5b77a0df45c3252bc3675c3d389c0ba154a366d6b359f7a8db20206"
        "1910a17176bcd9157012660512def6127b9f35ffa6cd119caa9fac2969987491"
        "5b340e88cb8655d304e1132dd810d9a88bb6706486e5a974d616b49f3e0a2e4a"
        "1ab4ede749010ac126a7759e86c2283d812a6fe3773ddbdde4e54c5aa0d9bf9c"
        "fe4e1e91670f78a5793908c2502bb524fc9bd711a37396e749ddf8d2e82c166c"
        "5b36cf856c627d0c7a49771a12469c2eff57d8ede26215e74f21762bc0cdf80f"
        "9bcdcfea543a12d7b47d8a29b86947a686b3c47de9163e65886236c1b14d7db3"
        "615a80fab2dca14563b2741689637ad6240a3871e571a28fd5363a586d60f8b9"
        "97d768f1124268770000000600862b89085a78e571fe3ce5e52a28380e87418f"
        "30268ab3bb00349bb4aabe6e291503d0fad11a6f1fee98805f925a0bb6ae3a95"
        "67261efda488a58e6497f14b82208f56c749af6b0dea4825bc30dd3fb947b6ba"
        "ce220923353a24e81706a4b85ab6d1682cf3b90d86f92f0b2857c318a9ebbccc"
        "23358314fb9041d6b61f8dbe0f1bae0acdce124ddb48394afadea06c1d9c02f3"
        "1781e5f8ad7bc7f59678cd3a46e5cda4bed80b53ad84a3e96195107e81a59cfa"
        "895a0049f4fb57f6065d723ce9dac1c65a481b4580e7a06374782f32d6d99787"
        "528755ac3e04c5735035415c3a685b1aa470c94cadb076cd5eec709c2cf804db"
        "7bd6fa5e68180929ef1b0d4b42cf403e62437286e9e336a47eae8185d6b35df0"
        "70b48abbe5fc881dc24159b3161a45b505ce606c67d08182c5d02fa9432814aa"
        "c7c9e9b411f233a626cbf0d900000000";

    static const char SIG_Q1_HEX[] =
        "0000000100000003baeddb24a2d61059c23387a526d33700e14ab082246bf1fb"
        "9ff1a9bf035163645f197aece51b83dcb4a8948a0be8c90e1065f8f16252f307"
        "89da5a2c03249b99113819d5f60d2ac3a9764c4127deeab15f26110e3919b9d8"
        "50b45a2e5da44688fa822dbfd797319795b4ccdc226879feeefb802ab335ece2"
        "6935a7b0985b82cc1c6568909fd95ba13fff6c2484eeed3d27d0a2865ccfd4b5"
        "36eaa160186da3eb0c0e48b8bcb0356ed2fac80bcf6555f08a24a3083c8c314a"
        "aefda2e061977caa041b475aa2b435275b11f5772e2771909db107871cfa14d0"
        "d76199e56b0de14af9ebef00b2bbf6057907cb3b425ae84847de6b26b9e30ad2"
        "b8abfc6cdb808388442a61aea3d82f9015763fd4e9d501e444b60f02b2f8a41f"
        "7d5e19d2abc26e06d950ed1567664baad270ce61ec2346e4837335b044220f9d"
        "e9054f1e9b476f7e9c37ceeaedbda8dcd7df208637755e7d2b9e55562b0c3320"
        "4b2239f0a44fea91f6157a7de5165c4b78b7a084d63e42dcab8cb44f59173642"
        "f911c88d0903ae04ae6ca1f7f2aa30533e6dffc39c2f08177d6ca69918683181"
        "082111938cdb6f6e76892001f61d7d32420cac1499d51f618b8cc17c11e1cae1"
        "c43b9378ea883453f43011e241039c4b79004d34709f162eb34c956c61a01cd0"
        "0d4a0370c6b8f1e0ed1944825e999cc8cd5f47334bf18642207713e0d8094203"
        "026bed6d9ab9d7d581bb304f4697ea719f4a1b7cab253b2fd7ee36e52e391130"
        "0a2d52d0c4161fb8ffffcb129caa34543ebfe133294e5924be7366f8c580c67d"
        "11d4eb421bf0ce418cb735e9eedd2562abb47735ffb77618f7542fbc0ec1a548"
        "6c78c619994658a78fa1a59121ee8e7869872d58f655b3a0fe2ddd8912b526e7"
        "432f38f8f97e49e60e3cc65ba96c34b898eb17d935a2ed1db4fc495cf91e20b0"
        "95209ce079f75681a98e92aec6c99d133a05c6504c14b7a4f6e0edb55596f669"
        "3c6ee9f0b8edabea5999a037c97df16684cf6703fabf52b31e3d4e0c03588dab"
        "71eae1c06992dfac522cd36754d733138cba48cf9cec1ef720fc2e920c2e39f3"
        "bc5002f572ebad05e61cb7fd7e2800384e6e66675156e649d3b39f8d7fac8a60"
        "989cb1777a8b70a2ba000c42f5ed4a184437d2c931bc44eb35da46801a3da22b"
        "5a6bc192ea14a97ed0ccfa53629ce3ba6ac193881e382f2f3b7ea85cd72d8b04"
        "563df99815b7c8f4b79858250e4dd486f59d757ced22fded93eec0b89c6f74d5"
        "9850461f0328af82199a911d5b2141750e1ff9e5f0f941c1d883ea0b0d20a6a5"
        "ab2f0159a73cd2c1b228c4f50e8e12362014a46a97f2f7c9c9eb733242e5b745"
        "cf0707c7c59306781a4f2250887cee54a44f7087013296a76c4930305ee3f8df"
        "0c4621247d0ce7e023ba2e745e2213e5cfc9a9c1b20a542b58fd0e6947ffc8d5"
        "738c9dc69d65d2ee86246b5e665ca0672d490e117b82e9085e06212822db031c"
        "70b69e28fffb48efe6c535a7a262d9ae40e175bf28d1f5c98810f13141b1b30d"
        "afbe0f1cbf8793c469f022357e439ef02f68e749980043ecaaf48ead212b04a0"
        "f6760f6f688632f6755979b33fdb5da388b943abfd04fca15cb42305a4685492"
        "a54d2429da76d3c3f569c77968cd7faf1b2b42a1d34429809741f7c525023b19"
        "f585da3e227adc9fcc51aeed325f6e98b6ff77dfde4ef654c80082f06e39bd7c"
        "f966bedd6cdc8a527b4b3f83e03cf5f14b4869278aae4e170ac64668f53d17ec"
        "9a233117d09a92384500ad137e2f2dcfc76f924a232619f2b965ba018facea7b"
        "51dc07c4370a388129683570dd4dfa2b9d1d5a9bd5e423a0974aa86d68978f01"
        "2459ef209841b1b9795e9d454b4ca9a1e58252a4614287b0b81cd7357161f443"
        "1179acc43525a7347a01789ca6c804e23dc3289a41a060e5917d7b6da585e280"
        "7a91cc94d91ceca82851d213c14ab0596f1ad47601f57365484e649545153903"
        "12b4d0fa831bf8e10b7e277083b9c87c6dae35b14b6daf4d361d159aae56756d"
        "980f2f1d5cb316804d54d1ac50d1ee57921b05eedf7ed3d703c7c31fe83f44e4"
        "1083898edfe0a0b4042311760f0fdbb9a425af79703e019898560bb240d24c46"
        "b0729d1755a92d1e91e58984ce8ae15d2e10b59deeb48d8349973e8a1e3058b8"
        "af48471bbca5d86eed0af24554ba08311b5cba105902db44f4fe2b3b00de64b2"
        "581b6f7eb8bdd249e8493513672b7a9f5a60334f057b996ef2630a1fe308346a"
        "a32f47b6c9bbd83b0f0fc8dd87da9bd0eeb64b9f8dc116edf3d091ff0b9bf83f"
        "8297dac93e535bbaf0233da4e6384e8f16dd8d4f40f9334b3298dedcf8829f56"
        "f902dc7ea257f16ec3d7f160d30d0a29786f08f58ea7e8833dbb2d24afe4a497"
        "3cf3358be74dfa2ccd75f2d3368ffe3f134fa7356062c1562e7d8e6e9da85144"
        "81f9c6307de3959a5d9b674abab2eceba8c80967f9ff1d1ef2cedfb17f1c0225"
        "03cca3b1678a19461c7d7a5a55fbb578ba60bdcd044b275f9d9239c2b4921584"
        "6cb01130ac508675ae0326a75fef4a6dc760da8c3ff6f53d49cb1848a6170cb6"
        "9012b85a0576f790abd17e6129d9488d08d64c1deeaa126ceec82e0a188f8d75"
        "ea3f176753196d9b8cb6574f3ac4d13e4a9a7abc8a54765b14edb7367b9dd298"
        "8a306f73a18e25b609504d8960227a2c6c05c6e47882651e4f5dee071015c3f9"
        "f3b75b996dfd726b80e65f0fd47bd45c76633d6326d210bde6cdf526d53cf4b8"
        "227283bc1d31ba6b991d638a56bc3da6971c81d84259c0c848aebeb0290406a0"
        "6745c2b01979eb6da20f4f1a8dd2da0dda75d79c5c751d629d9d622753e81e76"
        "fce882e31ae825972338052c758ade4d8236bc145a8d5cbb14d4ec1ba5b9fd54"
        "ce97b0e5a7711963a101520eadc9f49a3166dd6ac3f061a273a60402c8d1a43a"
        "47fb50a3209bbebec0906c34cbe2b8865e15b9df040f0e85d65aff32145d5793"
        "c485b0460d67f3d23633bb7a2bfea2eb1374840159cb42a8d297171f39150a93"
        "8f995fd9961f8cffc645407032c4711f6874c4d1f18831db9a07f4380cb3c429"
        "e180150eb2a2e97100000006414563b4566c2411ad8014a39c077efe52378448"
        "44e1bcdd981b7fb93df8da37291503d0fad11a6f1fee98805f925a0bb6ae3a95"
        "67261efda488a58e6497f14b82208f56c749af6b0dea4825bc30dd3fb947b6ba"
        "ce220923353a24e81706a4b85ab6d1682cf3b90d86f92f0b2857c318a9ebbccc"
        "23358314fb9041d6b61f8dbe0f1bae0acdce124ddb48394afadea06c1d9c02f3"
        "1781e5f8ad7bc7f59678cd3a46e5cda4bed80b53ad84a3e96195107e81a59cfa"
        "895a0049f4fb57f6065d723ce9dac1c65a481b4580e7a06374782f32d6d99787"
        "528755ac3e04c5735035415c3a685b1aa470c94cadb076cd5eec709c2cf804db"
        "7bd6fa5e68180929ef1b0d4b42cf403e62437286e9e336a47eae8185d6b35df0"
        "70b48abbe5fc881dc24159b3161a45b505ce606c67d08182c5d02fa9432814aa"
        "c7c9e9b411f233a626cbf0d900000000";

    const std::vector<uint8_t> sigQ0 = DecodeHex(SIG_Q0_HEX);
    const std::vector<uint8_t> sigQ1 = DecodeHex(SIG_Q1_HEX);
    PQ_CHECK_EQ(sigQ0.size(), static_cast<size_t>(2512));
    PQ_CHECK_EQ(sigQ1.size(), static_cast<size_t>(2512));

    PQ_CHECK_EQ(
        divi_pq_lms_m32_h10_verify(
            lmsPk.data(),
            lmsPk.size(),
            computedPrehash,
            64,
            sigQ0.data(),
            sigQ0.size()),
        DIVI_PQ_OK);
    PQ_CHECK_EQ(
        divi_pq_lms_m32_h10_verify(
            lmsPk.data(),
            lmsPk.size(),
            computedPrehash,
            64,
            sigQ1.data(),
            sigQ1.size()),
        DIVI_PQ_OK);

    // Negative 01: 1-byte trailing garbage appended to LMS signature
    {
        std::vector<uint8_t> badSig = sigQ0;
        badSig.push_back(0x00U);
        PQ_CHECK_EQ(
            divi_pq_lms_m32_h10_verify(
                lmsPk.data(), lmsPk.size(), computedPrehash, 64, badSig.data(), badSig.size()),
            DIVI_PQ_ERR_INVALID_SIG_LEN);
    }

    // Negative 02: 1-byte trailing garbage appended to LMS public key
    {
        std::vector<uint8_t> badPk = lmsPk;
        badPk.push_back(0xffU);
        PQ_CHECK_EQ(
            divi_pq_lms_m32_h10_verify(
                badPk.data(), badPk.size(), computedPrehash, 64, sigQ0.data(), sigQ0.size()),
            DIVI_PQ_ERR_INVALID_PUBKEY_LEN);
    }

    // Negative 03: Truncated 56-byte LMS public key
    {
        PQ_CHECK_EQ(
            divi_pq_lms_m32_h10_verify(
                lmsPk.data(), 56, computedPrehash, 64, sigQ0.data(), sigQ0.size()),
            DIVI_PQ_ERR_INVALID_PUBKEY_LEN);
    }

    // Negative 04: Wrong LMS typecode in pk[0..4] (5 instead of 6)
    {
        std::vector<uint8_t> badPk = lmsPk;
        WriteBe32(badPk.data(), 5U);
        PQ_CHECK_EQ(
            divi_pq_lms_m32_h10_verify(
                badPk.data(), badPk.size(), computedPrehash, 64, sigQ0.data(), sigQ0.size()),
            DIVI_PQ_ERR_LMS_INVALID_TYPECODE);
    }

    // Negative 05: Wrong LMOTS typecode in pk[4..8] (4 instead of 3)
    {
        std::vector<uint8_t> badPk = lmsPk;
        WriteBe32(badPk.data() + 4, 4U);
        PQ_CHECK_EQ(
            divi_pq_lms_m32_h10_verify(
                badPk.data(), badPk.size(), computedPrehash, 64, sigQ0.data(), sigQ0.size()),
            DIVI_PQ_ERR_LMS_INVALID_TYPECODE);
    }

    // Negative 06: Wrong LMOTS typecode in sig[4..8] (2 instead of 3)
    {
        std::vector<uint8_t> badSig = sigQ0;
        WriteBe32(badSig.data() + 4, 2U);
        PQ_CHECK_EQ(
            divi_pq_lms_m32_h10_verify(
                lmsPk.data(), lmsPk.size(), computedPrehash, 64, badSig.data(), badSig.size()),
            DIVI_PQ_ERR_LMS_INVALID_TYPECODE);
    }

    // Negative 07: Wrong LMS typecode in sig[2184..2188] (7 instead of 6)
    {
        std::vector<uint8_t> badSig = sigQ0;
        WriteBe32(badSig.data() + 2184, 7U);
        PQ_CHECK_EQ(
            divi_pq_lms_m32_h10_verify(
                lmsPk.data(), lmsPk.size(), computedPrehash, 64, badSig.data(), badSig.size()),
            DIVI_PQ_ERR_LMS_INVALID_TYPECODE);
    }

    // Negative 08: Leaf index q = 1024 out of range
    {
        std::vector<uint8_t> badSig = sigQ0;
        WriteBe32(badSig.data(), 1024U);
        PQ_CHECK_EQ(
            divi_pq_lms_m32_h10_verify(
                lmsPk.data(), lmsPk.size(), computedPrehash, 64, badSig.data(), badSig.size()),
            DIVI_PQ_ERR_LMS_INVALID_LEAF_INDEX);
    }

    // Negative 09: Leaf index q = 0xFFFFFFFF out of range
    {
        std::vector<uint8_t> badSig = sigQ0;
        WriteBe32(badSig.data(), 0xffffffffUL);
        PQ_CHECK_EQ(
            divi_pq_lms_m32_h10_verify(
                lmsPk.data(), lmsPk.size(), computedPrehash, 64, badSig.data(), badSig.size()),
            DIVI_PQ_ERR_LMS_INVALID_LEAF_INDEX);
    }

    // Negative 10..13: Single-bit flips in LMOTS chain y[0], y[66], Merkle path[0], path[9]
    const size_t flipOffsets[4] = {40, 2152, 2188, 2476};
    const uint8_t flipMasks[4] = {0x01U, 0x80U, 0x01U, 0x40U};
    for (size_t i = 0; i < 4; ++i) {
        std::vector<uint8_t> badSig = sigQ0;
        badSig[flipOffsets[i]] ^= flipMasks[i];
        PQ_CHECK_EQ(
            divi_pq_lms_m32_h10_verify(
                lmsPk.data(), lmsPk.size(), computedPrehash, 64, badSig.data(), badSig.size()),
            DIVI_PQ_ERR_VERIFICATION_FAILED);
    }

    // Negative 14: Domain tag mismatch ("Divi-PQ-TxSig-v1" vs "Divi-PQ-Spork-v1")
    {
        PQ_CHECK_EQ(
            divi_pq_lms_m32_h10_verify_with_domain(
                "Divi-PQ-TxSig-v1",
                16,
                networkMagic.data(),
                lmsPk.data(),
                lmsPk.size(),
                sporkPayload.data(),
                sporkPayload.size(),
                sigQ0.data(),
                sigQ0.size()),
            DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN);
    }

    // Negative 15: Network magic mismatch (PrivateDivi b7dc624e vs Divi dff0c8f3)
    {
        const std::vector<uint8_t> wrongMagic = DecodeHex("b7dc624e");
        PQ_CHECK_EQ(
            divi_pq_lms_m32_h10_verify_with_domain(
                "Divi-PQ-Spork-v1",
                16,
                wrongMagic.data(),
                lmsPk.data(),
                lmsPk.size(),
                sporkPayload.data(),
                sporkPayload.size(),
                sigQ0.data(),
                sigQ0.size()),
            DIVI_PQ_ERR_VERIFICATION_FAILED);
    }

    // Negative 16: Unhardened HD child index
    {
        const std::vector<uint8_t> bip39Seed = DecodeHex(
            "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70"
            "5489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840");
        uint8_t masterK[32];
        uint8_t masterC[32];
        PQ_CHECK_EQ(divi_pq_derive_master(bip39Seed.data(), masterK, masterC), DIVI_PQ_OK);
        uint8_t childK[32];
        uint8_t childC[32];
        PQ_CHECK_EQ(
            divi_pq_derive_child_raw(masterK, masterC, 44U, childK, childC),
            DIVI_PQ_ERR_NON_HARDENED_DERIVATION);

        uint8_t stream64[64];
        PQ_CHECK_EQ(
            divi_pq_derive_leaf(
                bip39Seed.data(),
                301U,
                0U,
                DIVI_PQ_SCHEME_MLDSA44,
                0x80000000UL,
                childK,
                childC,
                stream64,
                64),
            DIVI_PQ_ERR_NON_HARDENED_DERIVATION);
    }

    // Negative 17: Unknown scheme IDs (0x00, 0x05, 0xFF) & forbidden domain combinations
    {
        const uint8_t badSchemes[3] = {0x00U, 0x05U, 0xffU};
        for (size_t i = 0; i < 3; ++i) {
            PQ_CHECK_EQ(divi_pq_scheme_pubkey_len(badSchemes[i]), static_cast<size_t>(0));
            PQ_CHECK_EQ(divi_pq_scheme_sig_len(badSchemes[i]), static_cast<size_t>(0));
            PQ_CHECK_EQ(
                divi_pq_validate_pubkey_encoding(badSchemes[i], lmsPk.data(), lmsPk.size()),
                DIVI_PQ_ERR_UNKNOWN_SCHEME_ID);
        }
        PQ_CHECK_EQ(
            divi_pq_scheme_allowed_in_domain(
                DIVI_PQ_SCHEME_LMS_SHA256_M32_H10, "Divi-PQ-TxSig-v1", 16),
            DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN);
        PQ_CHECK_EQ(
            divi_pq_scheme_allowed_in_domain(
                DIVI_PQ_SCHEME_LMS_SHA256_M32_H10, "Divi-PQ-BlockSig-v1", 19),
            DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN);
        PQ_CHECK_EQ(
            divi_pq_scheme_allowed_in_domain(
                DIVI_PQ_SCHEME_SLHDSA128S, "Divi-PQ-BlockSig-v1", 19),
            DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN);
    }
}

// ============================================================================
// 2. DIP-PQ-0: Argon2id + XChaCha20-Poly1305 Crypter & MasterKey Lockstep Tests
// ============================================================================

static void RunDipPq0CrypterAndMasterKeyVectorsTest()
{
    PQ_CHECK_EQ(MASTER_KEY_DERIVATION_LEGACY_SHA512_AES, 0U);
    PQ_CHECK_EQ(MASTER_KEY_DERIVATION_ARGON2ID_XCHACHA20, 1U);
    PQ_CHECK_EQ(WALLET_CRYPTO_ARGON2_SALT_SIZE, 16U);
    PQ_CHECK_EQ(WALLET_CRYPTO_KDF_PARAMS_V2_SIZE, 13U);
    PQ_CHECK_EQ(WALLET_CRYPTO_SEALED_KEY_V2_SIZE, 72U);

    // Vector 1: Canonical KdfParamsV2 encoding (13 B) & 49-byte master_key_aad
    const divi_pq::KdfParamsV2 params = divi_pq::KdfParamsV2::Default();
    PQ_CHECK(params.IsValid());
    const std::vector<uint8_t> encodedParams = params.Encode();
    PQ_CHECK_EQ(EncodeHex(encodedParams), std::string("02000001000300000001000000"));

    divi_pq::KdfParamsV2 decodedParams;
    PQ_CHECK(divi_pq::KdfParamsV2::Decode(encodedParams, decodedParams));
    PQ_CHECK(decodedParams == params);

    const std::vector<uint8_t> salt = DecodeHex("000102030405060708090a0b0c0d0e0f");
    const std::vector<uint8_t> aad49 = divi_pq::BuildMasterKeyAadV2(params, salt.data(), salt.size());
    PQ_CHECK_EQ(aad49.size(), static_cast<size_t>(49));
    PQ_CHECK_EQ(
        EncodeHex(aad49),
        std::string("656e637279707465645f6d61737465725f6b657902000001000300000001000000000102030405060708090a0b0c0d0e0f"));

    // RFC 9106 / Rust Crypto Argon2id v0x13 reference vector (m=65536, t=2, p=1)
    {
        const divi_pq::KdfParamsV2 rfcParams(65536U, 2U, 1U);
        const char* pass = "password";
        const char* salt8 = "somesalt";
        uint8_t outKey[32];
        PQ_CHECK(rfcParams.DeriveKey(pass, reinterpret_cast<const uint8_t*>(salt8), 8, outKey));
        PQ_CHECK_EQ(
            EncodeHex(outKey, 32),
            std::string("09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"));
    }

    // Vector 2B (dip-pq-0-hndl-and-crypter.md §6): Production Default (m=65536, t=3, p=1)
    {
        const std::string phase0Pass = "divi-pq-phase0-passphrase";
        uint8_t phase0Key[32];
        PQ_CHECK(params.DeriveKey(phase0Pass, salt.data(), salt.size(), phase0Key));
        PQ_CHECK_EQ(
            EncodeHex(phase0Key, 32),
            std::string("f9044f83473c5d1aa53258e876d2d262ad4d1dcf6366fce306bcdb3b0bbdfb9f"));

        uint8_t phase0MasterKey[32];
        uint8_t phase0XNonce[24];
        std::memset(phase0MasterKey, 0x11, 32);
        std::memset(phase0XNonce, 0x22, 24);
        std::vector<uint8_t> phase0Sealed;
        PQ_CHECK(
            divi_pq::SealMasterKeyWithNonceV2(
                phase0MasterKey,
                phase0Pass,
                salt.data(),
                salt.size(),
                params,
                phase0XNonce,
                phase0Sealed));
        PQ_CHECK_EQ(
            EncodeHex(phase0Sealed),
            std::string(
                "222222222222222222222222222222222222222222222222"
                "31d5a7690d0bd5adf44822342a065bc8807550b429e906201032170a6842cee2"
                "17e1784358f2061301a2093c2c201bf7"));
    }

    // Vector 2C: Argon2id(m=65536, t=3, p=1) + XChaCha20-Poly1305 roundtrip & tamper rejection
    const std::string passphrase = "correct horse battery staple";
    const std::vector<uint8_t> nonce24 =
        DecodeHex("2122232425262728292a2b2c2d2e2f303132333435363738");
    const std::vector<uint8_t> masterKey32 =
        DecodeHex("4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60");

    uint8_t derivedKey[32];
    PQ_CHECK(params.DeriveKey(passphrase, salt.data(), salt.size(), derivedKey));
    PQ_CHECK_EQ(
        EncodeHex(derivedKey, 32),
        std::string("0d1a3c6523c8f06e4e0af9c515aa5b5448cfebd6838f2d52c3d8b6ef8ddc3c2e"));

    std::vector<uint8_t> sealed72;
    PQ_CHECK(
        divi_pq::SealMasterKeyWithNonceV2(
            masterKey32.data(),
            passphrase,
            salt.data(),
            salt.size(),
            params,
            nonce24.data(),
            sealed72));
    PQ_CHECK_EQ(sealed72.size(), static_cast<size_t>(WALLET_CRYPTO_SEALED_KEY_V2_SIZE));
    PQ_CHECK_EQ(
        EncodeHex(sealed72),
        std::string(
            "2122232425262728292a2b2c2d2e2f303132333435363738"
            "0bfc85229c8d94133d93387ceb1cf60eaaf51bd6a790ade9281c0d38a13bc2ad"
            "02aad9f8452ced8e9617593fd4756959"));

    uint8_t openedMasterKey[32];
    PQ_CHECK(
        divi_pq::OpenMasterKeyV2(
            sealed72.data(),
            sealed72.size(),
            passphrase,
            salt.data(),
            salt.size(),
            params,
            openedMasterKey));
    PQ_CHECK(std::memcmp(openedMasterKey, masterKey32.data(), 32) == 0);

    // Wrong passphrase must fail Poly1305 tag verification
    PQ_CHECK(
        !divi_pq::OpenMasterKeyV2(
            sealed72.data(),
            sealed72.size(),
            "wrong passphrase",
            salt.data(),
            salt.size(),
            params,
            openedMasterKey));

    // CMasterKey integration roundtrip + tamper rejection
    CMasterKey kMasterKey;
    PQ_CHECK(
        divi_pq::EncryptCMasterKeyV2(
            masterKey32.data(),
            passphrase,
            salt.data(),
            params,
            nonce24.data(),
            kMasterKey));
    PQ_CHECK_EQ(kMasterKey.nDerivationMethod, MASTER_KEY_DERIVATION_ARGON2ID_XCHACHA20);
    PQ_CHECK_EQ(kMasterKey.vchOtherDerivationParameters.size(), WALLET_CRYPTO_KDF_PARAMS_V2_SIZE);
    PQ_CHECK_EQ(kMasterKey.vchCryptedKey.size(), WALLET_CRYPTO_SEALED_KEY_V2_SIZE);

    uint8_t decryptedFromMasterKey[32];
    PQ_CHECK(divi_pq::DecryptCMasterKeyV2(kMasterKey, passphrase, decryptedFromMasterKey));
    PQ_CHECK(std::memcmp(decryptedFromMasterKey, masterKey32.data(), 32) == 0);

    // Per-record ckey and chdchain AEAD sealing/opening & cross-context tamper rejection
    const std::vector<uint8_t> pubkey33 =
        DecodeHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    const std::vector<uint8_t> ckeyAad = divi_pq::BuildCkeyRecordAad(pubkey33.data(), pubkey33.size());
    const std::vector<uint8_t> chdAad = divi_pq::BuildChdchainRecordAad();
    const std::vector<uint8_t> secret32 =
        DecodeHex("1111111111111111111111111111111111111111111111111111111111111111");

    std::vector<uint8_t> sealedCkey;
    PQ_CHECK(
        divi_pq::SealRecordWithNonceV2(
            masterKey32.data(),
            ckeyAad.data(),
            ckeyAad.size(),
            secret32.data(),
            secret32.size(),
            nonce24.data(),
            sealedCkey));

    std::vector<uint8_t> openedSecret;
    PQ_CHECK(
        divi_pq::OpenRecordV2(
            masterKey32.data(),
            ckeyAad.data(),
            ckeyAad.size(),
            sealedCkey.data(),
            sealedCkey.size(),
            openedSecret));
    PQ_CHECK_EQ(openedSecret.size(), static_cast<size_t>(32));
    PQ_CHECK(std::memcmp(openedSecret.data(), secret32.data(), 32) == 0);

    // Swapping AAD to chdchain or another pubkey must fail authentication
    PQ_CHECK(
        !divi_pq::OpenRecordV2(
            masterKey32.data(),
            chdAad.data(),
            chdAad.size(),
            sealedCkey.data(),
            sealedCkey.size(),
            openedSecret));
}

// ============================================================================
// 3. DIP-PQ-2: Hybrid Spork v2 (secp256k1 + LMS-SHA256-M32-H10) Lockstep Tests
// ============================================================================

static void RunDipPq2HybridSporkTests()
{
    const std::vector<uint8_t> lmsPk = DecodeHex(
        "0000000600000003bf2fd2b1a59e04f9b9da4243bb4b78d6"
        "a2cccf5a07cc294fd61b762122616dc1884927cfeb3f340e5a6949502bd4a60100000000");
    const std::vector<uint8_t> magic = DecodeHex("dff0c8f3");

    uint8_t sigSecp[65];
    sigSecp[0] = 31U; // valid compact recovery header (31..=34)
    for (size_t i = 1; i < 65; ++i) {
        sigSecp[i] = static_cast<uint8_t>(i);
    }

    // Integer value "4070908800" vs i64 4070908800 must produce identical 32-byte payload hash (Case A)
    uint8_t hashI64[32];
    uint8_t hashStrA[32];
    SporkPq::ComputeSporkPqPayloadHashI64(10013, 4070908800LL, 1750000100LL, sigSecp, hashI64);
    SporkPq::ComputeSporkPqPayloadHash(10013, "4070908800", 1750000100LL, sigSecp, hashStrA);
    PQ_CHECK(std::memcmp(hashI64, hashStrA, 32) == 0);

    // Multi-value string "5000;100" uses Case B (>=107-byte preimage) and differs from Case A
    uint8_t hashStrB[32];
    SporkPq::ComputeSporkPqPayloadHash(10013, "5000;100", 1750000100LL, sigSecp, hashStrB);
    PQ_CHECK(std::memcmp(hashStrA, hashStrB, 32) != 0);

    // Classical 65-byte v1 Spork verification under ClassicalOnly, HybridOptional, and HybridRequiredAfter
    std::vector<uint8_t> v1Sig(sigSecp, sigSecp + 65);
    SporkPq::SporkVerifyResult res;

    PQ_CHECK_EQ(
        SporkPq::VerifySporkWithPolicy(
            10013,
            "4070908800",
            1750000100LL,
            v1Sig,
            true,
            SporkPq::SporkAuthPolicy::ClassicalOnly(),
            res),
        SporkPq::SporkVerifyErrorCode::Ok);
    PQ_CHECK_EQ(res.kind, SporkPq::SporkAuthKind::ClassicalV1);

    const SporkPq::SporkAuthPolicy cutoffPolicy =
        SporkPq::SporkAuthPolicy::HybridRequiredAfter(lmsPk.data(), magic.data(), 1750000500LL);

    // Before cutoff: 65-byte v1 signature is accepted
    PQ_CHECK_EQ(
        SporkPq::VerifySporkWithPolicy(
            10013, "4070908800", 1750000499LL, v1Sig, true, cutoffPolicy, res),
        SporkPq::SporkVerifyErrorCode::Ok);

    // At or after cutoff: 65-byte v1 signature is rejected with MissingPostQuantumSignatureAfterCutoff
    PQ_CHECK_EQ(
        SporkPq::VerifySporkWithPolicy(
            10013, "4070908800", 1750000500LL, v1Sig, true, cutoffPolicy, res),
        SporkPq::SporkVerifyErrorCode::MissingPostQuantumSignatureAfterCutoff);

    // Stateful LMS leaf tracker monotonicity & one-time leaf reuse detection
    SporkPq::SporkLmsStateTracker tracker;
    uint8_t msgHash1[32] = {0x11U};
    uint8_t msgHash2[32] = {0x22U};
    PQ_CHECK_EQ(tracker.RecordVerifiedLeaf(10013, msgHash1, 0U), SporkPq::SporkVerifyErrorCode::Ok);
    // Idempotent duplicate of same message hash at q=0
    PQ_CHECK_EQ(tracker.RecordVerifiedLeaf(10013, msgHash1, 0U), SporkPq::SporkVerifyErrorCode::Ok);
    // Reusing leaf q=0 on a distinct message hash is rejected
    PQ_CHECK_EQ(
        tracker.RecordVerifiedLeaf(10013, msgHash2, 0U),
        SporkPq::SporkVerifyErrorCode::LmsLeafReusedAcrossDistinctMessages);
    // Advancing to q=1 succeeds
    PQ_CHECK_EQ(tracker.RecordVerifiedLeaf(10013, msgHash2, 1U), SporkPq::SporkVerifyErrorCode::Ok);
    PQ_CHECK_EQ(tracker.LastGlobalLeafIndex(), 1U);
}

// ============================================================================
// 4. DIP-PQ-3: Bech32m, P2PQPKH (34 B), PQ_STAKING_VAULT (74 B) & Witness Tests
// ============================================================================

static void RunDipPq3ScriptsAddressesAndWitnessTests()
{
    // Canonical Vector 1: P2PQPKH (v1, addr_key_hash_256 = [0x11; 32])
    uint8_t hashV1[32];
    std::memset(hashV1, 0x11, 32);
    const std::vector<uint8_t> p2pqpkhScript = CreateP2pqpkhScript(hashV1);
    PQ_CHECK_EQ(p2pqpkhScript.size(), P2PQPKH_SCRIPT_LEN);
    PQ_CHECK_EQ(
        EncodeHex(p2pqpkhScript),
        std::string("51201111111111111111111111111111111111111111111111111111111111111111"));

    uint8_t extractedHashV1[32];
    PQ_CHECK(IsP2pqpkhScript(p2pqpkhScript, extractedHashV1));
    PQ_CHECK(std::memcmp(extractedHashV1, hashV1, 32) == 0);

    struct HrpVec {
        PqAddressHrp hrp;
        const char* expectedAddr;
    };
    static const HrpVec V1_ADDRS[5] = {
        {PqAddressHrp::DiviMainnet, "divi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsvgff7j"},
        {PqAddressHrp::DiviTestnet, "tdivi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsnfa2ee"},
        {PqAddressHrp::DiviRegtest, "rdivi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsj9gcf6"},
        {PqAddressHrp::PrivateDiviMainnet, "pdivi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs2puk7m"},
        {PqAddressHrp::PrivateDiviTestnet, "tpdivi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsf68lva"}
    };

    for (size_t i = 0; i < 5; ++i) {
        std::string addr;
        PQ_CHECK_EQ(EncodeP2pqpkhAddress(V1_ADDRS[i].hrp, hashV1, addr), PqAddressErrorCode::Ok);
        PQ_CHECK_EQ(addr, std::string(V1_ADDRS[i].expectedAddr));

        PqAddressHrp decodedHrp = PqAddressHrp::DiviMainnet;
        std::vector<uint8_t> roundtripScript;
        PQ_CHECK_EQ(PqAddressToScriptPubKey(addr, decodedHrp, roundtripScript), PqAddressErrorCode::Ok);
        PQ_CHECK_EQ(decodedHrp, V1_ADDRS[i].hrp);
        PQ_CHECK(roundtripScript == p2pqpkhScript);
    }

    // Canonical Vector 2: PQ_STAKING_VAULT (v2, owner = [0x22; 32], vault = [0x33; 32])
    uint8_t ownerV2[32];
    uint8_t vaultV2[32];
    std::memset(ownerV2, 0x22, 32);
    std::memset(vaultV2, 0x33, 32);
    const std::vector<uint8_t> pqVaultScript = CreatePqStakingVaultScript(ownerV2, vaultV2);
    PQ_CHECK_EQ(pqVaultScript.size(), PQ_STAKING_VAULT_SCRIPT_LEN);
    PQ_CHECK_EQ(
        EncodeHex(pqVaultScript),
        std::string(
            "63202222222222222222222222222222222222222222222222222222222222222222"
            "67b9203333333333333333333333333333333333333333333333333333333333333333"
            "6878a888ac"));

    std::pair<std::vector<uint8_t>, std::vector<uint8_t> > keyHashes;
    PQ_CHECK(GetPqStakingVaultKeyHashes(pqVaultScript, keyHashes));
    PQ_CHECK_EQ(keyHashes.first.size(), static_cast<size_t>(32));
    PQ_CHECK_EQ(keyHashes.second.size(), static_cast<size_t>(32));
    PQ_CHECK(std::memcmp(keyHashes.first.data(), ownerV2, 32) == 0);
    PQ_CHECK(std::memcmp(keyHashes.second.data(), vaultV2, 32) == 0);

    std::string vaultAddr;
    PQ_CHECK_EQ(
        EncodePqVaultAddress(PqAddressHrp::DiviMainnet, ownerV2, vaultV2, vaultAddr),
        PqAddressErrorCode::Ok);
    PQ_CHECK_EQ(
        vaultAddr,
        std::string(
            "divi1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3"
            "rxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvc5tmafc"));

    // Posture classification
    StakingQuantumPosture vaultPosture = ClassifyStakingQuantumPosture(pqVaultScript);
    PQ_CHECK(vaultPosture.IsVaultInsulated());
    PQ_CHECK_EQ(std::string(vaultPosture.AdvisoryLabel()), std::string("vault_only"));

    // Segregated PQ witness stack & wtxid (Vector 3 from dip-pq-3-witness-and-vaults.md §5)
    uint8_t txid[32];
    std::memset(txid, 0x44, 32);

    std::vector<PqInputWitness> emptyWitnesses(1, PqInputWitness::Empty());
    uint8_t wtxidEmpty[32];
    ComputePqWitnessId(txid, emptyWitnesses, wtxidEmpty);
    PQ_CHECK(std::memcmp(wtxidEmpty, txid, 32) == 0);

    std::vector<uint8_t> pk5(5, 0xbbU);
    std::vector<uint8_t> sig4(4, 0xaaU);
    PqInputWitness w1 = PqInputWitness::ForP2pqpkh(0x02U, pk5, sig4, 0x01U);
    const std::vector<uint8_t> serW1 = w1.SerializeCanonical();
    PQ_CHECK_EQ(EncodeHex(serW1), std::string("020602aaaaaaaa010602bbbbbbbbbb"));

    uint8_t leafHash[32];
    w1.LeafHash(leafHash);
    PQ_CHECK_EQ(
        EncodeHex(leafHash, 32),
        std::string("6a54cfde88e05f76fe480d4c51006caaedca444709461f269b56f47861242360"));

    std::vector<PqInputWitness> oneWitness(1, w1);
    uint8_t wtxid1[32];
    ComputePqWitnessId(txid, oneWitness, wtxid1);
    PQ_CHECK_EQ(
        EncodeHex(wtxid1, 32),
        std::string("c7c7f733df91db4fff693716dcc3c31f45eb92873181d1def64a4c6a8936fe44"));
    PQ_CHECK(VerifyCoinstakeWitnessCommitment(leafHash, leafHash));

    // Weight accounting
    size_t weight = 0;
    PQ_CHECK_EQ(ValidatePqBlockWeight(250000, 500000, weight), PqWitnessErrorCode::Ok);
    PQ_CHECK_EQ(weight, static_cast<size_t>(1500000));
    PQ_CHECK_EQ(ValidatePqBlockWeight(1950000, 100000, weight), PqWitnessErrorCode::BlockWeightExceeded);
}

// ============================================================================
// 5. DIP-PQ-4: PqBlockSigEnvelope (1,566 B FN-DSA-512 & 3,735 B ML-DSA-44) Tests
// ============================================================================

static void RunDipPq4BlockSigningTests()
{
    const std::vector<uint8_t> magic = DecodeHex("dff0c8f3");

    // Canonical Vector 1 (dip-pq-4-pos-block-signing.md §6): 85-byte preimage & payload hash
    uint8_t blockHash[32];
    uint8_t coinstakeTxid[32];
    std::memset(blockHash, 0x11, 32);
    std::memset(coinstakeTxid, 0x22, 32);
    const uint32_t coinstakeVout = 1U;

    uint8_t preimage85[PqBlockSigning::POS_BLOCK_PAYLOAD_PREIMAGE_LEN];
    PqBlockSigning::SerializePosBlockPayloadPreimage(blockHash, coinstakeTxid, coinstakeVout, preimage85);
    PQ_CHECK_EQ(
        EncodeHex(preimage85, sizeof(preimage85)),
        std::string(
            "444956492d504f532d424c4f434b2d5631"
            "1111111111111111111111111111111111111111111111111111111111111111"
            "2222222222222222222222222222222222222222222222222222222222222222"
            "01000000"));

    uint8_t payloadHash32[32];
    PqBlockSigning::ComputePosBlockPayloadHash(blockHash, coinstakeTxid, coinstakeVout, payloadHash32);
    PQ_CHECK_EQ(
        EncodeHex(payloadHash32, 32),
        std::string("aa200288dc9adad3659598409fe8c11383ee0570d9965984a3b2c3c275d129fa"));

    // Build canonical FN-DSA-512 (1,566 B) and ML-DSA-44 (3,735 B) envelopes
    const std::vector<uint8_t> hotFnPk = BuildSampleFnDsa512Pubkey(1);
    const std::vector<uint8_t> hotFnSig = BuildSampleFnDsa512Signature(0x42U);
    const std::vector<uint8_t> coldFnPk = BuildSampleFnDsa512Pubkey(2);

    PqBlockSigning::PqBlockSigEnvelope fnEnv;
    PQ_CHECK_EQ(
        PqBlockSigning::PqBlockSigEnvelope::Create(
            DIVI_PQ_SCHEME_FNDSA512, hotFnPk, hotFnSig, fnEnv),
        PqBlockSigning::PqBlockSigErrorCode::Ok);
    const std::vector<uint8_t> fnEncoded = fnEnv.Encode();
    PQ_CHECK_EQ(fnEncoded.size(), PqBlockSigning::FN_DSA_512_BLOCK_SIG_ENVELOPE_LEN);

    const std::vector<uint8_t> mlPk = BuildSampleMlDsa44Pubkey(7);
    const std::vector<uint8_t> mlSig = BuildSampleMlDsa44Signature(0x55U);
    PqBlockSigning::PqBlockSigEnvelope mlEnv;
    PQ_CHECK_EQ(
        PqBlockSigning::PqBlockSigEnvelope::Create(
            DIVI_PQ_SCHEME_MLDSA44, mlPk, mlSig, mlEnv),
        PqBlockSigning::PqBlockSigErrorCode::Ok);
    const std::vector<uint8_t> mlEncoded = mlEnv.Encode();
    PQ_CHECK_EQ(mlEncoded.size(), PqBlockSigning::ML_DSA_44_BLOCK_SIG_ENVELOPE_LEN);

    // Hot vault_hash_256 binding succeeds; cold owner_hash_256 is strictly rejected
    uint8_t ownerHash[32];
    uint8_t vaultHash[32];
    divi_pq_address_key_hash_256(DIVI_PQ_SCHEME_FNDSA512, coldFnPk.data(), coldFnPk.size(), ownerHash);
    fnEnv.StakerKeyHash256(vaultHash);
    const std::vector<uint8_t> vaultScript = CreatePqStakingVaultScript(ownerHash, vaultHash);

    const PqBlockSigning::PosBlockAuthPolicy policy =
        PqBlockSigning::PosBlockAuthPolicy::PqRequiredForPqOutputs(magic.data());
    PqBlockSigning::VerifiedBlockSigBinding verified;
    PQ_CHECK_EQ(
        PqBlockSigning::VerifyBlockSigEnvelopeBinding(
            fnEncoded,
            vaultScript,
            blockHash,
            coinstakeTxid,
            coinstakeVout,
            1750002000U,
            policy,
            verified),
        PqBlockSigning::PqBlockSigErrorCode::Ok);
    PQ_CHECK_EQ(verified.kind, PqBlockSigning::BlockSigFormatKind::PostQuantumV1);
    PQ_CHECK_EQ(verified.schemeId, DIVI_PQ_SCHEME_FNDSA512);
    PQ_CHECK(std::memcmp(verified.payloadHash256, payloadHash32, 32) == 0);

    // Cold owner key attempting to sign vchBlockSig -> ColdOwnerKeyForbiddenForBlockSigning
    PqBlockSigning::PqBlockSigEnvelope coldAttemptEnv;
    PQ_CHECK_EQ(
        PqBlockSigning::PqBlockSigEnvelope::Create(
            DIVI_PQ_SCHEME_FNDSA512, coldFnPk, hotFnSig, coldAttemptEnv),
        PqBlockSigning::PqBlockSigErrorCode::Ok);
    PQ_CHECK_EQ(
        PqBlockSigning::VerifyBlockSigEnvelopeBinding(
            coldAttemptEnv.Encode(),
            vaultScript,
            blockHash,
            coinstakeTxid,
            coinstakeVout,
            1750002000U,
            policy,
            verified),
        PqBlockSigning::PqBlockSigErrorCode::ColdOwnerKeyForbiddenForBlockSigning);

    // Degenerate vault (ownerHash == vaultHash) must also be rejected as ColdOwnerKeyForbiddenForBlockSigning
    const std::vector<uint8_t> degenerateVaultScript = CreatePqStakingVaultScript(vaultHash, vaultHash);
    PQ_CHECK_EQ(
        PqBlockSigning::VerifyBlockSigEnvelopeBinding(
            fnEncoded,
            degenerateVaultScript,
            blockHash,
            coinstakeTxid,
            coinstakeVout,
            1750002000U,
            policy,
            verified),
        PqBlockSigning::PqBlockSigErrorCode::ColdOwnerKeyForbiddenForBlockSigning);

    // Forbidden schemes (SLH-DSA-128s 0x03 and LMS 0x04) in BlockSigV1 must return SchemeForbiddenInDomain
    size_t dummyLen = 0;
    PQ_CHECK_EQ(
        PqBlockSigning::PqBlockSigEnvelope::ExpectedEnvelopeLen(DIVI_PQ_SCHEME_SLHDSA128S, dummyLen),
        PqBlockSigning::PqBlockSigErrorCode::SchemeForbiddenInDomain);
    PQ_CHECK_EQ(
        PqBlockSigning::PqBlockSigEnvelope::ExpectedEnvelopeLen(DIVI_PQ_SCHEME_LMS_SHA256_M32_H10, dummyLen),
        PqBlockSigning::PqBlockSigErrorCode::SchemeForbiddenInDomain);
}

} // namespace

#ifdef DIVI_PQ_STANDALONE_TEST
int main()
{
    RunDipPq1KeyHashVectorsTest();
    RunDipPq1HdDerivationVectorsTest();
    RunDipPq1SigningPrehashVectorsTest();
    RunDipPq1LmsPositiveAnd17NegativeVectorsTest();
    RunDipPq0CrypterAndMasterKeyVectorsTest();
    RunDipPq2HybridSporkTests();
    RunDipPq3ScriptsAddressesAndWitnessTests();
    RunDipPq4BlockSigningTests();
    std::printf(
        "PASS: pq_lockstep_tests standalone runner — all DIP-PQ-0..DIP-PQ-4 positive + 17 adversarial vectors passed.\n");
    return 0;
}
#else
BOOST_AUTO_TEST_SUITE(pq_lockstep_tests)

BOOST_AUTO_TEST_CASE(dip_pq_1_key_hashes_and_hd_derivation)
{
    RunDipPq1KeyHashVectorsTest();
    RunDipPq1HdDerivationVectorsTest();
}

BOOST_AUTO_TEST_CASE(dip_pq_1_signing_prehashes_and_lms_17_negatives)
{
    RunDipPq1SigningPrehashVectorsTest();
    RunDipPq1LmsPositiveAnd17NegativeVectorsTest();
}

BOOST_AUTO_TEST_CASE(dip_pq_0_argon2id_xchacha20_crypter_and_master_key)
{
    RunDipPq0CrypterAndMasterKeyVectorsTest();
}

BOOST_AUTO_TEST_CASE(dip_pq_2_hybrid_spork_v2_and_lms_state_tracker)
{
    RunDipPq2HybridSporkTests();
}

BOOST_AUTO_TEST_CASE(dip_pq_3_bech32m_p2pqpkh_pq_staking_vault_and_witness)
{
    RunDipPq3ScriptsAddressesAndWitnessTests();
}

BOOST_AUTO_TEST_CASE(dip_pq_4_pos_block_sig_envelope_and_vault_binding)
{
    RunDipPq4BlockSigningTests();
    ActivationState state;
    BOOST_CHECK(!state.IsActive(Fork::HybridSporkV2));
    BOOST_CHECK(!state.IsActive(Fork::PostQuantumWitnessAndVaults));
    BOOST_CHECK(!state.IsActive(Fork::PostQuantumBlockSig));
    BOOST_CHECK(!state.IsActive(Fork::StrictPostQuantumBlockSig));
}

BOOST_AUTO_TEST_SUITE_END()
#endif
