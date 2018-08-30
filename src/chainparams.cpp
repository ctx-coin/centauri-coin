// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Genesis";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 840000;                                                                 // CTX
        consensus.BIP34Height = 0;                                                                                  // https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
        consensus.BIP34Hash = uint256S("0x1828ba6510112f50232472fa64c39235d811d400ded970afedad1d6ab1947699");
        consensus.BIP65Height = 335000;                                                                             // https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki
        consensus.BIP66Height = 335000;                                                                             // https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");          // CTX: pow limit is the same - ~uint256(0) >> 20
		consensus.DevMarketingPubKey = "8dbe79a6b89a0d43f3e6f23d7de3ae6e8a1e9c7d"; // CTX - Developer and Marketing Fee : CVPN2YB2Yd1rTHr2hp6oUCXSsc4HZjZ92w
		consensus.AcceptancePointsPubKey = "18942a9d29f520fb84125e28898efb3adf662a64"; // CTX - Acceptance Points Fee : CJhrHRyLz13SHc6KHb311YMm6u2BjhiYet
		consensus.POSCoachesPubKey = "12ed7fa6852661fe6a844d25a170df5cf1aeadaa"; // CTX - POS Coaches Fee : CJByFBtqsZZTZSXwZU4hqvGDSRAKNrvuus
        consensus.nPowTargetTimespan = 4 * 60 * 60; // CTX: re-targeting every 4 hours
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 6048; // 75% of 8064
        consensus.nMinerConfirmationWindow = 8064; // nPowTargetTimespan / nPowTargetSpacing * 4
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;                   // CTX
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601;    // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;      // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;                          // CTX
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1517439600;          // Feb 01, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1577876400;            // January 01, 2020

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;                       // CTX
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1517439600;       // Feb 01, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1577876400;         // January 01, 2020

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000000089caef1e6b"); // CTX: changed minimum chain work

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x1828ba6510112f50232472fa64c39235d811d400ded970afedad1d6ab1947699"); // CTX: changed assumeValid 254850 1503601277

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xdc; // CTX: changed start bytes
        pchMessageStart[1] = 0xca;
        pchMessageStart[2] = 0xae;
        pchMessageStart[3] = 0xea;
        nDefaultPort = 43228;
        nPruneAfterHeight = 100000;

        // CTX: changed genesis params
        genesis = CreateGenesisBlock(1463276265, 109063, 0x1e0ffff0, 1, 1 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x7dbce642d05f9901a7c4ca3fbe43dc59df167e6a4eb94f84c26fa36ac8b0ca7b"));
        assert(genesis.hashMerkleRoot == uint256S("0x18c372fe354185169070e1c23188f3d028271d8445e1be02f50db9aa353ed056")); //CTX: genesis merkle root

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.push_back(CDNSSeedData("alpha-centauri", "seed.alpha-centauri.co"));
        vSeeds.push_back(CDNSSeedData("ctx.nsfw", "seed.ctx.nsfw.systems"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,28); // CTX: Centauri addresses start with C
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,65);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,156); // CTX: PUBKEY_ADDRESS + 128
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x7dbce642d05f9901a7c4ca3fbe43dc59df167e6a4eb94f84c26fa36ac8b0ca7b"))        // CTX: changed checkpoints
            ( 254850, uint256S("0x1828ba6510112f50232472fa64c39235d811d400ded970afedad1d6ab1947699"))   // 1503601277
            ( 273440, uint256S("0x6f1e3a35b89edb9c1394a9988c6b16b7812470fe4c0bbcd4172e6f9ae9c17196"))   // 1506443471 "nonce": 461193, "bits": "1e06367d"
            ( 333555, uint256S("0x852ab0d021315cff7ca9bb9511c4b488df089fb1657219e37ed49cd2db6d6f69"))   // 1515543555 "nonce": 1193410560, "bits": "1e03739d"
            ( 409900, uint256S("0x776fc03682ce7006daa4eaafddcc6939f223a383e5406f0d2a766b084d34de58"))   // 1528896022 "nonce": 242548992, "bits": "1e0fffff"
        };

        chainTxData = ChainTxData{  // CTX: changed block and data
            // Data as of block b89edb9c1394a9988c6b16b7812470fe4c0bbcd4172e6f9ae9c17196 (height 273440).
            1506443471,     // * UNIX timestamp of last known number of transactions
            840143,         // * total number of transactions between genesis and that timestamp
                            //   (the tx=... number in the SetBestChain debug.log lines)
            1.0             // * estimated number of transactions per second after that timestamp
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0xb78197f0e175697646db1f738edc1ffdcb30588ebe70e7e16026489076577061");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 4 * 60 * 60; // CTX: re-targeting every 4 hours
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;                   // CTXTODO: change times?
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601;    // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;      // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;                          // CTXTODO: change times?
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1483228800;          // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801;            // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;                       // CTXTODO: change times?
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1483228800;       // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801;         // January 31st, 2018

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000001");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0xb78197f0e175697646db1f738edc1ffdcb30588ebe70e7e16026489076577061");

        pchMessageStart[0] = 0xbc;
        pchMessageStart[1] = 0xad;
        pchMessageStart[2] = 0xaf;
        pchMessageStart[3] = 0xc4;
        nDefaultPort = 33815;
        nPruneAfterHeight = 1000;

        // CTX: changed genesis parameter
        genesis = CreateGenesisBlock(1388880557, 387006691, 0x1e0ffff0, 1, 1 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0xb78197f0e175697646db1f738edc1ffdcb30588ebe70e7e16026489076577061"));   //CTXTODO: whats the genesis hash?
        //assert(genesis.hashMerkleRoot == uint256S("0x97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9"));       //CTXTODO: whats the merkle root?

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        // vSeeds.push_back(CDNSSeedData("litecointools.com", "testnet-seed.litecointools.com")); // CTXTODO: add testnet seeds
        // vSeeds.push_back(CDNSSeedData("loshan.co.uk", "seed-b.centauri.loshan.co.uk", true));
        // vSeeds.push_back(CDNSSeedData("thrasher.io", "dnsseed-testnet.thrasher.io", true));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0xb78197f0e175697646db1f738edc1ffdcb30588ebe70e7e16026489076577061")) //CTXTODO: whats the genesis hash?
        };

        chainTxData = ChainTxData{
            0,
            0,
            0.0
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 19444;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1296688602, 0, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        //assert(consensus.hashGenesisBlock == uint256S("0x530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9"));
        //assert(genesis.hashMerkleRoot == uint256S("0x97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9"))
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,58);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
