#ifndef BITCOIN_CHAINPARAMSSEEDS_H
#define BITCOIN_CHAINPARAMSSEEDS_H
/**
 * List of fixed seed nodes for the centauri network
 * AUTOGENERATED by contrib/seeds/generate-seeds.py
 *
 * Each line contains a 16-byte IPv6 address and a port.
 * IPv4 as well as onion addresses are wrapped inside a IPv6 address accordingly.
 */
static SeedSpec6 pnSeed6_main[] = { //CTXTODO: add additional server

    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x34,0x17,0xdd,0x09}, 43228}, //CTX: 52.23.221.9
    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x34,0x57,0xbb,0x80}, 43228}, //CTX: 52.87.187.128

    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x68,0x28,0x90,0x3c}, 43228}, //CTX: 104.40.144.60
    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x34,0xe8,0x06,0x7b}, 43228}, //CTX: 52.232.6.123

    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x6b,0xaa,0x9c,0x11}, 43228} //CTX: seed ip - old format: 0x119caa6b
};

static SeedSpec6 pnSeed6_test[] = {
    {{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x6b,0xaa,0x9c,0x11}, 33815} // CTXTODO: setup a testnet
};
#endif // BITCOIN_CHAINPARAMSSEEDS_H
