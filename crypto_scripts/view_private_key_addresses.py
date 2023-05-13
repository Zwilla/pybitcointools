import argparse
from cryptos.main import privtopub, encode_privkey, compress, decompress
from cryptos.script_utils import coin_list, get_coin


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("priv", help="Private Key")
    parser.add_argument("-x", "--coin", help="Coin",  choices=coin_list, default="btc")
    parser.add_argument("-t", "--testnet", help="For testnet", action="store_true")

    args = parser.parse_args()

    coin = get_coin(args.coin, testnet=args.testnet)
    priv = args.priv
    print('Private key: {}'.format(encode_privkey(priv, formt="hex")))
    priv_compressed = encode_privkey(priv, formt="hex_compressed")
    print('Private key compressed: {}'.format(priv_compressed))
    public_key = decompress(privtopub(priv))
    print('Public key: {}'.format(public_key))
    compressed_public_key = compress(public_key)
    print('Public key Compressed: {}'.format(compressed_public_key))
    p2pkh_wif = coin.encode_privkey(priv, "wif")
    p2pkh_wif_compressed = coin.encode_privkey(priv, "wif_compressed")
    print('P2PKH wif: {}'.format(p2pkh_wif))
    print('P2PKH wif compressed: {}'.format(p2pkh_wif_compressed))
    assert encode_privkey(p2pkh_wif, formt="hex_compressed") == priv_compressed
    p2pkh_address = coin.privtop2pkh(p2pkh_wif)
    p2pkh_compressed_address = coin.privtop2pkh(p2pkh_wif_compressed)
    assert p2pkh_address == coin.pubtoaddr(public_key)
    assert p2pkh_compressed_address == coin.pubtoaddr(compressed_public_key)
    assert privtopub(p2pkh_wif) == public_key
    assert privtopub(p2pkh_wif_compressed) == compressed_public_key
    assert p2pkh_address == coin.privtoaddr(p2pkh_wif)
    assert p2pkh_compressed_address == coin.privtoaddr(p2pkh_wif_compressed)
    print('P2PKH Address: {}'.format(p2pkh_address))
    print('P2PKH Compressed Public Key Address: {}'.format(p2pkh_compressed_address))
    if coin.segwit_supported:
        p2wpkh_p2sh_wif_compressed = coin.encode_privkey(priv, "wif_compressed", script_type="p2wpkh-p2sh")
        print('P2WPKH-P2SH wif compressed: {}'.format(p2wpkh_p2sh_wif_compressed))
        p2wpkh_p2sh_compressed_address = coin.privtop2wpkh_p2sh(p2wpkh_p2sh_wif_compressed)
        p2wpkh_p2sh_address2 = coin.pubtop2wpkh_p2sh(public_key)
        p2wpkh_p2sh_compressed_address2 = coin.pubtop2wpkh_p2sh(compressed_public_key)

        assert privtopub(p2wpkh_p2sh_wif_compressed) == compressed_public_key

        assert p2wpkh_p2sh_compressed_address == p2wpkh_p2sh_address2 == p2wpkh_p2sh_compressed_address2 == coin.privtoaddr(p2wpkh_p2sh_wif_compressed)

        p2wpkh_wif = coin.encode_privkey(priv, "wif", script_type="p2wpkh")
        p2wpkh_wif_compressed = coin.encode_privkey(priv, "wif_compressed", script_type="p2wpkh")
        print('P2WPKH Native Segwit wif compressed: {}'.format(p2wpkh_wif_compressed))
        native_segwit_address = coin.privtosegwitaddress(p2wpkh_wif)
        native_segwit_compressed_address = coin.privtosegwitaddress(p2wpkh_wif_compressed)

        print('P2WPKH Native Segwit Address: {}'.format(native_segwit_address))

        assert native_segwit_address == native_segwit_compressed_address

        native_segwit_address2 = coin.pub_to_segwit_address(public_key)
        native_segwit_compressed_address2 = coin.pub_to_segwit_address(compressed_public_key)

        assert native_segwit_address2 == native_segwit_compressed_address2

        assert native_segwit_address == native_segwit_address2

        assert native_segwit_address == coin.privtoaddr(p2wpkh_wif)
        assert native_segwit_address == coin.privtoaddr(p2wpkh_wif_compressed)


if __name__ == "__main__":
    main()
