import argparse
import binascii
import datetime
import asyncio
import sys
from cryptos.coins_async import BaseCoin
from cryptos.constants import SATOSHI_PER_BTC
from cryptos.main import safe_hexlify, is_pubkey
from cryptos.transaction import json_changebase, deserialize_script
from pprint import pprint
from typing import Callable, Any, Union, Optional, Dict, Tuple
from cryptos.script_utils import get_coin, coin_list


async def run_in_executor(func: Callable, *args) -> Any:
    return await asyncio.get_running_loop().run_in_executor(None, func, *args)


def is_block_height(coin: BaseCoin, obj_id: Union[str, int]) -> Optional[int]:
    try:
        return int(obj_id)
    except ValueError:
        return None


def is_tx(coin: BaseCoin, obj_id: str) -> Optional[str]:
    try:
        tx_id = binascii.unhexlify(obj_id)
        if len(tx_id) == coin.txid_bytes_len:
            return obj_id
        return None
    except binascii.Error:
        return None


def is_address(coin: BaseCoin, obj_id: str) -> Optional[str]:
    return obj_id if coin.is_address(obj_id) else None


def script_pubkey_is_pubkey(scriptPubKey: Dict[str, Any], pubkey: str) -> bool:
    return scriptPubKey['type'] == "pubkey" and deserialize_script(scriptPubKey['hex'])[0] == pubkey


def output_belongs_to_address(coin: BaseCoin, out: Dict[str, Any], address: str) -> bool:
    address_variations = coin.get_address_variations(address)
    scriptPubKey = out['scriptPubKey']
    return any(scriptPubKey.get('address') == address
               or script_pubkey_is_pubkey(scriptPubKey,address)
               or address
               in scriptPubKey.get('addresses', []) for address in address_variations)


def script_sig_pubkey(scriptSig: str) -> Optional[str]:
    try:
        return deserialize_script(scriptSig)[1]
    except IndexError:
        return None


def script_sig_script(scriptSig: str) -> Optional[str]:
    try:
        return deserialize_script(scriptSig)[-1]
    except IndexError:
        return None


async def input_belongs_to_address(coin: BaseCoin, inp: Dict[str, Any], address: str, received: Dict[str, int]) -> bool:
    if inp.get('txinwitness'):
        witness = inp.get('txinwitness')
        pubkey_or_script = witness[-1]
        if coin.is_p2wsh(address):
            return coin.p2sh_segwit_addr(pubkey_or_script) == address
        elif coin.is_segwit_or_p2sh(address):
            if is_pubkey(pubkey_or_script):
                return any(addr == address for addr in (  # P2W
                    coin.pub_to_segwit_address(pubkey_or_script),
                    coin.pubtop2wpkh_p2sh(pubkey_or_script),
                ))
        return False
    elif inp.get('scriptSig', {}).get('hex'):
        scriptSig = inp.get('scriptSig', {}).get('hex')
        if scriptSig.startswith('00'):
            script = script_sig_script(scriptSig)
            if coin.is_p2sh(address):
                return coin.p2sh_scriptaddr(script) == address
            if coin.is_cash_address(address):
                return coin.p2sh_cash_addr(script) == address
            return False
        elif script_sig_pubkey(scriptSig):
            pubkey = script_sig_pubkey(scriptSig)
            return coin.pub_is_for_p2pkh_addr(pubkey, address)  # P2PKH
        elif is_pubkey(address):
            txid = inp['txid']  # P2PK
            outno = inp['vout']
            outpoint = '{}:{}'.format(txid, outno)
            if outpoint in received:
                return True
            prev = await coin.get_verbose_tx(txid)
            out = prev['vout'][outno]
            script_pub_key = out['scriptPubKey']
            if script_pubkey_is_pubkey(script_pub_key, address):
                received[outpoint] = out['value']
                return True
        return False


async def print_item(obj_id: str, coin_symbol: str = "btc", testnet: bool = False) -> None:
    coin = get_coin(coin_symbol, testnet=testnet)
    try:
        if is_tx(coin, obj_id):
            tx_id = is_tx(coin, obj_id)
            tx = await coin.get_verbose_tx(tx_id)
            pprint(tx)
        elif is_address(coin, obj_id):
            address = is_address(coin, obj_id)
            history, unspent, balances = await asyncio.gather(coin.history(address),
                                                              coin.unspent(address),
                                                              coin.get_balance(address))
            print('HISTORY:')
            if len(history) > 20:
                print('Last 20 transactions only')
            verbose_history = await asyncio.gather(*[coin.get_verbose_tx(h['tx_hash']) for h in history[-21:-1]])
            received = {}
            coinbase = False
            for h in verbose_history:
                if h.get('time'):
                    _time = h.get('time')
                    timestamp = datetime.datetime.fromtimestamp(_time)
                else:
                    timestamp = ''
                spent_value = 0
                for inp in h['vin']:
                    coinbase = inp.get('coinbase')
                    if not coinbase and await input_belongs_to_address(coin, inp, address, received):
                        in_txid = inp["txid"]
                        outno = inp["vout"]
                        try:
                            outpoint = '{}:{}'.format(in_txid, inp["vout"])
                            value = received[outpoint]
                            spent_value += value
                        except KeyError:
                            tx = await coin.get_verbose_tx(in_txid)
                            for out in tx['vout']:
                                if output_belongs_to_address(coin, out, address):
                                    value = out['value']
                                    current_outno = out["n"]
                                    outpoint = '{}:{}'.format(in_txid, current_outno)
                                    received[outpoint] = value
                                    if outno == current_outno:
                                        spent_value += value
                out_value = 0
                for out in h['vout']:
                    if output_belongs_to_address(coin, out, address):
                        value = out['value']
                        outpoint = '{}:{}'.format(h["txid"], out["n"])
                        received[outpoint] = value
                        out_value += value
                total = int((out_value - spent_value) * SATOSHI_PER_BTC)
                if total > 0:
                    desc = "Received {}{}".format(total, ' COINBASE' if coinbase else '')
                else:
                    desc = "Spent {}".format(0 - total)
                print('{}{}{} {}'.format(timestamp, " " if timestamp else "", h["txid"], desc))
            print('\n{}'.format("UNSPENTS"))
            for u in unspent:
                u['confirmations'] = await coin.confirmations(u['height'])
                print(' '.join(["{}: {}".format(k, v) for k, v in u.items()]))
            print('\n')
            for k, v in balances.items():
                print('{} Balance: {}'.format(k.capitalize(), v))
            len_history = len(history)
            len_unspent = len(unspent)
            plural_history = '' if len_history == 1 else 's'
            plural_unspent = '' if len_unspent == 1 else 's'
            print('\nThis address was found in {} transaction{} and has {} unspent{}.'
                  .format(len_history, plural_history, len_unspent, plural_unspent))
        elif is_block_height(coin, obj_id):
            block_height = is_block_height(coin, obj_id)
            header = await coin.block_header(block_height)
            header = json_changebase(header, lambda x: safe_hexlify(x))
            pprint(header)
        else:
            coin_other_net = get_coin(coin_symbol, testnet=not testnet)
            try:
                if coin_other_net.is_address(obj_id):
                    if testnet:
                        message = "{} is a mainnet address. Try again without --testnet".format(obj_id)
                    else:
                        message = "{} is a testnet address. Try again with --testnet".format(obj_id)
                else:
                    message = "{} is not a block, transaction or address for {}".format(obj_id, coin.display_name)
                print(message, file=sys.stderr)
            finally:
                await coin_other_net.close()
                sys.exit(1)
    finally:
        await coin.close()
        await asyncio.sleep(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("obj", help="Object to search for, either a transaction ID, block height or address")
    parser.add_argument("-x", "--coin", help="Coin", choices=coin_list, default="btc")
    parser.add_argument("-t", "--testnet", help="For testnet", action="store_true")
    args = parser.parse_args()
    asyncio.run(print_item(args.obj, coin_symbol=args.coin, testnet=args.testnet))


if __name__ == "__main__":
    main()
