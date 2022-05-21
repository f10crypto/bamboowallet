# 0xf10

import hashlib
import binascii
import ed25519
from Crypto.Hash import RIPEMD160
import requests
import time


def generate_block_hash(header):
    merkleroot = header["merkleRoot"]
    lastblockhash = header["lastBlockHash"]
    difficulty = big_to_little_endian('{:08x}'.format(header["difficulty"]))
    timestamp = big_to_little_endian('{:016x}'.format(header["timestamp"]))

    return hashlib.sha256(binascii.unhexlify(merkleroot + lastblockhash + difficulty + timestamp)).hexdigest()


def big_to_little_endian(b):
    l = ""
    for i in range(0, len(b) // 2):
        l += b[len(b) - 1 - i * 2 - 1] + b[len(b) - 1 - i * 2]
    return l


def sign_tx(txhash, privkey):
    return privkey.sign(txhash, encoding="hex")


def generate_address_from_pubkey(pubkey):
    address = [0]

    hash1 = hashlib.sha256(pubkey)

    hash2 = RIPEMD160.new()
    hash2.update(hash1.digest())

    hash3 = hashlib.sha256(hash2.digest())
    hash4 = hashlib.sha256(hash3.digest())

    for i in range(0, 20):
        address.append(hash2.digest()[i])

    address.append(hash4.digest()[0])
    address.append(hash4.digest()[1])
    address.append(hash4.digest()[2])
    address.append(hash4.digest()[3])

    adress_s = ''.join('{:02x}'.format(x) for x in address).upper()

    return adress_s


def generate_tx_content_hash(tx):
    ctx = hashlib.sha256()

    ctx.update(binascii.unhexlify(tx["to"]))
    ctx.update(binascii.unhexlify(tx["from"]))
    ctx.update(binascii.unhexlify(big_to_little_endian("{:016x}".format(int(tx["fee"])))))
    ctx.update(binascii.unhexlify(big_to_little_endian("{:016x}".format(int(tx["amount"])))))
    ctx.update(binascii.unhexlify(big_to_little_endian("{:016x}".format(int(tx["timestamp"])))))

    txc_hash = ctx.digest()

    return txc_hash


def generate_tx_hash(txchash, signature):
    return hashlib.sha256(txchash + binascii.unhexlify(signature)).hexdigest()


def generate_tx_hash_from_json(tx):
    return hashlib.sha256(generate_tx_content_hash(tx[0]) + binascii.unhexlify(tx[0]["signature"])).hexdigest()


def generate_tx_json(from_addr, to_addr, amount, fee, privkey):
    timestamp = round(time.time())
    txchash = generate_tx_content_hash({"from": from_addr, "to": to_addr, "fee": fee,
                                        "amount": amount, "timestamp": timestamp})
    signature = sign_tx(txchash, privkey).decode().upper()
    pubkeys = privkey.get_verifying_key().to_ascii(encoding="hex").decode().upper()
    tx_json = [{"amount": amount, "fee": fee, "from": from_addr,
                "signature": signature,
                "signingKey": pubkeys, "timestamp": str(timestamp),
                "to": to_addr}]

    return tx_json


def submit_tx_json(txjson, hosts):

    r = None
    for i, host in enumerate(hosts):

        url = 'http://{}:3000/add_transaction_json'.format(host)
        if i == 0:
            r = requests.post(url, json=txjson)
        else:
            requests.post(url, json=txjson)

    if r.text != '[{"status":"SUCCESS"}]':
        return False
    return True
