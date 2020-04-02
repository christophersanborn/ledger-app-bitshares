"""
Wallet Transaction Actions for SimpleGUIWallet
"""

# STANDARD PYTHON MODULES
from datetime import datetime, timedelta
import binascii
import string
import struct
import json
import sys

# PYBITSHARES MODULES
from bitshares import BitShares
from bitshares.account import Account
from bitshares.amount import Amount
from bitshares.memo import Memo
from bitsharesbase import operations
from bitsharesbase.signedtransactions import Signed_Transaction
from graphenecommon.exceptions import AccountDoesNotExistsException
from graphenecommon.exceptions import AssetDoesNotExistsException
from grapheneapi.exceptions import RPCError
from grapheneapi.exceptions import NumRetriesReached

# NANO MODULES
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException

# THIRD PARTY MODULES
from asn1 import Encoder, Numbers
from logger import Logger


def init_chain_object(api_node):
    """
    initialize a Bitshares instance via websocket connection to a specified node
    """
    global blockchain
    try:
        blockchain = BitShares(api_node, num_retries=0)
        return blockchain
    except Exception:
        print("ERROR: Could not connect to API node at %s" % api_node)
        sys.exit()


def parse_bip32_path(path):
    """#"""
    if len(path) == 0:
        return bytes([])
    result = bytes([])
    elements = path.split("/")
    for path_element in elements:
        element = path_element.split("'")
        if len(element) == 1:
            result = result + struct.pack(">I", int(element[0]))
        else:
            result = result + struct.pack(">I", 0x80000000 | int(element[0]))
    return result


def head_block_blank_tx():
    """#"""
    tx_head = blockchain.new_tx()  # Pull recent TaPoS
    try:
        dummy = tx_head[
            "ref_block_num"
        ]  # Somehow this triggers tx_head to populate 'expiration'... (??)
    except NumRetriesReached:
        Logger.Write(
            "ERROR: Can't reach API node: "
            + "'NumRetries' reached.  Check network connection."
        )
        raise
    expiration = datetime.strptime(
        tx_head["expiration"], "%Y-%m-%dT%H:%M:%S"
    ) + timedelta(minutes=10)
    tx_head["expiration"] = expiration.strftime(
        "%Y-%m-%dT%H:%M:%S%Z"
    )  # Longer expiration to accomodate device interaction
    return tx_head


def append_transfer_to_tx(builder, from_name, to_name, amount, symbol):
    """
    TODO: Cleanup exception catching for better user feedback
    `builder` is a TransactionBuilder object. (E.g. from BitShares.new_tx())
    `dest_account_name` is a string from_account name.
    """
    try:
        from_account = Account(from_name, blockchain_instance=blockchain)
        to_account = Account(to_name, blockchain_instance=blockchain)
        amount_asset = Amount(amount, symbol, blockchain_instance=blockchain)
    except NumRetriesReached:
        Logger.Write(
            "ERROR: Can't reach API node: "
            + "'NumRetries' reached.  Check network connection."
        )
        raise
    except AssetDoesNotExistsException as error:
        Logger.Write("ERROR: Asset or token '%s' not known." % str(error))
        raise
    except AccountDoesNotExistsException as error:
        Logger.Write("ERROR: Account '%s' not known." % str(error))
        raise
    except Exception as error:
        Logger.Write("Unknown problem constructing Transfer operation: %s" % str(error))
        raise
    memo_obj = Memo(
        from_account=from_account, to_account=to_account, blockchain_instance=blockchain
    )
    memo_text = ""  # "Signed by BitShares App on Ledger Nano S!"
    operation = operations.Transfer(
        **{
            "fee": {"amount": 0, "asset_id": "1.3.0"},
            "from": from_account["id"],
            "to_account": to_account["id"],
            "amount": {
                "amount": int(amount_asset),
                "asset_id": amount_asset.asset["id"],
            },
            "memo": memo_obj.encrypt(memo_text),
        }
    )
    builder.appendOps(operation)
    return builder


def generate_transfer_json(from_name, to_name, amount, symbol):
    """
    Generate a TaPoS current transaction with a single Transfer operation
    in it, return as JSON string.
      _names's symbol are strings, amount is float
    """
    builder = head_block_blank_tx()
    builder = append_transfer_to_tx(builder, from_name, to_name, amount, symbol)
    builder.constructTx()
    return json.dumps(builder)


def serialized_tx_bytes(tx_json):
    """
    given transaction json, create a signed transaction and serialize it
    """
    trans = json.loads(tx_json)  # from json to dict
    signed_tx = Signed_Transaction(
        ref_block_num=trans["ref_block_num"],
        ref_block_prefix=trans["ref_block_prefix"],
        expiration=trans["expiration"],
        operations=trans["operations"],
    )
    serialized = encode_tlv_tx(
        binascii.unhexlify(blockchain.rpc.chain_params["chain_id"]), signed_tx
    )
    return serialized


def encode_tlv_tx(chain_id, trans):
    """#"""
    encoder = Encoder()
    encoder.start()
    encoder.write(struct.pack(str(len(chain_id)) + "s", chain_id), Numbers.OctetString)
    encoder.write(bytes(trans["ref_block_num"]), Numbers.OctetString)
    encoder.write(bytes(trans["ref_block_prefix"]), Numbers.OctetString)
    encoder.write(bytes(trans["expiration"]), Numbers.OctetString)
    encoder.write(bytes(trans["operations"].length), Numbers.OctetString)
    for op_idx in range(0, len(trans.toJson()["operations"])):
        encoder.write(
            bytes([trans["operations"].data[op_idx].opId]), Numbers.OctetString
        )
        encoder.write(bytes(trans["operations"].data[op_idx].op), Numbers.OctetString)
    if "extension" in trans:
        encoder.write(bytes(trans["extension"]), Numbers.OctetString)
    else:
        encoder.write(bytes([0]), Numbers.OctetString)
    return encoder.output()


def get_sig_from_nano(serial_tx_bytes, bip32_path):
    """
    fetch the user's signature from the nano ledger and parse the result
    """
    dongle_path = parse_bip32_path(bip32_path)
    path_size = int(len(dongle_path) / 4)
    try:
        dongle = getDongle(True)
    except Exception:
        Logger.Write("Ledger Nano not found! Is it plugged in and unlocked?")
        raise
    Logger.Write("Please review and confirm transaction on Ledger Nano S...")
    offset = 0
    first = True
    sign_size = len(serial_tx_bytes)
    while offset != sign_size:
        if sign_size - offset > 200:
            chunk = serial_tx_bytes[offset : offset + 200]
        else:
            chunk = serial_tx_bytes[offset:]
        if first:
            total_size = len(dongle_path) + 1 + len(chunk)
            apdu = (
                binascii.unhexlify(
                    "B5040000"
                    + "{:02x}".format(total_size)
                    + "{:02x}".format(path_size)
                )
                + dongle_path
                + chunk
            )
            first = False
        else:
            total_size = len(chunk)
            apdu = binascii.unhexlify("B5048000" + "{:02x}".format(total_size)) + chunk
        offset += len(chunk)
        try:
            result = dongle.exchange(apdu)
        except CommException as error:
            dongle.close()
            if error.sw == 0x6E00:
                Logger.Write("BitShares App not running on Nano.  Please check.")
            else:
                Logger.Write("User declined - transaction not signed.")
            raise
        except Exception:
            dongle.close()
            Logger.Write("An unknown error occured.  Was device unplugged?")
            raise
    dongle.close()
    return result


def broadcast_signed_tx(tx_json, sig_bytes):
    """
    given a transaction and a signature, broadcast it to the public api node
    """
    signed_tx = blockchain.new_tx(json.loads(str(tx_json)))
    signed_tx["signatures"].extend([binascii.hexlify(sig_bytes).decode()])
    Logger.Write("Broadcasting transaction...", echo=True)
    try:
        print(blockchain.broadcast(tx=signed_tx))
        Logger.Write("Success!  Transaction has been sent.", echo=True)
    except RPCError as error:
        Logger.Write("Could not broadcast transaction!", echo=True)
        Logger.Write(str(error))
        raise
    except NumRetriesReached:
        Logger.Write(
            "ERROR: Could not broadcast transaction: "
            + "'NumRetries' reached.  Check network connection."
        )
        raise


def pub_keys_from_nano(bip32_paths, confirm_on_device=False):
    """
    captures all exceptions and does not re-raise
    will return an empty or partial list if we don't suceed in retrieving all keys
    to determine success compare length of return list to length of key list
    """
    addresses = []
    try:
        dongle = getDongle(True)
    except Exception:
        Logger.Write("Ledger Nano not found! Is it plugged in and unlocked?")
        return []
    for path in bip32_paths:
        dongle_path = parse_bip32_path(path)
        apdu = (
            binascii.unhexlify(
                "B502"
                + ("01" if confirm_on_device else "00")
                + "00"
                + "{:02x}".format(len(dongle_path) + 1)
                + "{:02x}".format(int(len(dongle_path) / 4))
            )
            + dongle_path
        )
        try:
            result = dongle.exchange(apdu)
        except CommException as error:
            dongle.close()
            if error.sw == 0x6E00:
                Logger.Write("BitShares App not running on Nano.  Please check.")
            elif error.sw == 0x6985:
                Logger.Write(
                    "Warning! Address not confirmed by user - may not be valid!"
                )
                raise
            else:
                Logger.Write("Warning! Address not confirmed by user, or other error.")
            return addresses
        except Exception:
            dongle.close()
            Logger.Write("An unknown error occured.  Was device unplugged?")
            return addresses
        offset = 1 + result[0]
        address = bytes(result[offset + 1 : offset + 1 + result[offset]]).decode(
            "utf-8"
        )
        # TODO: Also extract pubkey and assert that it produces same address
        addresses.append(address)
    dongle.close()
    return addresses


def is_valid_account_name(name):
    """
    Rules: https://github.com/bitshares/bitshares-core/
        blob/master/libraries/protocol/account.cpp
    Perma: https://github.com/bitshares/bitshares-core/
        blob/a7f4f071324c81a6033965e79141fffeb143c03f/libraries/protocol/account.cpp#L30
    This is not a FULL check, but will return false on blatant offenders.
    """
    if len(name) < 3:
        return False
    if len(name) > 63:
        return False
    if not name[0] in string.ascii_lowercase:
        return False
    full = string.ascii_lowercase + string.digits + "-."
    if not all(c in full for c in name):
        return False
    return True
