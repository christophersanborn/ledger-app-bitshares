"""
Super Simple BitShares GUI Python Wallet

Run with:

  python3 SimpleGUIWallet.py [--sender=<sender_account_name>]

  Options:

    --sender=<name>      (Default: None)
    --node=<api_node>    (Default: "wss://bitshares.openledger.info/ws")
    --path=<bip32_path>  (Default: "48'/1'/1'/0'/0'")

Dependencies:

  The python dependencies are identical to those of signTransaction.py and
  getPublicKey.py except for the addition of the `tkinter` lib for the GUI.

  The latter may need to be installed with:

    $ sudo apt-get install python3-tk
    $ pip3 install --user pyttk

"""

# STANDARD PYTHON MODULES
import json
import binascii
import argparse  # maybe getopts ??
from tkinter import Tk, VERTICAL, BOTH, HORIZONTAL, StringVar
import ttk
import traceback

# BITSHARES MODULES
from bitshares.account import Account
from graphenecommon.exceptions import AccountDoesNotExistsException

# NANO MODULES
from wallet_forms import AssetListFrame, HistoryListFrame, QueryPublicKeysFrame
from wallet_forms import RawTransactionsFrame, AboutFrame, ActivityMessageFrame
from wallet_forms import TransferOpFrame, WhoAmIFrame
from wallet_actions import pub_keys_from_nano, init_chain_object, get_sig_from_nano
from wallet_actions import is_valid_account_name, generate_transfer_json
from wallet_actions import serialized_tx_bytes

# THIRD PARTY MODULES
from logger import Logger


def defaults():
    """
    Args and defaults:
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", help="BitShares API node to be use.")
    parser.add_argument(
        "--sender", help="BitShares account name from which to send tips."
    )
    parser.add_argument("--path", help="BIP 32 path to use for signing.")
    args = parser.parse_args()
    if args.node is None:
        args.node = "wss://bitshares.openledger.info/ws"
    if args.path is None:
        args.path = "48'/1'/1'/0'/0'"
    if args.sender is None:
        args.sender = ""
    bip32_path = args.path
    default_sender = args.sender
    return args, bip32_path, default_sender


def log_print_startup_message():
    """
    **** COMMODORE 64 BASIC V2  64K RAM SYSTEM  38911 BASIC BYTES FREE ****
    """
    # Logger.Write(log_print_startup_message.__doc__, echo=False)
    # Logger.Clear()
    Logger.Write("READY.", echo=False)


def serialize_tx_json():
    """
    var_tx_json ->(turn crank)-> var_tx_serial:
    """
    try:
        sign_data = serialized_tx_bytes(var_tx_json.get())
        var_tx_serial.set(binascii.hexlify(sign_data).decode())
    except json.decoder.JSONDecodeError as error:
        var_tx_serial.set("<<TX COULD NOT BE SERIALIZED>>")
        Logger.Write("JSON Decode Error: " + str(error))
        raise
    except Exception:
        var_tx_serial.set("<<TX COULD NOT BE SERIALIZED>>")
        raise
    finally:
        pass


def sign_tx_hex_bytes():
    """
    var_tx_serial ->(turn crank)-> var_tx_signature:
    """
    try:
        tx_hex = "".join(var_tx_serial.get().split())
        sign_data = binascii.unhexlify(tx_hex)
        sig_bytes = get_sig_from_nano(sign_data, var_bip32_path.get())
        var_tx_signature.set(binascii.hexlify(sig_bytes).decode())
    except Exception:
        var_tx_signature.set("<<COULD NOT GET SIGNATURE>>")
        raise


def broadcast_signed_tx():
    """
    Combine var_tx_json & var_tx_signature, broadcast
    """
    sig_hex = var_tx_signature.get().strip()
    sig_bytes = binascii.unhexlify(sig_hex)
    broadcast_signed_tx(var_tx_json.get(), sig_bytes)
    gui.after(3200, account_info_refresh)  # Wait-a-block, then refresh


def send_transfer(from_name, to_name, amount, symbol):
    """
    Send an amount of an asset from one account to annother
    """
    try:
        var_tx_json.set("")
        var_tx_serial.set("")
        var_tx_signature.set("")
        Logger.Write(
            'Preparing to send %f %s from "%s" to "%s"...'
            % (amount, symbol, from_name, to_name)
        )
        tx_json = generate_transfer_json(from_name, to_name, amount, symbol)
        var_tx_json.set(tx_json)
        serialize_tx_json()
        sign_tx_hex_bytes()
        broadcast_signed_tx()
    except Exception:
        pass


def account_info_refresh():
    """
    set the GUI fields with list of balances, list of history, and a.b.c account id
    """
    try:
        spending_account = Account(
            var_from_account_name.get(), blockchain_instance=blockchain
        )
        balances = spending_account.balances
        history = spending_account.history(limit=40)
        account_id = spending_account.identifier
    except AccountDoesNotExistsException:
        Logger.Write("ERROR: Specified account does not exist on BitShares network.")
        balances = []
        history = []
        account_id = ""
    frame_assets.set_balances(balances)
    frame_history.set_history(history, account_id)


def transfer_preprocess(to_account, amount, asset_symbol):
    """
    Transfer tab
    """
    send_transfer(var_from_account_name.get(), to_account, amount, asset_symbol)


if __name__ == "__main__":
    """
    Create a GUI window, then three top-to-bottom subregions as frames:
    +---------------------+
    |     frame_top       |
    +---------+-----------+
    | frame_  | frame_    |
    |    left |  center   |
    +---------+-----------+
    |    frame_bottom     |
    +---------------------+
    """
    args, bip32_path, default_sender = defaults()
    gui = Tk()
    gui.title("Super-Simple BitShares Wallet for Ledger Nano")
    gui.geometry("800x600")
    gui.minsize(640, 480)
    gui_style = ttk.Style()
    gui_style.theme_use("clam")
    gui_style.map(
        "TEntry",
        fieldbackground=[
            ("readonly", gui_style.lookup("TFrame", "background")),
            ("disabled", gui_style.lookup("TFrame", "background")),
        ],
    )
    gui_style.map(
        "TEntry",
        foreground=[
            ("readonly", gui_style.lookup("TFrame", "foreground")),
            ("disabled", gui_style.lookup("TFrame", "foreground")),
        ],
    )
    frame_top = ttk.Frame(gui)
    frame_top.pack(fill="both")
    paned_middle_bottom = ttk.PanedWindow(gui, orient=VERTICAL)
    paned_middle_bottom.pack(fill=BOTH, expand=1)
    paned_left_center = ttk.PanedWindow(paned_middle_bottom, orient=HORIZONTAL)
    paned_left_center.pack(expand=False, fill="both")
    paned_middle_bottom.add(paned_left_center)
    frame_left = ttk.Frame(paned_left_center)
    paned_left_center.add(frame_left)
    frame_center = ttk.Frame(paned_left_center)
    paned_left_center.add(frame_center)
    frame_bottom = ttk.Frame(paned_middle_bottom)
    paned_middle_bottom.add(frame_bottom)
    # Form Variables:
    var_from_account_name = StringVar(gui, value="")
    var_bip32_path = StringVar(gui, value=bip32_path)
    var_bip32_key = StringVar(gui, value="")
    var_selected_asset = StringVar(gui, value="BTS")
    var_tx_json = StringVar(gui)
    var_tx_serial = StringVar(gui)  # Hex representation of serial bytes
    var_tx_signature = StringVar(gui)  # Hex representation of signature
    # Who am I Frame:
    frame_who = WhoAmIFrame(
        frame_top,
        textvariable=var_from_account_name,
        textvar_bip32_path=var_bip32_path,
        textvar_bip32_key=var_bip32_key,
        command=account_info_refresh,
    )
    frame_who.pack(padx=10, pady=(16, 16), fill="both")
    # Asset List and History frames in tabbed_account_info Notebook:
    tabbed_account_info = ttk.Notebook(frame_left)
    frame_assets = AssetListFrame(
        tabbed_account_info, assettextvariable=var_selected_asset
    )
    frame_assets.pack(side="left", expand=False, fill="y")
    frame_history = HistoryListFrame(tabbed_account_info, jsonvar=var_tx_json)
    frame_history.pack()
    tabbed_account_info.add(frame_assets, text="Assets")
    tabbed_account_info.add(frame_history, text="History")
    tabbed_account_info.pack(padx=(8, 1), expand=True, fill="both")
    # Active Operation Tabbed Notebook container:
    tabbed_active = ttk.Notebook(frame_center)
    # Tab 1) Transfer
    form_transfer = TransferOpFrame(
        tabbed_active,
        command=transfer_preprocess,
        assettextvariable=var_selected_asset,
        sendernamevariable=var_from_account_name,
    )
    form_transfer.pack(expand=True, fill="both")
    # Tab 2) Public Keys
    form_pubkeys = QueryPublicKeysFrame(
        tabbed_active,
        textvar_bip32_path=var_bip32_path,
        textvar_bip32_key=var_bip32_key,
        lookupcommand=pub_keys_from_nano,
    )
    form_pubkeys.pack(expand=True, fill="both")
    # Tab 3) Raw Transactions
    form_raw_tx = RawTransactionsFrame(
        tabbed_active,
        serializecommand=serialize_tx_json,
        signcommand=sign_tx_hex_bytes,
        broadcastcommand=broadcast_signed_tx,
        jsonvar=var_tx_json,
        serialvar=var_tx_serial,
        signaturevar=var_tx_signature,
    )
    form_raw_tx.pack()
    # Tab 4) About
    form_about = AboutFrame(tabbed_active)
    form_about.pack()
    # Finalize tabbed container
    tabbed_active.add(form_transfer, text="Transfer")
    tabbed_active.add(form_pubkeys, text="Public Keys")
    tabbed_active.add(form_raw_tx, text="Raw Transactions")
    tabbed_active.add(form_about, text="About")
    tabbed_active.pack(padx=(1, 8), expand=True, fill="both")
    # Logging window
    form_activity = ActivityMessageFrame(frame_bottom)
    form_activity.pack(side="bottom", expand=True, fill="both", padx=8, pady=(2, 8))
    Logger.SetMessageWidget(form_activity.messages)
    # Startup:
    Logger.Write("Checking if Nano present and querrying public key...")
    tmp_keys = pub_keys_from_nano([var_bip32_path.get()], False)
    if len(tmp_keys) == 1:
        var_bip32_key.set(tmp_keys[0])
    Logger.Write("Initializing: Looking for BitShares network...")
    blockchain = init_chain_object(args.node)
    var_from_account_name.set(default_sender.strip().lower())
    if is_valid_account_name(var_from_account_name.get()):
        Logger.Write("Getting account info for '%s'..." % var_from_account_name.get())
        account_info_refresh()
    log_print_startup_message()
    # start the GUI
    gui.mainloop()
