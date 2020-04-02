"""
Input, Label, and Dialog Forms of the SimpleGUIWallet
"""

# STANDARD PYTHON MODULES
import webbrowser
import binascii
import string
import json
import ttk
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

# BITSHARES MODULES
from bitshares.block import Block, BlockHeader
from bitsharesbase.operations import getOperationNameForId

# NANO MODULES
from wallet_actions import is_valid_account_name

# THIRD PARTY MODULES
from logger import Logger
import version


class ScrolledTextVarBound(ScrolledText):
    """
    A scrolled Text widget, but bound to a StringVar just like Entry
    widgets can do.  By default, Text widgets don't support the
    `textvariable` config option (like Entry widgets do).  So we add
    that functionality in here, including setting up necessary tracing
    and callbacks so that the two entities track each other.
    """

    def __init__(self, parent, *args, **kwargs):
        self.textvariable = kwargs.pop("textvariable", None)  # Remote tk.StringVar
        ScrolledText.__init__(self, parent, *args, **kwargs)
        # Generally, we respond when remote is updated.  Unless WE are
        # the one who updated it...
        self.watch_remote = True
        self.watch_local = True
        # Notice when remote variable changes:
        self.textvariable.trace("w", self.remote_change_callback)
        # Notice when local content changes:
        self.bind("<<Modified>>", self.on_text_modified)

    def on_text_modified(self, *args):
        """
        We "notice" text changes by catching <<Modified>> event, which is a slight
        abuse, as this is meant as event when modified from a saved state, not *each*
        and every modification.  Thus we have to set our modified flag back to False
        every time we catch.  And something is causeing this event to "bounce" - it
        gets called twice every time we actually modify, which also double-calls
        local_change_callback... for the moment this seems harmless though.
        """
        self.edit_modified(False)
        self.local_change_callback()

    def local_change_callback(self, *args):
        """#"""
        if self.watch_local:
            old_watch = self.watch_remote
            self.watch_remote = False
            self.textvariable.set(self.get(1.0, tk.END))
            self.watch_remote = old_watch

    def remote_change_callback(self, *args):
        """#"""
        if self.watch_remote:
            old_watch = self.watch_local
            self.watch_local = False
            self.delete(1.0, tk.END)
            self.insert(tk.END, self.textvariable.get())
            self.watch_local = old_watch


class ScrolledListbox(tk.Listbox):
    """
    Create a Reusable list box with scrolling ability along two axis
    """

    def __init__(self, parent, *args, **kwargs):
        frameargs = {
            "borderwidth": kwargs.pop("borderwidth", 2),
            "relief": kwargs.pop("relief", "ridge"),
        }
        self.frame = ttk.Frame(parent, **frameargs)
        tk.Listbox.__init__(self, self.frame, *args, relief="sunken", **kwargs)
        self.v_scroll = tk.Scrollbar(self.frame, orient="vertical")
        self.v_scroll.pack(side="right", expand=False, fill="y")
        self.config(yscrollcommand=self.v_scroll.set)
        self.v_scroll.config(command=self.yview)
        self.h_scroll = tk.Scrollbar(self.frame, orient="horizontal")
        self.h_scroll.pack(side="bottom", expand=False, fill="x")
        self.config(xscrollcommand=self.h_scroll.set)
        self.h_scroll.config(command=self.xview)

    def pack(self, *args, **kwargs):
        """#"""
        self.frame.pack(*args, **kwargs)
        super(ScrolledListbox, self).pack(expand=True, fill="both")


class WhoAmIFrame(ttk.Frame):
    """
    Header: Enter Account Name and Slip Path.  Refresh Balances and Copy Public Key.
    """

    def __init__(self, parent, *args, **kwargs):
        self.parent = parent
        self.button_command = kwargs.pop("command", lambda *args, **kwargs: None)
        self.textvariable = kwargs.pop("textvariable", None)
        self.textvariable_path = kwargs.pop("textvar_bip32_path", None)
        self.textvariable_key = kwargs.pop("textvar_bip32_key", None)
        ttk.Frame.__init__(self, parent, *args, **kwargs)
        frame_row_1 = ttk.Frame(self, *args)
        frame_row_1.pack(fill="x")
        frame_row_2 = ttk.Frame(self, *args)
        frame_row_2.pack(fill="x")
        ttk.Label(
            frame_row_1, text="BitShares User Account:", font=("Helvetica", 16)
        ).pack(side="left")
        box_from_account_name = ttk.Entry(
            frame_row_1, width=30, textvariable=self.textvariable
        )
        box_from_account_name.pack(side="left", padx=10)
        box_from_account_name.bind("<FocusOut>", self.sender_focus_out)
        box_from_account_name.bind("<Return>", self.sender_focus_out)
        self.textvariable.trace("w", self.sender_field_on_change)
        self.button = ttk.Button(
            frame_row_1, text="Refresh balances", command=self.button_handler
        )
        self.button.pack(side="left", padx=5, pady=(0, 2))
        self.btn_copypub = ttk.Button(
            frame_row_1, text="Copy PubKey", command=self.btn_copy_handler
        )
        self.btn_copypub.pack(side="left", padx=5, pady=(0, 2))
        ttk.Label(frame_row_2, text="SLIP48 Path:", font=("Helvetica", 16)).pack(
            side="left"
        )
        box_bip32_path = ttk.Entry(
            frame_row_2, width=16, textvariable=self.textvariable_path
        )
        box_bip32_path.pack(side="left", padx=10)
        self.textvariable_path.trace("w", self.path_on_change)
        ttk.Label(frame_row_2, text="PubKey: ").pack(side="left")
        box_bip32_key = ttk.Entry(
            frame_row_2, width=48, textvariable=self.textvariable_key, state="readonly"
        )
        box_bip32_key.pack(side="left")
        self.textvariable_key.trace("w", self.pubkey_on_change)

    def sender_field_on_change(self, *args):
        """#"""
        if self.sender_is_validatable():
            self.button.configure(state="normal")
        else:
            self.button.configure(state="disabled")

    def sender_is_validatable(self, *args):
        """#"""
        sender_str = self.textvariable.get().strip().lower()
        return is_valid_account_name(sender_str)

    def sender_focus_out(self, *args):
        """#"""
        sender_str = self.textvariable.get().strip().lower()
        self.textvariable.set(sender_str)
        if str(self.button["state"]) != "disabled":
            self.button_handler()

    def path_on_change(self, *args):
        """#"""
        self.textvariable_key.set("")

    def pubkey_on_change(self, *args):
        """#"""
        if len(self.textvariable_key.get()) > 0:
            self.btn_copypub.configure(state="normal")
        else:
            self.btn_copypub.configure(state="disabled")

    def btn_copy_handler(self, *args):
        """#"""
        address = self.textvariable_key.get()
        self.parent.clipboard_clear()
        self.parent.clipboard_append(address)
        Logger.Clear()
        Logger.Write(
            (
                "Public key %s copied to clipboard.\n"
                + "Have you confirmed this key on your hardware device? "
                + "See Public Keys tab. "
                + "Do not add to a live account if you have not confirmed on device."
            )
            % address
        )

    def button_handler(self, *args):
        """#"""
        self.button.configure(state="disabled")
        Logger.Clear()
        try:
            account_name = self.textvariable.get()
            if len(account_name) == 0:
                Logger.Write("Please provide an account name!")
                return
            Logger.Write(
                "Refreshing account balances and history for '%s'..." % account_name
            )
            self.button_command()
        finally:
            self.button.update()  # Eat any clicks that occured while disabled
            self.button.configure(state="normal")  # Return to enabled state
            Logger.Write("READY.")


class AssetListFrame(ttk.Frame):
    """
    Displays a list of User Asset Balances in a Notebook Tab
    """

    def __init__(self, parent, *args, **kwargs):
        self.asset_text_var = kwargs.pop("assettextvariable", None)
        ttk.Frame.__init__(self, parent, *args, **kwargs)
        self.balances = []
        self.lst_assets = ScrolledListbox(self, *args)
        self.lst_assets.pack(padx=2, pady=2, side="left", fill="both", expand=True)
        self.lst_assets.bind("<ButtonRelease-1>", self.on_click)
        self.refresh()

    def set_balances(self, asset_list):
        """
        asset_list is a list of bitshares.amount.Amount
        """
        self.balances = asset_list
        self.refresh()
        self.lst_assets.update()

    def refresh(self, *args):
        """#"""
        self.lst_assets.delete(0, tk.END)
        for item in self.balances:
            self.lst_assets.insert(tk.END, str(item))

    def on_click(self, *args):
        """#"""
        try:
            idx = self.lst_assets.index(self.lst_assets.curselection())
            self.asset_text_var.set(self.balances[idx].symbol)
        except Exception:
            pass


class HistoryListFrame(ttk.Frame):
    """
    Displays a list of User Account History in a Notebook Tab
    """

    def __init__(self, parent, *args, **kwargs):
        self.tx_json_tkvar = kwargs.pop("jsonvar", None)
        ttk.Frame.__init__(self, parent, *args, **kwargs)
        self.hist_items = []
        self.account_id = ""
        self.lst_assets = ScrolledListbox(self, *args)
        self.lst_assets.pack(padx=2, pady=2, side="top", fill="both", expand=True)
        button_frame = ttk.Frame(self, *args)
        button_frame.pack(expand=False, fill="x", side="top")
        button_rawtx = ttk.Button(
            button_frame, text="Tx JSON", width=10, command=self.on_click_rawtx
        )
        button_rawtx.pack(side="left", fill="x", expand=True)
        button_explore = ttk.Button(
            button_frame, text="Block Explorer", command=self.on_click_explore
        )
        button_explore.pack(side="left", fill="x", expand=True)
        self.refresh()

    def set_history(self, hist_list, account_id):
        """
        hist_list is an iterator over dict objects
        containing the operation wrapped in metadata
        Let's make it into a proper list though.
        Used to determine if history items are to/from
        """

        self.hist_items = []
        self.account_id = account_id
        for item in hist_list:
            self.hist_items.append(item)
        self.refresh()

    def pprint_hist_item(self, item, resolve_time=True):
        """#"""
        block_time = "..."
        if resolve_time:
            # print("this can be slow, waits on API call")
            block = BlockHeader(item["block_num"])
            block_time = block.time()
        if item["op"][0] == 0:
            if item["op"][1]["to"] == self.account_id != item["op"][1]["from"]:
                op_desc = "Receive"
            elif item["op"][1]["from"] == self.account_id != item["op"][1]["to"]:
                op_desc = "Send"
            else:
                op_desc = "Transfer"
        else:
            op_desc = "%s" % getOperationNameForId(item["op"][0])
        return "%s - %s (Block: %d)" % (op_desc, block_time, item["block_num"])

    def refresh(self, *args):
        """#"""
        self.lst_assets.delete(0, tk.END)
        count = 0
        for item in self.hist_items:
            resolve_time = (
                count < 3
            )  # Limit how many we get full date for (API call.. slow)
            self.lst_assets.insert(
                tk.END, self.pprint_hist_item(item, resolve_time=resolve_time)
            )
            count += 1

    def on_click_rawtx(self, *args):
        """#"""
        idx = self.lst_assets.index(self.lst_assets.curselection())
        Logger.Clear()
        Logger.Write(
            "Retrieving transaction from block %d..."
            % self.hist_items[idx]["block_num"]
        )
        try:
            block = Block(self.hist_items[idx]["block_num"])
            trx = block.get("transactions")[self.hist_items[idx]["trx_in_block"]]
            self.tx_json_tkvar.set(json.dumps(trx))
            Logger.Write("Transaction JSON is in 'Raw Transactions' tab.")
        except Exception as error:
            Logger.Write("Error occurred: %s" % str(error))
        Logger.Write("READY.")

    def on_click_explore(self, *args):
        """#"""
        try:
            idx = self.lst_assets.index(self.lst_assets.curselection())
            webbrowser.open(
                "https://bitshares-explorer.io/#/operations/%s"
                % self.hist_items[idx]["id"]
            )
        except Exception:
            pass


class TransferOpFrame(ttk.Frame):
    """
    Sender Account, Destination Account, Amount, and Asset Input
    """

    def __init__(self, parent, *args, **kwargs):
        self.send_command = kwargs.pop("command", lambda *args, **kwargs: None)
        self.asset_text_var = kwargs.pop("assettextvariable", None)
        self.sender_text_var = kwargs.pop("sendernamevariable", None)
        ttk.Frame.__init__(self, parent, *args, **kwargs)
        label_args = {"font": ("Helvetica", 16)}  # (Larger font spec for field labels.)
        ttk.Label(
            self,
            justify="left",
            # background=ttk.Style().lookup("TFrame", "background"),
            text=(
                "\n1. Check sender's account name and SLIP48 path of signing key above."
                + "\n2. Set recipient's account name, amount, and asset symbol below."
                + "\n3. Click 'Send Transfer' to sign and broadcast to the network.\n"
            ),
        ).grid(row=1, column=1, columnspan=4)
        # Sender Account: (Read-Only)
        ttk.Label(self, text="Send From: ", anchor="e", width=10, **label_args).grid(
            row=2, column=1
        )
        self.box_sender_name = ttk.Entry(
            self, textvariable=self.sender_text_var, justify="center", state="disabled",
        )
        self.box_sender_name.grid(row=2, column=2)
        self.sender_text_var.trace("w", self.any_field_on_change)
        # Destination Account
        ttk.Label(self, text="Send To: ", anchor="e", width=10, **label_args).grid(
            row=3, column=1
        )
        self.recipient_text_var = tk.StringVar(value="")
        self.to_account_name = ttk.Entry(
            self, textvariable=self.recipient_text_var, justify="center"
        )
        self.to_account_name.grid(row=3, column=2)
        self.to_account_name.bind("<FocusOut>", self.recipient_focus_out)
        self.recipient_text_var.trace("w", self.any_field_on_change)
        # Amount and Asset
        ttk.Label(self, text="Amount: ", anchor="e", width=10, **label_args).grid(
            row=4, column=1
        )
        self.amount_text_var = tk.StringVar(value="0")
        self.box_amount_to_send = ttk.Entry(
            self, textvariable=self.amount_text_var, justify="right"
        )
        self.box_amount_to_send.grid(row=4, column=2)
        self.box_amount_to_send.bind("<FocusOut>", self.amount_focus_out)
        self.amount_text_var.trace("w", self.any_field_on_change)
        ttk.Label(self, text=" Asset: ", anchor="e", width=8, **label_args).grid(
            row=4, column=3
        )
        self.box_asset_to_send = ttk.Entry(self, textvariable=self.asset_text_var)
        self.box_asset_to_send.grid(row=4, column=4)
        self.box_asset_to_send.bind("<FocusOut>", self.symbol_focus_out)
        self.asset_text_var.trace("w", self.any_field_on_change)
        # TODO: cache external call for LTM status and fee schedule
        ttk.Label(
            self,
            text="\nThis transaction will incur a small transaction fee in BTS,"
            + "\nas required by the network fee schedule.\n",
            font="-slant italic",
            justify="center",
        ).grid(row=6, column=1, columnspan=4)
        # The Send Button
        self.button_send = ttk.Button(
            self,
            text="Send Transfer",
            state="disabled",
            command=self.button_send_handler,
        )
        self.button_send.grid(row=7, column=1, columnspan=4)
        # Lower Spacer
        lbl_spacer_bottom = ttk.Label(self, text="")
        lbl_spacer_bottom.grid(row=8, column=1)

    def any_field_on_change(self, *args):
        """#"""
        self.enable_send_if_all_fields_valid()

    def recipient_focus_out(self, *args):
        """#"""
        recipient_str = self.recipient_text_var.get().strip().lower()
        self.recipient_text_var.set(recipient_str)

    def symbol_focus_out(self, *args):
        """#"""
        symbol = self.asset_text_var.get().strip().upper()
        self.asset_text_var.set(symbol)

    def amount_focus_out(self, *args):
        """#"""
        amount_str = self.amount_text_var.get().strip()
        self.amount_text_var.set(amount_str)

    def sender_is_validatable(self, *args):
        """#"""
        sender_str = self.sender_text_var.get().strip().lower()
        return is_valid_account_name(sender_str)

    def recipient_is_validatable(self, *args):
        """#"""
        recipient_str = self.recipient_text_var.get().strip().lower()
        return is_valid_account_name(recipient_str)

    def symbol_is_validatable(self, *args):
        """#"""
        symbol = self.asset_text_var.get().strip().upper()
        if len(symbol) == 0:
            return False
        is_ok = string.ascii_uppercase + string.digits + "."
        if not all(c in is_ok for c in symbol):
            return False
        return True

    def amount_is_validatable(self, *args):
        """#"""
        amount_str = self.amount_text_var.get().strip()
        is_ok = string.digits + "."
        if not all(c in is_ok for c in amount_str):
            return False
        try:
            return float(amount_str) > 0
        except ValueError:
            return False

    def enable_send_if_all_fields_valid(self, *args):
        """#"""
        if (
            self.symbol_is_validatable()
            and self.amount_is_validatable()
            and self.sender_is_validatable()
            and self.recipient_is_validatable()
        ):
            self.button_send.configure(state="normal")
        else:
            self.button_send.configure(state="disabled")

    def button_send_handler(self, *args):
        """#"""
        self.button_send.configure(state="disabled")
        Logger.Clear()
        try:
            account_name = self.to_account_name.get()
            asset_symbol = self.box_asset_to_send.get()
            amount_str = self.box_amount_to_send.get()
            if len(account_name) == 0:
                Logger.Write("Please provide an account name to send to!")
                return
            if len(asset_symbol) == 0:
                Logger.Write("Please specify asset to send!")
                return
            if len(amount_str) == 0:
                Logger.Write("Please specify amount to send!")
                return
            self.send_command(account_name, float(amount_str), asset_symbol)
        except ValueError as error:
            Logger.Write("ValueError: %s" % str(error))
        finally:
            self.button_send.update()  # Eat any clicks that occured while disabled
            self.button_send.configure(state="normal")  # Return to enabled state
            Logger.Write("READY.")


# TODO: pylint, this has no public methods, code golf to def instead?
class ActivityMessageFrame(ttk.Frame):
    """#"""

    def __init__(self, parent, *args, **kwargs):
        ttk.Frame.__init__(self, parent, *args, **kwargs)
        log_frame = ttk.Frame(self, relief="groove", borderwidth=2)
        log_frame.pack(expand=True, fill="both")
        self.messages = tk.Label(
            log_frame,
            text="",
            background="light gray",
            anchor="n",
            pady=8,
            font="fixed",
        )
        self.messages.pack(expand=True, fill="both")


class QueryPublicKeysFrame(ttk.Frame):
    """
    Lists of Owner, Active, and Memo Key SLIP48 paths
    """

    def __init__(self, parent, *args, **kwargs):
        self.lookup_command = kwargs.pop("lookupcommand", lambda *args, **kwargs: None)
        self.textvariable_path = kwargs.pop("textvar_bip32_path", None)
        self.textvariable_key = kwargs.pop("textvar_bip32_key", None)
        ttk.Frame.__init__(self, parent, *args, **kwargs)
        self.owner_paths = [
            "48'/1'/0'/0'/0'",
            "48'/1'/0'/0'/1'",
            "48'/1'/0'/0'/2'",
            "48'/1'/0'/0'/3'",
            "48'/1'/0'/0'/4'",
        ]
        self.active_paths = [
            "48'/1'/1'/0'/0'",
            "48'/1'/1'/0'/1'",
            "48'/1'/1'/0'/2'",
            "48'/1'/1'/0'/3'",
            "48'/1'/1'/0'/4'",
        ]
        self.memo_paths = [
            "48'/1'/3'/0'/0'",
            "48'/1'/3'/0'/1'",
            "48'/1'/3'/0'/2'",
            "48'/1'/3'/0'/3'",
            "48'/1'/3'/0'/4'",
        ]
        self.owner_keys = []
        self.active_keys = []
        self.memo_keys = []
        self.account_idx_var = tk.StringVar(self, value="0'")
        # Hyperlink to More info about SLIP48
        lbl_slip_info = ttk.Label(
            self,
            foreground="blue",
            font=("fixed", "12", "italic"),
            cursor="hand2",
            text="SLIP-0048 schema:  48' / 1' / role' / account-index' / key-index'",
        )
        lbl_slip_info.pack(padx=10, pady=(10, 6), expand=True, fill="x")
        lbl_slip_info.bind("<ButtonRelease-1>", self.on_click_slip48)
        # Account information
        frame_account_idx = ttk.Frame(self, *args)
        frame_account_idx.pack(padx=10, expand=True, fill="x")
        label_account_idx = ttk.Label(frame_account_idx, text="account-index: ")
        label_account_idx.pack(side="left")
        self.box_account_idx = ttk.Entry(
            frame_account_idx,
            textvariable=self.account_idx_var,
            width=8,
            state="disabled",
        )
        self.box_account_idx.pack(side="left")
        lbl_roles_keys = ttk.Label(
            self, text="Roles and Keys: The following keys are available on your Nano."
        )
        lbl_roles_keys.pack(padx=10, pady=(6, 0), expand=True, fill="x")
        lbl_roles_keys2 = ttk.Label(
            self,
            text="To sign transactions, "
            + "select a key that is authorized for your account:",
        )
        lbl_roles_keys2.pack(padx=10, pady=(0, 4), expand=True, fill="x")
        #  3 Lists of keys by role
        frame_list_group = ttk.Frame(self, *args)
        frame_list_group.pack(padx=10, pady=5, fill="x")
        frame_owner_keys = ttk.LabelFrame(
            frame_list_group, text="Owner role:", borderwidth=0
        )
        frame_owner_keys.pack(expand=True, fill="both", side="left")
        frame_active_keys = ttk.LabelFrame(
            frame_list_group, text="Active role:", borderwidth=0
        )
        frame_active_keys.pack(expand=True, fill="both", side="left", padx=8)
        frame_memo_keys = ttk.LabelFrame(
            frame_list_group, text="Memo role:", borderwidth=0
        )
        frame_memo_keys.pack(expand=True, fill="both", side="left")
        self.list_owner_keys = ScrolledListbox(frame_owner_keys, height=8, width=6)
        self.list_owner_keys.pack(expand=True, fill="both")
        self.list_owner_keys.bind("<ButtonRelease-1>", self.on_click_owners)
        self.list_active_keys = ScrolledListbox(frame_active_keys, height=8, width=6)
        self.list_active_keys.pack(expand=True, fill="both")
        self.list_active_keys.bind("<ButtonRelease-1>", self.on_click_actives)
        self.list_memo_keys = ScrolledListbox(frame_memo_keys, height=8, width=6)
        self.list_memo_keys.pack(expand=True, fill="both")
        self.list_memo_keys.bind("<ButtonRelease-1>", self.on_click_memos)
        # Buttons
        frame_buttons = ttk.Frame(self, *args)
        frame_buttons.pack(pady=(4, 8), side="right")
        self.button_get_addrs = ttk.Button(
            frame_buttons, text="Query Addresses", command=self.on_click_get_addrs,
        )
        self.button_get_addrs.pack(side="left")
        self.button_confirm_addr = ttk.Button(
            frame_buttons, text="Confirm Address", command=self.on_click_confirm_addr,
        )
        self.button_confirm_addr.pack(padx=(12, 28), side="left")
        self.refresh()

    def refresh(self, *args):
        """#"""
        refresh_keylistbox(self.list_owner_keys, self.owner_paths, self.owner_keys)
        refresh_keylistbox(self.list_active_keys, self.active_paths, self.active_keys)
        refresh_keylistbox(self.list_memo_keys, self.memo_paths, self.memo_keys)

    def clear_keys(self, *args):
        """#"""
        self.owner_keys = []
        self.active_keys = []
        self.memo_keys = []
        self.refresh()

    def on_click_get_addrs(self, *args):
        """#"""
        self.button_get_addrs.configure(state="disabled")
        Logger.Clear()
        try:
            self.lookup_handler()
        finally:
            self.button_get_addrs.update()  # Eat any clicks that occured while disabled
            self.button_get_addrs.configure(state="normal")  # Return to enabled
            Logger.Write("READY.")

    def on_click_confirm_addr(self, *args):
        """#"""
        self.button_confirm_addr.configure(state="disabled")
        Logger.Clear()
        try:
            self.address_confirm_handler()
        finally:
            self.button_confirm_addr.update()  # Eat clicks that occured while disabled
            self.button_confirm_addr.configure(state="normal")  # Return to enabled
            Logger.Write("READY.")

    def lookup_handler(self, *args):
        """#"""
        self.clear_keys()
        # Owner Keys:
        Logger.Write("Querying Owner key paths from Nano...")
        self.owner_keys = self.lookup_command(self.owner_paths, False)
        self.refresh_keylistbox(self.list_owner_keys, self.owner_paths, self.owner_keys)
        self.list_owner_keys.update()
        if len(self.owner_keys) < len(self.owner_paths):
            return
        # Active Keys:
        Logger.Write("Querying Active key paths from Nano...")
        self.active_keys = self.lookup_command(self.active_paths, False)
        self.refresh_keylistbox(
            self.list_active_keys, self.active_paths, self.active_keys
        )
        self.list_active_keys.update()
        if len(self.active_keys) < len(self.active_paths):
            return
        # Memo Keys:
        Logger.Write("Querying Memo key paths from Nano...")
        self.memo_keys = self.lookup_command(self.memo_paths, False)
        self.refresh_keylistbox(self.list_memo_keys, self.memo_paths, self.memo_keys)
        self.list_memo_keys.update()

    def address_confirm_handler(self, *args):
        """#"""
        path = self.textvariable_path.get()
        Logger.Write("Confirming public key for path %s..." % path)
        try:
            address = self.lookup_command([path], False)[0]
            self.textvariable_key.set(address)
            Logger.Write("I retrieve key: %s" % address)
            Logger.Write("Please confirm that this matches the key shown on device...")
            self.lookup_command([path], True)
        except Exception:
            self.textvariable_key.set("")
            Logger.Write(
                "Could not confirm public key on device. Do not trust unconfirmed keys."
            )

    def on_click_keylistbox(self, listbox, paths, keys):
        """#"""
        idx = listbox.index(listbox.curselection())
        if idx < len(paths):
            self.textvariable_path.set(paths[idx])
            if idx < len(keys):
                self.textvariable_key.set(keys[idx])
            else:
                self.textvariable_key.set("")

    def on_click_owners(self, *args):
        """#"""
        self.on_click_keylistbox(
            self.list_owner_keys, self.owner_paths, self.owner_keys
        )

    def on_click_actives(self, *args):
        """#"""
        self.on_click_keylistbox(
            self.list_active_keys, self.active_paths, self.active_keys
        )

    def on_click_memos(self, *args):
        """#"""
        self.on_click_keylistbox(self.list_memo_keys, self.memo_paths, self.memo_keys)

    def on_click_slip48(self, *args):
        """
        Use desktop default web browser to open web based how-to document
        """
        url = "https://github.com/satoshilabs/slips/blob/master/slip-0048.md"
        try:
            webbrowser.open(url)
        except Exception:
            pass


class RawTransactionsFrame(ttk.Frame):
    """
    Allow the user to manually enter a Raw Transaction in JSON format
    """

    def __init__(self, parent, *args, **kwargs):
        self.serialize_command = kwargs.pop(
            "serializecommand", lambda *args, **kwargs: None
        )
        self.sign_command = kwargs.pop("signcommand", lambda *args, **kwargs: None)
        self.broadcast_command = kwargs.pop(
            "broadcastcommand", lambda *args, **kwargs: None
        )
        self.tx_json_tkvar = kwargs.pop("jsonvar", None)
        self.tx_serial_tkvar = kwargs.pop("serialvar", None)
        self.tx_signature_tkvar = kwargs.pop("signaturevar", None)
        ttk.Frame.__init__(self, parent, *args, **kwargs)
        # JSON Tx Panel
        frame_tx_json = ttk.LabelFrame(self, text="1. Paste transaction JSON here:")
        frame_tx_json.pack(padx=6, pady=(8, 4), expand=True, fill="both")
        self.entry_tx_json = ScrolledTextVarBound(
            frame_tx_json, height=6, textvariable=self.tx_json_tkvar
        )
        self.entry_tx_json.pack(expand=True, fill="both")
        self.tx_json_tkvar.trace("w", self.tx_json_changed)
        # Serialized Tx Panel
        frame_tx_serial = ttk.LabelFrame(
            self, text='2. Click "Serialize" to get APDU bytes for Nano to sign:'
        )
        frame_tx_serial.pack(padx=6, pady=4, expand=True, fill="both")
        self.entry_tx_serial = ScrolledTextVarBound(
            frame_tx_serial, height=4, textvariable=self.tx_serial_tkvar
        )
        self.entry_tx_serial.pack(expand=True, fill="both")
        self.entry_tx_serial.default_fg_color = self.entry_tx_serial.cget("fg")
        self.entry_tx_serial.tag_configure("tlvtag", background="lightgray")
        self.entry_tx_serial.tag_configure("tlvlen", background="lightgray")
        self.entry_tx_serial.tag_configure("chainid", background="cyan")
        self.entry_tx_serial.tag_configure("txfield", background="yellow")
        self.entry_tx_serial.tag_configure("opid", background="lightgreen")
        self.entry_tx_serial.tag_configure("opdata", background="lightgreen")
        self.entry_tx_serial.tag_raise("sel")
        self.tx_serial_tkvar.trace("w", self.tx_serial_changed)
        # Signature Panel
        frame_tx_signature = ttk.LabelFrame(
            self,
            text='3. Click "Sign" to get signature from Nano. '
            + 'Then click "Broadcast" when ready to send:',
        )
        frame_tx_signature.pack(padx=6, pady=4, expand=True, fill="both")
        self.entry_tx_sig = ScrolledTextVarBound(
            frame_tx_signature, height=2, textvariable=self.tx_signature_tkvar
        )
        self.entry_tx_sig.pack(expand=True, fill="both")
        self.entry_tx_sig.default_fg_color = self.entry_tx_sig.cget("fg")
        self.tx_signature_tkvar.trace("w", self.tx_sig_changed)
        # Buttons:
        buttons_frame = ttk.Frame(self, *args)
        buttons_frame.pack(pady=(4, 8))
        self.var_colorize = tk.IntVar(value=1)
        self.chk_colorize = ttk.Checkbutton(
            buttons_frame,
            text="Colorize Serial",
            variable=self.var_colorize,
            command=self.colorize_check_handler,
        )
        self.chk_colorize.pack(padx=4, side="left")
        self.btn_serialize = ttk.Button(
            buttons_frame, text="1. Serialize", command=self.serialize_handler
        )
        self.btn_serialize.pack(padx=4, side="left")
        self.btn_sign = ttk.Button(
            buttons_frame, text="2. Sign", command=self.sign_handler, state="disabled",
        )
        self.btn_sign.pack(padx=4, side="left")
        self.btn_broadcast = ttk.Button(
            buttons_frame,
            text="3. Broadcast",
            command=self.broadcast_handler,
            state="disabled",
        )
        self.btn_broadcast.pack(padx=4, side="left")

    def tx_json_changed(self, *args):
        """
        Twiddle foreground colors of entry_tx_serial to indicate correspondence
        to current contents of entry_tx_json.
        """
        self.entry_tx_serial.config(fg="gray")
        self.btn_sign.configure(state="disabled")
        self.btn_broadcast.configure(state="disabled")

    def tx_serial_changed(self, *args):
        """
        same as tx_json_changed
        """
        self.entry_tx_serial.config(fg=self.entry_tx_serial.default_fg_color)
        self.entry_tx_sig.config(fg="gray")
        self.btn_sign.configure(state="normal")
        self.btn_broadcast.configure(state="disabled")

    def tx_sig_changed(self, *args):
        """
        #
        """
        self.entry_tx_sig.config(fg=self.entry_tx_sig.default_fg_color)
        possible_hex = self.tx_signature_tkvar.get().strip()
        try:
            binascii.unhexlify(possible_hex)  # raise if not valid hex
            valid_hex = True
        except Exception:
            valid_hex = False
        if valid_hex and len(possible_hex) > 0:
            self.btn_broadcast.update()  # Eat any clicks queued while disabled
            self.btn_broadcast.configure(state="normal")
        else:
            self.btn_broadcast.configure(state="disabled")

    def colorize_check_handler(self, *args):
        """#"""
        self.colorize_serial_hex(self.entry_tx_serial)

    def serialize_handler(self, *args):
        """#"""
        self.btn_serialize.configure(state="disabled")
        Logger.Clear()
        Logger.Write("Attempting to serialize JSON transaction...")
        try:
            self.serialize_command()
        except Exception:
            pass
        self.colorize_serial_hex(self.entry_tx_serial)
        self.btn_serialize.update()
        self.btn_serialize.configure(state="normal")
        Logger.Write("READY.")

    def sign_handler(self, *args):
        """#"""
        self.btn_sign.configure(state="disabled")
        self.btn_broadcast.configure(state="disabled")
        Logger.Clear()
        Logger.Write("Asking Nano to sign serialized transaction...")
        try:
            self.sign_command()
            Logger.Write(
                "Received signature from Nano.  "
                + 'Click "Broadcast" when ready to transmit.'
            )
        except Exception:
            pass
        self.btn_sign.update()  # Eat any clicks that occured while disabled.
        self.btn_sign.configure(state="normal")
        Logger.Write("READY.")

    def broadcast_handler(self, *args):
        """#"""
        self.btn_broadcast.configure(state="disabled")
        Logger.Clear()
        try:
            self.broadcast_command()
        except Exception:
            pass
        self.btn_broadcast.update()  # Eat any clicks queued while disabled
        self.btn_broadcast.configure(state="normal")
        Logger.Write("READY.")

    def colorize_serial_hex(self, entry_tx):
        """#"""
        for tag in entry_tx.tag_names():
            entry_tx.tag_remove(tag, "1.0", tk.END)
        if self.var_colorize.get() != 1:
            return
        try:
            tag_index = entry_tx.index("1.0 + 0c")
            # ChainID
            tag_index = self.apply_tag_color(entry_tx, tag_index, "chainid")
            # Ref block, num, and expiration
            tag_index = self.apply_tag_color(entry_tx, tag_index, "txfield")
            tag_index = self.apply_tag_color(entry_tx, tag_index, "txfield")
            tag_index = self.apply_tag_color(entry_tx, tag_index, "txfield")
            # Num operations
            tag_index = self.apply_tag_color(entry_tx, tag_index, "txfield")
            num_ops = int.from_bytes(
                binascii.unhexlify("".join(entry_tx.lastHexField.split())),
                byteorder="big",
                signed=False,
            )
            # Operations
            while num_ops > 0:
                num_ops -= 1
                tag_index = self.apply_tag_color(entry_tx, tag_index, "opid")
                tag_index = self.apply_tag_color(entry_tx, tag_index, "opdata")
            # Tx Extensions
            tag_index = self.apply_tag_color(entry_tx, tag_index, "txfield")
        except Exception:
            pass


def apply_tag_color(entry_tx, tag_index, tagname):
    """#"""

    def get_hex_bytes(tag_index, numbytes):
        """#"""
        charbuf = ""
        nibblecount = 0
        charcount = 0
        char = ""
        while nibblecount < (2 * numbytes):
            char = entry_tx.get(
                tag_index + "+%dc" % charcount, tag_index + "+%dc" % (1 + charcount)
            )
            if len(char) == 0:
                raise Exception("Hex stream ended before N bytes read.")
            if len(char) != 1:
                raise Exception("Hex stream unexpected char string read.")
            charcount += 1
            if char.isspace():
                charbuf += char
                continue
            if char in string.digits + "abcdefABCDEF":
                nibblecount += 1
                charbuf += char
                continue
            raise Exception("Unparsible Hex character.")
        return charbuf

    tag_index0 = tag_index
    tag_hex = get_hex_bytes(tag_index0, 1)
    tag_byte = binascii.unhexlify("".join(tag_hex.split()))
    if tag_byte != b"\x04":
        raise Exception()
    tag_index1 = entry_tx.index(tag_index0 + "+%dc" % (len(tag_hex)))
    tag_len_hex = get_hex_bytes(tag_index1, 1)  # TODO: Is a varint so could be >1 bytes
    tag_len = int.from_bytes(
        binascii.unhexlify("".join(tag_len_hex.split())), byteorder="big", signed=False,
    )
    tag_index2 = entry_tx.index(tag_index1 + "+%dc" % (len(tag_len_hex)))
    if tag_len > 0:
        field_hex = get_hex_bytes(tag_index2, tag_len)
        tag_index3 = entry_tx.index(tag_index2 + "+%dc" % (len(field_hex)))
        entry_tx.lastHexField = field_hex  # Stash this value somewhere it can be found
    else:
        tag_index3 = tag_index2
        entry_tx.lastHexField = ""
    # TODO: when applying tags avoid leading/trailing whitespace
    entry_tx.tag_add("tlvtag", tag_index0, tag_index1)
    entry_tx.tag_add("tlvlen", tag_index1, tag_index2)
    if tag_len > 0:
        entry_tx.tag_add(tagname, tag_index2, tag_index3)
    return tag_index3


class AboutFrame(ttk.Frame):
    """
    # TODO: pylint, this has too few public methods, code golf to def instead?
    """

    def __init__(self, parent, *args, **kwargs):
        ttk.Frame.__init__(self, parent, *args, **kwargs)
        # Version:
        version_label = ttk.Label(
            self,
            text="\nSimpleGUIWallet, version " + version.VERSION,
            font=("fixed", 16),
        )
        version_label.pack(pady=4)
        # Description of SimpleGUIWallet Nano app
        description = tk.Label(
            self,
            anchor="n",
            justify="center",
            background=ttk.Style().lookup("TFrame", "background"),
            text=""
            + "- A very simple wallet for BitShares - \n\n"
            + "No private or public keys are stored by this app! \n\n"
            + "Transactions are sent to your Ledger Nano S for signing, \n"
            + "and then broadcast to the BitShares network. \n\n"
            + "Specify your own account name above.\nView account assets at left. \n\n"
            + "Use the tabs in this widget "
            + "for various operations (e.g. Transfer), \n"
            + "or to browse public keys managed by your Ledger device. \n\n"
            + "Your account will need a key from the device listed \n"
            + 'in its "authorities" before you can sign transactions. \n\n',
        )
        description.pack(expand=True, fill="x")
        # Hyperlink to SimpleGUIWallet tutorial
        tutorial = ttk.Label(
            self,
            text="A tutorial is available at https://how.bitshares.works/\n\n",
            foreground="blue",
            font=("fixed", "12", "italic"),
            cursor="hand2",
        )
        tutorial.pack(pady=4)
        tutorial.bind("<ButtonRelease-1>", self.on_click_tutorial)

    def on_click_tutorial(self, *args):
        """
        Use desktop default web browser to open web based how-to document
        """
        url = "https://how.bitshares.works/en/master/user_guide/ledger_nano.html"
        try:
            webbrowser.open(url)
        except Exception as e:
            print(e)


def refresh_keylistbox(listbox, paths, keys):
    """#"""
    listbox.delete(0, tk.END)
    for idx, _ in enumerate(paths):
        itemtext = "%s (%s)" % (paths[idx], keys[idx] if idx < len(keys) else "??")
        listbox.insert(tk.END, itemtext)
    listbox.insert(tk.END, "...")
