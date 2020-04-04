#### SimpleGUIWallet

## A Minimalistic Wallet for Hardware-secured BitShares Accounts

_SimpleGUIWallet_ is a minimalistic wallet interface for using the Ledger Nano S hardware wallet. It can sign transactions for BitShares accounts once it is configured with keys stored on a Ledger Nano device.  _SimpleGUIWallet_  is a "companion app" providing a graphical user interface (GUI) to the BitShares App running on the Ledger Nano device itself.

This is a minimalistic wallet, intended to support primarily simple transfer operations.  Additionally, it provides a "Raw Transactions" facility, for technically-inclined users, who wish to sign arbitrary transactions, with their Nano.

### Installation:

_SimpleGUIWallet_ is a Python app that can be easily run via a Python interpreter in Windows, MacOS, Raspian, or Linux.

**Note:** A OS platform specific "compiled app" may be available for users who just want a simple double-click icon.

Check _**[Releases (ledger-app-bitshares)](https://github.com/bitshares/ledger-app-bitshares/releases)**_ to see if your platform is listed.

If a precompiled app is not available, then the following instructions should get _SimpleGUIWallet_ up and running on your system.  The instructions assume a basic familiarity with the command line.

### Requirements:

* A Python 3.6+ interpreter

  * Under most Linux distributions, Python 3 is likely available by default.
  * Under MacOS, however, the Python version might be Python 2, which won't work.  Tutorials for how to install Python 3 are available on the web.  A recent one I found is here: https://wsvincent.com/install-python3-mac/
  * Installation instructions for various OS platforms, including Windows, are avaialble here: https://realpython.com/installing-python/

### Step-by-step:

First, clone the `ledger-app-bitshares` repository:

```
$ git clone https://github.com/bitshares/ledger-app-bitshares.git
```

The _SimpleGUIWallet_ companion app is in a subfolder:

```
$ cd ledger-app-bitshares/SimpleGUIWallet/
```

### Dependencies:

_SimpleGUIWallet_ depends on several packages, from the PyPI repository, as listed in `requirements.txt`.  These dependencies enable the GUI widgets, Nano communication, and interaction with the BitShares network.  These dependencies will be installed automatically on your first usage of the bash script below via "apt-get" and "pip3" installs.

### Usage:

```
./start-wallet.sh
```

### Enter Account Name:

At the top of the of the UI you must enter your BitShares Account Name.

### Account Balances and History:

The Assets and History tabs on the left side of the window list your account's balances and account's recent history respectively.  The app does not auto-update balances; to refresh them, use the "Refresh Balances" button.

### Simple Transfers:

The app provides a rudimentary interface for basic transfers.  Click the "Transfers" tab, and fill out each of:

* The "Send To" Recipient
* The Asset Amount
* The Asset Symbol

For convenience, the UI allows you to click on an asset in the "Assets" tab to auto-populate the Asset Symbol field.

Next, plug in your Nano device, log into the Nano device with your Pin Code, and start the BitShares app.

To finalize the transaction click "Send Transfer".  SimpleGUIWallet sends the transaction JSON to the Nano for you to view the details.  You will be prompted to confirm the transaction on your Nano device.   After you confirm, the Nano signs the transaction and sends the signed transaction back to SimpleGUIWallet to broadcast to the network over a public api node.

The activity panel at the bottom of the window will give feedback as to the progress and success of each step.

Note: Not all asset_names are recognized by the Nano firmware.  This is because disk space is limited and external call from the Nano device are not possible.   When SimpleGUIWallet seeks confirmation on an unrecognized asset_name, the Nano device will display the asset_id and "graphene integer amount", without the decimal place marked.  Pull requests for additional asset name translations will be considered on a case by case basis.

### Account Keys:

The purpose of _SimpleGUIWallet_ is to store your account's private keys only on the Ledger Nano;  _SimpleGUIWallet_ does NOT store or generate keys.  However, it will let you browse the public keys stored on your Nano, and select which one will be used to sign transactions.  These are identified by their "SLIP-48 path".  There is a hyperlink in the "Public Keys" tab to learn more about SLIP-48.

To browse public keys, go to the "Public Keys" tab.  Three lists appear covering the three "account roles" that define BitShares authorities.  The lists initialize by displaying only the derivation paths.  If you wish to see the actual keys, connect your Nano and click "Query Addresses".  This will retrieve each key from the device.  Selecting one from the list boxes will print the key in the PubKey box at the top of the window.  Here, you can copy-and-paste it elsewhere (e.g. when assigning those keys as authorities on the account).

Note: You do not need to retrieve keys from the Nano on a routine basis.  All you need to do is specify which path to use, and the Nano will sign with the corresponding key.  The default path is the correct one for typical usage.  You only need to retrieve keys when first setting up an account to be controlled by the Nano.

_A tutorial for how to set up a BitShares account to be controlled by your Ledger Nano can be found here:_

* **[Securing BitShares with Ledger Nano (how.bitshares.works)](https://how.bitshares.works/en/master/user_guide/ledger_nano.html)**

**Important:** before copying a key from your Nano device to access to your BitShares Account, be sure to click the "Confirm Address" button.  Doing so will allow you to view the key on your Nano's screen to ensure that the key on the device matches the key as reported by _SimpleGUIWallet_.

### Advanced Operations:

If you know how to construct the JSON represention of BitShares transactions, you can use the "Raw Transactions" tab to send any arbitrary transaction to the Nano for signing and broadcasting.  This tab isn't necessarily easy to use, but it makes almost any BitShares transaction "possible".
