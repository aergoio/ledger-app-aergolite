# ledger-app-aergolite

AergoLite signing application for Ledger Nano S

![ledger-app-aergolite](https://user-images.githubusercontent.com/7624275/73798570-ec639280-4791-11ea-8a1f-7cb3ea836ec8.jpg)

This application can be used by the blockchain administrator to sign its transactions:

* Authorize nodes on the network
* Remove nodes from the network
* Execute reserved SQL commands


## Requirements

To build and install the app on your Ledger Nano S you must set up the Ledger Nano S build environments. 

Only Linux is supported to build the Ledger app so if you do not have one you can use a VM.

Please follow the Getting Started instructions at [here](https://ledger.readthedocs.io/en/latest/userspace/getting_started.html).

If you don't want to setup a global environnment, you can also setup one just for this app by sourcing `prepare-devenv.sh` with the right target (s or x):

```
sudo apt install python3-venv python3-dev libudev-dev libusb-1.0-0-dev
# (s or x, depending on your device)
source prepare-devenv.sh s
```


You must also set up the udev rules for the Ledger devices. Execute this on a Linux terminal:

```
wget -q -O - https://raw.githubusercontent.com/LedgerHQ/udev-rules/master/add_udev_rules.sh | sudo bash
```


## Installation

Connect the device to your computer and type:

```
make load
```


## Uninstall

```
make delete
```
