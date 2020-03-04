# ledger-app-aergolite

AergoLite signing application for Ledger Nano S

![ledger-app-aergolite](https://user-images.githubusercontent.com/7624275/75843449-f4731a00-5db1-11ea-8c13-d401041e3baa.jpg)

This application can be used by the blockchain administrator to sign its transactions:

* Authorize nodes on the network
* Remove nodes from the network
* Execute reserved SQL commands


## Requirements

To build and install the app on your Ledger Nano S you must set up the Ledger Nano S build environments.

Only Linux is supported to build the Ledger app so if you do not have one you can use a VM.

First set up the udev rules for the Ledger devices by executing this on a Linux terminal:

```
wget -q -O - https://raw.githubusercontent.com/LedgerHQ/udev-rules/master/add_udev_rules.sh | sudo bash
```

Then install the requirements in a virtual environnment by sourcing `prepare-devenv.sh`:

```
sudo apt install gcc-multilib g++-multilib python3-venv python3-dev libudev-dev libusb-1.0-0-dev
source prepare-devenv.sh
```

You can optionally follow the [Getting Started](https://ledger.readthedocs.io/en/latest/userspace/getting_started.html) instructions from Ledger.


## Installation

Connect the device to your computer and type:

```
make load
```


## Uninstall

```
make delete
```
