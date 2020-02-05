# ledger-app-aergolite

AergoLite signing application for Ledger Nano S

![ledger-app-aergolite](https://user-images.githubusercontent.com/7624275/73798570-ec639280-4791-11ea-8a1f-7cb3ea836ec8.jpg)

This application can be used by the blockchain administrator to sign its transactions:

* Authorize nodes on the network
* Remove nodes from the network
* Execute reserved SQL commands


## Requirements

To build and install the app on your Ledger Nano S you must set up the Ledger Nano S build environments. 

Please follow the Getting Started instructions at [here](https://ledger.readthedocs.io/en/latest/userspace/getting_started.html).


##  Installation

Connect the device to your computer and type:

```
make load
```


## Uninstall

```
make delete
```
