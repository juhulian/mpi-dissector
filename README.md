# mpi-dissector

This [Wireshark](https://www.wireshark.org/) Plugin dissect the general [Open MPI](http://www.open-mpi.org/) TCP-Traffic.

Please note: It is a proof of concept plugin with no claim to completeness! Usage at your own risk! It was only tested on a Linux machine with `Wireshark 1.99.2` and `Open MPI 1.8.4`.

## installation

To install this dissector, please read the [README.plugins](https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=doc/README.plugins) section `3.2 Permanent addition`. The help file is also available in the Wireshark `doc` folder.

## features

* [x] **dissect oob headers**
    * [x] basic oob header
    * [x] support more oob headers in one packet
    * [x] carry the length over packets
* [ ] **dissect oob messages**
    * [x] connection ack
    * [ ] send handler (partly)
    * [ ] orte daemon tree spawn
    * [ ] orte daemon add local procs
    * [ ] orte daemon message local procs
    * [ ] orte daemon exit cmd
    * [ ] orte plm update proc state
    * [ ] orte plm init routes cmd
    * [ ] orte grpcomm peer\_modex
    * [ ] orte grpcomm peer\_init\_barrier
    * [ ] orte grpcomm peer\_fini\_barrier
    * [x] orte rml tag iof
    * [ ] orte rml tag show help
* [ ] **dissect btl header**
    * [x] base header
    * [x] common header
    * [x] match header
    * [x] rendezvous header (not tested!)
    * [x] rget header (not tested!)
    * [x] ack header (not tested!)
    * [ ] nack header
    * [x] frag header (not tested!)
    * [ ] get header
    * [x] put/rdma header (not tested!)
    * [x] fin header (not tested!)
    * [x] rndvrestartnotify header (not tested!)
    * [ ] rndvrestartack header
    * [ ] rndvrestartnack header
    * [ ] recverrnotify header
* [ ] **dissect btl message**
    * [x] synchronization
    * [ ] barrier
* [ ] update this feature/todo list :-)

## screenshots

![oob msg data](https://raw.githubusercontent.com/juhulian/mpi-dissector/master/screenshots/wireshark-oob-msg.png "oob message data")

![btl sync req](https://raw.githubusercontent.com/juhulian/mpi-dissector/master/screenshots/wireshark-sync.png "btl synchronization request")

![btl match](https://raw.githubusercontent.com/juhulian/mpi-dissector/master/screenshots/wireshark-match.png "btl match")

![btl match full](https://raw.githubusercontent.com/juhulian/mpi-dissector/master/screenshots/wireshark-match-full.png "btl match full")
