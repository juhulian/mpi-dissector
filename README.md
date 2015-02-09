# <a name="top"></a> mpi-dissector

This [Wireshark](https://www.wireshark.org/) Plugin dissect the general [Open MPI](http://www.open-mpi.org/) TCP-Traffic.

Please note: It is a proof of concept plugin with no claim to completeness! Usage at your own risk! It was only tested on a Linux machine with `Wireshark 1.99.2` and `Open MPI 1.8.4`.

## Table of Contents

* [Installation](#Installation)
* [Features/Todos](#Features)
* [Screenshots](#Screenshots)

## <a name="Installation"></a>Installation ##
[back to top ↑](#top)

To install this dissector, please read [README.plugins](https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=doc/README.plugins). The help file is also available in the Wireshark `doc` folder.

1. Download, if you have not already done, the [Wireshark sources](https://www.wireshark.org/download.html) **or** clone the git repository

   ```
   git clone https://code.wireshark.org/review/wireshark
   ```

2. Pack the following files in the `wireshark/plugins/mpi` folder
   * AUTHORS
   * COPYING
   * ChangeLog
   * CMakeLists.txt
   * Makefile.am
   * Makefile.common
   * Makefile.nmake
   * moduleinfo.h
   * moduleinfo.nmake
   * packer-mpi.c
   * packer-mpi.h
   * plugin.rc.in

3. Changes to existing Wireshark files (e.g. see section `3.2 Permanent addition` in the readme file)  <br />
   **Make all changes in alphabetical order!**<br />
   You will need to change the following files:
	  * configure.ac
	  * CMakeLists.txt
	  * epan/Makefile.am
	  * Makefile.am
	  * packaging/nsis/Makefile.nmake
	  * packaging/nsis/wireshark.nsi
	  * plugins/Makefile.am
	  * plugins/Makefile.nmake

 3.1. Changes to plugins/Makefile.am
   
   ```
   SUBDIRS = $(_CUSTOM_SUBDIRS_) \
      docsis \
      ...
      mate \
      mpi \
      opcua \
      ...
   ```
 3.2. Changes to plugins/Makefile.nmake
   
   ```
   PLUGIN_LIST = \
      docsis      \
      ...
      mate        \
      mpi         \
      opcua       \
      ...
   ```
   
 3.3. Changes to the top level Makefile.am

   ```
   if HAVE_PLUGINS
   -include plugins/Custom.make
   plugin_ldadd = $(_CUSTOM_plugin_ldadd_) \
      -dlopen plugins/docsis/docsis.la \
      ...
      -dlopen plugins/mate/mate.la \
      -dlopen plugins/mpi/mpi.la \
      -dlopen plugins/opcua/opcua.la \
      ...
   ```
   
 3.4. Changes to the top level configure.ac

   ```
   AC_CONFIG_HEADERS(config.h)
   AC_OUTPUT(
      Makefile
      ...
      plugins/mate/Makefile
      plugins/mpi/Makefile
      plugins/opcua/Makefile
      ...
   ```
   
 3.5. Changes to epan/Makefile.am

   ```
   if ENABLE_STATIC
   -include ../plugins/Custom.make
   plugin_src = \
      ../plugins/asn1/packet-asn1.c \
      ...
      ../plugins/m2m/wimax_tlv.c \
      ../plugins/mpi/packet-mpi.c \
      ../plugins/wimax/crc.c \
      ...
   ```
 3.6. Changes to CMakeLists.txt

   ```
   if(ENABLE_PLUGINS)
      ...
      set(PLUGIN_SRC_DIRS
         plugins/docsis
         ...
         plugins/mate
         plugins/mpi
         plugins/opcua
         ...
   ```
 3.7. Changes to the installers   <br />
 If you want to include your plugin in an installer you have to change following files:
	 * packaging/nsis/Makefile.nmake
	 * packaging/nsis/wireshark.nsi

  3.7.1. Changes to packaging/nsis/Makefile.nmake
   
   ```
   PLUGINS= \                           
      ../../plugins/docsis/docsis.dll \
      ...
      ../../plugins/mate/mate.dll \
      ../../plugins/mpi/mpi.dll \    
      ../../plugins/opcua/opcua.dll \
      ...
   ```

  3.7.2. Changes to packaging/nsis/wireshark.nsi

   ```
   Section "Dissector Plugins" SecPlugins             
   ;-------------------------------------------       
   SetOutPath '$INSTDIR\plugins\${VERSION}'           
   File "${STAGING_DIR}\plugins\${VERSION}\docsis.dll"
   ...
   File "${STAGING_DIR}\plugins\${VERSION}\m2m.dll"  
   File "${STAGING_DIR}\plugins\${VERSION}\mpi.dll"  
   File "${STAGING_DIR}\plugins\${VERSION}\opcua.dll"
   ...
   ```

4. (Re)Build/Install Wireshark<br />
   Run the following commands in the Wireshark root folder.<br />

   ```bash
   autogen.sh
   ./configure #optional with some options, e.g. --prefix=...
   make install
   ```
   
   This will also create the Makfile for the Plugin. For future works on the plugin, just run `make install` in the plugin dir (`plugins/mpi/`).


## <a name="Features"></a>Features/Todos ##
[back to top ↑](#top)

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
* [ ] push the todo's to the milestones

## <a name="Screenshots"></a>Screenshots ##
[back to top ↑](#top)

![oob msg data](https://raw.githubusercontent.com/juhulian/mpi-dissector/master/screenshots/wireshark-oob-msg.png "oob message data")

![btl sync req](https://raw.githubusercontent.com/juhulian/mpi-dissector/master/screenshots/wireshark-sync.png "btl synchronization request")

![btl match](https://raw.githubusercontent.com/juhulian/mpi-dissector/master/screenshots/wireshark-match.png "btl match")

![btl match full](https://raw.githubusercontent.com/juhulian/mpi-dissector/master/screenshots/wireshark-match-full.png "btl match full")
