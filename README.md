**I'm not the original author of the software and the license of this code is unknown yet**
**This is just my personal work to make the software run on modern Linux distros**

------------------------------------------------------

devolo dLAN Software Package for Linux

Version 6.1, 2010-07-08

Copyright (c) 2006-2010 devolo AG, Aachen (Germany)

------------------------------------------------------


This package contains software to find and configure your devolo dLAN devices 
on a Linux system.

The software has been tested on Debian GNU/Linux 4.0 (etch) with GCC 4.1.2 and 
on Debian 5.0 (lenny) with GCC 4.3.2, but every platform with recent Linux and 
GCC versions should work fine.

To build the software, change into the directory where the makefile is located 
and call 'make':

  $ make

After compilation, you should find two binaries in the same directory:

  $ ls dlan*
  dlanlist
  dlanpasswd

Install them by calling 'make install' with root privileges:

  $ sudo make install

Use dlanlist to get an overwiev over all dLAN devices in your network, to see 
information about their firmware version, and to see connection speeds for 
devices connected via PowerLine.

Use dlanpasswd to assign an encryption password to a dLAN device. You need to 
assign a common password to your devices in order to get them connected via 
PowerLine. Call dlanpasswd without arguments to get command line help.

These tools need root privileges, because they use raw sockets to send and 
receive full ethernet frames. Installing them with 'make install' takes care 
of this by setting the setuid bit, allowing non privileged users to use them.

