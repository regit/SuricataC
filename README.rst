=========
SuricataC
=========

What is this
============

This program is an example code which show how to connect to suricata unix
socket. Its main capability is to ask suricata to work on pcap files.

Using it
========

Syntax is the following ::

 SuricataC [-f file] [pcap] [dir]

Two running modes here. Or you give two arguments which are a pcap file and
an output directory. Or use -f to specify a file containing a list of treatment
to do ::

 /path/to/file;/path/to/output/dir
