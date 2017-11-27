# Return Link Encapsulation (RLE) library

## Introduction

This piece of software is an implementation of the Return Link Encapsulation
(RLE) standard defined by ETSI for Linux (or other Unix-compatible OS). The
library may be used to add RLE encapsulation/de-encapsulation capabilities to
an application.

## License

The RLE library is licensed under the GNU GPL version 3 or later. The full text
is available in the [COPYING](COPYING) file.

## Install the RLE library from sources

The sources are in the `src` subdirectory. The sources build an unique library
that handle both encapsulation and de-encapsulation.

You may build the library as follow:
```
$ mkdir -p build
$ cd build
$ cmake ..       # configure the project
$ make clean
$ make all       # build the library itself
```

You may then build and run the unit and non-regression tests as follow:
```
$ make check
```

You may finally install the library on your system:
```
$ su
# make install
```

## Use the RLE library

To compile an application using the RLE library use the following expression:
```
$ gcc `pkg-config rle --cflags` `pkg-config rle --libs` -Wall -o myappli myappli.c
```

## References

`Digital Video Broadcasting (DVB)
Satellite Earth Stations and Systems (SES);
Return Link Encapsulation (RLE) protocol
ETSI TS 103 179
V1.1.1 (2013-08)`

