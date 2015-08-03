# Introduction #

The p2pship uses a pretty normal automake-based build setup. That is, after unpacking the source, the build is done using the following commands:

```
$ sh ./autogen.sh
$ ./configure
$ make
```

# Prerequisites #

The build requires a healthy gnu-system with the common development tools (autoconf, automake, make, gcc, libtool, m4 etc) installed. Furthermore, even the simplest build (feature-set wise) will also require a number of additional, but common, libraries (with development headers). the `./configure` script will enlighten you on this matter, but on the top of my head I recall at least `libxml2` and `libssl` (openssl).

For some of the additional features, the following will also be needed:

**SIP support**

The SIP message parsing (and composition) is based on the osip2 library. Both versions 2.x and 3.x will do. Most distributions maintain this under the package name `libosip2`. Remember the development headers also!

_Maemo caveat:_ As osip2 isn't provided through any official repository, this often has to be installed manually. The 2.2 version has been found to compile and install nicely in the Maemo environment, and is currently recommended for it. However, you will need to make pkg-config aware of it also by copying the `libosip2.pc` file found in the root of the source package into pkg-config's awareness (`/usr/share/pkgconfig/` for instance).

**Python support**

Python requires the Python development files to compile. As we are maintaining compatibility with the Maemo environment, it currently requires Python 2.5 (often named `python2.5-dev` in the distributions).

**HIP support**

HIP is supported through the HIP for Linux (http://hipl.hiit.fi). Get the source (from launchpad), compile according to the instructions and install. The `./configure` script should be able to locate the required libraries.

# Configuring #

The `./configure` script is set to configure the system using pretty sane default values. Noteworthy is:

  * SIP support is ON by default (`--disable-sip` to disable)
  * Python support is OFF by default (`--enable-python` to enable)
  * HIP support is ON by default (`--disable-hip` to disable)
  * Maemo-friendly configurations can be set by the `--enable-maemo` (no Python support) and `--enable-maemopre` (with Python support)

Please do a `./configure --help` to find specific features.