

# Overview #

The system uses a key-value- based configuration. This is stored, by default, in the file `~/.p2pship/settings.conf` of the user running p2pship. Furthermore, the proxy supports a number of command-line options (including changing the default configuration file), and has a web-based configuration interface.

The format of the configuration file is simple; a normal ascii-encoded text file with key=value pairs, one per line. Empty lines and lines starting in `#` are ignored.

Values not set in the configuration file (or through command line switches) are set to a default value.

# Command line options #

Please use the `-h` switch to get a full listing of these. As the number of configurable items has grown, it hasn't seemed useful to implement those as command-line options as most are quite seldomly used anyway.

A couple of useful ones:

`--import [filename]`

Imports the identities and CA certs found in an XML formatted identity file.

`--list`

Lists the installed identities.

`--list-ca`

Lists the CAs installed.

`--list-hits`

Lists the HITs of the HIP stack.

`--shell`

Starts the proxy with a Python (PRE) shell on the console. Useful for testing minor things in the PRE.

`--run [filename]`

Starts the proxy and executes the PRE script found in the given file. Useful when developing new PRE extensions.

`-q`, `-v`. `-vv`

Changes the logging verbosity. `-q` for no logging, `-v` and `-vv` for more/most logging information.

# List of built-in settings #

**Note: These may change at times**

**Key** is the key for the settings used in the settings file.

**Name** is the name of the settings as shown in the web configuration interface.

**Type** is the type of the value:

  * `int` integer
  * `boolean` a string specifying a boolean value - either `true, yes, 1` or `false, no, 0`
  * `iface` a network interface, e.g., `eth0`. The value `all` can be used for indicating all interfaces and `ext` for all external (omitting loopback and internal)
  * `addr` a network transport address, e.g., `localhost:9080`
  * `enum:<comma-separated values>` only one of the given values is possible. E.g., `enum:apple,banana,cantalope` can be set to either `apple`, `banana` or `cantalope`.
  * `string` a string (free text value)
  * `file` a file on the local filesystem
  * `dir` a directory on the local filesystem

**Command line** specifies the command-line option for modifying the setting (if available)

| **Key** | **Name** | **Type** | **Description** | **Command line** |
|:--------|:---------|:---------|:----------------|:-----------------|

## System ##

| `ship_daemon` | Daemon mode | `bool` | Whether the proxy should start in background | `-D` |
|:--------------|:------------|:-------|:---------------------------------------------|:-----|
| `ship_worker_threads` | Number of worker threads | `int`  | The number of worker thread used by the system | `--threads` |
| `ship_port`   | The initial SHIP protocol port to try | `int`  | The initial SHIP protocol port to try        | `N/A` |
| `ship_port_range` | The range (forward) or ship ports to try if first fails | `int`  | The range (forward) or ship ports to try if first fails | `N/A` |
| `ship_ifaces` | Public SHIP interface to advertise | `iface` | Public SHIP interface to advertise           | `N/A` |
| `webconf`     | The webconf interface address | `addr` | The webconf interface address                | `N/A` |
| `remote_debug` | The remote debug monitor | `addr` | The remote debug monitor                     | `N/A` |
| `conf_file`   | _not available_ | `file` | The configuration file location              | `N/A` |
| `log_file`    | _not available_ | `file` | Log file location                            | `N/A` |
| `web_dir`     | _not available_ | `dir`  | Web configuration interface root folder      | `N/A` |

## Identity ##

| `ident_allow_unknown_registrations` | Allow unknown registrations | `bool` | Allow unknown registrations | `N/A` |
|:------------------------------------|:----------------------------|:-------|:----------------------------|:------|
| `ident_allow_untrusted`             | Allow untrusted peers       | `bool` | Allow untrusted peers       | `N/A` |
| `ident_require_authentication`      | Require SIP UA authentication | `bool` | Require SIP UA authentication | `N/A` |
| `ident_ignore_cert_validity`        | Ignore the validity of peer certificates | `bool` | Ignore the validity of peer certificates | `N/A` |
| `ident_renegotiate_secret`          | Re-negotiate shared secret on each contact | `bool` | Re-negotiate shared secret on each contact | `N/A` |
| `ident_ua_mode`                     | UA mode                     | `enum:open,relax,paranoid` | UA mode                     | `N/A` |
| `idents_file`                       | _not available_             | `file` | The identity file location  | `N/A` |
| `autoreg_file`                      | _not available_             | `file` | Autoregistration cache file location | `N/A` |

## Lookup ##

| `ol_secret` | Overlay key secret | `string` | Overlay key secret | `N/A` |
|:------------|:-------------------|:---------|:-------------------|:------|

### Broadcast ###

| `bc_addr` | Broadcast address | `addr` | Broadcast address | `N/A` |
|:----------|:------------------|:-------|:------------------|:------|
| `bc_ifaces` | Broadcast interfaces | `iface` | Broadcast interfaces | `N/A` |

### OpenDHT ###

| `opendht_proxy` | OpenDHT proxy to use | `addr` | OpenDHT proxy to use | `N/A` |
|:----------------|:---------------------|:-------|:---------------------|:------|

### P2PEXT ###

| `p2pext_proxy` | P2PSHIP EXT proxy to use | `addr` | P2PSHIP EXT proxy to use | `N/A` |
|:---------------|:-------------------------|:-------|:-------------------------|:------|

## Connectivity ##

| `conn_keepalive` | Keepalive interval in seconds | `int` | Keepalive interval in seconds | `N/A` |
|:-----------------|:------------------------------|:------|:------------------------------|:------|

### HIP ###

| `hip_provide_rvs` | Provide RVS for others | `bool` | Provide RVS for others | `N/A` |
|:------------------|:-----------------------|:-------|:-----------------------|:------|
| `hip_nat_traversal` | NAT traversal          | `enum:none,plain,ice` | NAT traversal          | `N/A` |
| `hip_rvs`         | RVS to use             | `addr` | RVS to use             | `N/A` |
| `hip_shutdown`    | hipd shutdown command  | `string` | hipd shutdown command  | `N/A` |
| `hip_allow_nonhip` | Allow non-hip control & data connections | `bool` | Allow non-hip control & data connections | `N/A` |

## SIP ##

| `sip_proxy_ifaces` | SIP proxy interface | `iface` | SIP proxy interface | `N/A` |
|:-------------------|:--------------------|:--------|:--------------------|:------|
| `sip_proxy_port`   | SIP proxy port      | `int`   | SIP proxy port      | `N/A` |
| `sip_media_proxy`  | Enable media proxy  | `bool`  | Enable media proxy  | `N/A` |
| `sip_media_proxy_mobility` | Enable media proxy mobility hack | `bool`  | Enable media proxy mobility hack | `N/A` |
| `sip_force_proxy`  | Force use of media proxy | `bool`  | Force use of media proxy | `N/A` |
| `sip_tunnel_proxy` | Tunnel media proxy traffic | `bool`  | Tunnel media proxy traffic | `N/A` |
| `call_log_show_path` | Show trustpath for accepted calls | `bool`  | Show trustpath for accepted calls | `N/A` |
| `call_log_show_dropped` | Show dropped calls  | `bool`  | Show dropped calls  | `N/A` |
| `pdd_reset_mode`   | Reset peer connections before each call | `bool`  | Reset peer connections before each call | `N/A` |
| `pdd_log`          | Log PDD data to separate file | `bool`  | Log PDD data to separate file | `N/A` |

### Access Control ###

| `ac_use_pathfinder` | Use the pathfinder | `bool` | Use the pathfinder | `N/A` |
|:--------------------|:-------------------|:-------|:-------------------|:------|
| `ac_pathfinder`     | The pathfinder     | `addr` | The pathfinder     | `N/A` |
| `ac_http`           | The HTTP access control module | `addr` | The HTTP access control module | `N/A` |
| `ac_maxpath`        | Max path length allowed for incoming requests | `int`  | Max path length allowed for incoming requests | `N/A` |
| `contacts_log`      | _not available_    | `file` | Contacts log file location | `N/A` |
| `whitelist_file`    | _not available_    | `file` | Whitelist file location | `N/A` |
| `blacklist_file`    | _not available_    | `file` | Blacklist file location | `N/A` |

### Gateway ###

| `sip_routing_file` | _not available_ | `file` | SIP gateway routing file location | `N/A` |
|:-------------------|:----------------|:-------|:----------------------------------|:------|

## ExtAPI ##

| `extapi` | The ext interface address | `addr` | The ext interface address | `N/A` |
|:---------|:--------------------------|:-------|:--------------------------|:------|

## P2PHTTP ##

| `httpproxy` | The HTTP client proxy address | `addr` | The HTTP client proxy address | `N/A` |
|:------------|:------------------------------|:-------|:------------------------------|:------|
| `httpproxy_reveal_original` | Reveal original HTTP url when making proxy requests | `bool` | Reveal original HTTP url when making proxy requests | `N/A` |

## Webcache ##

| `webcache_filelimit` | Webcache file size limit | `int` | Webcache file size limit | `N/A` |
|:---------------------|:-------------------------|:------|:-------------------------|:------|
| `webcache_limit`     | Webcache disk usage limit | `int` | Webcache disk usage limit | `N/A` |
| `webcache_strictness` | Webcache strictness      | `enum:all,relaxed,strict` | Webcache strictness      | `N/A` |
| `webcache_use_p2p_lookup` | Use P2P webcache lookups | `bool` | Use P2P webcache lookups | `N/A` |
| `webcache_index`     | _not available_          | `file` | The web cache index file location | `N/A` |

## Python run-time ##

| `py_start_shell` | Start Python shell on stdin | `bool` | Start Python shell on stdin | `N/A` |
|:-----------------|:----------------------------|:-------|:----------------------------|:------|
| `py_run_script`  | Run a script at startup     | `file` | Run a script at startup     | `N/A` |
| `py_lib`         | _not available_             | `dir`  | Python library folder       | `N/A` |
| `py_scripts`     | _not available_             | `dir`  | Python start-up scripts folder | `N/A` |
| `py_instances`   | _not available_             | `dir`  | Python application instances root folder | `N/A` |
| `py_packages`    | _not available_             | `dir`  | Python application packages root folder | `N/A` |


# Dynamic settings #

It is possible to add dynamically new configuration values to the system. This is mainly used by the [Python run-time environment](PRE#API.md)