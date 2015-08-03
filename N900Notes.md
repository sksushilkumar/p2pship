# Nokia N900 #

Recently we've made an experimental release for the Nokia N900 'mobile computer'. The installer package can be found in the downloads section. However, please note the following:

  * No transport security (all communication is unencrypted)

  * No easy GUI for installing identities or controlling the filtering

  * Requires the oSIP (2.2) library (a pre-compiled package is available in the download section)

The lack of transport security is due to the fact that we do not have a version of HIPL that would easily go on the N900. Building one is not a problem, but as the N900 lacks ipv6 support out-of-the-box (as well as a number of other things related to packetfiltering and cryptography) it would require building and flashing a new kernel to the device. We are slowly making progress on the [dtn](DTN.md) branch of p2pship which will include TLS to fix the issue.

We have not ported the existing maemo UI (based on maemo 4.x) to the maemo version the N900 uses (fremantle, 5.0). This means that the only way to configure the p2pship daemon is through the web interface (by default at http://localhost:9080) or by manually editing the config file.

On the brighter side, this enables phone calls in different sorts of networks from a real mobile phone. Doesn't even need to be connected to the larger Internet, an ad-hoc WLAN connection works just as well. Also, video calling is possible. This is actually the first time I've seen that done on the N900, finally a use for the front-facing camera! :)

# Using p2pship on N900 #

Despite the shortcomings, the p2pship suite can well be used on the N900. Here's a quick howto:

  * Install the osip-2.2 package (from the download section)

  * Install the p2pship package

  * Point the N900 web browser at http://localhost:9080

At this point you should either have an identity file ready or choose to skip authentication completely.

In case you have an identity you want to use:

  * Go to 'Identity management'

  * Upload the identity file

In case you opt for the easy solution, ignoring secure authentication:

  * Goto 'System configuration'

  * Enable 'Allow unknown registrations' and 'Allow untrusted peers'

After one of these, configure the N900 to use p2pship:

  * Go to the N900 Setting

  * Open 'VoIP and IM accounts'

  * Create a new SIP account

  * As 'Address', type your identity's SIP AOR (e.g., jookos@p2psip.hiit.fi) OR just anything you want, if you are not using secure authentication

  * Enter something short for password (this isn't verified, so anything will do, e.g., 'qwerty')

  * Open Advanced settings, enter '127.0.0.1' as Outbound proxy and '1234' as its Port

  * Save & enable the newly created account

When calling, select as 'Call type' (in the caller-app) the account as well.