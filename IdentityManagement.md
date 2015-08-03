# Introduction #




# Quick & dirty #

Identities are managed (contained) by default in the file `~/.p2pship/identities.xml`. This should preferably not be edited manually.

The identities installed can be listed (CLI) by providing the `--list` switch. The proxy usually provides a lot of log output making it hard to read, but these can be silenced with the `-q` switch.

The certificate authorities are listed using the `--list-ca` switch.
```
user:~p2pship-src/p2pship$ ./p2pship --list -q
user:~p2pship-src/p2pship$ ./p2pship --list-ca -q
```

New identities are imported using the `--import` action.
```
user:~p2pship-src/p2pship$ ./p2pship -q --import new-idents.xml
```

Depending on how the UI was built, this will either ask through the command line for confirmation or using GTK dialogs.