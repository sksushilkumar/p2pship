#
# some identity-related wrappers
#

import p2pship

class Buddy:
    def __init__(self, arr):
        self.aor = arr.get("aor", "")
        self.name = arr.get("name", "")
        self.secret = arr.get("secret", "")
        self.friend = arr.get("friend", False)

        self._cert = arr.get("cert", "")


class Ident:

    def __init__(self, aor = ""):
        
        arr = p2pship.get_ident(aor)
        self.aor = arr.get("aor", "")
        self.name = arr.get("name", "")
        self.password = arr.get("password", "")
        self.status = arr.get("status", "")

        # we should do m2 keys of these ..
        self._cert = arr.get("cert", "")
        self._key = arr.get("key", "")

        self.buddies = {}
        for sb in arr["buddies"]:
            b = Buddy(sb)
            self.buddies[b.aor] = b

    list_all = p2pship.get_idents



