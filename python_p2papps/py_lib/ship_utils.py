#
# misc. utils
#

import time, p2pship
import tempfile
import pwd
import os
import re

LOG_ERROR = 0
LOG_WARN = 1
LOG_INFO = 2
LOG_DEBUG = 3
LOG_VDEBUG = 4

def warn(str):
    p2pship.log(LOG_WARN, str + "\n")

def info(str):
    p2pship.log(LOG_INFO, str + "\n")

def debug(str):
    p2pship.log(LOG_DEBUG, str + "\n")

def vdebug(str):
    p2pship.log(LOG_VDEBUG, str + "\n")

def error(str):
    p2pship.log(LOG_ERROR, str + "\n")

#
# init the data dir.
P2PSHIP_DATA_DIR = p2pship.get_datadir()
def get_datadir():
    return P2PSHIP_DATA_DIR

def get_tmpfile():
    t = tempfile.mkstemp(dir=get_datadir())
    return t[1]

#
# configuration handler
class ConfigHandler:

    def value_update(self, key, value):
        debug("Value updated: %s -> %s" % (key, value))

    def create(self, key, description, type, value):
        p2pship.config_create(key, description, type, value)
        self.track(key)

    def get(self, key, default = None):
        try:
            return p2pship.config_get(key)
        except Exception, ex:
            if default is not None:
                return default
            else:
                raise ex

    def get_path(self, key, default = None):
        """Translates tildes etc"""
        data = self.get(key, default)
        if data is not None and len(data) > 0:
            m = re.match("^[~]([^ /]*)(.*)$", data)
            if m is not None:
                uid = m.group(1)
                path = m.group(2)
                if len(uid) == 0:
                    pw = pwd.getpwuid(os.getuid())
                else:
                    pw = pwd.getpwnam(uid)

                if pw is not None:
                    return pw[5] + path
            elif data[0] != '/':
                return get_datadir() + "/" + data
        return data
        
    def set(self, key, value):
        p2pship.config_set(key, value)

    def save(self):
        """Saves the config to disk"""
        p2pship.config_save()
        
    def track(self, key):
        p2pship.config_set_update(key, self.value_update)

    def is_true(self, key):
        val = self.get(key)
        if val != None and len(val) > 0:
            val = val.lower()
            if val[0] == "t" or val[0] == "y":
                return True
        return False
