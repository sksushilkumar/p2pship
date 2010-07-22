#
# misc. utils
#

import time, p2pship

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
