#
# p2pship helpers
#

import time, p2pship

class OlCallback:
    """Class that handles giving back the data to the p2pship engine"""
    
    def __init__(self, id):
        self.id = id

    def err(self):
        p2pship.ol_data_got(self.id, -1);

    def got(self, data):
        p2pship.ol_data_got(self.id, 1, data);

    def done(self, data = None):
        if data is None:
            p2pship.ol_data_got(self.id, 0);
        else:
            p2pship.ol_data_got(self.id, 0, data);


class OlHandler:

    def __init__(self, name):
        self.name = name

    def __get(self, key, id):
        callback = OlCallback(id)
        self.get(key, callback)

    def __get_signed(self, key, id):
        callback = OlCallback(id)
        self.get_signed(key, callback)

    def register(self):
        obj = self
        if self.get_signed is None:
            self.__get_signed = None
        p2pship.register_ol_handler(obj.name, obj.put, obj.__get, obj.remove, obj.close,
                                    obj.put_signed, obj.__get_signed)

    def unregister(self):
        p2pship.unregister_ol_handler(obj.name)

    #
    # to be overridden:
    #

    def put(self, key, data, timeout, secret):
        pass

    def get(self, key, callback):
        callback.err()

    def remove(self, key, secret):
        print "remove " + self.name

    def close(self):
        print "close " + self.name

    # not defined by default
    put_signed = None
    get_signed = None
