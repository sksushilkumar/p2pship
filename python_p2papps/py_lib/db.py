import cPickle as pickle

"""filedict.py
a Persistent Dictionary in Python
 
Author: Erez Shinan
Date  : 31-May-2009

Updated by joakim.koskela@hiit.fi to fit into the p2pship framework

"""

import UserDict
import sqlite3
 
class DefaultArg:
    pass
 
class Solutions:
    Sqlite3 = 0


#class FileDict(UserDict.DictMixin):
class PersistentDict(UserDict.DictMixin):
    "A dictionary that stores its data persistantly in a file"
 
    #def __init__(self, solution=Solutions.Sqlite3, **options):
    def __init__(self, appid, table):
        #assert solution == Solutions.Sqlite3
        solution = Solutions.Sqlite3

        self.filename = p2pship.get_data_dir() + "/" + appid + ".db"
        self.__conn = sqlite3.connect(self.filename)
        self.__tablename = table
        self._nocommit = False
 
        self.__conn.execute('create table if not exists %s (id integer primary key, hash integer, key blob, value blob);'%self.__tablename)
        self.__conn.execute('create index if not exists %s_index ON %s(hash);' % (self.__tablename, self.__tablename))
        self.__conn.commit()
        self._close()

    def use_conn(fn):
        """Decorator for opening & closing the db on every call"""
        def new(self, *args):
            self._connect()
            try:
                ret = fn(self, *args)
            except Exception, ex:
                self._close()
                raise ex
            self._close()
            return ret
        return new

    def _connect(self):
        self.__conn = sqlite3.connect(self.filename)

    def _close(self):
        try:
            self.__conn
        except AttributeError:
            pass
        else:
            self.__conn.commit()
            self.__conn.close()

    def _commit(self):
        if self._nocommit:
            return
 
        self.__conn.commit()
 
    def __pack(self, value):
        return sqlite3.Binary(pickle.dumps(value, -1))
    def __unpack(self, value):
        return pickle.loads(str(value))

    def __get_id(self, key):
        cursor = self.__conn.execute('select key,id from %s where hash=?;'%self.__tablename, (hash(key),))
        for k,id in cursor:
            if self.__unpack(k) == key:
                return id
 
        raise KeyError(key)
 
    @use_conn
    def __getitem__(self, key):
        cursor = self.__conn.execute('select key,value from %s where hash=?;'%self.__tablename, (hash(key),))
        for k,v in cursor:
            if self.__unpack(k) == key:
                return self.__unpack(v)
 
        raise KeyError(key)
 
    def __setitem(self, key, value):
        value_pickle = self.__pack(value)
 
        try:
            id = self.__get_id(key)
            cursor = self.__conn.execute('update %s set value=? where id=?;'%self.__tablename, (value_pickle, id) )
        except KeyError:
            key_pickle = self.__pack(key)
            cursor = self.__conn.execute('insert into %s (hash, key, value) values (?, ?, ?);'
                    %self.__tablename, (hash(key), key_pickle, value_pickle) )
 
        assert cursor.rowcount == 1
 
    @use_conn
    def __setitem__(self, key, value):
        self.__setitem(key, value)
        self._commit()
 
    @use_conn
    def __delitem__(self, key):
        id = self.__get_id(key)
        cursor = self.__conn.execute('delete from %s where id=?;'%self.__tablename, (id,))
        if cursor.rowcount <= 0:
            raise KeyError(key)
 
        self._commit()
 
    @use_conn
    def update(self, d):
        for k,v in d.iteritems():
            self.__setitem(k, v)
        self._commit()
 
    @use_conn
    def __iter__(self):
        return (self.__unpack(x[0]) for x in self.__conn.execute('select key from %s;'%self.__tablename) )
    def keys(self):
        return iter(self)
    @use_conn
    def values(self):
        return (self.__unpack(x[0]) for x in self.__conn.execute('select value from %s;'%self.__tablename) )
    @use_conn
    def items(self):
        return (map(self.__unpack, x) for x in self.__conn.execute('select key,value from %s;'%self.__tablename) )
    def iterkeys(self):
        return self.keys()
    def itervalues(self):
        return self.values()
    def iteritems(self):
        return self.items()
 
    @use_conn
    def __contains__(self, key):
        try:
            self.__get_id(key)
            return True
        except KeyError:
            return False
 
    @use_conn
    def __len__(self):
        return self.__conn.execute('select count(*) from %s;' % self.__tablename).fetchone()[0]
 
    @use_conn
    def __del__(self):
        try:
            self.__conn
        except AttributeError:
            pass
        else:
            self.__conn.commit()
 
    @property
    def batch(self):
        return self._Batch(self)
 
    class _Batch:
        def __init__(self, d):
            self.__d = d
 
        def __enter__(self):
            self.__old_nocommit = self.__d._nocommit
            self.__d._nocommit = True
            return self.__d
 
        def __exit__(self, type, value, traceback):
            self.__d._nocommit = self.__old_nocommit
            self.__d._commit()
            return True







# testing..
class Emu:

    store = {}
    
    def db_get(self, appid, table, key):
        print "++ get " + appid + " / " + table + ": " + key
        return self.store.get(key, None)

    def db_set(self, appid, table, key, value):
        print "++ set " + appid + " / " + table + ": " + key
        self.store[key] = value

    def db_del(self, appid, table, key):
        print "++ del " + appid + " / " + table + ": " + key
        del self.store[key]

    def db_get_keys(self, appid, table):
        print "++ keys " + appid + " / " + table
        self.store.keys()

    def db_get_values(self, appid, table):
        print "++ values " + appid + " / " + table
        self.store.values()

class PersistentDict2(object):
    """Todo: use the p2pship for actually accessing the data!"""
 
    def __init__(self, appid, name = "default"):
        self.__appid = appid
        self.__table = name
 
    def __pack_key(self, key):
        return sqlite3.Binary(pickle.dumps(key, 1))
    def __pack_value(self, value):
        return sqlite3.Binary(pickle.dumps(value, -1))
    def __unpack_value(self, value):
        return pickle.loads(str(value))
 
    def get(self, key, default=None):
        try:
            return self.__getitem__(key)
        except KeyError:
            return default
 
    def __getitem__(self, key):
        s = p2pship.db_get(self.__appid, self.__table, pickle.dumps(key))
        if s is None:
            raise KeyError(key)
        return pickle.loads(s)
 
    def __setitem__(self, key, value):
        p2pship.db_set(self.__appid, self.__table, pickle.dumps(key), pickle.dumps(value))
 
    def __delitem__(self, key):
        s = p2pship.db_del(self.__appid, self.__table, pickle.dumps(key))
 
    def update(self, d):
        for k,v in d.iteritems():
            self.__setitem__(k, v)
 
    def pop(self, key, default=None):
        try:
            value = self[key]
        except KeyError:
            if default is None:
                raise
            else:
                value = self.get(key, default)
        else:
            del self[key]
        return value
 
    def keys(self):
        return (pickle.loads(x) for x in p2pship.db_get_keys(self.__appid, self.__table))

    def values(self):
        return (pickle.loads(x) for x in p2pship.db_get_values(self.__appid, self.__table))
    
    def items(self):
        ks = self.keys()
        ret = []
        for k in ks:
            ret.append((k, self[k]))
 
    def has_key(self, key):
        return self.get(key) is not None
 
    def __contains__(self, key):
        return self.has_key(key)
 
    def __len__(self):
        return len(self.keys())
 
    def __del__(self):
        pass
 


def test():
    p2pship = Emu()
    d = PersistentDict("uuid223423")
    d["hello"] = "justsa"

    print "this is hello: " + d["hello"]

