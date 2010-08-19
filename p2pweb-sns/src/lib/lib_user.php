<?php

require_once('db.php');

/* boject cache */
$_obj_cache = array();

/* generic db class object */
class DbObj {

	public $_table;
	
	public function __construct($table, $data = FALSE) {
		$this->_table = $table;
		if ($data)
			foreach ($data as $k => $v)
				$this->$k = $v;
	}
	
	/* removes an entry */
	public function remove() {
		$c = get_db_conn();
		$c->insert("delete from " . $this->_table . " where id=?i", $this->id);
	}

	/* saves changes */
	public function save() {
		$c = get_db_conn();
		$r = $c->select("describe " . $this->_table);
		
		$args = array();
		$sql = "";
		foreach ($r as $v) {
			$name = $v['Field'];
			$type = $v['Type'];
			if ($name == 'id')
				continue;
			if (!isset($this->$name))
				continue;
			if (strlen($sql) > 0)
				$sql .= ", ";
			$sql .= $name . " = ?";
			if (!(strpos($type, "int") === FALSE))
				$sql .= "i";
			$args[] = $this->$name;
		}
		$sql = "update " . $this->_table . " set " . $sql . " where id=?i";
		$args[] = $this->id;
		$q = $c->create_sql(array_merge(array($sql), $args));
		$c->sql_query_raw($q);
	}
	

	public function reset_cache() {
		global $_obj_cache;
		$_obj_cache = array();
	}

	public function get_cached($id) {
		global $_obj_cache;
		$key = $id . "_" . get_class($this);

		if (array_key_exists($key, $_obj_cache)) {
			return $_obj_cache[$key];
		} else {
			return null;
		}
	}

	public function cache(&$obj) {
		global $_obj_cache;
		$key = $obj->id . "_" . get_class($this);
		$_obj_cache[$key] = &$obj;
	}
	/*
	public function by_value($arr) {
		$c = get_db_conn();
		$w = "";
		foreach ($arr as $k => $v) {
			if (strlen($w) > 0)
				$w .= " and";
			$w .= 
		}
			
		return $this->by_id($c->select_value("select id from " . $this->_table . " where fb_id = ?", $id));
	}
	*/

	public function by_value($k, $v) {
		$c = get_db_conn();
		return $this->by_id($c->select_value("select id from " . $this->_table . " where $k = ?", $v));
	}

	public function by_id($id) {
		$c = get_db_conn();
		$cn = get_class($this);
		
		if (!($ret = $this->get_cached($id))) {
			$ret = new $cn($c->select_line("select * from " . $this->_table . " where id = ?i", $id));
			$this->cache($ret);
		}
		return $ret;
	}

	public function all() {
		/* don't know how to get the class name on static funcs. this needs an instance .. */
		$c = get_db_conn();
		$ret = array();
		foreach ($c->select('select id from ' . $this->_table) as $l)
			$ret[] = $this->by_id($l['id']);
		return $ret;
	}

	public function create($arr) {
		$c = get_db_conn();
		$r = $c->select("describe " . $this->_table);
		
		$args = array();
		$sql = "";
		$sql2 = "";
		foreach ($r as $v) {
			$name = $v['Field'];
			$type = $v['Type'];
			if ($name == 'id')
				continue;
			if (!isset($arr[$name]))
				continue;
			if (strlen($sql) > 0) {
				$sql .= ", ";
				$sql2 .= ", ";
			}
			$sql .= $name;
			$sql2 .= "?";
			if (!(strpos($type, "int") === FALSE))
				$sql2 .= "i";
			$args[] = $arr[$name];
		}
		$sql = "insert into " . $this->_table . " (" . $sql . ") values (" . $sql2 . ")";
		$q = $c->create_sql(array_merge(array($sql), $args));
		$c->sql_query_raw($q);

		return $this->by_id($c->last_id());
	}
}


class Log
{
	public function add($fbid, $event) {
		$c = get_db_conn();
		$c->insert('insert into fb_log (log_date, log_event, log_user) values (now(), ?, ?)',
			   $event, $fbid);
	}
}


class FbUser extends DbObj
{
	public $id;
	public $fb_id;
	public $user_id;
	public $name;
	public $active;
	public $friends;
	public $session;

	// ..
	public $user;

	public function __construct($line = null) {
		parent::__construct('fb_users', $line);
		if (isset($this->user_id)) {
			$this->user = new User();
			$this->user = $this->user->by_id($this->user_id);
		}
	}
	
	public function get_friends_content($limit = 100) {
		/* .. hm.. */
		
		// this is dangerous!
		$c = get_db_conn();
		$lines = $c->select("select * from content where user_id in (select u.id from users u, fb_users f where f.fb_id in (".$this->friends.") and f.user_id = u.id) order by added desc limit " . $limit);

		$ret = array();
		if ($lines) {
			foreach ($lines as $line) 
				$ret[] = new Content($line);
		}
		

	}

	public function get_content() {
		if (isset($this->user))
			return $this->user->get_content();
		return array();

		/* testing;
		if (!isset($this->content)) {
		
		$this->content = array();
		$r = rand(-10, 20);
		$r2 = rand(0, 1);
		if ($r > 0 && $r2 = 1) {
			while ($r > 0) {
				$this->content[] = new Content(array("added" => strftime("%Y-%m-%d %H:%M:%S", time() - rand(0,3600*24*14))));
				$r--;
			}
			
		}
		}
		return $this->content;
		*/
	}

	public function by_fbid($id, $create = true) {
		$c = get_db_conn();
		$uid = $c->select_value("select id from " . $this->_table . " where fb_id = ?", $id);
		if (!$uid)
			return $this->create(array('fb_id' => $id));
		else
			return $this->by_id($uid);
	}
	
	public function by_session($session) {
		$c = get_db_conn();
		return $this->by_id($c->select_value("select id from " . $this->_table . " where session = ?", $session));
	}

	public function fb_update($token) {

		$me = file_get_contents("https://graph.facebook.com/me?access_token=" . urlencode($token));
		
		$arr = json_decode($me);
		$this->name = $arr->name;

		$friends = file_get_contents("https://graph.facebook.com/me/friends?access_token=" . urlencode($token));
		$arr = json_decode($friends);
		
		$this->friends = "";
		foreach ($arr->data as $friend) {
			$f = $this->by_fbid($friend->id);
			$f->name = $friend->name;
			$f->save();
			$this->friends .= $friend->id . ",";
		}
	}

	public function set_p2pid($id) {
		$u = new User();
		$u = $u->by_p2pid($id);
		if ($u) {
			$this->user_id = $u->id;
			$this->user = $u;
			$this->save();
		}
	}

	public function get_friends($content_sharing_only = false) {
		$ret = array();
		foreach (explode(",", $this->friends) as $fid) {
			$f = $this->by_fbid($fid);
			if ($content_sharing_only) {
				$c = $f->get_content();
				if (count($c) == 0)
					break;
			}
			$ret[] = $f;
		}
		$ret[] = $this;
		return $ret;
	}
}


/* user class .. */
class User {

	var $id;
	var $name;
	var $p2pid;

	var $friends = null;
	var $friend_requests = null;

	public function load_friendships() {
		if ($this->friend_requests != null)
			return $this->friend_requests;
		$this->friend_requests = array();

		$c = get_db_conn();
		$arr = $c->select("select * from friendship where user1 = ?i or user2 = ?i", $this->id, $this->id);
		if ($arr != null) {
			foreach ($arr as $line) {
				$this->friend_requests[$line['user1'].":".$line['user2']] = true;
			}
		}
		return $this->friend_requests;
	}

	public function is_me($id) {
		if ($id instanceof User)
			$id = $id->id;
		return $this->id == $id;
	}

	/* whether $id is a friend */
	public function is_friend($id) {
		return $this->made_friend_request($id) && $this->got_friend_request($id);
	}

	/* whether the $id has been requested by this user as friend */
	public function made_friend_request($id) {
		if ($id instanceof User)
			$id = $id->id;
		$f = $this->load_friendships();
		if (isset($f[$this->id.":".$id]) && $f[$this->id.":".$id])
			return true;
		return false;
	}

	/* whether the $id has requested *this* user as friend */
	public function got_friend_request($id) {
		if ($id instanceof User)
			$id = $id->id;
		$f = $this->load_friendships();
		if (isset($f[$id.":".$this->id]) && $f[$id.":".$this->id])
			return true;
		return false;
	}

	public function request_friend($id, $doit, $ping = true) {
		$c = get_db_conn();
		if ($doit)
			$arr = $c->insert("insert into friendship (user1, user2) values (?i, ?i)", $this->id, $id);
		else
			$arr = $c->insert("delete from friendship where user1=?i and user2=?i", $this->id, $id);
		$this->friend_requests = null;
		$this->friends = null;
		
		$ret = User::by_id($id);

		/* bonus: send the friend req notif directly! */
		if ($doit && $ping) {
			if ($ret->made_friend_request($this->id))
				$resp = fetch_data(create_p2purl($ret->p2pid, "/info", array("msg" => $this->name . " has accepted your friend request!")));
			else {
				$resp = fetch_data(create_p2purl($ret->p2pid, "/query", array("msg" => "Friend request from " . $this->name,
											      "yes" => "Befriend",
											      "no" => "Deny")));
				if ($resp->ok && $resp->body == "Befriend") {
					$ret->request_friend($this->id, true, false);
				}
			}
		}
			
		return $ret;
	}

	public function get_friend_requests() {

	}


	public function __construct($a = null) {
		if ($a != null) {
			$this->id = $a['id'];
			$this->name = $a['name'];
			$this->p2pid = $a['p2pid'];
		}
	}
	
	public function by_login($login, $passwd) {

		$c = get_db_conn();
		$arr = $c->select_line("select * from users where p2pid=? and password=md5(?)", $login, $passwd);
		if ($arr != null)
			return new User($arr);
		else
			return null;
	}

	public function by_p2pid($login) {

		$c = get_db_conn();
		$arr = $c->select_line("select * from users where p2pid=?", $login);
		if ($arr != null)
			return new User($arr);
		else
			return null;
	}

	public function by_id($id) {

		$c = get_db_conn();
		$arr = $c->select_line("select * from users where id=?i", $id);
		if ($arr != null)
			return new User($arr);
		else
			return null;
	}

	public function get_wall() {
		$ret = array();
		$c = get_db_conn();
		$arr = $c->select("select w.time as time, w.msg as msg, u.name as user from wall w, users u where w.user_id=?i and w.poster = u.id order by w.time desc", $this->id);
		if ($arr != null) {
			foreach ($arr as $line) {
				$ret[] = new WallMessage($line);
			}
		}
		return $ret;
	}

	public function get_notifs() {
		$ret = array();
		$c = get_db_conn();
		
		/* friend requests */
		$nr = $c->select_value("select count(user1) from friendship where user2=?i and user1 not in (select user2 from friendship where user1=?i);", $this->id, $this->id);
		if ($nr) {
			$ret[] = "<div class='notif' onclick=\"load_content($('#content'), 'friends', null, 'pending');\">You have $nr friend requests</div>";
		}


		return $ret;
	}

	/* static keyword search */
	public function find($key) {
		$ret = array();
		$c = get_db_conn();
		$arr = $c->select("select * from users where upper(name) like upper('%" . mysql_real_escape_string($key) . "%') or p2pid like upper('%" . mysql_real_escape_string($key) . "%')");
		if ($arr != null) {
			foreach ($arr as $line) {
				$ret[$line['id']] = new User($line);
			}
		}
		return $ret;
	}

	public function get_friends($normal = true, $pending = false, $requests = false) {
		$ret = array();
		$c = get_db_conn();
		if ($pending) {
			$arr = $c->select("select u.id as id, u.name as name, u.p2pid as p2pid from users u, friendship f where f.user2=?i and f.user1 not in (select user2 from friendship where user1=?i) and f.user1 = u.id;", $this->id, $this->id);
			if ($arr != null) {
				foreach ($arr as $line) {
					$ret[$line['id']] = new User($line);
				}
			}
		}

		if ($normal) {
			if ($this->friends == null) {
				$this->friends = array();
				$arr = $c->select("select u.id as id, u.name as name, u.p2pid as p2pid from users u, friendship f where f.user2 in (select user1 from friendship where user2=?i) and f.user1=?i and f.user2 = u.id;", $this->id, $this->id);
				if ($arr != null) {
					foreach ($arr as $line) {
						$this->friends[$line['id']] = new User($line);
					}
				}
			}
			
			foreach ($this->friends as $id => $v)
				$ret[$id] = $v;
		}

		if ($requests) {
			$arr = $c->select("select u.id as id, u.name as name, u.p2pid as p2pid from users u, friendship f where f.user1=?i and f.user2 not in (select user1 from friendship where user2=?i) and f.user2 = u.id;", $this->id, $this->id);
			if ($arr != null) {
				foreach ($arr as $line) {
					$ret[$line['id']] = new User($line);
				}
			}
		}
		return $ret;
	}
	
	public function image_url() {
		// todo
		return "images/profile.png";
	}

	public function get_friend($id) {
		if ($id == $this->id)
			return $this;
		else {
			$arr = $this->get_friends();
			return $arr[$id];
		}
	 }

	public function add_to_wall($id, $msg) {
		if ($id == $this->id || $this->get_friend($id) != null) {
			$c = get_db_conn();
			$c->insert("insert into wall (user_id, poster, time, msg) values (?i, ?i, now(), ?)", $id, $this->id, $msg);
			return true;
		}
		return false;
	}

	public function create_user($p2pid,
				    $name,
				    $password) {
		$c = get_db_conn();
		$c->insert("insert into users (p2pid, name, password) values (?, ?, md5(?))", $p2pid, $name, $password);
		return User::by_login($p2pid, $password);
	}


	/*
	 * content handling
	 *
	 */
	public function remove_content($id) {
		$c = get_db_conn();
		$c->insert("delete from content where user_id=?i and id=?i", $this->id, $id);
	}


	public function get_content() {
		$c = get_db_conn();
		$arr = $c->select("select * from content where user_id=?i order by added desc", $this->id);
		$ret = array();
		foreach ($arr as $line)
			$ret[] = new Content($line);
		return $ret;
		/*
		return array(new Content("Golden gate", 
					 "From my trip down to wine country.",
					 "images/img1.jpg"),

			     new Content("SF from the ferry", 
					 "Taken from the Alcatraz ferry. San Francisco in the fog",
					 "images/img2.jpg"),
			     new Content("Alcatraz", 
					 "Finally we arrived at Alcatraz. The weather made it so much more spooky.",
					 "images/img3.jpg"),
			     new Content("Rock bottom brewery", 
					 "I hit Rock bottom in Portland :)",
					 "images/img4.jpg"),
			     new Content("Me goofing around",
					 "I wonder why I took this picture",
					 "...."),
			     new Content("Oh no",
					 "You'll never guess who that is!",
					 "...."),
			     new Content("Jumping bird",
					 "I ran into a bunch of these. I wonder what they are..?",
					 "images/img5.jpg"),
			     new Content("Old volcano",
					 "I really did walk around this whole think. Took forever. And a lot of sunscreen.",
					 "images/img6.jpg"),
			     new Content("Blackhat",
					 "Las Vegas is the perfect place for this. So unbelievable itself.",
					 "images/img7.jpg")
			     );
		*/
	}

	/* add content */
	public function add_content($id, $name, $description, $type) {
		$c = get_db_conn();
		$c->insert("insert into content (user_id, cid, name, description, type, added) values (?i, ?, ?, ?, ?, now())", $this->id, $id, $name, $description, $type);
	}
}

class Content extends DbObj {
	
	var $url;
	var $name;
	var $description;
	var $type;
	var $id;
	var $added;
	var $user_id;
	
	public function __construct($line = null) {
		parent::__construct('content', $line);
		if ($line && isset($this->user_id)) {
			$this->user = User::by_id($this->user_id);
			$this->url = create_p2purl($this->user->p2pid, "/get", array("id" => $line['cid']));
		}
	}
}

class WallMessage {
	
	var $user;
	var $time;
	var $message;
	var $replies;

	public function __construct($a = null) {
		// todo
		if ($a != null) {
			$this->user = $a['user'];
			$this->time = $a['time'];
			$this->message = $a['msg'];
			$this->replies = array();
		}
	}
}

