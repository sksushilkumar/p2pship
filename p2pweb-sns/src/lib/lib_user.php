<?php

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
		$arr = $c->select("select * from content where user_id=?i", $this->id);
		$ret = array();
		foreach ($arr as $line) {
			$ret[] = new Content($line['id'],
					     create_p2purl($this->p2pid, "/get", array("id" => $line['cid'])),
					     $line['name'],
					     $line['description'],
					     $line['type']);
		}
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
		$c->insert("insert into content (user_id, cid, name, description, type) values (?i, ?, ?, ?, ?)", $this->id, $id, $name, $description, $type);
	}
}

class Content {
	
	var $url;
	var $name;
	var $description;
	var $type;
	var $id;

	public function __construct($id, $url, $name, $description, $type) {
		$this->id = $id;
		$this->url = $url;
		$this->name = $name;
		$this->description = $description;
		$this->type = $type;
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

