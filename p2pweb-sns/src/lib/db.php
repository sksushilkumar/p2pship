<?php

$connection = null;

function get_db_conn()
{
  global $connection;
  if (!$connection) {
    $connection = new DbConnection();
    $connection->connect();
  }
  
  return $connection;
}

#
# The connection
#
class DbConnection
{
  var $dbconn;
  
  # init
  function connect() 
  {
    global $DB_HOST;		
    global $DB_USER;
    global $DB_PASSWD;
    global $DB_DBNAME;

    if (!$this->dbconn) {
      $this->dbconn = mysql_pconnect($DB_HOST, $DB_USER, $DB_PASSWD);
      mysql_select_db($DB_DBNAME);
    }
  }

  function test_sql($line) {
    echo $this->create_sql(func_get_args());
  }
  
  # creates the query - escapes strings
  function create_sql($args) {
    
    $subst = "?";

    $i=1;
    $line = $args[0];
    $pos = 0;
    while ($i < count($args) && ($pos = strpos($line, $subst, $pos))) {
      $sub = "";
      $sublen = 0;
      if (strlen($line) > $pos+1 && $line[$pos+1] == 'i') {
	$sublen = strlen($subst)+1;
	if (is_numeric($args[$i])) {
	  $sub = $args[$i] . "";
	} else {
	  $sub = "'" . mysql_real_escape_string($args[$i]) . "'";
	}
      } else {
	$sub = "'" . mysql_real_escape_string($args[$i]) . "'";
	$sublen = strlen($subst);
      }
      $line = substr_replace($line, $sub, $pos, $sublen);
      $pos += strlen($sub);
      $i++;
    }
    
    return $line;
  }
  
  #
  function select($line) {
    $result = $this->sql_query_raw($this->create_sql(func_get_args()));
    if ($result == NULL)
      return NULL;

    $ret = array();
    while ($line = mysql_fetch_array($result, MYSQL_BOTH))
      array_push($ret, $line);
    
    return $ret;
  }

  #
  function select_line($line) {
    $result = $this->sql_query_raw($this->create_sql(func_get_args()));
    if ($result == NULL)
      return NULL;
    
    return mysql_fetch_assoc($result);
  }
  
#
  function select_value($line) {
    $result = $this->sql_query_raw($this->create_sql(func_get_args()));
    if ($result) {
      $row = mysql_fetch_row($result);
      if ($row && count($row))
	return $row[0];
    }
    
    return NULL;
  }
  
  #
  function insert($line) {
    return $this->sql_query_raw($this->create_sql(func_get_args()));
  }

  #
  function sql_query_raw($line) {
	  //error_log("sql: " . $line);
    //error_log("sql: " . $line);
    //return mysql_query($line);	  
	  $startt = time();
	  $ret = mysql_query($line);
	  $durt = time() - $startt;
	  //error_log("sql($durt): " . $line);
	  return $ret;
  }
	
  #
  function last_id() {
    return mysql_insert_id();
  }
}  

?>
