

create table users (

	id	int(32) not null auto_increment,
	
	p2pid	varchar(250) not null,	
	name	varchar(250) not null,
	password	varchar(250) not null,

	primary key(id)
);

create table wall (
	
	id int(32) not null auto_increment,
	user_id int(32) not null,

	poster int(32) not null,
	time timestamp,
	msg varchar(250),

	primary key(id)
);

create table friendship (
	user1 int(32) not null,
	user2 int(32) not null,
	status int(8) default 0,
	
	unique(user1, user2)
);

create table content (

	id 	int(32) not null auto_increment,
	user_id  int(32) not null,

	name 	varchar(250),
	description  varchar(250),
	type 	varchar(250),
	cid 	varchar(250),
	
	
	primary key(id)
);

