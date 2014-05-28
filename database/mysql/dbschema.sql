--  IDA Pro Collabreation/Synchronization Plugin
--  Copyright (C) 2008 Chris Eagle <cseagle at gmail d0t com>
--  Copyright (C) 2008 Tim Vidas <tvidas at gmail d0t com>
--
--
--  This program is free software; you can redistribute it and/or modify it
--  under the terms of the GNU General Public License as published by the Free
--  Software Foundation; either version 2 of the License, or (at your option)
--  any later version.
--
--  This program is distributed in the hope that it will be useful, but WITHOUT
--  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
--  FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
--  more details.
--
--  You should have received a copy of the GNU General Public License along with
--  this program; if not, write to the Free Software Foundation, Inc., 59 Temple
--  Place, Suite 330, Boston, MA 02111-1307 USA

-- mysql JDBC driver is available here
-- http://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-java-5.1.6.tar.gz/from/pick#mirrors

-- used to create the collabreate db in mysql, something like:

CREATE DATABASE IF NOT EXISTS collabDB;

use collabDB;

CREATE TABLE users (
   userid INT AUTO_INCREMENT UNIQUE,
   username VARCHAR(32) UNIQUE,
   pwhash VARCHAR(64),
   -- some sort of general permissions (eg novice user)
   sub BIGINT,
   pub BIGINT,
   PRIMARY KEY(userid)
) ENGINE=InnoDB ;


CREATE TABLE projects (
   pid INT AUTO_INCREMENT UNIQUE NOT NULL, -- still want a local pid so that compares in update are fast
   gpid VARCHAR(128) UNIQUE NOT NULL, -- global pid across all instances of collabreate servers
   hash VARCHAR(64) NOT NULL, 
   description TEXT NOT NULL,
   created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
   touched TIMESTAMP,
   owner INTEGER REFERENCES users(userid),
   -- project permissions (initial creator of project is 'owner' - sets default perms)
   sub BIGINT,
   pub BIGINT,
   snapupdateid BIGINT, -- replaces entire snapshot table
   protocol INTEGER NOT NULL,
   PRIMARY KEY (pid)
) ENGINE=InnoDB;

CREATE INDEX projects_hash_index ON projects(hash);

CREATE TABLE updateid (
   seq bigint
);

INSERT INTO updateid values(1);

delimiter //
CREATE FUNCTION nextid() RETURNS BIGINT
BEGIN
   DECLARE temp BIGINT;
   SELECT seq into temp FROM updateid;
   UPDATE updateid SET seq = temp + 1;
   RETURN temp;
END;
//
delimiter ;

CREATE TABLE updates (
   updateid BIGINT NOT NULL,    -- DOES NOT WORK! can't assign default as the result of a function
   userid INTEGER REFERENCES users(userid),
   pid INTEGER REFERENCES projects(pid),  -- pid not gpid for faster comparison
   cmd INTEGER,
   data BLOB,
   created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
   PRIMARY KEY (updateid,pid)
) ENGINE=InnoDB;

delimiter //
CREATE FUNCTION insertUpdate(uid INTEGER, proj_id INTEGER, command INTEGER, value BLOB) RETURNS BIGINT
BEGIN
   DECLARE temp BIGINT;
   SELECT nextid() INTO temp;
   INSERT INTO updates (updateid,userid,pid,cmd,data) VALUES (temp, uid, proj_id, command, value);
   RETURN temp;
END;
//
delimiter ;

delimiter //
CREATE PROCEDURE copyUpdates(old_pid int, max_update int, new_pid int)
BEGIN
   CREATE TEMPORARY TABLE tmptable (LIKE updates);
   INSERT INTO tmptable SELECT * FROM updates WHERE pid = old_pid AND updateid <= max_update;
   UPDATE tmptable SET pid = new_pid;
   INSERT INTO updates (SELECT * FROM tmptable); 
   DROP TABLE tmptable;
END;
//
delimiter ;

CREATE TABLE forklist (
   fid INT AUTO_INCREMENT UNIQUE NOT NULL,
   child INTEGER REFERENCES projects(pid),
   parent INTEGER REFERENCES projects(pid), 
   PRIMARY KEY(fid)
) ENGINE=InnoDB;

delimiter //
CREATE FUNCTION addUserQuery(user varchar(32), pw varchar(64), p BIGINT, s BIGINT) RETURNS INTEGER
BEGIN
  insert into users (username,pwhash,pub,sub) values (user, pw, p, s);
  return LAST_INSERT_ID();
END;
//

CREATE FUNCTION updateUserQuery(user varchar(32), pw varchar(64), p BIGINT, s BIGINT, uid INTEGER) RETURNS INTEGER
BEGIN
  update users set username=user,pwhash=pw,pub=p,sub=s where userid=uid;
  return LAST_INSERT_ID();
END;
//

CREATE FUNCTION addProjectQuery(hash varchar(64), gpid varchar(128), descr text, owner int, p BIGINT, s BIGINT, protocol INTEGER) RETURNS INTEGER
BEGIN
  insert into projects (hash,gpid,description,owner,pub,sub,protocol) values (hash, gpid, descr, owner, p, s, protocol);
  return LAST_INSERT_ID();
END;
//

CREATE FUNCTION addProjectSnapQuery(hash varchar(64), gpid varchar(128), descr text, owner int, snapid BIGINT, protocol INTEGER) RETURNS INTEGER
BEGIN
  insert into projects (hash,gpid,description,owner,snapupdateid,protocol) values (hash, gpid, descr, owner, snapid, protocol);
  return LAST_INSERT_ID();
END;
//

CREATE FUNCTION addProjectForkQuery(child int, parent int) RETURNS INTEGER
BEGIN
  insert into forklist (child,parent) values (child, parent);
  return LAST_INSERT_ID();
END;
//
delimiter ;

CREATE USER collab IDENTIFIED BY 'collabpass';
GRANT ALL on collabDB.* to 'collab'@'%';
GRANT SELECT ON mysql.proc to 'collab'@'%';
