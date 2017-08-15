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

-- postgresql JDBC driver is available here
-- http://jdbc.postgresql.org/download.html

--used to create the collabreate db in postgres, something like:
-- createuser collab
--    Not a superuser, but allow user to create databases
-- createdb -U collab collabDB
-- psql -U collab collabDB
-- psql> \i dbschema.sql


CREATE TABLE users (
   userid SERIAL UNIQUE,
   username TEXT UNIQUE,
   pwhash TEXT,
   --some sort of general permissions (eg novice user)
   sub BIGINT,
   pub BIGINT,
   PRIMARY KEY(userid)
);

CREATE SEQUENCE projects_pid_seq;

CREATE TABLE projects (
   pid SERIAL UNIQUE NOT NULL, --still want a local pid so that compares in update are fast
   gpid TEXT UNIQUE NOT NULL, --global pid across all instances of collabreate servers
   hash TEXT NOT NULL, 
   description TEXT NOT NULL,
   created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
   touched TIMESTAMP,
--   parent INTEGER,  --for forked projects, should reference projects.pid
   owner TEXT REFERENCES users(username),
   --project permissions (initial creator of project is 'owner' - sets default perms)
   sub BIGINT,
   pub BIGINT,
   snapupdateid BIGINT DEFAULT 0, -- replaces entire snapshot table
   protocol INTEGER NOT NULL,     --server protocol used to create this project
   PRIMARY KEY (pid)
);

CREATE TABLE tablename (
    colname integer NOT NULL DEFAULT nextval('projects_pid_seq')
);

--ALTER SEQUENCE tablename_colname_seq OWNED BY tablename.colname;

CREATE INDEX projects_hash_index ON projects(hash);

CREATE SEQUENCE updates_updateid_seq START 1;

CREATE TABLE updates (
   updateid BIGINT DEFAULT nextval('updates_updateid_seq') NOT NULL,
   username text REFERENCES users(username),
   pid INTEGER REFERENCES projects(pid) ON DELETE CASCADE,  --pid not gpid for faster comparison
   cmd TEXT NOT NULL,
   json TEXT NOT NULL,
   created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
   PRIMARY KEY (updateid,pid)
);

CREATE SEQUENCE snapshots_sid_seq;

CREATE TABLE forklist (
   fid SERIAL UNIQUE NOT NULL,
   child INTEGER REFERENCES projects(pid),
   parent INTEGER REFERENCES projects(pid), 
   PRIMARY KEY(fid)
);
--tracker is no longer required, since the last update is stored in the idb
--CREATE TABLE tracker (
--   username TEXT references users(username),
--   project INTEGER references projects(pid),
--   updates INTEGER references updates(updateid),
--   PRIMARY KEY (username, project, updates)
--);

CREATE LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION next_project_id() RETURNS integer AS $$
BEGIN
   RETURN nextval('projects_pid_seq');
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fork_project(oldpid integer) RETURNS integer AS $$
DECLARE
    projects_row projects%ROWTYPE;
    newpid integer;
BEGIN
   SELECT * INTO projects_row FROM projects WHERE pid = oldpid;
   newpid := next_project_id();
   INSERT INTO projects VALUES(newpid, projects_row.hash);

--   SELECT newpid, cmd, json FROM updates WHERE pid == oldpid AS fork_updates;
--   INSERT INTO updates(pid, cmd, json) SELECT * from fork_updates;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION copy_updates(ppid integer, maxid integer, lpid integer) RETURNS VOID AS $$
DECLARE
BEGIN
   INSERT INTO updates (SELECT updateid,username,lpid,cmd,json,created FROM updates WHERE pid = ppid AND updateid <= maxid);
END;
$$ LANGUAGE plpgsql;

--sample data
--insert into users (username,pwhash) values ('someuser', MD5('SomePassword'));
