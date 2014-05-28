-- use to drop the collabreate db, something like:
-- mysql collabDB < my_dbclean.sql

use collabDB;

DROP TABLE forklist;
DROP TABLE updates;
DROP TABLE projects;
DROP TABLE users;
DROP TABLE updateid;
DROP FUNCTION nextid;
DROP FUNCTION insertUpdate;
DROP PROCEDURE copyUpdates;
DROP FUNCTION addUserQuery;
DROP FUNCTION addProjectQuery;
DROP FUNCTION addProjectSnapQuery;
DROP FUNCTION addProjectForkQuery;

