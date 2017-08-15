-- use to drop the collabreate db, something like:
-- psql -U collab collabDB
-- psql> \i dbclean.sql
DROP TABLE tracker;
DROP TABLE forklist;
DROP TABLE snapshots;
DROP SEQUENCE snapshots_sid_seq;
DROP TABLE updates;
DROP SEQUENCE updates_updateid_seq;
DROP TABLE tablename;
DROP TABLE projects;
DROP SEQUENCE projects_pid_seq;
DROP TABLE users;
DROP LANGUAGE plpgsql cascade;
