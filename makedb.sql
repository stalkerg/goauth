CREATE KEYSPACE goauth
WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 };
USE goauth;

CREATE TABLE users (
	user_id uuid PRIMARY KEY,
	login text,
	password text
);

CREATE INDEX ON users (login);

CREATE TABLE sessions (
	key text PRIMARY KEY,
	user_id uuid
);

INSERT INTO users (user_id, login, password) VALUES (uuid(), 'test', 'e10adc3949ba59abbe56e057f20f883e'); 
