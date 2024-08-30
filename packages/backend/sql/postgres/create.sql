
drop table if exists oauthauthorization;
drop table if exists oauthclientredirecturi;
drop table if exists oauthclientvalidflow;
drop table if exists oauthclient cascade;

drop table if exists keys;

drop table if exists usersecrets;
drop table if exists users cascade;
drop index if exists usersecrets_userid_idx;
drop index if exists keys_value_idx;

/* users and usersecrets */

create table users (
    id                   serial            primary key,
    username             varchar(128)      unique,
    username_normalized   varchar(128)      unique,
    email                varchar(128)      unique,
    email_normalized      varchar(128)      unique,
    phone                varchar(128)      null,
    state                varchar(128)      default 'active',
    factor1              varchar(128)      default 'password',
    factor2              varchar(128)      default '',
    dummyfield           varchar(128)      default ''
);

create unique index users_username_idx on users (username);
create unique index users_username_normalized_idx on users (username_normalized);
create unique index users_email_idx on users (email);
create unique index users_email_normalized_idx on users (email_normalized);

create table usersecrets (
    password            varchar(256),
    totpsecret          varchar(256)      default '',
    userid              int               references users
);

create unique index usersecrets_userid_idx on usersecets (userid);

/* kesy */

create table keys (
    id             serial            primary key,
    value          text              unique,
    userid         int               null references users,
    created        timestamp,
    expires        timestamp,
    lastActive     timestamp         null,
    data           text              null
);

create unique index keys_value_idx on keys (value);

/* OAuth client */

create table oauthclient (
    client_id       varchar(128)    primary key,
    confidential    boolean         default true,
    client_name     text            ,
    client_secret   varchar(128)    null,
    userid          int             null references users
);

create unique index client_user_name_idx on oauthclient (userid, client_name);

/* OAuth redirect Uri */

create table oauthclientredirecturi (
    id             serial           primary key,
    client_id      varchar(128)     references oauthclient,
    uri            text
);

create index redirecturi_client_id_idx on oauthclientredirecturi (client_id);
/*create unique index redirecturi_client_id_uri_idx on oauthclientredirecturi (client_id, uri);*/
create unique index redirecturi_client_id_uri_idx on oauthclientredirecturi (uri); /* this is more secure if it works for your use case */


create table oauthclientvalidflow (
    id             serial           primary key,
    client_id      varchar(128)     references oauthclient,
    flow           text
);

create index validflow_client_id_idx on oauthclientvalidflow (client_id);
create unique index redirecturi_client_id_flow_idx on oauthclientvalidflow (client_id, flow);

/* OAuth authorization */
create table oauthauthorization (
    id             serial           primary key,
    client_id      varchar(128)     references oauthclient,  
    userid         int              null references users,
    scope          varchar(128)     null
);

create index oauthauthorization_client_id_idx on oauthauthorization (client_id);
create unique index oauthauthorization_client_id_scope_idx on oauthauthorization (client_id, scope);
