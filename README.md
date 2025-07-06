# Crossauth.js

Crossauth is a package for authentication and authorization using username/password, LDAP and OAuth2.  It has two components, each can be used without the other: server for the backend and client for the frontend.  

Crossauth is designed to work with multiple web frameworks.  Currently, [Fastify](https://fastify.dev/) and [Sveltekit](https://svelte.dev/) are supported.

There is also a Python version at [https://github.com/mbakereth/pycrossauth](https://github.com/mbakereth/pycrossauth).  The longer-term ambition is for this to have the same functionality.  Currently, it only hacve the OAuth client and resource server functionality.

## Package structure

This is a monorepo consisting of several packages:

#### common

Shared functionality for backend and frontend, eg error reporting,
abstract OAuth client class.

#### backend

Code for backend servers, independent of web framework.  The web
framework-specific packages use classes here.

#### fastify

Backend code for use in Fastify-based applications

#### Sveltkit 

Backend code for use in Sveltekit-based applications

#### Frontend

Pure Javascript framework-independent code for the browsers, eg 
OAuth client.

## Package dependencies

This package intends to be flexible regarding other packages that need to be present.  As well as choosing between two popular web frameworks, you can choose between several database management systems

* Postgres
* Sqlite
* Prisma

Out of the box, it doesn't use any logging packages, provide its own simple one.  However it can support other error logging packages such as [Pino](https://github.com/pinojs/pino).  See the `CrossauthLoggerInterface` in the `common` package as well as `setLogger` in the `CrossauthLogger` class.

## Using this package

The above packages are in NPM.  For example, to use them in a Sveltekit application, do

```shell
npm install @crossauth/common
npm install @crossauth/backend
npm install @crossauth/common
```

If you also want to use the browser-based functionality in the frontend, eg the OAuth client, do the following in addition

```
npm install @crossauth/frontend
```

Note that Crossauth makes Sveltekit a dependency in your built bundle.  Normally for Sveltekit applications, Sveltekit is only a dev dependency

## Building this package

If you want to build Crossauth from source, clone it from [https://github.com/mbakereth/crossauthjs](https://github.com/mbakereth/crossauthjs), install [pnpm](https://pnpm.io/) then do the following from the top-level directory in the repo:

```shell
bash pnpminstall.sh
bash pnpm build.sh
```

## The Examples

The `examples` directory contains a number of examples to get you going

### Fastify

#### fastifysessionserver

Example application that implements session-based authentication (ie a session cookie).  It implements two-factor authorization, password change and password reset.

#### fastifyapikeyserver

Simple example that shows how to use API keys instead of OAuth or session-based authentication

#### fastifyoauthserver

A simple OAuth server, ie an application that issues OAuth access tokens.  It doesn't include much in the way of user account management.  For examples of how to do password change and reset, for example, see `fastifysessionserver`.  The functionality can be used unchanged in a Fastify-based OAuth server.

#### fastifyoauthclient

Shows how to implement each of the OAuth flows from the client side.   It shows how to require a user to log in first as well as how to use it without a local user account.

To run this application you also need `fastifyoauthserver` running.

### Sveltekit

#### sveltekitserverexample

An example showing session-based authentication (session cookies) as well as an OAuth server.  Implements user management operations such as adding and deleting users,
configuring user details, password change and reset, two-factor authentication.

#### sveltekitclientexample

Shows how to implement each of the OAuth flows from the client side.   It shows how to require a user to log in first as well as how to use it without a local user account.

To run this application you also need `sveltekitserverexample ` running.

#### sveltekitpasswordandldap

Simple example that shows how local password-based accounts can co-exist with LDAP-based accounts.  

### CLI-based

#### oauthpasswordcli

Shows how to implement a CLI-based OAuth client using the Password and Password MFA flows.

To run this application you also need `sveltekitserverexample ` running.

#### oauthdevicecli

Shows how to implement the OAuth device code flow as a UI-restricted app (in this case, a CLI).

To run this application you also need `sveltekitserverexample ` running.

### Running the examples

The examples are intended as sample code.  However, each one can be run from the source tree.

First, build crossauth by following the instructions above.

Then, for the example you want to run, cd to its directory and:

```shell
pnpm install
pnpm prisma generate
pnpm prisma db push
pnpm run dev
```