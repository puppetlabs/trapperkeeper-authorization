# Trapperkeeper Authorization Service

[![Build Status](https://travis-ci.org/puppetlabs/trapperkeeper-authorization.svg?branch=master)](https://travis-ci.org/puppetlabs/trapperkeeper-authorization)

This project provides an authorization service for use with the
[trapperkeeper service framework](https://github.com/puppetlabs/trapperkeeper).
It aims to port Puppet's
[`auth.conf`](https://docs.puppetlabs.com/puppet/latest/reference/config_file_auth.html)
feature to Clojure and the trapperkeeper framework, with a different way to 
express authorization rules.

## Installation

To use this service in your trapperkeeper application, simply add this project
as a dependency in your leiningen project file:

[![Clojars Project](http://clojars.org/puppetlabs/trapperkeeper-authorization/latest-version.svg)](http://clojars.org/puppetlabs/trapperkeeper-authorization)

Then add the authorization service to your
[`bootstrap.cfg`](https://github.com/puppetlabs/trapperkeeper/wiki/Bootstrapping)
file, via:

    puppetlabs.trapperkeeper.services.authorization.authorization-service/authorization-service

The authorization service provides an implementation of the
 `:AuthorizationService` interface.

The authorization service is configured via the
[trapperkeeper configuration service](https://github.com/puppetlabs/trapperkeeper/wiki/Built-in-Configuration-Service);
so, you can control the authorization logic by adding an `authorization` section
to one of your Trapperkeeper configuration files, and setting various 
properties therein.  For more info, see
[Configuring the Authorization Service](doc/authorization-config.md).

## Example code

One example, a Trapperkeeper service which wraps the authorization service
around a Ring handler, is included with this project
([source code](./examples/ring_app/README.md)).

## Service protocol

This is the protocol for the current implementation of the `:AuthorizationService`:

~~~~clj
(defprotocol AuthorizationService
  (wrap-with-authorization-check [this handler]))
~~~~

### `wrap-with-authorization-check`

`wrap-with-authorization-check` takes one argument - `handler`.  The `handler`
argument is just a
[Ring handler](https://github.com/ring-clojure/ring/wiki/Concepts#handlers).
`wrap-with-authorization-check` will wrap logic for authorizing web requests 
around the supplied `handler` argument and return the wrapped handler.

Here is an example of how a Trapperkeeper service can use the
`:AuthorizationService`:

~~~~clj
(defservice hello-service-using-tk-authz
    [[:AuthorizationService wrap-with-authorization-check]
     [:WebserverService add-ring-handler]]
     (init [this context]
         (add-ring-handler
             (wrap-with-authorization-check
                 (fn [_]
                     {:status  200
                     :headers {"Content-Type" "text/plain"}
                     :body    "Hello, World!"}))
                 "/hello")
             context))
~~~~

See the
[Trapperkeeper web service](https://github.com/puppetlabs/trapperkeeper-webserver-jetty9)
project for more information on the `:WebserverService`.

For this example, if the web server were to receive a request to the "/hello"
endpoint, the middleware logic behind the `wrap-with-authorization-check` 
function would evaluate the request to see if it is "authorized".  If the
request were determined to be "allowed", the request would be handed on to 
the `handler` passed into the original `wrap-with-authorization-check` 
function call.  If the request were determined to be "denied", a Ring response
with an HTTP status code of "403" and a message body with details about the 
authorization failure is returned.  In the latter case, the original 
`handler` supplied to the `wrap-with-authorization-check` function would not be
called.

For more information on the rule evaluation behavior (e.g., how a request is
determined to be "allowed" or "denied"), see
[Configuring the Authorization Service](doc/authorization-config.md).

## Credits

The original work for this library, service, and the original REST authconfig
work in Ruby Puppet were all contributed by [Brice Figureau](https://github
.com/masterzen).  This project has been graciously transferred to Puppet Labs for
further development and maintenance as it becomes a critical part of the
[Puppet Server](https://github.com/puppetlabs/puppet-server) security model as
authconfig became a critical part of Puppet's security model.

## Support

We use the
[Trapperkeeper project on JIRA](https://tickets.puppetlabs.com/browse/TK) for
tickets on the Trapperkeeper Authorization Service, although Github issues 
are welcome too.  Please note that the best method to get our attention on an
issue is via JIRA.
