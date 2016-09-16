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

## Documentation

Trapperkeeper-authorization's docs are housed [in this repository](doc/index.md).

## Example code

One example, a Trapperkeeper service which wraps the authorization service
around a Ring handler, is included with this project
([source code](./examples/ring_app/README.md)).

## Service protocol

This is the protocol for the current implementation of the `:AuthorizationService`:

~~~~clj
(defprotocol AuthorizationService
  (wrap-with-authorization-check [this handler])
  (authorization-check [this request]))
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

For this example, if the web server receives a request to the "/hello"
endpoint, the middleware logic behind the `wrap-with-authorization-check` 
function evaluates the request to see if it is "authorized".  If the
request is determined to be "allowed", the request is handed on to
the `handler` passed into the original `wrap-with-authorization-check` 
function call.  If the request is determined to be "denied", a Ring response
with an HTTP status code of "403" and a message body with details about the 
authorization failure is returned.  In the latter case, the original 
`handler` supplied to the `wrap-with-authorization-check` function is not
called.

For more information on the rule evaluation behavior (e.g., how a request is
determined to be "allowed" or "denied"), see
[Configuring the Authorization Service](doc/authorization-config.md).

Upon successful authorization, a key name of `authorization` is appended to
the Ring request map which is passed through to the `handler` function.  The
value associated with the `authorization` key is a map containing the
following key/value pairs:

* `name` - CN (Common Name) extracted from the Distinguished Name in the
  subject of the certificate presented with the request.  When the
  `allow-header-cert-info` configuration setting is `false`, the `name` value
  is pulled from the CN attribute in the certificate provided by the client
  during SSL session negotiation.  When the `allow-header-cert-info`
  configuration setting is `true`, the `name` value is pulled from the CN
   attribute in the `X-Client-DN` HTTP header provided with the request.
  If no certificate is available or a CN value cannot be retrieved from the
  certificate, the `name` is set to an empty string.

* `authenticated` - A boolean value representing whether or not the client
  request included an authenticated user.  In any case where the `name` value
  has an empty string, `authenticated` is `false`.  If the
  `allow-header-cert-info` configuration setting is `false` and the `name` value
  is non-empty, `authenticated` is `true`.  If the `allow-header-cert-info`
  configuration setting is `true`, the `name` value is non-empty, and an HTTP
  header named `X-Client-Cert` with a value of `SUCCESS` is provided,
  `authenticated` is `true`; for a value other than `SUCCESS` for
  `X-Client-Cert`, `authenticated` is `false`.

* `certificate` - An `java.security.cert.X509Certificate` object for the client's
  certificate, if available for the request, else a value of `nil`.  If the
  `allow-header-cert-info` configuration setting is `false`, the value is just
  reassigned from whatever is set for the `ssl-client-cert` key in the Ring
  request map.  If the `allow-header-cert-info` configuration setting is `true`,
  the `X509Certificate` object is constructed by URL-decoding the string
  value passed in for the request's `X-Client-Cert` HTTP header and parsing
  the result as a PEM-formatted (Base-64 encoded) certificate.  If the header
  value cannot be URL-decoded and/or converted from a Base-64 encoded string, a
  value of `nil` is set.
  
> **Note:** Apache's mod_proxy converts line breaks in PEM documents in HTTP
headers to spaces for some reason and trapperkeeper-authorization can't URL
decode the result.  We're tracking this issue as
[SERVER-217](https://tickets.puppetlabs.com/browse/SERVER-217).

### `authorization-check`

A function for directly checking whether a request is authorized or not.
Useful if you'd like to take more control of the behavior than what
`wrap-authorization-check` allows for, such as if you've got a servlet request.

The result of this function contains the authorization boolean as well as a
user-friendly message if it's denied, and some meta-information like the
request in question. The request will be updated to include things like
destructured query parameters and authorization information.
See the [`wrap-with-authorization-check`](#wrap-with-authorization-check)
section for more information on the authorization information.

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

Tickets: https://tickets.puppetlabs.com/browse/TK
