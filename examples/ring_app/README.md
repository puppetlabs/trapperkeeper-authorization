# Simple Ring App with Authorization Example

This example demonstrates how to incorporate the trapperkeeper-authorization
service into a simple Ring app.  This is based loosely upon the
[ring_app example] (https://github.com/puppetlabs/trapperkeeper-webserver-jetty9/tree/master/examples/ring_app)
in the trapperkeeper-webserver-jetty9 project.  See that example for more
information on the use of the `jetty9-service` and the Jetty web server
integration with Ring.

This example includes a simple set of default authorization rules which can be
used to protect access to the `/hello` endpoint that is handled by the service.

All code needed to execute this example is located in `./src/examples/ring_app`.
The Clojure code is contained in the `ring_app.clj` file.

## Launching trapperkeeper and running the app

To start up _trapperkeeper_ and launch the sample application, use the
following _lein_ command while in the _trapperkeeper-authorization_ home
directory:

~~~~sh
lein trampoline run --config ./examples/ring_app/ring-example.conf \
                    --bootstrap-config ./examples/ring_app/bootstrap.cfg
~~~~

For convenience, the application could also be run instead via the
`ring-example` alias:

~~~~sh
lein ring-example
~~~~

### The `bootstrap.cfg` file

The bootstrap config file contains a list of services that _trapperkeeper_ will
load up and make available.  They are listed as fully-qualified Clojure
namespaces and service names. For this example, the bootstrap.cfg looks like
this:

~~~~
puppetlabs.trapperkeeper.services.webserver.jetty9-service/jetty9-service
puppetlabs.trapperkeeper.services.authorization.authorization-service/authorization-service
examples.ring-app.ring-app/hello-service
~~~~

This configuration indicates that the jetty9 `WebserverService`, authorization
service, and new "hello" service, defined in the `ring_app.clj` file, are to be
loaded.

### The `ring-example.conf` configuration file

For the application configuration, a file called `ring-example.conf` provides
a fairly minimal configuration for the hello service:

~~~~hocon
global: {
    logging-config: ./examples/ring_app/logback.xml
}

webserver: {
    port: 8080
    ssl-port: 8081
    ssl-cert: "./examples/ring_app/ssl/certs/localhost.pem"
    ssl-ca-cert: "./examples/ring_app/ssl/certs/ca.pem"
    ssl-key: "./examples/ring_app/ssl/private_keys/localhost.pem"
}

authorization: {
    version: 1
    rules: [
        {
            match-request: {
                path: "/hello/all-allowed"
                type: "path"
            }
            allow-unauthenticated: true
            name: "all users allowed"
            sort-order: 500
        },
        {
            match-request: {
                path: "/hello/user-allowed/([^/]+)$"
                type: "regex"
            }
            allow: "$1"
            name: "users allowed by backreference"
            sort-order: 500
        }
    ]
}
~~~~

This configuration sets up two different web server ports - one unencrypted
(8080) and one encrypted (8081) - and some simple authorization rules.  Some
pre-generated certificates and keys for use with SSL have been provided in the
`./examples/ring_app/ssl` directory.

### Testing the authorization rules

The effect that the rules have can be seen by making requests to the `/hello`
web service endpoint.  Here are some sample requests, using
[cURL](http://curl.haxx.se/).  For each request that should be "allowed",
the result of the call should be a response payload with `Hello, World!` in the
text and an HTTP status code of `200 OK`.  For each request that should be
"denied", the result of the call should be a response payload with
`Forbidden request: ... denied by rule <rule-name>` and an HTTP status code of
`403 Forbidden`.

~~~~sh
curl "http://localhost:8080/hello/all-allowed"
~~~~

Should be "allowed".  The "all users allowed" rule, by virtue of its
`allow-unauthenticated` setting being set to `true`, should allow requests
which supply no client certificate.

~~~~sh
curl "http://localhost:8080/hello/user-allowed/localhost"
~~~~

Should be "denied".  The "users allowed by backreference" rule only allows
access to users whose name is contained in the URL.  Since no client
certificate was provided, no user name could be matched to the URL.

~~~~sh
curl "https://localhost:8081/hello/user-allowed/localhost" \
  --cacert ./examples/ring_app/ssl/certs/ca.pem \
  --cert ./examples/ring_app/ssl/certs/localhost.pem \
  --key ./examples/ring_app/ssl/private_keys/localhost.pem
~~~~

Should be "allowed" since the Common Name (CN) on the user's client
certificate has a value of "localhost" and the request matches the
`/hello/user-allowed/([^/]+)$` regular expression which, when substituted with
the CN from the client certificate via the backreference, would be
`/hello/user-allowed/localhost`.

~~~~sh
curl "https://localhost:8081/hello/user-allowed/not-localhost" \
  --cacert ./examples/ring_app/ssl/certs/ca.pem \
  --cert ./examples/ring_app/ssl/certs/localhost.pem \
  --key ./examples/ring_app/ssl/private_keys/localhost.pem
~~~~

Should be "denied" since the Common Name (CN) on the user's client
certificate has a value of "localhost" and the request does not match the
`/hello/user-allowed/([^/]+)$` regular expression after substitution of the
backreference.

~~~~sh
curl "https://localhost:8081/hello" \
  --cacert ./examples/ring_app/ssl/certs/ca.pem \
  --cert ./examples/ring_app/ssl/certs/localhost.pem \
  --key ./examples/ring_app/ssl/private_keys/localhost.pem
~~~~

Should be "denied" since no rule matches the request.  In this case, the
response message would contain `global deny all - no rules matched`.
