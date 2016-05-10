### 0.6.0

 * [TK-293](https://tickets.puppetlabs.com/browse/TK-293) Allow authorization
   rules that match on CSR Attributes instead of just certname

### 0.5.1

 * [TK-360](https://tickets.puppetlabs.com/browse/TK-360) Remove IP address,
   requestor name, and rule from HTTP response to forbidden requests.

### 0.5.0

 * [TK-286](https://tickets.puppetlabs.com/browse/TK-286) Rename API term
   `authentic?` to `authenticated` for clarity.
 * [TK-289](https://tickets.puppetlabs.com/browse/TK-289) No longer log warning
   message when rules are out of sort order in configuration file.
 * [TK-285](https://tickets.puppetlabs.com/browse/TK-285) Add validation for
   rule regex paths with capture groups and allow/deny back-references.

### 0.1.5

 * Added API function `authorization-check` to the AuthorizationService
   protocol to support authorization from non-Ring-based handlers such as Java
   Servlets.
 * [TK-268](https://tickets.puppetlabs.com/browse/TK-268) Weight 'deny' ACEs
   before 'allow' ACEs - regardless of any attributes of their patterns - to
   simplify behavior.

### 0.1.4

 * [TK-282](https://tickets.puppetlabs.com/browse/TK-282) Added support for an
   `allow-header-cert-info` field to the `authorization` config.

### 0.1.3

 * [TK-262](https://tickets.puppetlabs.com/browse/TK-262) Added support for a
   `version` field to the `authorization` config.
 * [TK-266](https://tickets.puppetlabs.com/browse/TK-266) Added support for
   `sort-order` and `name` fields in a rule definition.
 * [TK-271](https://tickets.puppetlabs.com/browse/TK-271) Added support for more
   than one `method` to be specified in a rule definition.
 * [TK-277](https://tickets.puppetlabs.com/browse/TK-277) Use wrapper function
   for parsing query-params from the Ring request, to avoid prematurely slurping
   a request body for a request which is a urlencoded form post.
 * [TK-279](https://tickets.puppetlabs.com/browse/TK-279) Log error-level message
   when a request is denied.
 * [TK-280](https://tickets.puppetlabs.com/browse/TK-280) Updated the
   `README.md` with more documentation on using the trapperkeeper-authorization
   service from a developer perspective.  Also added a
   `doc/authorization-config.md` page which documents the available settings in
   the `authorization` configuration.
 * Created simple standalone Ring-based example which integrates with
   trapperkeeper-authorization.

### 0.1.2

 * [TK-259](https://tickets.puppetlabs.com/browse/TK-259) Added support for
   matching rules on `query-params` from the request.
 * [TK-260](https://tickets.puppetlabs.com/browse/TK-260) Added optional
   `allow-unauthenticated` attribute to the rule definition to be used for
   specifying that a rule would match any request - whether or not an
   authenticated name could be derived for the request.
 * [TK-272](https://tickets.puppetlabs.com/browse/TK-272) Fixed ability for the
   `deny: "*"` directive to deny - rather than allow - all matching requests.
 * [TK-275](https://tickets.puppetlabs.com/browse/TK-275) Move elements of the
   rule definition which determine whether the rule is a match for the request
   into a `match-request` section.

### 0.1.1

 * [TK-258](https://tickets.puppetlabs.com/browse/TK-258) Created a Trapperkeeper
   service, AuthorizationService, with a `wrap-with-authorization-check`
   function for accessing the authorization middleware from another service.
   Rules loaded from `authorization` section in Trapperkeeper configuration.
 * Removed ability to obtain the request's authenticated name from a
   reverse-proxy DNS lookup when no name can be retrieved from the client
   certificate on the request.
 * Bumped `puppetlabs/ssl-utils` dependency from 0.8.0 to 0.8.1.
 * Authorization failures returned as HTTP 403 instead of 401.

### 0.0.1

 * Not released by PuppetLabs.  Code imported from the 0.0.1 tag on
   https://github.com/masterzen/trapperkeeper-authorization.
