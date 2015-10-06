## Configuring The Authorization Service

The `authorization` section in a Trapperkeeper configuration file controls the
logic that the `wrap-with-authorization-check` handler uses to authorize a 
[Ring](https://github.com/ring-clojure/ring) request.  Here is one example of
 an `authorization` section, using the
[HOCON](https://github.com/typesafehub/config/blob/master/HOCON.md)
configuration format:

~~~~hocon
authorization: {
    version: 1
    rules: [
            {
                match-request: {
                    path: "^/my_path/([^/]+)$"
                    type: regex
                    method: get
                }
                allow: "$1"
                sort-order: 1
                name: "user-specific my_path"
            },
            {
                match-request: {
                    path: "/my_other_path"
                    type: path
                }
                allow-unauthenticated: true
                sort-order: 2
                name: "my_other_path"
            },
    ]
}
~~~~
    
This document covers the individual settings in the `authorization` section,
including information about how the service evaluates [`rules`](#rules) when 
authorizing a request.

### `version`

Required.  Version of the rule definitions that the authorization service 
should use.  The only supported value is "1".

### `allow-header-cert-info`

Optional.  Controls how the authenticated user "name" is derived for a 
request being authorized.  Default value for the setting is `false`.

For a value of `false`, the authenticated "name" for the request is derived 
from the Common Name (CN) attribute within an X.509 certificate's Subject 
Distinguished Name (DN).  The `wrap-with-authorization-check` middleware 
tries to get the request's X.509 certificate from the `ssl-client-cert` key
in the Ring request map.  If the certificate cannot be found, e.g., if the 
request was made over plaintext or was made over SSL/TLS but no certificate 
was provided by the client, or the CN is not present in the certificate, the
request is considered "unauthenticated".

For a value of `true`, the authenticated "name" for the request is derived from
evaluating the values set for the `X-Client-DN` and `X-Client-Verify` HTTP 
headers in the request.  The value for an `X-Client-DN` HTTP header should be
in the form of a Subject DN from an X.509 certificate (e.g., `CN=myname`).  A
value of `SUCCESS` for the `X-Client-Verify` HTTP header indicates that the
request was validated successfully.  If the `X-Client-Verify` HTTP header is not
present or does not have a value of `SUCCESS` and/or the CN cannot be extracted
from the `X-Client-DN` value, the request is considered "unauthenticated".

The `X-Client-DN` will attempt to be parsed first as a DN per
[RFC 2253](https://www.ietf.org/rfc/rfc2253.txt).  For example:
 
~~~~
O=tester\, inc., CN=tester.test.org
~~~~

If the DN is not found to conform to the RFC 2253 format, the `X-Client-DN`
will be parsed per the OpenSSL
[compat](https://www.openssl.org/docs/manmaster/apps/x509.html) DN format, where
attribute key/value pairs are delimited by solidus, `/`, characters:

~~~~
/O=tester, inc./CN=tester.test.org
~~~~

If a CN value cannot be derived via either parsing approach, the handler returns
an HTTP 400/Bad Request response.

> **Note:** The "compat" OpenSSL DN format does not provide a way to escape
special characters in the DN.  If a solidus character were intended to be
part of the value of an attribute, an unintended CN value could be derived.
For example, the CN extracted from a DN of `/CN=tester/ inc.` is interpreted as
`tester` rather than as `tester/ inc.`.  The RFC 2253 format has a specified
approach for escaping special characters and is, therefore, preferred for
expressing DN values, where possible.

An "unauthenticated" request can only be "allowed" when the first matching 
rule has an `allow-unauthenticated` setting with a value of `true`.  If 
`allow-unauthenticated` is set to `false` for the first rule matching the 
request, the request is "denied" - in which case the handler returns an HTTP 
403/Forbidden response.  For an "authenticated" request, the authenticated 
"name" for the request is evaluated against the `allow` and/or `deny` 
settings for the first rule which matches the request.  See the documentation
for the [`allow`](#allow) and [`deny`](#deny) settings for more information.

### `rules`

Required.  An array in which each of the elements is a map of settings 
pertaining to a rule.  Here is an example of an array with two rules:

~~~~hocon
rules: [
        {
            match-request: {
                path: "^/my_path/([^/]+)$"
                type: regex
                method: get
            }
            allow: "$1"
            sort-order: 1
            name: "user-specific my_path"
        },
        {
            match-request: {
                path: "/my_other_path"
                type: path
            }
            allow-unauthenticated: true
            sort-order: 2
            name: "my_other_path"
        },
       ]
~~~~

The request is evaluated against each rule until either a rule is determined
to be a match for the request or no match can be found for the request.  If 
no rule can be matched to the request, the request is considered to be 
"denied" and, therefore, an HTTP 403/Forbidden response is returned from the
`wrap-with-authorization-check` handler.  If a rule is considered a match for
the request, the authenticated "name" associated with the request is 
compared to the Access Control Entries (ACEs) in the rule - represented 
within `allow`, `deny`, and/or `allow-unauthenticated` settings - to 
determine whether the request should be "allowed" - in which case the handler
calls through to the next handler in the middleware chain - or "denied".  If 
a rule is found to be a match for the request but no `allow`, `deny`, or
`allow-unauthenticated` setting matches the authenticated "name" for the 
request, the request is implicitly "denied".

A request is considered a match for the rule if it satisfies all of the 
criteria in the rule's [`match-request`](#match-request) section.  The 
authenticated "name" associated with the request is determined by the value 
set for the [`allow-header-cert-info`](#allow-header-cert-info) setting.

Rules are ordered in memory prior to authorization being performed.  Rules 
are ordered primarily by the numeric value in their `sort-order` fields, 
where the lower-numbered rules (e.g., 1) are evaluated before 
higher-numbered rules (e.g., 2).  More than one rule can use the same 
`sort-order` value.  In these cases, rules are secondarily sorted by the 
values in their `name` field.  The `name` sort is lexicographical, using the 
Unicode code points of characters in the value, and does not account for 
locale-specific character ordering.  Where the relative order in which rules are
evaluated is critical, appropriate unique values should be used for the 
`sort-order` field in the rules.

The following settings in this section pertain to the fields for individual 
rule entries.

#### `match-request`

Required.  In order for a rule to be considered a match for the request, the
request must match each of the settings in the rule's `match-request` section.
For example, if the rule were to specify values for `path`, `type`, and `method`
and the request were to match the values for all three settings, the rule 
would be considered a match for the request and the result of the 
authorization attempt would be determined by matching the authenticated 
request's "name" to one of the ACEs in the rule.  If the request were to only 
match the `path` and `type` but not the `method` in the rule, however, the 
rule would not be considered a match for the request and the service would 
move on to the next rule to see if it matches the request.

##### `path`

Required.  The `path` setting is matched up against the
[path component] (https://tools.ietf.org/html/rfc3986#section-3.3) of the 
request's URL.  For example, if the request URL were 
`"http://my-host:8080/the/path?myvar1=myvarval"`, the portion of the URL 
matched up against the `path` would be `"/the/path"`.  The type of match to 
be performed depends upon the value of the corresponding `type` setting for 
the rule.

##### `type`

Required.  The `type` setting controls the type of match which is done with 
the value in the `path` setting against the path component in the request URL.
The available values are:

* `path` - Any request's path component *starting with* the literal value in
 the `path` setting would be a match.  For example, a request URL of
 `"http://my-host:8080/the/path?myvar1=myvarval"` would be a match for a rule
 path of `"/the/path/something/else"` for a type of `path`.  A request URL of
 "http://my-host:8080/the/wrong/path?myvar1=myvarval"`, however, would not be
 considered a match.
           
* `regex` - Any request's path component matching the full regular expression
 in the `path` setting would be a match.  For example, a request URL of 
 `"http://my-host:8080/the/path?myvar1=myvarval"` would be a match for a 
 rule path of `"^/the/path$"` for a type of `regex`.  A request URL of 
 `"http://my-host:8080/the/path/something?myvar1=myvarval"`, however, would 
 not be considered a match.

##### `method`

Optional.  The `method` setting controls which HTTP methods (see section 5.1.1
of http://www.w3.org/Protocols/rfc2616/rfc2616.txt) would be considered a 
match for a request.  If the method from the request matches any of the 
methods specified for the rule, the request is considered a match.  If the 
`method` setting is omitted from the rule definition, any request would be 
considered a match.  The `method` can be represented either as a single 
string value ...

~~~~hocon
method: get
~~~~

... or as an array of values ...

~~~~hocon
method: [ get, post ]
~~~~

Allowed values for `method` include `get`, `post`, `put`, `delete`, and `head`.

##### `query-params`

Optional.  If present, the value should be a map of key/value pairs which are
matched against the
[query component] (https://tools.ietf.org/html/rfc3986#section-3.4) of the 
request URL.  The rule is only considered a match if each of the keys listed 
in the `query-params` section are present in the request's query string and 
at least one of the corresponding values for each key is present in the 
values in the rule.

For example, the `query-params` section may have the following content:

~~~~hocon
query-params: {
                oneparam: [ valuea, valueb ]
                twoparam: valuec
              }
~~~~

The following request URLs would be considered a match for this 
`query-params` section:

- http://my-host:8080/the/path?oneparam=valuea&twoparam=valuec
- http://my-host:8080/the/path?oneparam=valuea&twoparam=valuec&threeparam=whatever
- http://my-host:8080/the/path?oneparam=valueb&twoparam=valuec
- http://my-host:8080/the/path?oneparam=valuea&oneparam=somethingelse&twoparam=valuec

The following request URLs would not be considered a match for this 
`query-params` section:

- http://my-host:8080/the/path
- http://my-host:8080/the/path?threeparam=whatever
- http://my-host:8080/the/path?oneparam=valuea
- http://my-host:8080/the/path?twoparam=valuec

If the `query-params` is omitted from the rule, any request - regardless of 
what query string is associated with it - would be considered a match.

##### `sort-order`

Required.  `sort-order` is a numeric value, where any value from 1 to 999 
(inclusive) is valid.  `sort-order` controls the order in which one rule is 
evaluated relative to another rule when authorizing a request.  Rules with 
lower-numbered values are evaluated before rules with higher-numbered values.
In these cases, rules are secondarily sorted by the values in their `name` 
field.  The `name` sort is lexicographic, using the Unicode code points of 
each character, and does not account for locale-specific character ordering. 
Where the order in which rules are relatively are evaluated is critical, 
appropriate unique values should be used for the `sort-order` field in the rules.

A block in the middle of the `sort-order` range - from 400 to 600 
(inclusive) is reserved for use by Puppet, e.g., for the default rules 
delivered with a package.  Rules from 1 to 399 (inclusive) are reserved for 
users to insert custom rules ahead of any default Puppet ones and from 601 to
998 (inclusive) for inserting custom rules behind any default Puppet ones.

The 999 `sort-order` is reserved for a Puppet rule that denies all users access
to all routes in the event that no other rule in the configuration was a match
for the request.

#### `name`

Required.  `name` values are represented as a string and each rule's `name` 
value must be unique from any other rule's `name` value.  The presence of the
same `name` value in one or more rules would result in a service startup 
failure.  When choosing a value, consider that the `name` may be written both
to server logs and in the body of an error response returned to an
unauthorized client.

#### `allow`

One of `allow`, `deny`, or `allow-unauthenticated` is required to be present
for a rule.  If `allow-unauthenticated` is set to `true` for a rule, `allow`
may not be used.

The value for an `allow` setting can be represented either as a single 
string value ...

~~~~hocon
allow: node1
~~~~

... or as an array of values ...

~~~~hocon
allow: [ node1, node2, node3 ]
~~~~

If a request matches the criteria in the [`match-request`] (#match-request) 
section of the rule and the authenticated "name" of the request matches one 
of the `allow` entries, the request is "allowed" - in which case the handler
calls through to the next handler in the middleware chain.  See the 
[`allow-header-cert-info`] (#allow-header-cert-info) setting for information 
on how the authenticated "name" is derived for a request.

Note that if both `allow` and `deny` settings are included in the rule and 
the authenticated "name" matches an entry in both settings, the request is
denied.

One of the following forms may be used as the value for an `allow` entry:

* An exact name.  For example: `www.domain.org`.  In this case, only a 
 request whose "name" were `www.domain.org` would be considered a match for 
 the entry.
  
* A glob of names, with an asterisk, `*`, in place of the leftmost segment. 
 For example: `*.domain.org`.  In this case, either `www.domain.org` or 
 `test.domain.org` would be considered a match for the entry.
  
* A regular expression, with surrounding solidus, `/`, characters.  For 
 example: `/domain/`.  In this case, `www.domain.org`, `test.domain.org`, or 
 `www.domain.com` would be considered a match for the entry.
  
* A backreference to a capture group, only applicable when used with a rule 
 whose `type` is `regex`.  For example, if the `path` for the rule were 
`"^/the/path/([^/]+)$"`, a backreference to the first capture group in the 
 regular expression could be made by using a value like `"$1.domain.org"`.  
 In this case, if the authenticated user's "name" were `www.domain.org` and 
 the request URL were `"http://my-host:8080/the/path/www"`, the authenticated 
 "name" would be considered a match for the entry.  An authenticated "name" 
 of `xyz.domain.org` and a request URL of
 `"http://my-host:8080/the/path/xyz"`, however, would not be considered a 
 match for the entry.

#### `deny`

One of `allow`, `deny`, or `allow-unauthenticated` is required to be present
for a rule.  If `allow-unauthenticated` is set to `true` for a rule, `deny` 
may not be used.

The value for a `deny` setting can be represented either as a single string 
value ...

~~~~hocon
deny: node1
~~~~

... or as an array of values ...

~~~~hocon
deny: [ node1, node2, node3 ]
~~~~

If a request matches the criteria in the [`match-request`] (#match-request) 
section of the rule and the authenticated "name" of the request matches one 
of the `deny` entries, the request is "denied" - in which case the handler returns
an HTTP 403/Forbidden response.  See the
[`allow-header-cert-info`] (#allow-header-cert-info) setting for information on
how the authenticated "name" is derived for a request.

Note that if both `allow` and `deny` settings are included in the rule and 
the authenticated "name" matches an entry in both settings, the request is
denied.

The supported forms for a `deny` entry are the same as those for an `allow` 
entry.  See documentation for the [`allow`] (#allow) setting for more 
information.

#### `allow-unauthenticated`

One of `allow`, `deny`, or `allow-unauthenticated` is required to be present
for a rule.  If `allow-unauthenticated` is set to `true` for a rule, neither
`allow` nor `deny` may be used.

If a request matches the criteria in the [`match-request`] (#match-request) 
section of the rule and `allow-unauthenticated` is either omitted from the 
rule or explicitly set to `false`, the request is "allowed" or "denied" per 
the result of evaluating the request's authenticated "name" against the 
[`allow`] (#allow) and [`deny`] (#deny) setting entries.  If no authenticated
"name" can be determined for the request, the request is "denied" - in which
case the handler returns an HTTP 403/Forbidden response.

If a request matches the criteria in the `match-request` section of the rule 
and `allow-unauthenticated` is set to `true`, the request is "allowed" - in 
which case the handler calls through to the next handler in the middleware
chain.  Whether or not an authenticated "name" can be determined for the 
request, the request is "allowed".
