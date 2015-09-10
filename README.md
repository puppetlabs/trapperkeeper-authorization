# Trapperkeeper-authorization

[![Build Status](https://travis-ci.org/puppetlabs/trapperkeeper-authorization.svg?branch=master)](https://travis-ci.org/puppetlabs/trapperkeeper-authorization)

This clojure project is an authorization service for PuppetLabs Trapperkeeper.
It aims to port Puppet's `auth.conf` feature to clojure, along with a different
way to express authorization rules.

The core of this service is a configuration format to express authorization
rules which govern the REST API by parsing authentication information out of
the incoming request, then matching the request against the configured rules.

# Credits

The original work for this library, service, and the original REST authconfig
work in Ruby Puppet were all contributed by [Brice
Figureau](https://github.com/masterzen).  This project has been graciously
transferred to Puppet Labs for further development and maintenance as it
becomes a critical part of the [Puppet
Server](https://github.com/puppetlabs/puppet-server) security model as
authconfig became a critical part of Puppet's security model.

## Installation

Add the following to your _leiningen_ `project.clj`:

[![Clojars Project](http://clojars.org/puppetlabs/trapperkeeper-authorization/latest-version.svg)](http://clojars.org/puppetlabs/trapperkeeper-authorization)


## Terminology

At the core of the library is the ACL. An ACL (access control list) is a list
of ACE (access control entry).

A _rule_ protects a given resource, either by exact path or by regular
expression. An ACL is attached to a rule.  When an incoming request goes
through the process of checking if it is an authorized request, or not, this
service will check if the pattern expressed in the rule matches the request and
then check if the ACL allows the request by comparing the request identity
against the list of allowed identities in the ACL.

The authorization service assumes authenticated identities are parsed from the
CN attribute of a verified SSL client certificate.

Finally, we have the top-level rules, which is an ordered list of discrete
rules.  The authorization service always processes this list in-order until it
matches an incoming request with a discrete rule.

## ACE

This library supports two types of entries:

* `allow`: if the entry matches the incoming request identity, then the request will be allowed access
* `deny`: if the entry matches the incoming request identity, then the resource access will be denied

A third type is planned, something akin to Puppet's `allow any` behavior which
is commonly used to authorize unauthenticated requests, which is common when
bootstrapping a puppet agent that does not yet possess a valid client SSL
certificate.

### Restricting access by name

This library supports those different possibilities:

* _exact name_: `www.domain.org`, only client with this exact CN will trigger a match
* _wildcard name_: `*.domain.org`, only client whose CN will be under domain.org will match
* _regex_: `(this-host|other-host)\.domain\.org`, only clients whose CN matches this regex will match
* _backreferences_: `$1.domain.org` in combination with rule set as regex

## ACL

An ACL is an ordered list of ACE.  The system works the same as Puppet,
ordering _allows_ before _deny_, and with an implicit _deny all_.

## Rules


### Rule

A `Rule` is:
* a path or a regex
* a sort-order number, which may be reused across rules
* a name, which must be unique
* an optional method (get, post, put, delete, head)
* an optional map of request query parameters
* an ACL

Using the internal DSL to build a rule is very simple:

~~~clojure
(-> (new-path-rule "/path/to/resource")
    (allow "*.domain.org"))
    (deny "*.evil.com"))
~~~

Restricting a rule with a method:

~~~clojure
(-> (new-path-rule "/path/to/resource" :get)
    (allow "*.domain.org"))
~~~

A Regex rule:

~~~clojure
(-> (new-regex-rule "(this|that)/resource")
    (allow "*.domain.org"))
~~~

Restricting a rule to requests with query parameters:

~~~clojure
(-> (new-path-rule "/path/to/resource")
    (query-param "environment" ["staging" "test"]))
~~~

### Rules

A `Rules` is a vector of `Rule`.

#### Building rules

To build a set of rule:

~~~clojure
(-> rules/empty-rules
    (rules/add-rule (-> (new-path-rule "/path/to/resource")
                  (allow "*.domain.org")))
    (rules/add-rule (-> (new-regex-rule "(this|that)-resource")
                  (allow "$1.domain.org"))))
~~~

#### Checking a request

Incoming Ring requests are matched against the list of sorted rules. When a
rule resource path (or regex) matches the request URI then the rule ACL is
checked.

The rules are sorted in ascending order based on their sort-order (e.g. a rule
with sort-order 1 will be checked before a rule with sort-order 2). When rules
have the same sort-order, they will be sorted by their name.

~~~clojure
(rules/allowed? rules request)
~~~

This returns a `AuthorizationResult`, which tells us if the request was
allowed, and if not, which rule prevented it to be allowed.

## authorization files

Alongside with the programmatic access, this service also supports
authorization files in typical Trapperkeeper configuration file formats.  This
format and specification is currently evolving, see SERVER-111 for more
information about the format and expression of authorization rules.

# Support

We use the [Trapperkeeper project on
JIRA](https://tickets.puppetlabs.com/browse/TK) for tickets on the
Trapperkeeper Authorization Service, although Github issues are welcome too.
Please note that the best method to get our attention on an issue is via JIRA.
