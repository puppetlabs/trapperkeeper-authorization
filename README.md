# Trapperkeeper-authorization

This clojure project is an authorization library for PuppetLabs Trapperkeeper based products.
It aims to port Puppet's `auth.conf` feature to clojure, along with a different way to express
authorization rules.

The core of this library is a system to express host-based authorization rules to access resources and
to check incoming requests against them.

## Terminology

At the core of the library is the ACL. An ACL (access control list) is a list of ACE (access control entry).
There are several types of ACE. 

Then we have the rule. A rule protects a given resource (either by exact path or by regex). An ACL is attached to a rule. 
When one need to check if an incoming request is allowed, this library will check the rule path matches the request and 
then check the ACL allows the request (by name and/or ip address).

Then we have the rules which are an list of individual rules.

## ACE

This library supports several 4 types of entries:

* allow: if the entry matches the incoming request host name, then the request will be allowed access
* allow-ip: if the entry matches the incoming IP address, then the request will be allowed access
* deny: if the entry matches the incoming request host name, then the resource access will be denied
* deny-ip: if the entry matches the incoming request IP address, then the resource access will be denied

### Restricting access by name

This library supports those different possibilities:
* _exact name_: `www.domain.org`, only host with this exact name will trigger a match
* _wildcard name_: `*.domain.org`, only hosts whose name will be under domain.org will match
* _regex_: '(this-host|other-host)\.domain\.org', only hosts whose name matches this regex will match
* _backreferences_: '$1.domain.org', in combination with rule set as regex

### Restricting access by IP addresses

The library supports both IPv6 and IPv4.
* _exact IP_: '192.168.1.1', only this IP address will match
* _ip network_: '192.168.0.0/24', only IP in this network will match
* _wildcard ip_: '192.168.*', only IP in 192.168.0.0/16 will match

## ACL

An ACL is an ordered list of ACE.
The system works the same as Puppet, ordering _allows_ before _deny_, and with an implicit _deny all_.

## Rules


### Rule

A `Rule` is:
* a path or a regex
* an optional method (get, post, put, delete, head)
* an ACL

Using the internal DSL to build a rule is very simple:

```Clojure
(-> (new-path-rule "/path/to/resource")
    (allow-ip "192.168.0.0/24")
    (allow "*.domain.org"))
```

Restricting a rule with a method:

```Clojure
(-> (new-path-rule "/path/to/resource" :get)
    (allow "*.domain.org"))
```

A Regex rule:
```Clojure
(-> (new-regex-rule "(this|that)/resource")
    (allow "*.domain.org"))
```

### Rules

A `Rules` is a list of `Rule`.

#### Building rules

To build a set of rule:

```Clojure
(-> empty-rules
    (add-rule (-> (new-path-rule "/path/to/resource")
                  (allow "*.domain.org")))
    (add-rule (-> (new-regex-rule "(this|that)-resource")
                  (allow "$1.domain.org"))))
```

#### Checking a request

Incoming Ring requests are matched against the list of rules (in insertion order), when a rule resource path (or regex)
matches the request URI then the rule ACL is checked.

```Clojure
(allowed? rules request)
```

This returns a `AuthorizationResult`, which tells us if the request was allowed, and if not, which rule prevented it 
to be allowed.


## authorization files

Alongside with the programmatic access, this library also supports authorization files in two formats:
* [HOCON](https://github.com/typesafehub/config#using-hocon-the-json-superset)
* [Puppet's auth.conf](https://docs.puppetlabs.com/guides/rest_auth_conf.html)

### HOCON

The format must obey:

```
rules = [
  {
    path: /path/to/resource
    type: path
    allow: [ "*.domain.org", "*.test.com" ]
    allow-ip: "192.168.0.0/24"
    deny: "bad.guy.com"
    deny-ip: "192.168.1.0/24"
  },
  {
    type: regex
    path: "(incoming|outgoing)"
    allow: "www.domain.org"
  }
  ]
```

To load and use an HOCON authorization file:

```Clojure
  (-> (io/file file-path)
      (ConfigFactory/parseFileAnySyntax)
      (config/config->rules))
```

This returns a `Rules`.

### Auth.conf format

This isn't yet supported.



