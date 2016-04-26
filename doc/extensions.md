# Working with x.509 Extensions in tk-auth

When a certificate is signed, one can include arbitrary key-value pairs using x.509
extensions. To learn more about these extensions,
[here is a pretty okay overview](https://access.redhat.com/documentation/en-US/Red_Hat_Certificate_System/8.0/html/Admin_Guide/Standard_X.509_v3_Certificate_Extensions.html)
from red hat.

Actually specifying extensions in your tk-auth configuration is explained in
[the configuration docs](./authorization-config.md).

## subject-alt-name

[subject-alt-name](https://en.wikipedia.org/wiki/SubjectAltName) is an
x.509 extension that tk-auth handles differently from normal string -> string
extensions.

Specifically, when we see an incoming request, we pull out alt-names stored
under `subjectAlternativeName` on the request's certificate and store them as a
map of keyword -> string. Using this map, we do two things:

* match a certname (exact or regex) that appears in an allow/deny rule against any `:dns-name` entries
* match an explicit allow/deny extension rule for a key value pair in a `subject-alt-name` map

If so, that request is considered a match for the given allow/deny rule.

The supported `subject-alt-name` keys are:

* dns-name
* ip
* other-name
* rfc822-name
* x400-address
* directory-name
* edi-party-name
* uri
* registered-id

For example, given an `allow` rule like:


~~~~hocon
authorization: {
    version: 1
    rules: [
            {
                match-request: {...}
                allow: {
                    extensions: {
                        subject-alt-name: {
                            ip: "192.168.1.0"
                            dns-name: ["foo.bar.org" "baz.bar.org"]
                        }
                    }
                }
                sort-order: 1
                name: "my path"
            }
    ]
}
~~~~

A cert with IP "192.168.1.10" signed as its ip subjectAlternativeName and either
"foo.bar.org" or "baz.bar.org" would be allowed.
