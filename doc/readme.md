# Trapperkeeper Authorization

This is the documentation for Trapperkeeper Authorization (fondly referred to as
`tk-auth`).

The goal of this project is to allow x.509 certificate-based authorization for
[Trapperkeeper](https://github.com/puppetlabs/trapperkeeper) applications. You
would use this project if, for example, you are setting up relationships between
servers in your data center or cluster.

Setting up a certificate authority is beyond the scope of this project. Use of
tk-auth assumes you have your CA stuff all figured out and working happily. Of
course, you could use self-signed certificates if you wanted.

* [Configuration](./authorization-config.md)
* [Working with x.509 Extensions](./extensions.md)
