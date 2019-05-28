[![Build Status](https://travis-ci.org/tomsanbear/xpf.svg?branch=master)](https://travis-ci.org/tomsanbear/xpf) [![codecov](https://codecov.io/gh/tomsanbear/xpf/branch/master/graph/badge.svg)](https://codecov.io/gh/tomsanbear/xpf)


# CoreDNS XPF

This coredns plugin appends an XPF record to the DNS request, containing the Source & Destination Address & Port. This aims to allow you to use CoreDNS as a DNS proxy, while still passing client information through for audit/analysis purposes.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. 

### Prerequisites

- Go 1.12 or later
- Go modules should be enabled

### Installing

1. First clone the CoreDNS repository [CoreDNS](https://github.com/coredns/coredns)
2. Add ```xpf:github.com/tomsanbear/xpf``` to the plugins.cfg file within the repo (IMPORTANT NOTE: this must appear before any other resolving plugin you may be using. See below for more details)
3. Build the binary with 'make', or if you are building on OSX and want to target a linux docker container 'GOOS=linux make'

Plugin Note:
Due to the way the server chains plugins, you need to ensure that any plugin that comes after this one, in the plugin.cfg, does not care about the record being there. See the plugins.cfg file comments for more detail.

### Corefile Configuration

Example usage within a Corefile:
```
.:53 {
    xpf {
        rr_type 65422
    }
    forward . 8.8.8.8
}
```
Note: Do consider the security risks of forwarding this record to the upstream server. You (should) only be doing this for internal resolvers

## Running the tests

Test coverage is still a little lacking, but I'm looking to get the full thing tested, with performance metrics as well in the future. 

Just run ```go test ./...``` for the main suite, and 

### Code Style Tests

Enforcing style with the <em>golangci-lint</em> tool

## Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/tomsanbear/xpf/tags). 

## Authors

* **Thomas Santerre** - *Initial work* - [tomsanbear](https://github.com/tomsanbear)

See also the list of [contributors](https://github.com/tomsanbear/xpf/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* [CoreDNS](https://github.com/coredns/coredns) for being a great DNS server/project
* [Ray Bellis](https://github.com/raybellis) for the initial draft on [DNS XPF](https://www.ietf.org/archive/id/draft-bellis-dnsop-xpf-04.txt)
* [PurpleBooth](https://github.com/PurpleBooth) for the nice Readme template
