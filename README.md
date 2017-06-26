[![Build Status](https://travis-ci.org/mushorg/go-dpi.svg?branch=master)](https://travis-ci.org/mushorg/go-dpi)
[![Coverage Status](https://coveralls.io/repos/github/mushorg/go-dpi/badge.svg?branch=master)](https://coveralls.io/github/mushorg/go-dpi?branch=master)
[![](https://godoc.org/github.com/mushorg/go-dpi?status.svg)](https://godoc.org/github.com/mushorg/go-dpi)

# go-dpi

go-dpi is an open source Go library for application layer protocol identification of traffic flows. In addition to its own heuristic methods, it contains wrappers for other popular and well-established libraries that also perform protocol identification, such as nDPI and libprotoident. It aims to provide a simple, easy-to-use interface and the capability to be easily extended by a developer with new detection methods and protocols.

It attempts to classify flows to different protocols regardless of the ports used. This makes it possible to detect protocols on non-standard ports, which is ideal for honeypots, as malware might often try and throw off detection methods by using non-standard and unregistered ports. Also, with its layered architecture, it aims to be fast in its detection, only using heavier classification methods when the simpler ones fail.

It is being developed in the context of the Google Summer of Code 2017 program, under the mentorship of The Honeynet Project.

go-dpi is available under the MIT license and distributed in source code format.

Please read the project's [Wiki page](https://github.com/mushorg/go-dpi/wiki) for more information.
