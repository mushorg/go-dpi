FROM golang:1.18

RUN curl -1sLf 'https://dl.cloudsmith.io/public/wand/libwandio/cfg/setup/bash.deb.sh' | bash
RUN curl -1sLf 'https://dl.cloudsmith.io/public/wand/libwandder/cfg/setup/bash.deb.sh' | bash
RUN curl -1sLf 'https://dl.cloudsmith.io/public/wand/libtrace/cfg/setup/bash.deb.sh' | bash
RUN curl -1sLf 'https://dl.cloudsmith.io/public/wand/libflowmanager/cfg/setup/bash.deb.sh' | bash
RUN curl -1sLf 'https://dl.cloudsmith.io/public/wand/libprotoident/cfg/setup/bash.deb.sh' | bash

RUN apt update

RUN apt -y install autoconf automake libtool git libpcap-dev libtrace4 libtrace4-dev libprotoident libprotoident-dev liblinear4 liblinear-dev

RUN git clone --branch 3.2-stable https://github.com/ntop/nDPI/ /tmp/nDPI
RUN cd /tmp/nDPI && ./autogen.sh && ./configure && make && make install && cd -

RUN mkdir -p $GOPATH/src/github.com/mushorg/go-dpi
WORKDIR $GOPATH/src/github.com/mushorg/go-dpi

ADD . .
RUN go build ./... && \
    go test ./... && \
    go test -bench=. && \
    go install ./godpi_example

ENTRYPOINT ["godpi_example"]
