FROM golang:1.7.4
RUN echo "deb http://packages.wand.net.nz trusty main" | tee -a /etc/apt/sources.list
RUN apt-get update
RUN apt-get -y --force-yes install autoconf automake libtool git libpcap-dev libtrace4 libtrace4-dev libprotoident libprotoident-dev liblinear1 liblinear-dev
RUN go get github.com/Masterminds/glide
RUN git clone --branch 2.0-stable https://github.com/ntop/nDPI/ /tmp/nDPI
RUN cd /tmp/nDPI && ./autogen.sh && ./configure && make && make install && cd -

RUN mkdir -p $GOPATH/src/github.com/mushorg/go-dpi
WORKDIR $GOPATH/src/github.com/mushorg/go-dpi
ADD . .
RUN glide install && \
    glide update && \
    echo $GO_DIRS | xargs go test -bench=. && \
    go install ./godpi_example

ENTRYPOINT ["godpi_example"]
