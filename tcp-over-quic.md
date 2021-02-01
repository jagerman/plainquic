# "liblokinet" TCP-over-QUIC

In order for lokinet to work in an embedded version (which I will call "liblokinet" in this
document), which lokinet cannot create TUN device (either because the host OS doesn't support them,
or because lokinet needs to run without permissions to manage them) lokinet needs a solution for
sending TCP data from the device to a remote lokinet client (i.e. a snapp, a snode, or another
liblokinet client).  Since the vast majority of network connectivity relies on TCP stream
connections, not supporting them would be a severe limitation of a lokinet library that would make
it nearly useless.

Traditional "full" lokinet does not need to solve this problem: it creates virtual IPs on the TUN
interface that map to every looked-up `.loki` address and then the host system's in-kernel TCP layer
handles the intricacies of TCP including acknowledgement, retry, and so on.  While there are
user-space TCP implementations available, they are generally incomplete, unmaintained, or both,
which would mean substantial work and ongoing maintenance for us to adopt or reimplement such a
user-space TCP layer, for which we would most likely be the only user and contributor.

Instead this proposal is for lokinet to support a tunneled TCP stream mode where TCP traffic is
carried over lokinet via a subset of the
[QUIC](https://datatracker.ietf.org/doc/draft-ietf-quic-transport/) protocol.  Unlike TCP, QUIC has
several well-maintained user-space implementations which allow us to use, rather than create, a
well-maintained QUIC implementation.

## Overview

The high-level strategy of how we handle such a stream connection is to have TCP connections
established only within the local device.  A liblokinet application would invoke a lokinet call to
establish such a connection to proxy to a remote host by lokinet name and TCP port.  This would
first establish a lokinet connection to the remote host, then open a QUIC connection over it and
start listening for TCP connections on a local port.  When a new TCP connection is established on
this port lokinet will establish a new QUIC stream over the existing connection, specifying the
destination port while initializing the stream.  (The client is free to establish as many TCP
connections as it wants: each one becomes a separate QUIC stream).

The situation is similar for the receiving lokinet client: it would listen for incoming QUIC
connections on the local lokinet IP and, when establishing a QUIC stream, would establish a local
TCP connection to the requested port on the lokinet IP.  Any incoming stream data is then forwarded
into this TCP connection, and any responses are sent back via the QUIC stream.

## Example

For example, suppose `snap7.loki` is a lokinet snapp with a web server listening on port 80 and a
liblokinet client `omg42.loki` wants to connect to it to retrieve a cat photo.  With a full
lokinet client, the DNS request for `omg56789.loki` triggers creation of a virtual IP on the TUN
device, returns the IP to the system, and any TCP packets sent to this IP are forwarded to the
primary lokinet IP of `azfoj123.loki`, where an HTTP server is ready and waiting to provide cat
photos.

With a liblokinet client, this process will looks a little different: the client will first make a
call to the liblokinet library (rather than a DNS request) specifying the lokinet host name and TCP
port it wants to connect to (note that this is pseudo-code; the actual implementation calls will
have to deal with various details such as connection delays and timeouts that are omitted here):

    result = lokinet_stream_connect(lokinet_addr, port)
    if result->connection_established:
        http_get("http://" + result->local_address + ":" + result->local_port + "/cat.jpg")

Here `http_get` would need no knowledge of lokinet at all: it will simply connect via TCP to an
address such as `127.0.0.1:4716` for the HTTP request.  It will send the request, and receive it,
over this localhost TCP socket.

Internally, lokinet will have established a QUIC connection to the remote host, and started
listening for TCP connections on the localhost port.  When `http_get` establishes a TCP connection
on this local port it will create a QUIC stream on the established QUIC connection and forward all
stream data received from the TCP connection into the QUIC stream, and any data that comes back over
the QUIC stream will similarly be copied into the localhost TCP connection.

Effectively the data path of data send from the app on omg42.loki to the HTTP snapp on omg42.loki
looks like this:

    ┌omg42.loki────────────┐                             ┌omg42.loki───────────┐
    │ Main app thread      │                             │ HTTP                │
    │ TCP localhost:4567 ─>│─┐                           │ TCP 172.16.0.1:80 <─│─┐
    ├──────────────────────┤ │                           ╞═════════════════════╡ │
    │ liblokinet (in app)  │ │                           │ lokinet (on host)   │ │
    │ TCP localhost:4567 <─│─┘                         ┌>│─> QUIC UDP          │ │
    │           QUIC UDP ─>│───... Lokinet routers ...─┘ │ TCP 172.16.0.1:80 ─>│─┘
    └──────────────────────┘                             └─────────────────────┘

(These connections are all bi-direction, so any TCP stream data replied from omg42.loki follows the
same path in reverse.)


