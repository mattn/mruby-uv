mruby-uv
========

interface to libuv for mruby(experimental)

License
-------

MIT

libuv
-----

Current mruby-uv use [libuv-v1.0.0](http://libuv.org/dist/v1.0.0/libuv-v1.0.0.tar.gz).
In Windows mruby-uv doesn't provide libuv builder so install it before you use this.
In OS X install it with `brew install libuv --devel` to reduce build time.

Compiling libuv requires `automake` and `libtool` to be installed on the system.
You can install them on OS X with `brew install automake libtool`.
