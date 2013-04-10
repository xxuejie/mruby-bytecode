#mruby-bytecode

Parse [mruby](https://github.com/mruby/mruby) bytecode into Ruby data structures for visualization or manipulation uses.

This project will be written in the compatible part between mruby and CRuby. As a result, the following two parts can be derived:

* A CRuby gem used to parse mruby bytecode. A CMD program should also be included in this gem.

* A mrbgem to parse mruby bytecode inside of mruby. Note currently mruby requires us to dump bytecode into a `FILE*`. If we can work around this restriction, we will be able to parse mruby source code, dump bytecode and then parse the bytecode all inside of mruby.
