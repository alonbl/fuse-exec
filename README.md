# fuse-exec

A simple dynamic filesystem in which every file is created by the output of a
program.

A shadow directory is provided, each file in shadow directory is a script, the
filesystem will expose an entry per script, opening the entry will execute the
script and will provide the output as the file content.

NOTE: The shadow directory must be provided as full path.

NOTE: When using fuse-2 the `-o direct_io` must be provided.
