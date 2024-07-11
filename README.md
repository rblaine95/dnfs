## Domain Name File System (DNFS): The Document Store Nobody Asked For
#### When you absolutely, positively need to misuse DNS, because FTP was just too practical.

![Static Badge](https://img.shields.io/badge/unsafe-forbidden-red)

This project is _heavily_ inspired by Dr Tom Murphy's "_Harder Drive: Hard drives we didn't want or need_" [video on Youtube](https://youtu.be/JcJSW7Rprio) and the subsequent [SIGBOVIK 2022 paper](http://tom7.org/papers/murphy2022harder.pdf).

Functionality we have:
- [x] Read a file from localfs and upload it to Cloudflare as TXT records one record per chunk
- [x] Download a file from DNS TXT records and write it stdout
- [x] Update an existing file
- [x] Delete an existing file
- [x] List all files in a domain
- [x] Delete all files in a domain (purge)
- [x] Compression ([snap](https://crates.io/crates/snap))
- [x] Parallel Uploads and Deletes
- [x] Encryption (AES-256 via [magic-crypt](https://crates.io/crates/magic-crypt))

Example - uploading and reading [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)
```sh
$ ./dnfs upload ./rfc1035.txt
2024-07-04T13:01:28.464241Z  INFO dnfs::helpers: Writing TXT record: "rfc1035.dnfs.bunkerlab.net"
2024-07-04T13:01:30.082295Z  INFO dnfs::helpers: Writing TXT record: "chunk0.rfc1035.dnfs.bunkerlab.net"
2024-07-04T13:01:30.083282Z  INFO dnfs::helpers: Writing TXT record: "chunk1.rfc1035.dnfs.bunkerlab.net"
2024-07-04T13:01:30.083687Z  INFO dnfs::helpers: Writing TXT record: "chunk2.rfc1035.dnfs.bunkerlab.net"
2024-07-04T13:01:30.084066Z  INFO dnfs::helpers: Writing TXT record: "chunk3.rfc1035.dnfs.bunkerlab.net"
[...]
2024-07-04T13:01:40.688690Z  INFO dnfs::helpers: Writing TXT record: "chunk29.rfc1035.dnfs.bunkerlab.net"
2024-07-04T13:01:40.717044Z  INFO dnfs::helpers: Writing TXT record: "chunk30.rfc1035.dnfs.bunkerlab.net"
2024-07-04T13:01:41.140325Z  INFO dnfs::helpers: Writing TXT record: "chunk31.rfc1035.dnfs.bunkerlab.net"
2024-07-04T13:01:42.169609Z  INFO dnfs::helpers: Writing TXT record: "chunk32.rfc1035.dnfs.bunkerlab.net"
2024-07-04T13:01:42.179387Z  INFO dnfs::helpers: Writing TXT record: "chunk33.rfc1035.dnfs.bunkerlab.net"
File successfully uploaded - rfc1035.dnfs.bunkerlab.net

$ ./dnfs download rfc1035.dnfs.bunkerlab.net
Network Working Group                                     P. Mockapetris
Request for Comments: 1035                                           ISI
                                                           November 1987
Obsoletes: RFCs 882, 883, 973

            DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION


1. STATUS OF THIS MEMO

This RFC describes the details of the domain system and protocol, and
assumes that the reader is familiar with the concepts discussed in a
companion RFC, "Domain Names - Concepts and Facilities" [RFC-1034].

The domain system is a mixture of functions and data types which are an
official protocol and functions and data types which are still
experimental.  Since the domain system is intentionally extensible, new
data types and experimental behavior should always be expected in parts
of the system beyond the official protocol.  The official protocol parts
include standard queries, responses and the Internet class RR data
formats (e.g., host addresses).  Since the previous RFC set, several
definitions have changed, so some previous definitions are obsolete.
```

Records will be structured as such:
* `file.dnfs.example.com` - `v=dnfs1 chunks=<number of chunks> size=<total size of file in bytes> hash=<SHA256 of full content>, mime=<file mimetype> extension=<file extension>`
* `chunk0.file.dnfs.example.com` - `<"<first 255 characters>" "<next 255 characters>" ... "<last characters of chunk>">`
* `chunk1.file.dnfs.example.com` - `<"<first 255 characters>" "<next 255 characters>" ... "<last characters of chunk>">`
* `chunkn.file.dnfs.example.com` - `<"<first 255 characters>" "<next 255 characters>" ... "<last characters of chunk>">`

## Hack-job Disclaimer
To say this codebase is a hack-job is putting it lightly.

I wrote this, pretty much, as a joke and paid little to no attention to best practices, security, or even good code.

If you are reading this, please do not use this code in production.
In fact, please just don't use this code at all.

Please judge me lightly for the sins I have committed.
