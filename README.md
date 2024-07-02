![Static Badge](https://img.shields.io/badge/unsafe-forbidden-red)

Notes:

Cloudflare TXT records have a maximum length of 2048 characters.
Cloudflare has no cost for usage.
Cloudflare has a free tier that allows for 1000 records to be created.
Cloudflare has a limit of 3500 records on paid plans.
Cloudflare has an API rate limit of 1200 requests per 5 minutes per user.
    If you exceed this limit, all API calls for the next five minutes will be blocked, receiving a HTTP 429 response.

DNFS - Domain Name File System

Functionality we want:
- [x] Read a file from localfs and upload it to Cloudflare TXT records
    one record per chunk
- [x] Download a file from Cloudflare TXT records and write it to localfs or stdout
- [x] Update an existing file (optional)
- [x] Delete an existing file
- [x] List all files in a domain
- [x] Delete all files in a domain (purge)
- [x] Compression (maybe [snap](https://crates.io/crates/snap)?)
- [ ] Encryption (symmetric or maybe asymmetric via [x25519-dalek](https://crates.io/crates/x25519-dalek)?)

We want to:
1. Read an input file
2. Compress the file
3. Encrypt the file - output is a `Vec<u8>`
4. Split the file into chunks of 2048 characters
5. Upload the chunks to Cloudflare TXT records
6. Download the chunks from Cloudflare TXT records
7. Decrypt the chunks
8. Decompress the chunks
9. Write the output file

https://datatracker.ietf.org/doc/html/rfc1035

Records will be structured as such:
* `file.dnfs.example.com` - `v=DNFS1 chunks=<number of chunks> size=<size of each chunk> hash=<SHA256 of full content>`
* `chunk0.file.dnfs.example.com` - `"<first 255 characters>" "<next 255 characters>" ... "<last characters of chunk>"`
* `chunk1.file.dnfs.example.com` - `"<first 255 characters>" "<next 255 characters>" ... "<last characters of chunk>"`
* `meta.file.dnfs.example.com` - optional metadata about the file
    * Title - title of the file
    * Description - description of the file
    * Author - author of the file
    * Created - date the file was created
    * Mime - MIME type of the file
    * Extension - file extension
