Notes:

Cloudflare TXT records have a maximum length of 2048 characters.
Cloudflare has no cost for usage.
Cloudflare has a free tier that allows for 1000 records to be created.
Cloudflare has a limit of 3500 records on paid plans.
Cloudflare has an API rate limit of 1200 requests per 5 minutes per user.
    If you exceed this limit, all API calls for the next five minutes will be blocked, receiving a HTTP 429 response.

DNFS - Domain Name File System

Functionality we want:
1. Read a file from localfs and upload it to Cloudflare TXT records
    one record per chunk
2. Download a file from Cloudflare TXT records and write it to localfs or stdout
3. Update an existing file (optional)
4. Delete an existing file
5. List all files in a directory
    a directory can be a Cloudflare TXT record with a list of file names and
    their corresponding Cloudflare TXT record IDs
6. Delete all files in a directory
7. Use a specific subdomain to store our file structure
    e.g: `dnfs.example.com` is the root of the file system and
    `*.dnfs.example.com` is a file or directory

Reading data will be done over plain DNS Lookups to `1.1.1.1` or `1.0.0.1`
Writing data will be done over the Cloudflare API
Listing data will be done over DNS lookups too.
    `ls dnfs.example.com` will return a list of files and directories in from the top-level directory
    `ls dir1.dnfs.example.com` will return a list of files and directories in `dir1`
    `cat file1.dir1.dnfs.example.com` will return the contents of `file1` in `dir1`

We want to:
1. Read an input file
2. Compress the file
3. Encrypt the file - output is a Vec<u8>
4. Split the file into chunks of 2048 characters
5. Upload the chunks to Cloudflare TXT records
6. Download the chunks from Cloudflare TXT records
7. Decrypt the chunks
8. Decompress the chunks
9. Write the output file
