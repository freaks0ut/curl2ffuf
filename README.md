# curl2ffuf

`curl2ffuf` converts curl requests (e.g. exported from Burp Suite) into ready-to-use ffuf fuzzing commands.

Built for web pentesting, bug bounty and CTF workflows.

## Features

- GET and POST support
- Headers, cookies and body preserved
- Works with Burp / ANSI-C quoting (`$'...'`)
- Shell-safe output (no variable expansion issues)
- Query and body parameter fuzzing
- Simple CLI with `-h` help

## Installation

```git clone https://github.com/<your-user>/curl2ffuf.git
cd curl2ffuf
chmod +x curl2ffuf.py```

Optional:
`sudo ln -s $(pwd)/curl2ffuf.py /usr/local/bin/curl2ffuf`

## Usage

`curl2ffuf '<curl command>' [options]`

Help:
curl2ffuf -h

## Examples

GET:
`curl2ffuf 'curl "https://target/search?q=test&lang=en"'`

POST:
`curl2ffuf 'curl -X POST https://target/login -d "user=admin&pass=admin"'`

Burp export:
`curl2ffuf "curl -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' -b $'PHPSESSID=abc123' --data-binary $'q=test' $'http://target/search.php'"`

Fuzz specific parameter:
`curl2ffuf 'curl "https://target/search?q=test&lang=en"' -p q`

Custom wordlist:
`curl2ffuf 'curl -X POST https://target/login -d "user=admin&pass=admin"' -p pass -w rockyou.txt`

## Options

-h, --help        show help  
-w, --wordlist    ffuf wordlist (default: wordlist.txt)  
-p, --param       parameter to fuzz  

## Notes

- ffuf flag order does not matter
- Tool prints a command, it does not execute ffuf
- Use only on systems you are authorized to test

## License

MIT
