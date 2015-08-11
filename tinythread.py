#!/usr/bin/env python
"""
The MIT License (MIT)

Copyright (c) 2015 Christian Uhsat <christian@uhsat.de>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import base64
import binascii
import os
import re
import sys


try:
    import requests
except ImportError:
    sys.exit("Requires Requests (https://github.com/kennethreitz/requests)")


try:
    from Crypto import Random
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA512
except ImportError:
    sys.exit("Requires PyCrypto (https://github.com/dlitz/pycrypto)")


__all__, __version__ = ["TinyThread"], "0.2.1"


class TinyThread(object):
    """
    Chain links hidden messages to threads using TinyURL as a key/value store.
    """
    SALT = b"[USE YOUR OWN SALT]"

    class Chunk(object):
        """
        Thread chunk consisting of link and data.
        """
        def __init__(self, link, data=b""):
            """
            Inits the chunk with the parsed data.
            """
            digest = SHA512.new(TinyThread.SALT + link).digest()

            self.alias = binascii.hexlify(digest)[:30].decode("ascii")
            self.key = digest[:32]
            self.iv = digest[-16:]
            self.data = data

        def follow(self):
            """
            Follows this chunks link to next chunk.
            """
            url = "http://tinyurl.com/" + self.alias

            response = requests.get(url, allow_redirects=False)

            if response.status_code == 301:
                data = response.headers["location"].split("#")[-1]
                data = base64.urlsafe_b64decode(data)
                data = AES.new(self.key, AES.MODE_CFB, self.iv).decrypt(data)

                return TinyThread.Chunk(data[:16], data[16:])

        def append(self, message):
            """
            Appends a new chunk to this one.
            """
            url = "http://tinyurl.com/create.php"

            data = Random.get_random_bytes(16) + message
            data = AES.new(self.key, AES.MODE_CFB, self.iv).encrypt(data)
            data = b"#" + base64.urlsafe_b64encode(data)

            requests.post(url, params={"alias": self.alias, "url": data})

    def __init__(self, thread):
        """
        Inits the used thread.
        """
        self.chunks = [self.Chunk(thread.encode("utf-8"))]
        self.update()

    def update(self):
        """
        Updates the thread state.
        """
        while True:
            chunk = self.chunks[-1].follow()

            if chunk:
                self.chunks.append(chunk)
            else:
                break

    def read(self):
        """
        Returns all messages in this thread.
        """
        messages = [chunk.data.decode("utf-8") for chunk in self.chunks]

        return "\n".join(messages).strip()

    def post(self, message):
        """
        Adds a new message to the thread.
        """
        self.chunks[-1].append(message.encode("utf-8"))
        self.update()


def main(script, arg="--help", *args):
    """
    Usage: %s [option|thread] [message...]

    Options:
      -h --help      Shows this text
      -l --license   Shows license
      -v --version   Shows version

    Report bugs to <christian@uhsat.de>
    """
    try:
        script = os.path.basename(script)

        if arg in ("/?", "-h", "--help"):
            print(re.sub("(?m)^ {4}", "", main.__doc__ % script).strip())

        elif arg in ("-l", "--license"):
            print(__doc__.strip())

        elif arg in ("-v", "--version"):
            print("TinyThread " + __version__)

        else:
            thread = TinyThread(arg)

            if args:
                thread.post(" ".join(args))

            print(thread.read())

    except Exception as ex:
        return "%s error: %s" % (script, ex)


if __name__ == "__main__":
    sys.exit(main(*sys.argv))
