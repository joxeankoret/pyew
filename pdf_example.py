#!/usr/bin/env python

import os
import sys

from pyew_core import CPyew
from plugins.easygui import choicebox, fileopenbox, msgbox

def main(filename=None):
    if filename is None:
        filename = fileopenbox(msg="Select PDF file", default="*.pdf", filetypes=["*.pdf"])
        if filename is None:
            return

    pyew = CPyew(batch=True)
    pyew.loadFile(filename)

    streams = pyew.plugins["pdfilter"](pyew, doprint=True)
    if len(streams) == 0:
        msgbox(title="PDF Streams",msg="No encoded streams found")

    l = []
    l.append("About PDF Streams Viewer")
    l.append("See all streams (both encoded and unencoded)")
    for x in streams:
        l.append("Stream %d encoded with %s" % (x, streams[x]))
    l.append("Quit")

    while 1:
        c = choicebox(msg="Select one stream to view it decoded", title="Stream Viewer", choices=l)
        if c is None:
            break
        elif c.lower() == "quit":
            break
        elif c.lower().startswith("about"):
            msgbox(title="About PDF Streams Viewer",
                   msg="Example usage of the Pyew APIs to see PDF streams. Written by Joxean Koret")
        elif c.lower().startswith("see all"):
            pyew.plugins["pdfview"](pyew, doprint=False, stream_id=-1)
        else:
            stream_id = int(c.split(" ")[1])
            pyew.plugins["pdfview"](pyew, stream_id=stream_id)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        main()
    else:
        main(sys.argv[1])

