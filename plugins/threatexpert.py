#!/usr/bin/env python

"""
This file is part of Pyew

Copyright (C) 2009, 2010 Joxean Koret

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""

import webbrowser
from hashlib import md5

def threatExpertSearch(pyew):
    """ Search in Threat Expert for the behavior's report """

    baseurl = "http://www.threatexpert.com/report.aspx?md5="
    buf = pyew.getBuffer()
    url = baseurl + md5(buf).hexdigest()

    webbrowser.open(url)

functions={"threat":threatExpertSearch}
