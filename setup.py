#!/usr/bin/python

import glob
import os
import sys
from distutils.core import setup

setup(name="courier-pythonfilter",
      version="1.8",
      description="Python filtering architecture for the Courier MTA.",
      author="Gordon Messmer",
      author_email="gordon@dragonsdawn.net",
      url="http://www.dragonsdawn.net/~gordon/courier-pythonfilter/",
      license="GPL",
      scripts=['pythonfilter', 'pythonfilter-quarantine', 'dropmsg'],
      packages=['courier', 'pythonfilter'],
      package_dir={'pythonfilter': 'filters'},
      data_files=[('/etc/', ['pythonfilter.conf',
                             'pythonfilter-modules.conf'])]
     )
