#!/usr/bin/python
# pythonfilter -- A python framework for Courier global filters
# Copyright (C) 2006  Gordon Messmer <gordon@dragonsdawn.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

import os
import unittest
import time
import courier.config
import TtlDb


class TestTtlDb(unittest.TestCase):
    
    def setUp(self):
        os.mkdir('tmp')
        os.mkdir('tmp/pythonfilter')

    def tearDown(self):
        os.system('rm -rf tmp')

    def testdbm(self):
        courier.config._standardConfigPaths = './configfiles/pythonfilter-modules.conf'
        db = TtlDb.TtlDb('testTtlDb', 1, 1)
        db.purge()
        db.lock()
        value1 = time.time()
        db['name1'] = value1
        db.unlock()
        self.assertEqual(db.has_key('name1'), True)
        self.assertEqual(int(db['name1']), int(value1))
        time.sleep(2)
        value2 = time.time()
        db['name2'] = value2
        db.purge()
        self.assertEqual(db.has_key('name1'), False)
        self.assertEqual(db.has_key('name2'), True)
        self.assertEqual(int(db['name2']), int(value2))


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestTtlDb)
    unittest.TextTestRunner(verbosity=2).run(suite)
