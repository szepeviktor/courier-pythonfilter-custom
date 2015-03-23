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

import unittest
import courier.config


class TestModuleConfig(unittest.TestCase):
    
    def testLoader(self):
        courier.config._standardConfigPaths = './configfiles/pythonfilter-modules.conf'
        config = courier.config.getModuleConfig('test1')
        self.assertEqual(config['name1'], 'value1')
        self.assertEqual(config['name2'], 'value2')
        self.assertEqual(config.has_key('name3'), False)
        self.assertEqual(config.has_key('name4'), False)
        self.assertEqual(config.has_key('atuple'), False)
        self.assertEqual(config.has_key('alist'), False)
        self.assertEqual(config.has_key('adict'), False)

        config = courier.config.getModuleConfig('test2')
        self.assertEqual(config['name3'], 'value3')
        self.assertEqual(config['name4'], 'value4')
        self.assertEqual(config.has_key('name1'), False)
        self.assertEqual(config.has_key('name2'), False)
        self.assertEqual(config.has_key('atuple'), False)
        self.assertEqual(config.has_key('alist'), False)
        self.assertEqual(config.has_key('adict'), False)

        config = courier.config.getModuleConfig('test3')
        self.assertEqual(config.has_key('name1'), False)
        self.assertEqual(config.has_key('name2'), False)
        self.assertEqual(config.has_key('name3'), False)
        self.assertEqual(config.has_key('name4'), False)
        self.assertEqual(type(config['atuple']), tuple)
        self.assertEqual(config['atuple'], (1,2,3))
        self.assertEqual(type(config['alist']), list)
        self.assertEqual(config['alist'], [1,2,3])
        self.assertEqual(type(config['adict']), dict)
        self.assertEqual(config['adict']['dict1'], 'dictval1')
        self.assertEqual(config['adict']['dict2'], 'dictval2')


    def testApply(self):
        courier.config._standardConfigPaths = './configfiles/pythonfilter-modules.conf'
        config = {}
        courier.config.applyModuleConfig('test1', config)
        self.assertEqual(config['name1'], 'value1')
        self.assertEqual(config['name2'], 'value2')
        self.assertEqual(config.has_key('name3'), False)
        self.assertEqual(config.has_key('name4'), False)
        self.assertEqual(config.has_key('atuple'), False)
        self.assertEqual(config.has_key('alist'), False)
        self.assertEqual(config.has_key('adict'), False)

        config = {}
        courier.config.applyModuleConfig('test2', config)
        self.assertEqual(config['name3'], 'value3')
        self.assertEqual(config['name4'], 'value4')
        self.assertEqual(config.has_key('name1'), False)
        self.assertEqual(config.has_key('name2'), False)
        self.assertEqual(config.has_key('atuple'), False)
        self.assertEqual(config.has_key('alist'), False)
        self.assertEqual(config.has_key('adict'), False)

        config = {}
        courier.config.applyModuleConfig('test3', config)
        self.assertEqual(config.has_key('name1'), False)
        self.assertEqual(config.has_key('name2'), False)
        self.assertEqual(config.has_key('name3'), False)
        self.assertEqual(config.has_key('name4'), False)
        self.assertEqual(type(config['atuple']), tuple)
        self.assertEqual(config['atuple'], (1,2,3))
        self.assertEqual(type(config['alist']), list)
        self.assertEqual(config['alist'], [1,2,3])
        self.assertEqual(type(config['adict']), dict)
        self.assertEqual(config['adict']['dict1'], 'dictval1')
        self.assertEqual(config['adict']['dict2'], 'dictval2')


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestModuleConfig)
    unittest.TextTestRunner(verbosity=2).run(suite)
