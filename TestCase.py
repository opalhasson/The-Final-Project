import unittest
import os
import re
from os.path import join
import requests
import platform
from NVDsearch import componentsOnPC
from torSearch import CVEsInTOR

# Specify the base directory where you want to store the downloaded and extracted files

class TestCase(unittest.TestCase):

    def test_NVDdownload(self):
        if not os.path.exists('nvdTEST'):
            os.makedirs('nvdTEST')

        r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
        for filename in re.findall("nvdcve-1.1-202[1-3]\.json\.zip", r.text):
            print(filename)

            r_file = requests.get("https://static.nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
            with open(join('nvdTEST', filename), 'wb') as f:
                for chunk in r_file:
                    f.write(chunk)

        dir = os.listdir('nvdTEST')
        print(dir)
        self.assertNotEqual(len(dir), 0)

    def test_scanComponentsOnPC(self):
        componentsOnPC(platform.system())
        result = os.path.exists("components_on_pc.txt")
        self.assertEqual(result, True)

    def test_DebianForumScan(self):
        CVEsInTOR()
        result = os.path.exists("forum.txt")
        self.assertEqual(result, True)




# Run the tests
if __name__ == '__main__':
    unittest.main()
