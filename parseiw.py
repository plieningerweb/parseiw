#!/usr/bin/env python
#
# Script to parse the output of iw scan command into a table
#
# yh0- 2011-2015 <yysjryysjr DOT gmail DOT com>
#
# Licence: GPLv3 
#
# Inspired from iwlist scan parser by Hugo Chargois - 17 jan. 2010, links:
# - https://bbs.archlinux.org/viewtopic.php?pid=689963
# - https://bbs.archlinux.org/viewtopic.php?pid=737357
#
# Special thanks to jookey
#

from __future__ import with_statement

__author__ = 'Yahya Sjahrony "yh0-"'
__email__ = 'yysjryysjr@gmail.com'
__website__= ''
__version__ = '0.4'
__file__ = 'parseiw.py'
__data__ = 'A class for parsing iw scan command output'
__licence__ = 'GPLv3'

import os
import sys
import subprocess
import re
import time
import datetime
import traceback
import argparse

class iwScanParse:
    """
    Class for parsing iw scan command output
    """
    def __init__(self, dev=None, infile=None, bssid=None, logfile=None,
                 cont=False, more=False, oui=None, iw=None):
        """
        intialization
        """
        self.dev = dev
        self.infile = infile
        self.bssid = bssid
        self.more = more
        self.cont = cont
        self.oui = oui
        self.iw_path = iw
        self.iw = None
        self.full_path = os.path.dirname(os.path.abspath(__file__))
        self.logfile = logfile or "%s.log" % os.path.join(self.full_path, 
                                              os.path.basename(__file__))
        self.oui_url = (""
            "http://standards.ieee.org/develop/regauth/oui/oui.txt")
        self.oui_path = [
            "/etc/aircrack-ng/airodump-ng-oui.txt",
            "/usr/local/etc/aircrack-ng/airodump-ng-oui.txt",
            "/usr/share/aircrack-ng/airodump-ng-oui.txt",
            "/var/lib/misc/oui.txt",
            "/usr/share/misc/oui.txt",
            "/var/lib/ieee-data/oui.txt",
            "/usr/share/ieee-data/oui.txt",
            "/etc/manuf/oui.txt",
            "/usr/share/wireshark/wireshark/manuf/oui.txt",
            "/usr/share/wireshark/manuf/oui.txt"
        ]

        self.phydev = "null"
        self.bss_status = ""

        #XXX
        if not (self.dev or self.infile or self.bssid):
            raise Exception("dev/infile/bssid not set")
        if (self.dev and self.infile) is not None:
            raise Exception("dev and infile are both set")
        else:
            if self.infile:
                if self.bssid:
                    if not isinstance(self.infile, str):
                        raise Exception("infile: need str")
                    return
                else:
                    if not isinstance(self.infile, list):
                        raise Exception("infile: need list")
            elif self.bssid:
                if not os.path.isfile(self.logfile):
                    #raise Exception("%s does not exist"%self.logfile)
                    with open(self.logfile, "a"):
                        os.utime(self.logfile, None)
                with open(self.logfile, "r") as f:
                    self.infile = f.read()
                self.bssid = bssid
                return

        if self.infile and self.cont:
            self.cont = False

        # OUI init
        if self.oui is not None:
            self.oui_path.append(self.oui)
        oui = None
        for path in self.oui_path:
            if os.path.isfile(path):
                oui = path

        if oui is None:
            raise IOError("IEEE OUI file not found. OUI file can be " 
                          "downloaded from this link:\n%s" % self.oui_url)
        self.ouiTxt = oui
        self.ouiRaw = self.ouiOpen()
        self.oui_company = self.ouiParse()
        #sys.exit()
        # DEV init
        if self.dev is not None: # iw check
            iw_found = False
            if os.path.isfile("%s/iw" % self.iw_path):
                proc_iw = subprocess.Popen(['%s/iw' % self.iw_path,
                                            '--version'],
                                            stdout=subprocess.PIPE)
                if "iw version" in proc_iw.communicate()[0]:
                    iw_found = True
                    self.iw = "%s/iw" % self.iw_path

            if not iw_found:
                try:
                    proc_iw = subprocess.Popen(['iw'], stdout=subprocess.PIPE)
                except OSError:
                    raise OSError("iw not found. Please install it from"
                                  "your distro's package manager.")
                self.iw = "iw"

            try: #XXX
                with open("/sys/class/net/%s/address" % self.dev, "r") as f:
                    self.devmac = f.read().strip()
            except IOError:
                raise IOError("/sys/class/net/%s/address not found" % self.dev)

            path = "/sys/class/net/%s/phy80211" % self.dev #XXX
            if os.path.islink(path):
                old_dir = os.getcwd()
                os.chdir(path)
                self.phydev = os.path.basename(os.getcwd())
                os.chdir(old_dir)

            # time to sleep between running iw scan command
            self.slept = 0.5 #XXX

            # iw scan command list
            self.iw_scan_cmd = [
                self.iw,
                'dev',
                self.dev,
                'scan'#,
                #'passive'
            ]

            # iw reg get command list
            self.iw_reg_get_cmd = [self.iw, 'reg', 'get']

        # sort rows by PWR
        self.sortby = "PWR"

        # columns list
        self.columns = [
            'SSID',
            'BSSID',
            #'FREQ',
            'CH',
            'ENC',
            'PWR', 
            'MODE',
            'ETC',
            'WPS'
        ]

        # rules dictionary
        self.rules = {
            'SSID':self.getSSID,
            'BSSID':self.getBSS, 
            #'FREQ':self.getFreq,
            'CH':self.getChannel, 
            'ENC':self.guessBSSCrypto,
            'PWR':self.getSignal, 
            'MODE':self.guessBSSMode,
            'ETC':self.getETC,
            'WPS':self.getWPSState2
        }

        if self.more:
            if self.rules.has_key('WPS'):
                self.rules.pop('WPS')
                self.columns.remove('WPS')

            self.columns.extend(['WPS', 'STA', 'CO']) #, 'MANUF'])
            self.columns.insert(self.columns.index('ENC')+1, 'CIPHERS')
            self.columns.insert(self.columns.index('ENC')+2, 'AUTH')
            self.columns.insert(self.columns.index('PWR')+1, 'UPTIME')

            self.rules.update({
                 'CIPHERS':self.getPairwiseCiphers,
                 'AUTH':self.getAuthSuites,
                 'UPTIME':self.getTSF,
                 'WPS':self.getWPSConfigMethods2,
                 'STA':self.getStationCount,
                 'CO':self.getCountryIE #,
                 #'MANUF':self.getManuf
            })

        self.get_timestamp = lambda : time.strftime('%Y-%m-%d %H:%M:%S', 
                                                      time.localtime())

    def ouiOpen(self):
        """
        open the file and read it in
        """
        with open(self.ouiTxt, "r") as f:
            text = f.read()
        return text
    
    def ouiParse(self): # taken from Airdrop-ng
        """
        generate a oui to company lookup dict
        """
        HexOui= {}
        Hex = re.compile('.*(hex).*')
        ouiLines = self.ouiRaw.split("\n")

        #XXX?
        for line in ouiLines:
            line = line.strip()
            if Hex.search(line) is not None:
                if "(hex)" not in line:
                    continue
                lineList = Hex.search(line).group().split("(hex)")
                oui = lineList[0].strip().replace("-",":")
                manuf = lineList[1].strip().replace(',','').replace('.','').replace('(','').replace(')','').replace('/','').replace('&','').replace(' ','')
                HexOui[oui] = [manuf[0:8]]

        return HexOui

    def matchingLine(self, lines, keyword): #taken from iwlist scan
        """
        matchingLine
        """
        ret = None
        for line in lines:
            length = len(keyword)
            if line[:length] == keyword: 
                ret = line[length:]
                break
        return ret

    def getBSS(self, bss):
        """
        getBSS
        """
        ret = self.matchingLine(bss, 'BSS')
        if ret is None: return ''

        bss_line = ret.split('(on %s)' % self.dev)
        bss = bss_line[0].strip()
        if bss_line[-1]:
            bss_status = bss_line[-1].split('--')[-1].strip()
            self.bss_status = "BSS status: %s on %s BSS: %s" % (bss_status,
                                                              self.dev, bss)
        return bss

    def getTSF(self, bss):
        """
        return TSF ie: UPTIME
        """
        ret = self.matchingLine(bss, '\tTSF:')
        if ret is not None:
            ret = ret.strip().split('usec')[-1].strip().\
                      replace(' ','').\
                      replace('(','').\
                      replace(')','')
        else:
            ret = '-'
        return ret

    def getFreq(self, bss):
        """
        return frequency
        """
        ret = self.matchingLine(bss, '\tfreq:')
        if ret is not None: ret = ret.strip()
        else: ret = ''
        return ret

    def getCapability(self, bss):
        """
        return capability
        """
        ret = self.matchingLine(bss, '\tcapability:')
        if ret is not None: ret = ret.strip()
        else: ret = ''
        return ret

    def getSignal(self, bss):
        """
        return signal
        """
        ret = self.matchingLine(bss, '\tsignal:')
        if ret is not None: ret = ret.strip().split('.')[0]
        else: ret = ''
        return ret

    def getSSID(self, bss):
        """
        return SSID
        """
        ret = ''
        ssid = self.matchingLine(bss, '\tSSID:')
        if ssid is None: return ret
        if ssid == '': ret = '<length=0>'
        elif r'\x00' in ssid: ret = '<length=%s>' % (len(ssid.strip())/4)
        else: ret = ssid.strip()
        return ret

    def getSupprates(self, bss):
        """
        return supported rates
        """
        ret = self.matchingLine(bss, '\tSupported rates:')
        if ret is not None: ret = ret.strip()
        else: ret = ''
        return ret

    def getExtSupprates(self, bss):
        """
        return extended supported rates
        """
        ret = self.matchingLine(bss, '\tExtended supported rates:')
        if ret is not None: ret = ret.strip()
        else: ret = ''
        return ret

    def getChannel(self, bss):
        """
        return channel
        """
        ret = self.matchingLine(bss, '\tDS Parameter set:')
        if ret is not None: ret = ret.strip().split('channel ')[-1]
        else: ret = ''
        return ret

    def guessBSSMode(self, bss):
        """
        return BSS mode
        """
        ret = ''
        cap = self.getCapability(bss)
        if 'ESS' in cap: ret = 'ESS'
        elif 'IBSS' in cap: ret = 'IBSS'
        else: ret = cap
        return ret

    def guessBSSCrypto(self, bss): #XXX
        """
        return encryption type
        """
        ret = ''
        wpa = None
        wpa2 = None
        cap = self.getCapability(bss)
        if 'Privacy' in cap:
            for line in bss:
                if self.matchingLine(bss, '\tWPA:') is not None:
                    wpa = 'wpa'
                break

            for line in bss:
                if self.matchingLine(bss, '\tRSN:') is not None:
                    wpa2 = 'wpa2'
                break

            if wpa is not None:
                if wpa2 is not None:
                    ret = 'WPA2'
                else:
                    ret = 'WPA'
            else:
                if wpa2 is not None:
                    ret = 'WPA2'  
                else:
                    ret = 'WEP'
        else:
            ret = 'OPN' if cap != '' else cap
        return ret

    def getPairwiseCiphers(self, bss):
        """
        return pairwise ciphers
        """
        ret = self.matchingLine(bss, '\t\t * Pairwise ciphers:')
        if ret is not None: ret = ret.strip()
        else: ret = ''
        return ret

    def getAuthSuites(self, bss):
        """
        return authentication suites
        """
        ret = self.matchingLine(bss, '\t\t * Authentication suites:')
        if ret is not None: ret = ret.strip()
        else: ret = ''
        return ret

    def guessBSSMaxSupprates(self, bss): #XXX
        """
        guessBSSMaxSupprates
        """
        rates = self.getSupprates(bss)
        if 'HT' in rates: return 'HT'

        ext_rates = self.getExtSupprates(bss)
        if 'HT' in ext_rates: return 'HT'

        if ext_rates != '':
            max_rate = int(max([
                               float(rates.split(' ')[-1].split('*')[0]),
                               float(ext_rates.split(' ')[-1].split('*')[0])
                               ]))
        else:
            max_rate = int(float(rates.split(' ')[-1].split('*')[0]))
        return max_rate

    def getETC(self, bss):
        """
        getETC
        """
        ret = ''
        if self.matchingLine(bss, '\tWMM:') is not None:
            ret = ''.join([ret, 'e'])
        if self.matchingLine(bss, '\tHT capabilities:') is not None: #XXX
            ret = ''.join([ret, 'N'])
        return ret

    def getCountryIE(self, bss):
        """
        return country IE
        """
        country = {}
        co_env_dict = {
            'Indoor only': 'I',
            'Outdoor only': 'O', 
            'Indoor/Outdoor': 'I/O'
        }
        ret = self.matchingLine(bss, "\tCountry:")

        if ret is not None:
            country.update({'Country':ret.split('\t')[0].strip()})
            if 'data' in country.get('Country'):
                ret = country.get('Country')
                country.update({'Country':ret.split(',')[0].split(' ')[0]})
                country.update({'Environment':ret.split(',')[0].split(' ')[1].\
                    replace('(','').replace(')','')})
                country.update({'Channels':ret.split(',')[1].strip()})
            else:
                country.update({'Environment':ret.split('\t')[1].strip().\
                    split(':')[1].strip()})
                idx = bss.index('\tCountry:%s'%ret)
                country.update({'Channels':bss[idx+1].strip().\
                    replace('Channels ','')})
                co_env = co_env_dict.get(country['Environment'])
                if co_env is None:
                    co_env = country['Environment']
            ret = country.get('Country')
        else:
            ret = '-'
        return ret

    def getWPS(self, bss):
        """
        getWPS
        """
        key = None
        val = None
        wps = {}
        wps_print = []
        ret = self.matchingLine(bss, '\tWPS:')
        if ret is not None:
            idx = bss.index('\tWPS:%s'%ret)
            key = ret.strip().split(':')[0].strip()
            val = ret.strip().split(':')[1].strip()
            wps.update({key: val})
            wps_print.append(': '.join([key, val]))
            idx += 1 
            while idx < len(bss) and re.search('\t\t * ([^:]+):', bss[idx]):
                key = bss[idx].strip().split(':')[0].strip()
                val = bss[idx].strip().split(':')[1].strip()
                wps.update({key: val})
                wps_print.append(': '.join([key, val]))
                idx += 1

            ret = wps
        else:
            ret = None
        return ret

    def getWPSState(self, bss):
        """
        return Wi-Fi Protected Setup State
        """
        ret = ''
        res = self.getWPS(bss)
        if res is not None:
            if res.has_key('* Wi-Fi Protected Setup State'):
                ret = res['* Wi-Fi Protected Setup State'].split(' ')[0]
        return ret

    def getWPSState2(self, bss):
        """
        return WPS state
        """
        state = self.getWPSState(bss)
        if state == '':
            state = '-'
        return state

    def getWPSConfigMethods(self, bss):
        """
        return WPS Config methods
        """
        ret = ''
        res = self.getWPS(bss)
        if res is not None:
            if res.has_key('* Config methods'):
                ret = res['* Config methods'].replace(' ','')
        return ret

    def getWPSConfigMethods2(self, bss):
        """
        return WPS state & Config methods
        """
        state = self.getWPSState(bss)

        ret = ''
        res = self.getWPS(bss)
        if res is not None:
            if res.has_key('* Config methods'):
                ret = res['* Config methods'].replace(' ','')

        res = ','.join([state,ret]) if ret != '' else state
        if res == '': res = '-'
        return res

    def getExtCapabilities(self, bss):
        """
        return extended capabilities
        """
        ret = self.matchingLine(bss, '\tExtended capabilities:')
        if ret is not None: ret = ret.strip()
        else: ret = ''
        return ret

    def getStationCount(self, bss):
        """
        return station count
        """
        ret = self.matchingLine(bss, '\t\t * station count:')
        if ret is not None: ret = ret.strip()
        else: ret = '-'
        return ret

    def sortBSSs(self, sortby, bsss): #taken from iwlist scan
        """
        return sorted BSSs
        """
        return sorted(bsss, key=lambda k: k[sortby], reverse=False)

    def parseBSS(self, bss):
        """
        return parsed BSS
        """
        parsed_bss = {}
        for key in self.rules:
            rule = self.rules[key]
            parsed_bss.update({key:rule(bss)})
        return parsed_bss

    def printTable(self, table):
        """
        print table
        """
        i = 1
        widths = map(max, map(lambda l:map(len, l), zip(*table)))
        justified_table = []
        for line in table:
            justified_line = []
            for i, el in enumerate(line):
                justified_line.append(el.ljust(widths[i]))
            justified_table.append(justified_line)

        for line in justified_table:
            for el in line:
                print (el),
            print("")

    def printBSSs(self, bsss):
        """
        print BSSs
        """
        table = [self.columns]
        for bss in bsss:
            bss_properties = [] 
            for column in self.columns:
                bss_properties.append(bss[column])
            table.append(bss_properties)
        self.printTable(table)
        print("")

    def getManuf(self, bss):
        """
        return manufacturer/OUI company
        """
        ret = "Unknown"
        mac = self.getBSS(bss)
        if mac is None:
            return 'none'

        mac = mac[0:8].upper()
        if mac in self.oui_company:
            ret = self.oui_company[mac][0].strip()
        return ret

    def getIdxs(self, value, qlist):
        """
        return all indices of an item given a list containing it
        """
        indices = []
        idx = -1
        while 1:
            try:
                idx = qlist.index(value, idx+1)
                indices.append(idx)
            except ValueError:
                break
        return indices

    def iwRegGet(self):
        """
        return output of iw reg get command
        """
        iw_reg_proc = subprocess.Popen(self.iw_reg_get_cmd,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
        stdout, stderr = iw_reg_proc.communicate()
        co = stdout.split('\n')
        return co[0].split('country')[-1].replace(':','').strip()

    def timer(self, st=None):
        """
        timer
        """
        if st is None:
            return datetime.datetime.fromtimestamp(time.time())
        et = datetime.datetime.fromtimestamp(time.time())
        dt = et - st
        return dt

    def iwScanParse(self):
        """
        iwScanParse
        """
        if self.bssid is not None: #XXX
            bss_line_tmp = self.infile.split('BSS %s' % self.bssid)
            try:
                bss_line = bss_line_tmp[1]
            except IndexError:
                return 1

            if len(bss_line_tmp) > 2:
                print(self.infile)
                return

            match = re.search('BSS ([0-9a-f]{2}[:]){5}[0-9a-f]{2}', bss_line)
            if not match:
                print("BSS %s%s" % (self.bssid, bss_line))
            else:
                print("BSS %s%s" % (self.bssid, bss_line.\
                                    split(match.group())[0]))
            return

        t = self.timer()
        while 1:
            self.bss_status = ""
            parsed_bsss = []

            if self.infile is None:
                try: 
                    iw_scan_proc = subprocess.Popen(self.iw_scan_cmd,
                                                    stdout=subprocess.PIPE, 
                                                    stderr=subprocess.PIPE)
                    time.sleep(self.slept)
                except OSError:
                    raise Exception("Something went wrong with iw")

                stdout, stderr = iw_scan_proc.communicate()
                if stderr != '': #XXX
                    err = stderr.strip()
                    if (int(err.split('(')[-1].split(')')[0])) == -16:
                        time.sleep(self.slept)
                        continue
                    else:
                        raise Exception("Something went wrong with iw, "
                                        "printing the error:\n%s" % err)

                with open(self.logfile, "w") as f:
                    f.write(stdout)

                if self.cont:
                    subprocess.check_call(["clear"], shell=True)

                data = stdout.split('\n')

                if len(data) == 1:
                    if self.cont:
                        print("\nFound %s BSS(s) on [%s]%s "
                              "(MAC: %s) (%s)" % (len(parsed_bsss), self.phydev,
                                                  self.dev, self.devmac,
                                                  self.iwRegGet()))

                        print("Elapsed: %s ][ %s\n" % (self.timer(t), 
                                                       self.get_timestamp()))
                        continue
                    else:
                        break
            else:
                data = self.infile
                if data:
                    if data[0].startswith('BSS'):
                        self.dev = data[0].strip('BSS').\
                                   split('(on')[1].split(')')[0].\
                                   strip()
                    else:
                        raise Exception("Something went wrong with input, "
                                        "printing the first line:\n"
                                        "'%s'" % data[0])
                else:
                    break

            cleaned_data = []
            idxs = []
            idxs2 = []
            apz = []

            for line in data:
                cur_line = line.rstrip()
                cleaned_data.append(cur_line)
                if line.startswith('BSS'):
                    if data.count(cur_line) > 1:
                        ap = cur_line.split(' ')[1].replace('(on','')
                        if apz.count(ap) == 0:
                            apz.append(ap)
                            idxs2.extend(self.getIdxs(cur_line, data))
                    else:
                        idxs.append(cleaned_data.index(cur_line))

            idxs.append(len(cleaned_data)-1)
            if len(idxs2) != 0:
                idxs.extend(idxs2)
                idxs.sort()

            k = 0
            while k < len(idxs):
                k += 1
                if k < len(idxs):
                    parsed_bsss.append(
                               self.parseBSS(cleaned_data[idxs[k-1]:idxs[k]]))

            if self.infile is None:
                print("\nFound %s BSS(s) on [%s]%s "
                      "(MAC: %s) (%s)" % (len(parsed_bsss), self.phydev,
                                          self.dev, self.devmac,
                                          self.iwRegGet()))
            else:
                print("\nFound %s BSS(s) on %s" % (len(parsed_bsss), self.dev))

            if self.bss_status != "":
                print(" %s" % self.bss_status)

            print("Elapsed: %s ][ %s\n" % (self.timer(t), 
                                            self.get_timestamp()))

            self.printBSSs(self.sortBSSs(self.sortby, parsed_bsss))

            if len(apz) > 0:
                print("WARNING: checkout the BSS: %s\n" % str(apz).\
                                                           replace('[','').\
                                                           replace(']','').\
                                                           replace('\'',''))
            if not self.cont:
                break

if __name__ == "__main__":
    trace = False
    dev = None
    infile = None
    bssid = None
    logfile = '%s.log' % os.path.basename(__file__).split('.')[0] #XXX

    parser = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        formatter_class=argparse.RawTextHelpFormatter, 
        description="%(prog)s - parse iw scan command output into table",
        usage="python %(prog)s [<devname|filename>] [bssid] [-h] [-c] [-m]")

    parser.add_argument('input', metavar='<devname|filename>', nargs='?', 
                         help="Specify wireless interface OR output filename\n"
                         "(iw dev <devname> scan > <filename>).")

    parser.add_argument('bssid', metavar='[bssid]', nargs='?', 
                         help="Print BSS info for the specified "
                              "bssid (if any).")

    #parser.add_argument('-c', '--cont', action="store_true", default=False, 
    #                     help="Run continuously until Ctrl+C is pressed.")

    parser.add_argument('-m', '--more', action="store_true", default=False, 
                         help="Show more columns in the output table.")

    if os.geteuid() != 0:
        parser.exit("Run it as root")

    args = parser.parse_args()

    if not sys.stdin.isatty():
        if args.input:
            if re.match('^([0-9a-fA-F]{2}[:|\-]){5}[0-9a-fA-F]{2}$',
                                                        args.input):
                bssid = args.input.replace('-',':').lower()
            else:
                print("%s: invalid bssid: '%s'" % (parser.prog,args.input))
                args.input = None

        infile = sys.stdin.read()

        if not args.input:
            infile = infile.split('\n')

    elif args.input:
        if os.path.isfile(args.input):
            if args.bssid:
                if re.match('^([0-9a-fA-F]{2}[:|\-]){5}[0-9a-fA-F]{2}$',
                                                            args.bssid):
                    bssid = args.bssid.replace('-',':').lower()
                else:
                    print("%s: invalid bssid: '%s'" % (parser.prog,args.bssid))
                    args.bssid = None

            with open(args.input, "r") as f:
                infile = f.read()

            if not args.bssid:
                infile = infile.split('\n')

        elif os.path.exists("/sys/class/net/%s/" % args.input): #XXX
            dev = args.input
            if args.bssid:
                parser.print_help()
                sys.exit(2)

        elif re.match('^([0-9a-fA-F]{2}[:|\-]){5}[0-9a-fA-F]{2}$',
                                                      args.input):
            bssid = args.input.replace('-',':').lower()
        else:
            parser.error("no such file or device, or bssid not valid: "
                         "'%s'" % args.input)
    else:
        parser.error("device, file or bssid not set")

    try:
        parser = iwScanParse(dev=dev, infile=infile,
                        bssid=bssid, logfile=logfile, 
                        cont=False, more=args.more,
                        oui=None,
                        iw=None) #XXX
        parser.iwScanParse()
    except KeyboardInterrupt:
        print
    except Exception as err:
        if trace:
            traceback.print_exc()
        else:
            print(err)
        sys.exit(1)
