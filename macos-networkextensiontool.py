#!/usr/bin/env python
# vim: ts=4 sw=4 et
#
# Copyright (c) 2015, Jeff Mahoney. All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written
#       permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import sys
import argparse

import plistlib

def revdict(d):
    n = {}
    for k in d:
        n[d[k]] = k
    return n

# Numbers correspond to IKEv2 definitions
DHGroups = {
    "modp768" : 1,      # Not recommended
    "modp1024" : 2,     # Not recommended
    "modp1536" : 5,     # Not recommended
    "modp2048" : 14,
    "modp3072" : 15,
    "modp4096" : 16,
    "modp6144" : 17,
    "modp8192" : 18,
    "ecp256" : 19,
    "ecp384" : 20,
    "ecp521" : 21,
}
revDHGroups = revdict(DHGroups)

# Numbers correspond to NEVPNIKEv2SecurityAssociationParameters
EncryptionAlgorithms = {
    "DES"           : 1,        # Not recommended
    "3DES"          : 2,        # Not recommended
    "AES-128"       : 3,
    "AES-256"       : 4,
    "AES-128-GCM"   : 5,
    "AES-256-GCM"   : 6,
}
revEncryptionAlgorithms = revdict(EncryptionAlgorithms)

IntegrityAlgorithms = {
    "SHA1-96"   : 1,        # Not recommended
    "SHA1-160"  : 2,        # Not recommended
    "SHA2-256"  : 3,
    "SHA2-384"  : 4,
    "SHA2-512"  : 5,
}
revIntegrityAlgorithms = revdict(IntegrityAlgorithms)


class NetworkConfigurationPlist:
    def __init__(self, xmlfile):
        self.plist = plistlib.readPlist(xmlfile)
        self.objects = self.plist['$objects']
        self.fetch_classes()
        self.fetch_configs()

    def fetch_classes(self):
        pos = 0
        self.classes = {}
        for object in self.objects:
            if isinstance(object, dict) and '$classname' in object:
                self.classes[object['$classname']] = pos
            pos += 1

    def fetch_configs(self):
        self.configs = {}
        pos = 0
        for object in self.objects:
            if isinstance(object, dict) and '$class' in object:
                if object['$class']['CF$UID'] == \
                   self.classes['NEConfiguration']:
                    self.configs[self.objects[object['Name']['CF$UID']]] = pos
            pos += 1

    def list_configs(self):
        return self.configs.keys()

    def get_params(self, config):
        vpn = self.objects[netconfig.configs[config]]['VPN']['CF$UID']
        proto = self.objects[vpn]['Protocol']['CF$UID']
        child_sa_param_idx = self.objects[proto]['ChildSAParameters']['CF$UID']
        child_sa_params = self.objects[child_sa_param_idx]
        ike_sa_param_idx = self.objects[proto]['IKESAParameters']['CF$UID']
        ike_sa_params = self.objects[ike_sa_param_idx]
        return {
            'ike' : {
                'EncryptionAlgorithm' : 
                    revEncryptionAlgorithms[ike_sa_params['EncryptionAlgorithm']],
                'IntegrityAlgorithm' : 
                    revIntegrityAlgorithms[ike_sa_params['IntegrityAlgorithm']],
                'DiffieHellmanGroup' : 
                    revDHGroups[ike_sa_params['DiffieHellmanGroup']],
                },
            'child' : {
                'EncryptionAlgorithm' : 
                    revEncryptionAlgorithms[child_sa_params['EncryptionAlgorithm']],
                'IntegrityAlgorithm' : 
                    revIntegrityAlgorithms[child_sa_params['IntegrityAlgorithm']],
                'DiffieHellmanGroup' : 
                    revDHGroups[child_sa_params['DiffieHellmanGroup']],
                }
            }

    def update_params(self, config, params):
        vpn = self.objects[netconfig.configs[config]]['VPN']['CF$UID']
        proto = self.objects[vpn]['Protocol']['CF$UID']
        child_sa_param_idx = self.objects[proto]['ChildSAParameters']['CF$UID']
        child_sa_params = self.objects[child_sa_param_idx]
        if 'EncryptionAlgorithm' in params['child']:
             child_sa_params['EncryptionAlgorithm'] = \
                EncryptionAlgorithms[params['child']['EncryptionAlgorithm']]
        if 'IntegrityAlgorithm' in params['child']:
             child_sa_params['IntegrityAlgorithm'] = \
                IntegrityAlgorithms[params['child']['IntegrityAlgorithm']]
        if 'DiffieHellmanGroup' in params['child']:
             child_sa_params['DiffieHellmanGroup'] = \
                DHGroups[params['child']['DiffieHellmanGroup']]

        ike_sa_param_idx = self.objects[proto]['IKESAParameters']['CF$UID']
        ike_sa_params = self.objects[ike_sa_param_idx]
        if 'EncryptionAlgorithm' in params['ike']:
             ike_sa_params['EncryptionAlgorithm'] = \
                EncryptionAlgorithms[params['ike']['EncryptionAlgorithm']]
        if 'IntegrityAlgorithm' in params['ike']:
             ike_sa_params['IntegrityAlgorithm'] = \
                IntegrityAlgorithms[params['ike']['IntegrityAlgorithm']]
        if 'DiffieHellmanGroup' in params['ike']:
             ike_sa_params['DiffieHellmanGroup'] = \
                DHGroups[params['ike']['DiffieHellmanGroup']]


def check_encryption(alg):
    if alg is None:
        return True
        
    if alg in EncryptionAlgorithms:
        return True

    print >>sys.stderr, "Error: `%s' is not a valid encryption algorithm" % alg
    return False

def check_integrity(alg):
    if alg is None:
        return True
        
    if alg in IntegrityAlgorithms:
        return True

    print >>sys.stderr, "Error: `%s' is not a valid integrity algorithm" % alg
    return False

def check_dhgroup(alg):
    if alg is None:
        return True
        
    if alg in DHGroups:
        return True

    print >>sys.stderr, "Error: `%s' is not a valid Diffie-Hellman group" % alg
    return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--list', action="store_true", default=False, help="List VPN encryption configurations")
    parser.add_argument('-f', '--file', help="XML-format plist file")
    parser.add_argument("config_name", type=str, nargs='?', help="Configuration to modify", default=None)
    parser.add_argument('-E', '--encryption', help="Encryption Algorithm")
    parser.add_argument('-I', '--integrity', help="Integrity Algorithm")
    parser.add_argument('-D', '--dhgroup', help="Diffie-Hellman Group")
    parser.add_argument('--child-encryption',
                      help="Encryption Algorithm for Child SA")
    parser.add_argument('--child-integrity',
                      help="Integrity Algorithm for Child SA")
    parser.add_argument('--child-dhgroup',
                      help="Diffie-Hellman Group for Child SA")
    parser.add_argument("--list-encryption", action="store_true", default=False, help="List supported encryption algorithms")
    parser.add_argument("--list-integrity", action="store_true", default=False, help="List supported integrity algorithms")
    parser.add_argument("--list-dhgroups", action="store_true", default=False, help="List supported Diffie-Hellman groups")

    parser.add_argument('-N', '--dry-run', action="store_true", default=False, help="Output XML-format plist to stdout instead of overwriting source file.")
    options = parser.parse_args()

    if options.list_encryption:
        print "Supported encryption algorithms:"
        print " ".join(sorted(EncryptionAlgorithms.keys()))

    if options.list_integrity:
        print "Supported integrity algorithms:"
        print " ".join(sorted(IntegrityAlgorithms.keys()))

    if options.list_dhgroups:
        print "Supported Diffie-Hellman groups:"
        print " ".join(sorted(DHGroups.keys()))

    if options.list_encryption or options.list_integrity or \
       options.list_dhgroups:
        sys.exit(0)

    if not check_encryption(options.encryption):
        missing_options = True
    if not check_encryption(options.child_encryption):
        missing_options = True
    if not check_integrity(options.integrity):
        missing_options = True
    if not check_integrity(options.child_integrity):
        missing_options = True
    if not check_dhgroup(options.dhgroup):
        missing_options = True
    if not check_dhgroup(options.child_dhgroup):
        missing_options = True

    netconfig = NetworkConfigurationPlist("plist.xml")

    if options.list:
        for config in netconfig.list_configs():
            print config
            params = netconfig.get_params(config)
            print " IKE SA"
            print "  Encryption:\t%s" % params['ike']['EncryptionAlgorithm'] 
            print "  Integrity:\t%s" % params['ike']['IntegrityAlgorithm'] 
            print "  DH Group:\t%s" % params['ike']['DiffieHellmanGroup'] 
            print ""
            print " Child SA"
            print "  Encryption:\t%s" % params['child']['EncryptionAlgorithm'] 
            print "  Integrity:\t%s" % params['child']['IntegrityAlgorithm'] 
            print "  DH Group:\t%s" % params['child']['DiffieHellmanGroup'] 
            print ""
        sys.exit(0)

    if not options.file:
        print >>sys.stderr, "XML-format plist required."
        sys.exit(1)

    if not options.config_name:
        print >>sys.stderr, "Configuration name required."
        sys.exit(1)

    configs = netconfig.list_configs()
    if not options.config_name in configs:
        print >>sys.stderr, "Invalid config `%s'" % options.config_name
        sys.exit(1)

    params = {
        'ike' : {},
        'child' : {}
    }
    if options.encryption:
        params['ike']['EncryptionAlgorithm'] = options.encryption
        params['child']['EncryptionAlgorithm'] = options.encryption

    if options.child_encryption:
        params['child']['EncryptionAlgorithm'] = options.child_encryption

    if options.integrity:
        params['ike']['IntegrityAlgorithm'] = options.integrity
        params['child']['IntegrityAlgorithm'] = options.integrity

    if options.child_integrity:
        params['child']['IntegrityAlgorithm'] = options.child_integrity

    if options.dhgroup:
        params['ike']['DiffieHellmanGroup'] = options.dhgroup
        params['child']['DiffieHellmanGroup'] = options.dhgroup

    if options.child_dhgroup:
        params['child']['DiffieHellmanGroup'] = options.child_dhgroup

    netconfig.update_params(options.config_name, params)

    if options.dry_run:
        print plistlib.writePlistToString(netconfig.plist)
        sys.exit(0)

    plistlib.writePlist(netconfig.plist, options.file)
