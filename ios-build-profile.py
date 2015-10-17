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

import uuid
import argparse
import sys
import plistlib
import OpenSSL
import os
import getpass

# defaults
DEFAULT_ENCRYPTION_ALGORITHM = "AES-256"
DEFAULT_INTEGRITY_ALGORITHM = "SHA2-256"
DEFAULT_DH_GROUP = 14

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

# Numbers correspond to NEVPNIKEv2SecurityAssociationParameters
EncryptionAlgorithms = {
    "DES"           : 1,        # Not recommended
    "3DES"          : 2,        # Not recommended
    "AES-128"       : 3,
    "AES-256"       : 4,
    "AES-128-GCM"   : 5,
    "AES-256-GCM"   : 6,
}

IntegrityAlgorithms = {
    "SHA1-96"   : 1,        # Not recommended
    "SHA1-160"  : 2,        # Not recommended
    "SHA2-256"  : 3,
    "SHA2-384"  : 4,
    "SHA2-512"  : 5,
}


class MobileProfile:
    def __init__(self, endpoint, certificate, cacertificate=None):
        self.IKEv2Params = {
            'EncryptionAlgorithm' : DEFAULT_ENCRYPTION_ALGORITHM,
            'IntegrityAlgorithm' : DEFAULT_INTEGRITY_ALGORITHM,
            'DiffieHellmanGroup' : DEFAULT_DH_GROUP,
        }
        self.ChildSAParams = {
            'EncryptionAlgorithm' : DEFAULT_ENCRYPTION_ALGORITHM,
            'IntegrityAlgorithm' : DEFAULT_INTEGRITY_ALGORITHM,
            'DiffieHellmanGroup' : DEFAULT_DH_GROUP,
        }
        self.CACertificateData = None
        self.CertificateData = None
        self.VPNEndpoint = endpoint
        self.PayloadIdentifier = self.payload_identifier()
        self.RemoteIdentifier = endpoint
        self.VPNName = "VPN to %s" % endpoint
        self.ProfileName = "%s IKEv2 Profile" % endpoint
        self.ConfigName = "%s IKEv2 Config 1" % endpoint
        self.LocalIdentifier = None

        self.CertificateUUID = str(uuid.uuid4())
        self.CACertificateUUID = str(uuid.uuid4()).upper()
        self.Config1UUID = str(uuid.uuid4()).upper()
        self.ConfigurationUUID = str(uuid.uuid4()).upper()

        self.load_ca_certificate(cacertificate)
        self.load_certificate(certificate)

    def load_certificate(self, certificate):
        certcontents = certificate

        if os.path.exists(certificate):
            certificate = open(certificate)

        if isinstance(certificate, file):
            certcontents = certificate.read()

        password = getpass.getpass("Password for Key:")

        cert = OpenSSL.crypto.load_certificate(OpenSSL.SSL.FILETYPE_PEM,
                                               certcontents)
        key = OpenSSL.crypto.load_privatekey(OpenSSL.SSL.FILETYPE_PEM,
                                             certcontents, password)

        pkcs12 = OpenSSL.crypto.PKCS12()
        pkcs12.set_certificate(cert)
        pkcs12.set_privatekey(key)

        self.CertificateCN = cert.get_subject().emailAddress
        if not self.CertificateCN:
            self.CertificateCN = cert.get_subject().commonName

        self.CertificateData = pkcs12.export(password)

    def load_ca_certificate(self, certificate):
        certcontents = certificate

        if certificate is None:
            return

        if os.path.exists(certificate):
            certificate = open(certificate)

        if isinstance(certificate, file):
            certcontents = certificate.read()

        cert = OpenSSL.crypto.load_certificate(OpenSSL.SSL.FILETYPE_PEM,
                                               certcontents)

        self.CACertificateCN = cert.get_subject().commonName
        self.CACertificateData = certcontents

    def payload_identifier(self):
        return ".".join(reversed(self.VPNEndpoint.split("."))) + ".vpn1"

    def set_profile_name(self, profile):
        self.ProfileName = "%s Profile" % profile
        self.ConfigName = "%s Config 1" % profile

    def __str__(self):
        localID = self.LocalIdentifier
        if not localID:
            localID = self.CertificateCN
        x = {
            'PayloadContent' : [
                {
                    'PayloadContent' : plistlib.Data(self.CertificateData),
                    'PayloadDisplayName' : self.CertificateCN,
                    'PayloadIdentifier' :
                        "com.apple.security.pkcs12.%s" % self.CertificateUUID,
                    'PayloadType' :
                        "com.apple.security.pkcs12",
                    'PayloadUUID' : self.CertificateUUID,
                    'PayloadVersion' : 1,
                },
                {
                    'IKEv2' : {
                        'AuthenticationMethod' : "Certificate",
                        'ChildSecurityAssociationParameters' :
                            self.ChildSAParams,
                        'ExtendedAuthEnabled' : False,
                        'IKESecurityAssociationParameters' :
                            self.IKEv2Params,
                        'LocalIdentifier': localID,
                        'PayloadCertificateUUID' : self.CertificateUUID,
                        'RemoteAddress' : self.VPNEndpoint,
                        'RemoteIdentifier' : self.RemoteIdentifier,
                    },
                    'PayloadDisplayName' : self.ConfigName,
                    'PayloadIdentifier' :
                        'com.apple.vpn.managed.%s' % self.Config1UUID,
                    'PayloadType' : 'com.apple.vpn.managed',
                    'PayloadUUID' : self.Config1UUID,
                    'PayloadVersion' : 1,
                    'UserDefinedName' : self.VPNName,
                    'VPNType' : 'IKEv2',
                },
            ],
            'PayloadDisplayName' : self.ProfileName,
            'PayloadIdentifier' : self.payload_identifier(),
            'PayloadType' : 'Configuration',
            'PayloadUUID' : self.ConfigurationUUID,
            'PayloadVersion' : 1,
        }

        if self.CACertificateData:
            ca_dict = {
                'PayloadContent' : plistlib.Data(self.CACertificateData),
                'PayloadDisplayName' :
                    "%s (CA Certificate)" % self.CACertificateCN,
                'PayloadIdentifier' :
                    "com.apple.security.root.%s" % self.CACertificateUUID,
                'PayloadType' :
                    "com.apple.security.root",
                'PayloadUUID' : self.CACertificateUUID,
                'PayloadVersion' : 1,
            }
            x['PayloadContent'].insert(0, ca_dict)

        return plistlib.writePlistToString(x)

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
        
    if alg in EncryptionAlgorithms:
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
    parser.add_argument('-o', '--outfile', help="Filename for output plist. Defaults to stdout.")
    parser.add_argument('-n', '--vpn-name', help="Friendly name for VPN connection")
    parser.add_argument('-N', '--profile-name', help="Friendly name for Profile, without \"Profile\" suffix")
    parser.add_argument('-e', '--vpn-endpoint', help="VPN Endpoint", required=True)
    parser.add_argument('-i', '--remote-identifier', help="Remote identifier (defaults to vpn endpoint")
    parser.add_argument('-C', '--ca-certificate', help="CA Certificate in PEM format")
    parser.add_argument('-c', '--certificate', help="Certificate and key in PEM format (single file)", required=True)
    parser.add_argument('-L', '--local-identifier', help="Local identifier (defaults to Certificate CN)")
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

    options = parser.parse_args()

    if options.list_encryption:
        print "Supported encryption algorithms:"
        print " ".join(EncryptionAlgorithms.keys())

    if options.list_integrity:
        print "Supported integrity algorithms:"
        print " ".join(IntegrityAlgorithms.keys())

    if options.list_dhgroups:
        print "Supported Diffie-Hellman groups:"
        print " ".join(DHGroups.keys())

    if options.list_encryption or options.list_integrity or \
       options.list_dhgroups:
        sys.exit(0)

    missing_options = False
    if not options.vpn_endpoint:
        print >>sys.stderr, "--vpn-endpoint is a required option."
        missing_options = True

    if not options.certificate:
        print >>sys.stderr, "--certificate is a required option."
        missing_options = True

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

    if missing_options:
        sys.exit(1)

    profile = MobileProfile(options.vpn_endpoint, options.certificate)

    if options.encryption:
        profile.IKEv2Params['EncryptionAlgorithm'] = options.encryption
        profile.ChildSAParams['EncryptionAlgorithm'] = options.encryption

    if options.child_encryption:
        profile.ChildSAParams['EncryptionAlgorithm'] = options.child_encryption

    if options.integrity:
        profile.IKEv2Params['IntegrityAlgorithm'] = options.integrity
        profile.ChildSAParams['IntegrityAlgorithm'] = options.integrity

    if options.child_integrity:
        profile.ChildSAParams['IntegrityAlgorithm'] = options.child_integrity

    if options.dhgroup:
        profile.IKEv2Params['DiffieHellmanGroup'] = options.dhgroup
        profile.ChildSAParams['DiffieHellmanGroup'] = options.dhgroup

    if options.child_dhgroup:
        profile.ChildSAParams['DiffieHellmanGroup'] = options.child_dhgroup

    if options.vpn_name:
        profile.VPNName = options.vpn_name

    if options.profile_name:
        profile.set_profile_name(options.profile_name)

    if options.ca_certificate:
        profile.load_ca_certificate(options.ca_certificate)

    outfile = sys.stdout
    if options.outfile:
        outfile = open(options.outfile, "w")

    print >>outfile, profile
