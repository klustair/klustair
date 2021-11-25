import subprocess
import json
import sys
from cvss import CVSS2, CVSS3
import logging as log
import os
import pprint
import uuid
import re

class Trivy:
    repoCredentials = {}

    def __init__(self):
        print("INFO: Start Trivy analysis")
        self.repoCredentials = {}

    def loadRepoCredentials(self, path):
        try:
            with open(path, 'r') as f:
                self.repoCredentials = json.load(f)
            #log.debug(self.repoCredentials)
        except:
            log.debug("Credentials not loaded")
            log.debug(sys.exc_info()[0])

    def __addCredentials(self, image):

        for credential, credentialData in self.repoCredentials.items():
            if credential in image:
                log.debug('got credentials for image {image} {credential}'.format(image=image, credential=credential ))
                if 'username' in credentialData:
                    os.environ['TRIVY_USERNAME'] = credentialData['username']
                if 'password' in credentialData:
                    os.environ['TRIVY_PASSWORD'] = credentialData['password']
                if 'registryToken' in credentialData:
                    os.environ['TRIVY_REGISTRY_TOKEN'] = credentialData['registryToken']
                if 'insecure' in credentialData:
                    os.environ['TRIVY_INSECURE'] = credentialData['insecure']
                if 'nonSsl' in credentialData:
                    os.environ['TRIVY_NON_SSL'] = credentialData['nonSsl']
        return

    def __removeCredenials(self):
        if 'TRIVY_USERNAME' in os.environ:
            del os.environ['TRIVY_USERNAME']
        if 'TRIVY_PASSWORD' in os.environ:
            del os.environ['TRIVY_PASSWORD']
        if 'TRIVY_REGISTRY_TOKEN' in os.environ:
            del os.environ['TRIVY_REGISTRY_TOKEN']
        if 'TRIVY_INSECURE' in os.environ:
            del os.environ['TRIVY_INSECURE']
        if 'TRIVY_NON_SSL' in os.environ:
            del os.environ['TRIVY_NON_SSL']

        return


    def getImageTrivyVulnerabilities(self, uniqueImagesList, reportsummary):
        print('INFO: Load trivy Vulnerabilities')
        VulnList = {}
        imageTrivyVulnSummary = {}
        for imageUid, image in uniqueImagesList.items():
            
            reportsummary['images'] += 1

            log.debug("run Trivy on: {}".format(image['fulltag']))
            vulnsum = {
                'Critical': {
                    'severity': 0,
                    'total': 0,
                    'fixed': 0
                },
                'High': {
                    'severity': 1,
                    'total': 0,
                    'fixed': 0
                },
                'Medium': {
                    'severity': 2,
                    'total': 0,
                    'fixed': 0
                },
                'Low': {
                    'severity': 3,
                    'total': 0,
                    'fixed': 0
                },
                'Unknown': {
                    'severity': 4,
                    'total': 0,
                    'fixed': 0
                }
            }
            VulnList[imageUid] = []
            
            self.__addCredentials(image['fulltag'])
            #log.debug(subprocess.run(['printenv'], stdout=subprocess.PIPE).stdout.decode('utf-8'))
            trivyresult = subprocess.run(["trivy", "-q", "i", "-f", "json", image['fulltag']], stdout=subprocess.PIPE).stdout.decode('utf-8')
            self.__removeCredenials()

            try:
                imageVuln = json.loads(trivyresult)
            except json.JSONDecodeError:
                print ("ERROR: could not parse {}".format(image['fulltag']))
                continue

            # skip empty images like busybox
            if type(imageVuln['Results']) is not list:
                continue
            
            for target in imageVuln['Results']:
                target['uid'] = str(uuid.uuid4())
                
                matches = ['debian', 'alpine', 'amazon', 'busybox', 'centos', 'oracle', 'photon', 'redhat', 'rhel', 'suse', 'ubuntu']
                if any(x in target['Type'] for x in matches):
                    target['isOS'] = True
                else:
                    target['isOS'] = False
                    
                if 'Vulnerabilities' in target and target['Vulnerabilities'] is not None: 
                    for vulnerability in target['Vulnerabilities']:
                        vulnerability['uid'] = str(uuid.uuid4())
                        #print("PkgName: {PkgName} {VulnerabilityID}".format(PkgName=vulnerability['PkgName'], VulnerabilityID=vulnerability['VulnerabilityID']))
                        if 'CVSS' in vulnerability:
                            
                            for provider, vectors in vulnerability['CVSS'].items():
                                if 'V3Vector' in vectors:
                                    cvss = CVSS3(vectors['V3Vector'])
                                    vectors['V3Vector_base_score']=str(round(cvss.base_score, 1))
                                    vectors['V3Vector_modified_isc']=str(round(cvss.modified_isc, 1))
                                    vectors['V3Vector_modified_esc']=str(round(cvss.modified_esc, 1))
                                    vectors['V3Vector_metrics']=cvss.metrics
                                    vectors['provider'] = provider
                                    #print("   CVSS3 {provider} {base_score} {modified_isc} {modified_esc} {vector}".format(provider=provider, base_score=vectors['V3Vector_base_score'], modified_isc=vectors['V3Vector_modified_isc'], modified_esc=vectors['V3Vector_modified_esc'], vector=vectors['V3Vector']))
                                    
                                if 'V2Vector' in vectors:
                                    cvss = CVSS2(vectors['V2Vector'])
                                    vectors['V2Vector_base_score']=str(round(cvss.base_score, 1))
                                    vectors['V2Vector_metrics']=cvss.metrics
                                    vectors['provider'] = provider
                                    #print("   CVSS2 {provider} {base_score}  {vector}".format(provider=provider, base_score=vectors['V2Vector_base_score'], vector=vectors['V2Vector']))
                                    
                        if 'Severity' in vulnerability:
                            vulnerability['SeverityInt'] = vulnsum[vulnerability['Severity'].capitalize()]['severity']

                        vulnsum[vulnerability['Severity'].capitalize()]['total'] += 1
                        reportsummary['vuln_total'] += 1
                        reportsummary['vuln_'+vulnerability['Severity'].lower()] += 1

                        if 'FixedVersion' in vulnerability:
                            vulnsum[vulnerability['Severity'].capitalize()]['fixed'] += 1
                            reportsummary['vuln_fixed'] += 1
                    target['summary'] = vulnsum
                
                VulnList[imageUid].append(target)
                
            imageTrivyVulnSummary[imageUid] = vulnsum

            #pprint.pprint(imageTryviVulnList)
        return VulnList, imageTrivyVulnSummary
