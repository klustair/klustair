#!/usr/bin/env python3

import subprocess, json, sys
import requests
import re
import logging as log
import argparse
import os
from datetime import datetime
import time
import pprint

def getNamespaces():
    
    namespaces = json.loads(subprocess.run(["kubectl", "get", "namespaces", "-o=json"], stdout=subprocess.PIPE).stdout.decode('utf-8'))
    
    nsList=[]
    for namespace in namespaces['items']:
        ns = {
            'name': namespace['metadata']['name'],
            'uid': namespace['metadata']['uid'],
            'creationTimestamp': namespace['metadata']['creationTimestamp']
        }

        if namespacesWhitelist and ns['name'] not in namespacesWhitelist: 
            continue
        if namespacesBlacklist and ns['name'] in namespacesBlacklist: 
            continue
        log.debug("Namespace: {}".format(ns['name']))
        nsList.append(ns)

    return nsList

def getPods(nsList):

    podsList=[]
    containersList=[]
    for ns in nsList:
        pods = json.loads(subprocess.run(["kubectl", "get", "pods", "-n", ns['name'], "-o=json"], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        
        for pod in pods['items']:
            p = {
                'name': pod['metadata']['name'],
                'namespace_uid': ns['uid'],
                'uid': pod['metadata']['uid'],
                'creationTimestamp': pod['metadata']['creationTimestamp']
            }
            log.debug("Pod: {}".format(p['name']))
            #pprint.pprint(pod)
            podsList.append(p)
            for container in pod['spec']['containers']: 
                c = {
                    'name': container['name'],
                    'namespace_uid': ns['uid'],
                    'pod_uid': p['uid'],
                    'image': container['image'],
                    'imagePullPolicy': container['imagePullPolicy'],
                    'securityContext': container.get('securityContext', ''),
                    'initContainer': False
                }
                ### ADD CONTAINER STATUS !!!!

                #pprint.pprint(container)
                containersList.append(c)

            if 'initContainers' in pod['spec']:
                for initContainer in pod['spec']['initContainers']:
                    c = {
                        'name': initContainer['name'],
                        'namespace_uid': ns['uid'],
                        'pod_uid': p['uid'],
                        'image': initContainer['image'],
                        'imagePullPolicy': initContainer['imagePullPolicy'],
                        'securityContext': initContainer.get('securityContext', ''),
                        'initContainer': True
                    }
                    containersList.append(c)

    return podsList, containersList

def getImages(containersList):
    imagesList = []
    for container in containersList:
        imagesList.append(container['image'])
    uniqueImagesList = list(set(imagesList))

    return uniqueImagesList

def submitImagesToAnchore(uniqueImagesList):
    for image in uniqueImagesList:
        anchoreAdd = json.loads(subprocess.run(["anchore-cli", "--json", "image", "add", image], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        log.debug("Submitted Image: {}".format(image))

def getImageVulnerabilities(uniqueImagesList):
    imageVulnList = {}
    imageVulnSummary = {}
    for image in uniqueImagesList:
        vulnlist = []
        vulnsum = {
            'Critical': {
                'total': 0,
                'fixed': 0
            },
            'High': {
                'total': 0,
                'fixed': 0
            },
            'Medium': {
                'total': 0,
                'fixed': 0
            },
            'Low': {
                'total': 0,
                'fixed': 0
            },
            'Negligible': {
                'total': 0,
                'fixed': 0
            },
            'Unknown': {
                'total': 0,
                'fixed': 0
            }
        }

        imageVuln = json.loads(subprocess.run(["anchore-cli", "--json", "image", "vuln", image, 'all'], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        for vulnerability in imageVuln['vulnerabilities']:
            vulnlist.append(vulnerability['vuln'])
            vulnsum[vulnerability['severity']]['total'] += 1
            if vulnerability['fix'] != 'None':
                vulnsum[vulnerability['severity']]['fixed'] += 1
        #pprint.pprint(imageVuln)

        imageVulnList[image] = vulnlist
        imageVulnSummary[image] = vulnsum

    return imageVulnList, imageVulnSummary

def createReport():
    report = {
        'checktime': datetime.now(),
    }

    return report

def awaitAnalysis():
    try:
        allAnalyzed = False
        while allAnalyzed == False:
            print("waiting")
            time.sleep(3)
            anchoreSyncStatus = json.loads(subprocess.run(["anchore-cli", "--json", "image", "list"], stdout=subprocess.PIPE).stdout.decode('utf-8'))

            # Check if all images are analyzed
            for status in anchoreSyncStatus: 
                if status['analysis_status'] != 'analyzed':
                    allAnalyzed = False
                    break
                else: 
                    allAnalyzed = True

    except (KeyboardInterrupt, SystemExit):
        print("ABORT: Analysis aborted. No data was saved. ")
        sys.exit(0)
    except:
        print("ERROR")

def saveToDB():
    return

def run():
    report = createReport()
    #pprint.pprint(report)
    nsList = getNamespaces()
    #pprint.pprint(nsList)
    [podsList, containersList] = getPods(nsList)
    #pprint.pprint(podsList)
    #pprint.pprint(containersList)
    uniqueImagesList = getImages(containersList)
    #pprint.pprint(uniqueImagesList)

    submitImagesToAnchore(uniqueImagesList)
    
    awaitAnalysis()

    [imageVulnList, imageVulnSummary] = getImageVulnerabilities(uniqueImagesList)
    #pprint.pprint(imageVulnList)
    #pprint.pprint(imageVulnSummary)

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action='store_true', required=False, help="increase output verbosity")
    parser.add_argument("-n", "--namespaces", required=False, help="Coma separated whitelist of Namespaces to check")
    parser.add_argument("-N", "--namespacesblacklist", required=False, help="Coma separated blacklist of Namespaces to skip")
    parser.add_argument("-c", "--capabilities", required=False, help="Coma separated whitelist of capabilities to check")
    parser.add_argument("-o", "--output", default='cli', choices=['cli', 'json'], help="report format")

    args = parser.parse_args()
    if args.verbose:
        log.basicConfig(format='%(levelname)s:%(message)s', level=log.DEBUG)

    namespacesWhitelist = []
    if args.namespaces:
        namespacesWhitelist = args.namespaces.split(',')

    namespacesBlacklist = []
    if args.namespacesblacklist:
        namespacesBlacklist = args.namespacesblacklist.split(',')

    capabilitiesWhitelist = []
    if args.capabilities:
        capabilitiesWhitelist = args.capabilities.split(',')

    run()
