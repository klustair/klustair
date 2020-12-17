#!/usr/bin/env python3

import subprocess, json, sys
import requests
import re
import logging as log
import argparse
import os
import pprint
import uuid
import base64
from database import Database
from anchore import Anchore
from trivy import Trivy

report = {}

def getNamespaces(reportsummary):
    print('INFO: Load Namespaces')
    namespaces = json.loads(subprocess.run(["kubectl", "get", "namespaces", "-o=json"], stdout=subprocess.PIPE).stdout.decode('utf-8'))
    
    nsList=[]
    for namespace in namespaces['items']:
        reportsummary['namespaces_total'] +=1 
        namespaceUid = str(uuid.uuid4())
        ns = {
            'name': namespace['metadata']['name'],
            'uid': namespaceUid,
            'kubernetes_namespace_uid': namespace['metadata']['uid'],
            'report_uid': report['uid'],
            'creation_timestamp': namespace['metadata']['creationTimestamp']
        }

        if namespacesWhitelist and ns['name'] not in namespacesWhitelist: 
            continue
        if namespacesBlacklist and ns['name'] in namespacesBlacklist: 
            continue

        reportsummary['namespaces_checked'] +=1 
        log.debug("Namespace: {}".format(ns['name']))
        nsList.append(ns)

    return nsList

def getKubeaudits(nsList):
    namespaceAudits = {}
    if 'none' in kubeaudit:
        return namespaceAudits

    print('INFO: Run Kubeaudit')
    kubeconfig = os.getenv('KUBECONFIG', "/configs/kube.config")
    for kubeauditCommand in kubeaudit:
        for ns in nsList:
            log.debug("Kubeaudit: audit {} on {}".format(kubeauditCommand, ns['name']))
            results = subprocess.run(["kubeaudit", kubeauditCommand, "-c", kubeconfig, "-n", ns['name'], "-p=json"], stdout=subprocess.PIPE).stdout.decode('utf-8').rstrip().split('\n')
            nsUid = ns['uid']
            namespaceAudits[nsUid] = {
                'auditItems': []
            }
            for result in results:
                try:
                    audit = json.loads(result)
                except:
                    break

                audit['uid'] = str(uuid.uuid4())


                if 'Container' in audit: 
                    audit['audit_type'] = 'container'
                elif audit['ResourceKind'] == 'Deployment': 
                    audit['audit_type'] = 'pod'
                elif audit['ResourceKind'] == 'StatefulSet': 
                    audit['audit_type'] = 'pod'
                elif audit['ResourceKind'] == 'Namespace':
                    audit['audit_type'] = 'namespace'
                else:
                    #pprint.pprint(audit)
                    print("not categorized: {}".format(audit['AuditResultName']))
                    audit['audit_type'] = 'unknown'
                    
                namespaceAudits[nsUid]['auditItems'].append(audit)

    #pprint.pprint(namespaceAudits)
    #sys.exit()
    return namespaceAudits

def getPods(nsList, reportsummary):
    print('INFO: Load Pod an Container informations')

    podsList=[]
    containersList={}
    for ns in nsList:
        pods = json.loads(subprocess.run(["kubectl", "get", "pods", "-n", ns['name'], "-o=json"], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        
        for pod in pods['items']:

            reportsummary['pods'] += 1

            podUid = str(uuid.uuid4())
            p = {
                'podname': pod['metadata']['name'],
                'report_uid': report['uid'],
                'namespace_uid': ns['uid'],
                'kubernetes_pod_uid': pod['metadata']['uid'],
                'uid': podUid,
                'creation_timestamp': pod['metadata']['creationTimestamp'],
                'pod_json': json.dumps(pod)
            }
            log.debug("Pod: {}".format(p['podname']))
            #pprint.pprint(pod)
            podsList.append(p)
            for container in pod['spec']['containers']:

                reportsummary['containers'] += 1

                containerUid = str(uuid.uuid4())
                c = {
                    'name': container['name'],
                    'report_uid': report['uid'],
                    'namespace_uid': ns['uid'],
                    'pod_uid': p['uid'],
                    'uid': containerUid,
                    'image': container['image'],
                    'image_pull_policy': container['imagePullPolicy'],
                    'security_context': json.dumps(container.get('securityContext', '')),
                    'init_container': False
                }
                log.debug("Container: {}".format(c['name']))

                #pprint.pprint(container)
                containersList[c['image']] = c

            if 'initContainers' in pod['spec']:
                for initContainer in pod['spec']['initContainers']:
                    initContainerUid = str(uuid.uuid4())
                    c = {
                        'name': initContainer['name'],
                        'report_uid': report['uid'],
                        'namespace_uid': ns['uid'],
                        'pod_uid': p['uid'],
                        'uid': initContainerUid,
                        'image': initContainer['image'],
                        'image_pull_policy': initContainer['imagePullPolicy'],
                        'security_context': json.dumps(initContainer.get('securityContext', '')),
                        'init_container': True
                    }
                    log.debug("initContainer: {}".format(c['name']))
                    containersList[c['image']] = c

            if 'containerStatuses' in pod['status']:
                for containerStatus in pod['status']['containerStatuses']:
                    if containerStatus['name'] in containersList:
                        if 'state' in containerStatus and 'running' in containerStatus['state']:
                            startedAt = containerStatus['state']['running']['startedAt']
                        else: 
                            startedAt = ''
                        
                        containersList[containerStatus['name']].update([
                            ('ready', containerStatus['ready']),
                            ('started', containerStatus['started']),
                            ('restartCount', containerStatus['restartCount']),
                            ('startedAt', startedAt),
                        ])

    return podsList, containersList

def getImages(containersList):
    imagesList = []
    uniqueImagesList = {}
    for container in containersList.values():
        imagesList.append(container['image'])

    for image in list(set(imagesList)):
        imageUid = str(uuid.uuid4())
        image_b64 = base64.urlsafe_b64encode(image.encode('utf-8'))
        uniqueImagesList[imageUid] = {
            'uid': imageUid,
            'fulltag': image,
            'image_b64': image_b64.decode('utf-8')
        }

    return uniqueImagesList

# NOT Working yet, waiting for a good idea
def checkContainerActuality(containersList, imageDetailsList): 
    print('INFO: Check container actuality')
    for container in containersList.values(): 
        image_created_at_date = datetime.strptime(imageDetailsList[container['image']]['created_at'], "%Y-%m-%dT%H:%M:%SZ")
        container_started_at_date = datetime.strptime(container['startedAt'], "%Y-%m-%dT%H:%M:%SZ")
        if (image_created_at_date > container_started_at_date):
            actuality = 'ERROR'
        else:
            actuality = 'OK   '
        log.debug("Image actuality: {actuality} created:{image_created_at} started:{container_started_at} {name} {image}".format(actuality=actuality, name=container['name'], image=container['image'], container_started_at=str(container_started_at_date), image_created_at=str(image_created_at_date)))
    return

def linkImagesToContainers(imagesList,containersList):
    containerHasImage = []
    for container in containersList.values(): 
        for image_uid, image in imagesList.items():
            if container['image'] == image['fulltag']:
                containerImage = {
                    'report_uid': report['uid'],
                    'container_uid': container['uid'],
                    'image_uid': image_uid
                }
                containerHasImage.append(containerImage)
    
    return containerHasImage

def createReport():
    global report
    reportUid = str(uuid.uuid4())
    report = {
        'uid': reportUid,
        'title': args.label
    }

    return report

def getReportSummary(report):
    reportsummaryUid = str(uuid.uuid4())
    reportsummary = {
        'uid': reportsummaryUid,
        'report_uid': report['uid'],
        'namespaces_total': 0,
        'namespaces_checked': 0,
        'vuln_total': 0,
        'vuln_high': 0,
        'vuln_critical': 0,
        'vuln_medium': 0,
        'vuln_low': 0,
        'vuln_unknown': 0,
        'vuln_fixed': 0,
        'pods': 0,
        'containers': 0,
        'images': 0
    }
    return reportsummary

def run():

    report = createReport()

    reportsummary = getReportSummary(report)

    nsList = getNamespaces(reportsummary)

    namespaceAudits = getKubeaudits(nsList)

    [podsList, containersList] = getPods(nsList, reportsummary)

    uniqueImagesList = getImages(containersList)

    #checkContainerActuality(containersList, imageDetailsList)
    #sys.exit()

    imageVulnSummary = {}
    if (args.trivy == True):
        trivy = Trivy()
        trivy.loadRepoCredentials(args.trivycredentialspath)
        
        [imageVulnListTrivy, imageVulnSummary] = trivy.getImageTrivyVulnerabilities(uniqueImagesList, reportsummary)
    else:
        imageTrivyVulnList = {}

    if (args.anchore == True):
        anchore = Anchore()
        
        anchore.submitImagesToAnchore(uniqueImagesList)
    
        anchore.awaitAnalysis()

        uniqueImagesList = anchore.getImageDetailsList(uniqueImagesList)

        [imageVulnListAnchore, imageVulnSummary] = anchore.getAnchoreVulnerabilities(uniqueImagesList)
    else:
        imageVulnListAnchore = {}

    
    containersHasImage = linkImagesToContainers(uniqueImagesList, containersList)

    db = Database()
    db.dbConnect()

    if db.connected:
        db.saveReport(report)
        db.saveNamespaces(report['uid'], nsList)
        db.saveNamespaceAudits(report['uid'], namespaceAudits)
        db.savePods(report['uid'], podsList)
        db.saveContainers(report['uid'], containersList)
        db.saveImages(report['uid'], uniqueImagesList)

        if (args.trivy == True):
            db.saveVulnTrivy(report['uid'], imageVulnListTrivy)
        

        if (args.anchore == True):
            db.saveVulnAnchore(report['uid'], imageVulnListAnchore)

        db.saveVulnsummary(report['uid'], imageVulnSummary)
            
        db.saveContainersHasImage(report['uid'], containersHasImage)
        db.saveReportsSummaries(report['uid'], reportsummary)

        db.cleanupDB(args.limitDate, args.limitNr)
        print("INFO: All Data saved to DB")
    else:
        print("INFO: No Data saved to DB")
        
    sys.exit(0)
    


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action='store_true', required=False, help="increase output verbosity")
    parser.add_argument("-n", "--namespaces", default=os.environ.get('KLUSTAIR_NAMESPACES'), required=False, help="Coma separated whitelist of Namespaces to check")
    parser.add_argument("-N", "--namespacesblacklist", default=os.environ.get('KLUSTAIR_NAMESPACEBLACKLIST'), required=False, help="Coma separated blacklist of Namespaces to skip")
    parser.add_argument("-k", "--kubeaudit", default=os.environ.get('KLUSTAIR_KUBEAUDIT', 'all'), required=False, help="Coma separated list of audits to run. default: 'all', disable: 'none'" )
    parser.add_argument("-l", "--label", default='', required=False, help="A optional title for your run" )
    parser.add_argument("-a", "--anchore", action='store_true', required=False, help="Run Anchore vulnerability checks" )
    parser.add_argument("-t", "--trivy", action='store_true', required=False, help="Run Trivy vulnerability checks" )
    parser.add_argument("-c", "--trivycredentialspath", default=os.environ.get('KLUSTAIR_TRIVYCREDENTIALSPATH', './repo-credentials.json'), required=False, help="Path to repo credentials for trivy" )
    parser.add_argument("-ld", "--limitDate", default=False, required=False, help="Remove reports older than X days" )
    parser.add_argument("-ln", "--limitNr", default=False, required=False, help="Keep only X reports" )

    args = parser.parse_args()
    if args.verbose:
        log.basicConfig(format='%(levelname)s:%(message)s', level=log.DEBUG)

    namespacesWhitelist = []
    if args.namespaces:
        namespacesWhitelist = args.namespaces.split(',')

    namespacesBlacklist = []
    if args.namespacesblacklist:
        namespacesBlacklist = args.namespacesblacklist.split(',')

    kubeaudit = []
    if args.kubeaudit:
        kubeaudit = args.kubeaudit.split(',')

    run()
