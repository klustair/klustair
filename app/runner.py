#!/usr/bin/env python3

import subprocess, json, sys
import logging as log
import argparse
import os
import pprint
import uuid
import base64
from anchore import Anchore
from trivy import Trivy
from api import Api

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
    for ns in nsList:
        nsUid = ns['uid']
        namespaceAudits[nsUid] = {
            'auditItems': []
        }
        for kubeauditCommand in kubeaudit:
            log.debug("Kubeaudit: audit {} on {}".format(kubeauditCommand, ns['name']))
            results = subprocess.run(["kubeaudit", kubeauditCommand, "-c", kubeconfig, "-n", ns['name'], "-p=json"], stdout=subprocess.PIPE).stdout.decode('utf-8').rstrip().split('\n')
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
    print('INFO: Load Pod and Container informations')

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
                'creation_timestamp': pod['metadata']['creationTimestamp']
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
                    'init_container': "false",
                    'ready': "true",
                    'started': "true",
                    'restartCount': 0,
                    'startedAt': ""
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
                        'init_container': "true",
                        'ready': "false",
                        'started': "false",
                        'restartCount': 0,
                        'startedAt': ""
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
#def checkContainerActuality(containersList, imageDetailsList): 
#    print('INFO: Check container actuality')
#    for container in containersList.values(): 
#        image_created_at_date = datetime.strptime(imageDetailsList[container['image']]['created_at'], "%Y-%m-%dT%H:%M:%SZ")
#        container_started_at_date = datetime.strptime(container['startedAt'], "%Y-%m-%dT%H:%M:%SZ")
#        if (image_created_at_date > container_started_at_date):
#            actuality = 'ERROR'
#        else:
#            actuality = 'OK   '
#        log.debug("Image actuality: {actuality} created:{image_created_at} started:{container_started_at} {name} {image}".format(actuality=actuality, name=container['name'], image=container['image'], container_started_at=str(container_started_at_date), image_created_at=str(image_created_at_date)))
#    return

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
        'vuln_negligible': 0,
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

    if (args.anchore == True):
        anchore = Anchore()
        
        anchore.submitImagesToAnchore(uniqueImagesList)
    
        anchore.awaitAnalysis()

        uniqueImagesList = anchore.getImageDetailsList(uniqueImagesList)

        [imageVulnListAnchore, imageVulnSummary] = anchore.getAnchoreVulnerabilities(uniqueImagesList, reportsummary)

    
    containersHasImage = linkImagesToContainers(uniqueImagesList, containersList)
    
    if args.apihost and args.apitoken:
        api.saveReport(report)
        api.saveNamespaces(report['uid'], nsList)
        api.saveNamespaceAudits(report['uid'], namespaceAudits)
        api.savePods(report['uid'], podsList)
        api.saveContainers(report['uid'], containersList)
        api.saveImages(report['uid'], uniqueImagesList)
        if (args.trivy == True):
            api.saveVulnTrivy(report['uid'], imageVulnListTrivy)

        api.saveVulnsummary(report['uid'], imageVulnSummary)
        api.saveContainersHasImage(report['uid'], containersHasImage)
        api.saveReportsSummaries(report['uid'], reportsummary)

        api.cleanupDB(args.limitDate, args.limitNr)
    else:
        log.info('INFO: NOT saving report to API')

    sys.exit(0)
    
def __loadConfig():
    config = api.getRunnerConfig(args.configkey)
    if config['found']:
        pprint.pprint(config)

        # Do not override parameters set by cli or env
        if not args.limitNr and not config['limit_nr'] == None:
            args.limitNr = config['limit_nr']
        if not args.limitDate and not config['limit_date'] == None:
            args.limitDate = config['limit_date']
        if not args.namespaces and not config['namespaces'] == None:
            args.namespaces = config['namespaces']
        if not args.namespacesblacklist and not config['namespacesblacklist'] == None:
            args.namespacesblacklist = config['namespacesblacklist']
        if not args.label and not config['runner_label'] == None:
            args.label = config['runner_label']
        if not args.trivy and not config['trivy'] == None:
            args.trivy = config['trivy']
        if not args.trivycredentialspath and not config['trivycredentialspath'] == None:
            args.trivycredentialspath = config['trivycredentialspath']
        if not args.verbose and not config['verbosity'] == None:
            args.verbose = config['verbosity']
        if not args.kubeaudit and not config['kubeaudit'] == None:
            args.kubeaudit = config['kubeaudit']

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
    parser.add_argument("-ld", "--limitDate", default=os.environ.get('KLUSTAIR_LIMITDATE', False), required=False, help="Remove reports older than X days" )
    parser.add_argument("-ln", "--limitNr", default=os.environ.get('KLUSTAIR_LIMITNR', False), required=False, help="Keep only X reports" )
    parser.add_argument("-C", "--configkey", default=os.environ.get('KLUSTAIR_CONFIGKEY', False), required=False, help="Load remote configuration from frontend" )
    parser.add_argument("-H", "--apihost", default=os.environ.get('KLUSTAIR_APIHOST', False), required=False, help="Remote API-host address [example: https://localhost:8443]" )
    parser.add_argument("-T", "--apitoken", default=os.environ.get('KLUSTAIR_APITOKEN'), required=False, help="API Access Token from Klustair Frontend" )

    args = parser.parse_args()

    if args.apihost and args.apitoken:
        api = Api(args.apihost ,args.apitoken)

        if args.configkey:
            __loadConfig()


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
