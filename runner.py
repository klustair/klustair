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
import uuid
import psycopg2

report = {}

def getNamespaces():
    print('INFO: Load Namespaces')
    namespaces = json.loads(subprocess.run(["kubectl", "get", "namespaces", "-o=json"], stdout=subprocess.PIPE).stdout.decode('utf-8'))
    
    nsList=[]
    for namespace in namespaces['items']:
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

def getPods(nsList):
    print('INFO: Load Pod an Container informations')

    podsList=[]
    containersList={}
    for ns in nsList:
        pods = json.loads(subprocess.run(["kubectl", "get", "pods", "-n", ns['name'], "-o=json"], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        
        for pod in pods['items']:
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
                containersList[c['name']] = c

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
                    containersList[c['name']] = c

            for containerStatus in pod['status']['containerStatuses']:
                if containerStatus['name'] in containersList:
                    if 'state' in containerStatus and 'running' in containerStatus['state']:
                        startedAt = containerStatus['state']['running']['startedAt']
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
        uniqueImagesList[imageUid] = image

    return uniqueImagesList

def submitImagesToAnchore(uniqueImagesList):
    print('INFO: Submit images to Anchore')
    for image in uniqueImagesList:
        json.loads(subprocess.run(["anchore-cli", "--json", "image", "add", image], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        log.debug("Submitted Image: {}".format(image))

def getImageDetailsList(uniqueImagesList):
    print('INFO: Load imagedetails')
    imagesList = {}
    for imageUid, image in uniqueImagesList.items():
        log.debug("Load Image: {}".format(image))
        imagedetails = json.loads(subprocess.run(["anchore-cli", "--json", "image", "get", image], stdout=subprocess.PIPE).stdout.decode('utf-8'))[0]
        
        imagesList[image] = {
            'uid': imageUid,
            'anchore_imageid': imagedetails['image_detail'][0]['imageId'],
            'analyzed_at': imagedetails['analyzed_at'],
            'created_at': imagedetails['created_at'],
            'fulltag': imagedetails['image_detail'][0]['fulltag'],
            'image_digest': imagedetails['imageDigest'],
            'arch': imagedetails['image_content']['metadata']['arch'],
            'distro': imagedetails['image_content']['metadata']['distro'],
            'distro_version': imagedetails['image_content']['metadata']['distro_version'],
            'image_size': imagedetails['image_content']['metadata']['image_size'],
            'layer_count': imagedetails['image_content']['metadata']['layer_count'],
            'registry': imagedetails['image_detail'][0]['registry'],
            'repo': imagedetails['image_detail'][0]['repo'],
            'dockerfile': imagedetails['image_detail'][0]['dockerfile']
        }
    return imagesList

def getImageTrivies(uniqueImagesList):
    print('INFO: Load trivy Vulnerabilities')
    imageTryviVulnList = {}
    for imageUid, image in uniqueImagesList.items():
        log.debug("Load Vuln: {}".format(image))
        print("Load Vuln: {}".format(image))
        vulnsum = {
            'CRITICAL': {
                'total': 0,
                'fixed': 0
            },
            'HIGH': {
                'total': 0,
                'fixed': 0
            },
            'MEDIUM': {
                'total': 0,
                'fixed': 0
            },
            'LOW': {
                'total': 0,
                'fixed': 0
            },
            'UNKNOWN': {
                'total': 0,
                'fixed': 0
            }
        }

        imageVuln = json.loads(subprocess.run(["trivy", "-q", "i", "-f", "json", image], stdout=subprocess.PIPE).stdout.decode('utf-8'))

        # skip empty images like busybox
        if type(imageVuln) is not list:
            continue
        
        imageTryviVulnList[imageUid] = []
        for target in imageVuln:
            for vulnerability in target['Vulnerabilities']:
                vulnsum[vulnerability['Severity']]['total'] += 1
                if 'FixedVersion' in vulnerability:
                    vulnsum[vulnerability['Severity']]['fixed'] += 1
            target['summary'] = vulnsum
            imageTryviVulnList[imageUid].append(target)
            

    return imageTryviVulnList

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
        containerImage = {
            'report_uid': report['uid'],
            'container_uid': container['uid'],
            'image_uid': imagesList[container['image']]['uid']
        }
        containerHasImage.append(containerImage)
    
    return containerHasImage

def getImageVulnerabilities(imageDetailsList):
    print('INFO: Load Vulnerabilities')
    imageVulnList = {}
    imageVulnSummary = {}
    for image, imagedetails in imageDetailsList.items():
        log.debug("Load Vuln: {}".format(image))
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
            vulnsum[vulnerability['severity']]['total'] += 1
            if vulnerability['fix'] != 'None':
                vulnsum[vulnerability['severity']]['fixed'] += 1

        image_uid = imagedetails['uid']
        imageVulnList[image_uid] = imageVuln['vulnerabilities']
        imageVulnSummary[image_uid] = vulnsum
    
    return imageVulnList, imageVulnSummary

def createReport():
    global report
    reportUid = str(uuid.uuid4())
    report = {
        'uid': reportUid,
        'title': args.title
    }

    return report

def awaitAnalysis():
    try:
        allAnalyzed = False
        while allAnalyzed == False:
            time.sleep(3)
            anchoreSyncStatus = json.loads(subprocess.run(["anchore-cli", "--json", "image", "list"], stdout=subprocess.PIPE).stdout.decode('utf-8'))

            # Check if all images are analyzed
            for status in anchoreSyncStatus:
                if status['analysis_status'] == 'analyzing':
                    print('INFO: waiting for image {0} to be analysed'.format(status['image_detail'][0]['fulltag']))
                    allAnalyzed = False
                    break
                else: 
                    allAnalyzed = True

    except (KeyboardInterrupt, SystemExit):
        print("ABORT: Analysis aborted. No data was saved. ")
        sys.exit(0)
    #except:
    #    print("ERROR: Analysis aborted. No data was saved. ")
    #    sys.exit(0)

def saveToDB(report, nsList, namespaceAudits, podsList, containersList, imageDetailsList, imageVulnSummary, imageVulnList, containersHasImage):
    # DEV: dbname=postgres user=postgres password=mysecretpassword host=127.0.0.1 port=5432
    pdgbConnection = os.getenv('DB_CONNECTION', False)
    pdgbDb = os.getenv('DB_DATABASE', 'postgres')
    pdgbUser = os.getenv('DB_USERNAME', False)
    pdgbPass = os.getenv('DB_PASSWORD', False)
    pdgbHost = os.getenv('DB_HOST', '127.0.0.1')
    pdgbPort = os.getenv('DB_PORT', '5432')
    
    conn = None
    if pdgbConnection:
        conn = psycopg2.connect(pdgbConnection)
    elif pdgbDb and pdgbUser and pdgbPass and pdgbHost and pdgbPort: 
        conn = psycopg2.connect(
            database=pdgbDb, user=pdgbUser, password=pdgbPass, host=pdgbHost, port= pdgbPort
        )
    
    if conn == None:
        print("INFO: No Data saved to DB")
        return
    
    print("INFO: Save data to DB")

    conn.autocommit = True
    cursor = conn.cursor()

    cursor.execute("INSERT INTO k_reports(uid, checktime, title) VALUES ('{0}', current_timestamp, '{1}')".format(report['uid'], report['title']))

    for ns in nsList:
        cursor.execute("INSERT INTO k_namespaces(name, kubernetes_namespace_uid, uid, report_uid, creation_timestamp) VALUES ('{0}', '{1}', '{2}', '{3}', '{4}')"
            .format(ns['name'], ns['kubernetes_namespace_uid'], ns['uid'], report['uid'], ns['creation_timestamp']))

    #pprint.pprint(namespaceAudits)
    for nsuid, namespaceAudit in namespaceAudits.items():
        for audit in namespaceAudit['auditItems']: 
            #pprint.pprint(namespaceAudit)
            cursor.execute('''INSERT INTO k_audits(
                    uid, 
                    namespace_uid, 
                    report_uid, 
                    audit_type, 
                    audit_name, 
                    msg, 
                    severity_level, 
                    audit_time,
                    resource_name,
                    capability,
                    container,
                    missing_annotation,
                    resource_namespace,
                    resource_api_version
                ) VALUES (
                    '{uid}', 
                    '{namespace_uid}', 
                    '{report_uid}', 
                    '{audit_type}', 
                    '{audit_name}', 
                    '{msg}', 
                    '{severity_level}', 
                    '{audit_time}', 
                    '{resource_name}', 
                    '{capability}', 
                    '{container}', 
                    '{missing_annotation}', 
                    '{resource_namespace}', 
                    '{resource_api_version}')'''
                .format(
                    uid=audit['uid'],
                    namespace_uid=nsuid, 
                    report_uid=report['uid'],
                    audit_type=audit['audit_type'],
                    audit_name=audit['AuditResultName'],
                    msg=audit['msg'].replace('\'', '"'), 
                    severity_level=audit['level'], 
                    audit_time=audit['time'], 
                    resource_name=audit['ResourceName'], 
                    capability=audit.get('Capability', ''),
                    container=audit.get('Container', ''),
                    missing_annotation=audit.get('MissingAnnotation', ''),
                    resource_namespace=audit['ResourceNamespace'], 
                    resource_api_version=audit['ResourceApiVersion']))
                    

    for pod in podsList:
        cursor.execute("INSERT INTO k_pods(podname, kubernetes_pod_uid, namespace_uid, uid, report_uid, creation_timestamp) VALUES ('{0}', '{1}', '{2}', '{3}', '{4}', '{5}')"
            .format(
                pod['podname'], 
                pod['kubernetes_pod_uid'], 
                pod['namespace_uid'], 
                pod['uid'], 
                report['uid'], 
                pod['creation_timestamp']))

    for container in containersList.values():
        cursor.execute('''INSERT INTO k_containers(
                name, 
                report_uid, 
                namespace_uid, 
                pod_uid, 
                uid, 
                image, 
                image_pull_policy, 
                security_context, 
                init_container,
                ready,
                started,
                restart_count,
                started_at
            ) VALUES (
                '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}', '{12}'
            )'''
            .format(
                container['name'], 
                report['uid'], 
                container['namespace_uid'], 
                container['pod_uid'],
                container['uid'], 
                container['image'],
                container['image_pull_policy'],
                container['security_context'],
                container['init_container'],
                container.get('ready', False),
                container.get('started', False),
                container.get('restartCount', 0),
                container.get('startedAt', ''),
        ))

    for image in imageDetailsList.values():
        cursor.execute('''INSERT INTO k_images(
                uid, 
                report_uid, 
                anchore_imageid, 
                analyzed_at, 
                created_at, 
                fulltag, 
                image_digest, 
                arch, 
                distro, 
                distro_version, 
                image_size, 
                layer_count, 
                registry, 
                repo,
                dockerfile
            ) VALUES (
                '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}', '{12}', '{13}', '{14}'
            )'''
            .format(
                image['uid'],
                report['uid'], 
                image['anchore_imageid'],
                image['analyzed_at'],
                image['created_at'],
                image['fulltag'],
                image['image_digest'],
                image['arch'],
                image['distro'],
                image['distro_version'],
                image['image_size'],
                image['layer_count'],
                image['registry'],
                image['repo'],
                image['dockerfile']
        ))
    
    for image_uid, imageSummary in imageVulnSummary.items():
        for severity, values in imageSummary.items():
            imagesummaryUid = str(uuid.uuid4())
            cursor.execute('''INSERT INTO k_images_vulnsummary(
                    uid,
                    image_uid, 
                    report_uid, 
                    severity,
                    total,
                    fixed
                ) VALUES (
                    '{0}', '{1}', '{2}', '{3}', '{4}', '{5}'
                )'''
                .format(
                    imagesummaryUid,
                    image_uid,
                    report['uid'], 
                    severity,
                    values['total'],
                    values['fixed']
            ))

    for image_uid, vulnList in imageVulnList.items():
        for vuln in vulnList:
            vulnUid = str(uuid.uuid4())
            try:
                nvd_data = vuln['nvd_data'][0]
            except IndexError:
                nvd_data = {'id': '', 'cvss_v3': {'base_score':0,'exploitability_score':0,'impact_score':0,}}

            cursor.execute('''INSERT INTO k_images_vuln(
                    uid,
                    image_uid, 
                    report_uid, 
                    feed,
                    feed_group,
                    fix,
                    nvd_data_id,
                    nvd_data_base_score,
                    nvd_data_exploitability_score,
                    nvd_data_impact_score,
                    package_fullname,
                    package_cpe,
                    package_cpe23,
                    package_name,
                    package_path,
                    package_type,
                    package_version,
                    severity,
                    url,
                    vuln
                ) VALUES (
                    '{0}', '{1}', '{2}', '{3}', '{4}', '{5}','{6}', {7}, {8}, {9}, '{10}', '{11}', '{12}', '{13}', '{14}', '{15}', '{16}', '{17}', '{18}', '{19}'
                )'''
                .format(
                    vulnUid,
                    image_uid,
                    report['uid'], 
                    vuln['feed'],
                    vuln['feed_group'],
                    vuln['fix'],
                    nvd_data['id'],
                    nvd_data['cvss_v3']['base_score'],
                    nvd_data['cvss_v3']['exploitability_score'],
                    nvd_data['cvss_v3']['impact_score'],
                    vuln['package'],
                    vuln['package_cpe'],
                    vuln['package_cpe23'],
                    vuln['package_name'],
                    vuln['package_path'],
                    vuln['package_type'],
                    vuln['package_version'],
                    vuln['severity'],
                    vuln['url'],
                    vuln['vuln']
            ))

    for item in containersHasImage:
        cursor.execute("INSERT INTO k_container_has_images (report_uid, container_uid, image_uid) VALUES ('{0}', '{1}', '{2}')"
            .format(
                item['report_uid'], 
                item['container_uid'], 
                item['image_uid']
        ))
    return

def run():
    report = createReport()
    #pprint.pprint(report)

    nsList = getNamespaces()
    #pprint.pprint(nsList)

    namespaceAudits = getKubeaudits(nsList)
    #pprint.pprint(namespaceAudits)

    [podsList, containersList] = getPods(nsList)
    #pprint.pprint(podsList)
    #pprint.pprint(containersList)

    uniqueImagesList = getImages(containersList)
    #pprint.pprint(uniqueImagesList)

    [imageTrivyVulnList, imageTrivyVulnSummary] = getImageTrivies(uniqueImagesList)
    #pprint.pprint(imageTrivyVulnList)
    #pprint.pprint(imageTrivyVulnSummary)

    submitImagesToAnchore(uniqueImagesList)
    
    awaitAnalysis()

    imageDetailsList = getImageDetailsList(uniqueImagesList)

    #checkContainerActuality(containersList, imageDetailsList)
    #sys.exit()

    containersHasImage = linkImagesToContainers(imageDetailsList, containersList)
    #pprint.pprint(containersHasImage)

    [imageVulnList, imageVulnSummary] = getImageVulnerabilities(imageDetailsList)
    #pprint.pprint(imageVulnList)
    #pprint.pprint(imageVulnSummary)

    saveToDB(report, nsList, namespaceAudits, podsList, containersList, imageDetailsList, imageVulnSummary, imageVulnList, containersHasImage)
    sys.exit(0)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action='store_true', required=False, help="increase output verbosity")
    parser.add_argument("-n", "--namespaces", required=False, help="Coma separated whitelist of Namespaces to check")
    parser.add_argument("-N", "--namespacesblacklist", required=False, help="Coma separated blacklist of Namespaces to skip")
    parser.add_argument("-k", "--kubeaudit", default='all', required=False, help="Coma separated list of audits to run. default: 'all', disable: 'none'" )
    parser.add_argument("-t", "--title", default='', required=False, help="A optional title for your run" )

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
