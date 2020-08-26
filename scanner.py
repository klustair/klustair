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

def getPods(nsList):

    podsList=[]
    containersList=[]
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
                'creation_timestamp': pod['metadata']['creationTimestamp']
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
                ### ADD CONTAINER STATUS !!!!

                #pprint.pprint(container)
                containersList.append(c)

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
        json.loads(subprocess.run(["anchore-cli", "--json", "image", "add", image], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        log.debug("Submitted Image: {}".format(image))

def getImageDetailsList(uniqueImagesList):
    imagesList = {}
    for image in uniqueImagesList:
        imagedetails = json.loads(subprocess.run(["anchore-cli", "--json", "image", "get", image], stdout=subprocess.PIPE).stdout.decode('utf-8'))[0]
        imageUid = str(uuid.uuid4())
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
            'repo': imagedetails['image_detail'][0]['repo']
        }
    return imagesList

def getImageVulnerabilities(imageDetailsList):
    imageVulnList = {}
    imageVulnSummary = {}
    for image, imagedetails in imageDetailsList.items():
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
    }

    return report

def awaitAnalysis():
    try:
        allAnalyzed = False
        while allAnalyzed == False:
            print('waiting for images to be analysed')
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

def saveToDB(report, nsList, podsList, containersList, imageDetailsList, imageVulnSummary):
    # DEV: dbname=postgres user=postgres password=mysecretpassword host=127.0.0.1 port=5432
    pdgbConnection = os.getenv('PGDBDB_CONNECTION', False)
    pdgbDb = os.getenv('PGDBDB_db', 'postgres')
    pdgbUser = os.getenv('PGDBDB_USER', False)
    pdgbPass = os.getenv('PGDBDB_PASS', False)
    pdgbHost = os.getenv('PGDBDB_HOST', '127.0.0.1')
    pdgbPort = os.getenv('PGDBDB_PORT', '5432')
    
    if pdgbConnection:
        conn = psycopg2.connect(pdgbConnection)
    elif pdgbUser and pdgbUser: 
        conn = psycopg2.connect(
            database=pdgbDb, user=pdgbUser, password=pdgbPass, host=pdgbHost, port= pdgbPort
        )

    conn.autocommit = True
    cursor = conn.cursor()

    cursor.execute("INSERT INTO k_reports(uid, checktime) VALUES ('{0}', current_timestamp)".format(report['uid']))

    for ns in nsList:
        cursor.execute("INSERT INTO k_namespaces(name, kubernetes_namespace_uid, uid, report_uid, creation_timestamp) VALUES ('{0}', '{1}', '{2}', '{3}', '{4}')"
            .format(ns['name'], ns['kubernetes_namespace_uid'], ns['uid'], report['uid'], ns['creation_timestamp']))

    for pod in podsList:
        cursor.execute("INSERT INTO k_pods(podname, kubernetes_pod_uid, namespace_uid, uid, report_uid, creation_timestamp) VALUES ('{0}', '{1}', '{2}', '{3}', '{4}', '{5}')"
            .format(
                pod['podname'], 
                pod['kubernetes_pod_uid'], 
                pod['namespace_uid'], 
                pod['uid'], 
                report['uid'], 
                pod['creation_timestamp']))

    for container in containersList:
        cursor.execute("INSERT INTO k_containers(name, report_uid, namespace_uid, pod_uid, uid, image, image_pull_policy, security_context, init_container) VALUES ('{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}')"
            .format(
                container['name'], 
                report['uid'], 
                container['namespace_uid'], 
                container['pod_uid'],
                container['uid'], 
                container['image'],
                container['image_pull_policy'],
                container['security_context'],
                container['init_container']
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
                repo
            ) VALUES (
                '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}', '{12}', '{13}'
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
                image['repo']
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

    #submitImagesToAnchore(uniqueImagesList)
    
    #awaitAnalysis()

    imageDetailsList = getImageDetailsList(uniqueImagesList)


    [imageVulnList, imageVulnSummary] = getImageVulnerabilities(imageDetailsList)
    #pprint.pprint(imageVulnList)
    #pprint.pprint(imageVulnSummary)

    saveToDB(report, nsList, podsList, containersList, imageDetailsList, imageVulnSummary)
    sys.exit(0)


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
