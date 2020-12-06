#!/usr/bin/env python3

import subprocess, json, sys
import requests
import re
import logging as log
import argparse
import os
from datetime import datetime, timedelta
import time
import pprint
import uuid
import psycopg2
from psycopg2.extras import Json
from cvss import CVSS2, CVSS3
import base64
import docker

report = {}

def loadRepoCredentials(path):
    repoCredentials = {}
    try:
        with open(path, 'r') as f:
            repoCredentials = json.load(f)
        #log.debug(repoCredentials)
    except:
        log.debug("Credentials not loaded")
    return repoCredentials

def getImageDetails(uniqueImagesList):
    cli = docker.APIClient()

    imageTag = 'klustair/klustair:latest'
    imageTag = 'quay.io/k8scsi/csi-attacher:v2.0.0'
    image = cli.pull(imageTag)
    pprint.pprint(image) 

    inspect_image = cli.inspect_image(imageTag)
    pprint.pprint(inspect_image)

    inspect_distribution = cli.inspect_distribution(imageTag)
    pprint.pprint(inspect_distribution)

    history = cli.history(imageTag)
    pprint.pprint(history)

    image = cli.get_image(imageTag)
    f = open('/tmp/container.tar', 'wb')
    for chunk in image:
        f.write(chunk)
    f.close()

    #imagelist = cli.images()
    #pprint.pprint(imagelist)

    #image = cli.get_image('mysql:8')
    #pprint.pprint(image)

    
    #inspect_image = cli.inspect_image('mysql:8')
    #pprint.pprint(inspect_image)
    
    #cli = docker.from_env()
    #imagea = cli.images.pull('mysql:latest')
    #pprint.pprint(imagea.attrs)
    
    #image = cli.images.get("klustair/klustair-frontend:latest")
    #pprint.pprint(image.attrs)
    imagedetails = {}
    
    return imagedetails

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

def submitImagesToAnchore(uniqueImagesList):
    print('INFO: Submit images to Anchore')
    for image in uniqueImagesList.values():
        json.loads(subprocess.run(["anchore-cli", "--json", "image", "add", image['fulltag']], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        log.debug("Submitted Image: {}".format(image['fulltag']))

def getImageDetailsList(uniqueImagesList):
    print('INFO: Load imagedetails')
    for imageUid, image in uniqueImagesList.items():
        log.debug("Load Image: {}".format(uniqueImagesList[imageUid]['image']))
        imagedetails = json.loads(subprocess.run(["anchore-cli", "--json", "image", "get", uniqueImagesList[imageUid]['image']], stdout=subprocess.PIPE).stdout.decode('utf-8'))[0]
        
        uniqueImagesList[imageUid] = {
            'image_b64': image['image_b64'],
            'uid': image['uid'],
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
    return uniqueImagesList

def addCredentials(image, repoCredentials):

    for credential, credentialData in repoCredentials.items():
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

def removeCredenials():
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

def getImageTrivyVulnerabilities(uniqueImagesList, repoCredentials):
    print('INFO: Load trivy Vulnerabilities')
    imageTrivyVulnList = {}
    imageTrivyVulnSummary = {}
    for imageUid, image in uniqueImagesList.items():
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
        imageTrivyVulnList[imageUid] = []
        
        addCredentials(image['fulltag'], repoCredentials)
        #log.debug(subprocess.run(['printenv'], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        trivyresult = subprocess.run(["trivy", "-q", "i", "-f", "json", image['fulltag']], stdout=subprocess.PIPE).stdout.decode('utf-8')
        removeCredenials()

        try:
            imageVuln = json.loads(trivyresult)
        except json.JSONDecodeError:
            print ("ERROR: could not parse {}".format(image['fulltag']))
            continue

        # skip empty images like busybox
        if type(imageVuln) is not list:
            continue
        
        for target in imageVuln:
            if target['Vulnerabilities'] is not None: 
                for vulnerability in target['Vulnerabilities']:
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
                    if 'FixedVersion' in vulnerability:
                        vulnsum[vulnerability['Severity'].capitalize()]['fixed'] += 1
                target['summary'] = vulnsum
                imageTrivyVulnList[imageUid].append(target)
            
        imageTrivyVulnSummary[imageUid] = vulnsum

        #pprint.pprint(imageTryviVulnList)
    return imageTrivyVulnList, imageTrivyVulnSummary

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

def getImageVulnerabilities(imageDetailsList):
    print('INFO: Load Vulnerabilities')
    imageVulnList = {}
    imageVulnSummary = {}
    for image in imageDetailsList.values():
        log.debug("Load Vuln: {}".format(image['fulltag']))
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

        imageVuln = json.loads(subprocess.run(["anchore-cli", "--json", "image", "vuln", image['fulltag'], 'all'], stdout=subprocess.PIPE).stdout.decode('utf-8'))
        
        for vulnerability in imageVuln['vulnerabilities']:
            vulnsum[vulnerability['severity']]['total'] += 1
            if vulnerability['fix'] != 'None':
                vulnsum[vulnerability['severity']]['fixed'] += 1

        image_uid = image['uid']
        imageVulnList[image_uid] = imageVuln['vulnerabilities']
        imageVulnSummary[image_uid] = vulnsum
    
    return imageVulnList, imageVulnSummary

def createReport():
    global report
    reportUid = str(uuid.uuid4())
    report = {
        'uid': reportUid,
        'title': args.label
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

def dbConnect():
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
    
    return conn

def saveToDB(conn, report, nsList, namespaceAudits, podsList, containersList, imageTrivyVulnList, imageDetailsList, imageTrivyVulnSummary, imageVulnList, containersHasImage):
    # DEV: dbname=postgres user=postgres password=mysecretpassword host=127.0.0.1 port=5432

    
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
                    resource_namespace=audit.get('ResourceNamespace', ''),
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
                image_b64, 
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
                '{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}', '{12}', '{13}', '{14}', '{15}'
            )'''
            .format(
                image['uid'],
                image['image_b64'],
                report['uid'], 
                image.get('anchore_imageid', ''),
                image.get('analyzed_at', '01.01.1970'),
                image.get('created_at', '01.01.1970'),
                image['fulltag'],
                image.get('image_digest', ''),
                image.get('arch', ''),
                image.get('distro', ''),
                image.get('distro_version'),
                image.get('image_size', 0),
                image.get('layer_count', 0),
                image.get('registry', ''),
                image.get('repo', ''),
                image.get('dockerfile', '')
        ))
    
    for image_uid, imageSummary in imageTrivyVulnSummary.items():
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
    

    for image_uid, vulnList in imageTrivyVulnList.items():
        for target in vulnList:
            #pprint.pprint(target)
            for vuln in target['Vulnerabilities']:
                vulnUid = str(uuid.uuid4())
                
                cursor.execute('''INSERT INTO k_images_trivyvuln(
                        uid,
                        image_uid, 
                        report_uid, 
                        vulnerability_id,
                        pkg_name,
                        title,
                        descr,
                        installed_version,
                        fixed_version,
                        severity_source,
                        severity,
                        last_modified_date,
                        published_date,
                        links,
                        cvss,
                        cwe_ids
                    ) VALUES (
                        '{uid}', 
                        '{image_uid}', 
                        '{report_uid}', 
                        '{vulnerability_id}',
                        '{pkg_name}',
                        '{title}',
                        '{descr}',
                        '{installed_version}',
                        '{fixed_version}',
                        '{severity_source}',
                        '{severity}',
                        '{last_modified_date}',
                        '{published_date}',
                        {links},
                        {cvss},
                        {cwe_ids}
                    )'''
                    .format(
                        uid=vulnUid,
                        image_uid=image_uid, 
                        report_uid=report['uid'], 
                        vulnerability_id=vuln.get('VulnerabilityID', ''),
                        pkg_name=vuln['PkgName'],
                        title=vuln.get('Title', '').replace("'", "''"),
                        descr=vuln.get('Description', '').replace("'", "''"),
                        installed_version=vuln.get('InstalledVersion', ''),
                        fixed_version=vuln.get('FixedVersion', ''),
                        severity_source=vuln.get('SeveritySource', ''),
                        severity=vuln['SeverityInt'],
                        last_modified_date=vuln.get('LastModifiedDate', ''),
                        published_date=vuln.get('PublishedDate', ''),
                        links=Json(json.loads(json.dumps(vuln.get('References', '')))),
                        cvss=Json(json.loads(json.dumps(vuln.get('CVSS', '')))),
                        cwe_ids=Json(json.loads(json.dumps(vuln.get('CweIDs', ''))))
                ))


    for item in containersHasImage:
        cursor.execute("INSERT INTO k_container_has_images (report_uid, container_uid, image_uid) VALUES ('{0}', '{1}', '{2}')"
            .format(
                item['report_uid'], 
                item['container_uid'], 
                item['image_uid']
        ))
    return

def cleanupDB(conn, limitDate=False, limitNr=False ):
    conn.autocommit = True
    cursor = conn.cursor()

    if limitNr is not False:
        log.debug('CLEANUP: keep only {limitNr} reports'.format(limitNr=limitNr))
        cursor.execute('''
            DELETE FROM k_reports
            WHERE uid NOT IN (select uid from k_reports ORDER BY checktime DESC LIMIT {limitNr});
        '''.format(
            limitNr=limitNr
        ))

    if limitDate is not False:
        now = datetime.now()
        d = timedelta(days = int(limitDate))
        checktimeLimit = now - d


        log.debug('CLEANUP: removing reports older than {checktimeLimit}'.format(checktimeLimit=checktimeLimit))

        cursor.execute('''
            DELETE FROM k_reports
            WHERE checktime < '{checktimeLimit}'::date;
        '''.format(
            checktimeLimit=checktimeLimit
        ))

def run():
    getImageDetails('klustair/klustair:v0.2.7')
    sys.exit()

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

    #checkContainerActuality(containersList, imageDetailsList)
    #sys.exit()

    if (args.trivy == True):
        repoCredentials = loadRepoCredentials(args.trivycredentialspath)

        [imageTrivyVulnList, imageTrivyVulnSummary] = getImageTrivyVulnerabilities(uniqueImagesList, repoCredentials)
        #pprint.pprint(imageTrivyVulnList)
        #pprint.pprint(imageTrivyVulnSummary)
    else:
        imageTrivyVulnList = {}
        imageTrivyVulnSummary = {}

    if (args.anchore == True):
        submitImagesToAnchore(uniqueImagesList)
    
        awaitAnalysis()

        imageDetailsList = getImageDetailsList(uniqueImagesList)

        [imageVulnList, imageVulnSummary] = getImageVulnerabilities(uniqueImagesList)
        #pprint.pprint(imageVulnList)
        #pprint.pprint(imageVulnSummary)
    else:
        imageDetailsList = {}
        imageVulnList = {}
        imageVulnSummary = {}

    
    containersHasImage = linkImagesToContainers(uniqueImagesList, containersList)
    #pprint.pprint(containersHasImage)

    conn = dbConnect()

    if conn == None:
        print("INFO: No Data saved to DB")
        sys.exit(0)
    
    saveToDB(conn, report, nsList, namespaceAudits, podsList, containersList, imageTrivyVulnList, uniqueImagesList, imageTrivyVulnSummary, imageVulnList, containersHasImage)
    
    cleanupDB(conn,  args.limitDate, args.limitNr)


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
