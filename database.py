import os
import uuid
import psycopg2
import json
import pprint
import logging as log
from psycopg2.extras import Json
from datetime import datetime, timedelta

class Database: 
    connected=False
    def __init__(self, connection=False, database='postgres', username=False, password=False, host='127.0.0.1', port='5432'):
        print("INFO: Save data to DB")
        self.__connection = os.getenv('DB_CONNECTION', connection)
        self.__database = os.getenv('DB_DATABASE', database)
        self.__username = os.getenv('DB_USERNAME', username)
        self.__password = os.getenv('DB_PASSWORD', password)
        self.__host = os.getenv('DB_HOST', host)
        self.__port = os.getenv('DB_PORT', port)

    def dbConnect(self):
        
        conn = None
        if self.__connection:
            conn = psycopg2.connect(self.__connection)
        elif self.__database and self.__username and self.__password and self.__hostost and self.__port: 
            conn = psycopg2.connect(
                database=self.__database, 
                user=self.__username, 
                password=self.__password, 
                host=self.__host, 
                port= self.__port
            )
        if conn == None:
            self.connected = False
            print("INFO: No DB Connection.")
            return
        else:
            self.connected = True
            print("INFO: Got a DB Connection.")

        conn.autocommit = True
        self.__cursor = conn.cursor()

    def cleanupDB(self, limitDate=False, limitNr=False ):
        if limitNr is not False:
            log.debug('CLEANUP: keep only {limitNr} reports'.format(limitNr=limitNr))
            self.__cursor.execute('''
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

            self.__cursor.execute('''
                DELETE FROM k_reports
                WHERE checktime < '{checktimeLimit}'::date;
            '''.format(
                checktimeLimit=checktimeLimit
            ))

    def saveReport(self, report):
        self.__cursor.execute('''INSERT INTO k_reports(
                uid, 
                checktime, 
                title
            ) VALUES (
                '{uid}', 
                current_timestamp, 
                '{title}'
            )'''
            .format(
                uid=report['uid'], 
                title=report['title']
            ))

    def saveNamespaces(self, report_uid, nsList):
        for ns in nsList:
            self.__cursor.execute('''INSERT INTO k_namespaces(
                    name, 
                    kubernetes_namespace_uid, 
                    uid, 
                    report_uid, 
                    creation_timestamp
                ) VALUES (
                    '{name}', 
                    '{kubernetes_namespace_uid}', 
                    '{uid}', 
                    '{report_uid}', 
                    '{creation_timestamp}'
                )'''
                .format(
                    name=ns['name'], 
                    kubernetes_namespace_uid=ns['kubernetes_namespace_uid'], 
                    uid=ns['uid'], 
                    report_uid=report_uid, 
                    creation_timestamp=ns['creation_timestamp']
                ))
    
    def saveNamespaceAudits(self, report_uid, namespaceAudits):
        for nsuid, namespaceAudit in namespaceAudits.items():
            for audit in namespaceAudit['auditItems']: 
                #pprint.pprint(namespaceAudit)
                self.__cursor.execute('''INSERT INTO k_audits(
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
                        '{resource_api_version}'
                    )'''
                    .format(
                        uid=audit['uid'],
                        namespace_uid=nsuid, 
                        report_uid=report_uid,
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
                        resource_api_version=audit['ResourceApiVersion']
                    ))
    
    def savePods(self, report_uid, podsList):
        for pod in podsList:
            self.__cursor.execute('''INSERT INTO k_pods(
                podname, 
                kubernetes_pod_uid, 
                namespace_uid, 
                uid, 
                report_uid, 
                creation_timestamp
            ) VALUES (
                '{podname}', 
                '{kubernetes_pod_uid}', 
                '{namespace_uid}', 
                '{uid}', 
                '{report_uid}', 
                '{creation_timestamp}')
            '''
            .format(
                podname=pod['podname'], 
                kubernetes_pod_uid=pod['kubernetes_pod_uid'], 
                namespace_uid=pod['namespace_uid'], 
                uid=pod['uid'], 
                report_uid=report_uid, 
                creation_timestamp=pod['creation_timestamp']
            ))

    def saveContainers(self, report_uid, containersList):
        for container in containersList.values():
            self.__cursor.execute('''INSERT INTO k_containers(
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
                    '{name}', 
                    '{report_uid}', 
                    '{namespace_uid}', 
                    '{pod_uid}', 
                    '{uid}', 
                    '{image}', 
                    '{image_pull_policy}', 
                    '{security_context}', 
                    '{init_container}', 
                    '{ready}', 
                    '{started}', 
                    '{restartCount}', 
                    '{startedAt}'
                )'''
                .format(
                    name=container['name'], 
                    report_uid=report_uid, 
                    namespace_uid=container['namespace_uid'], 
                    pod_uid=container['pod_uid'],
                    uid=container['uid'], 
                    image=container['image'],
                    image_pull_policy=container['image_pull_policy'],
                    security_context=container['security_context'],
                    init_container=container['init_container'],
                    ready=container.get('ready', False),
                    started=container.get('started', False),
                    restartCount=container.get('restartCount', 0),
                    startedAt=container.get('startedAt', ''),
            ))

    def saveImages(self, report_uid, uniqueImagesList):
        for image in uniqueImagesList.values():
            self.__cursor.execute('''INSERT INTO k_images(
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
                    '{uid}',
                    '{image_b64}',
                    '{report_uid}',
                    '{anchore_imageid}',
                    '{analyzed_at}',
                    '{created_at}',
                    '{fulltag}',
                    '{image_digest}',
                    '{arch}',
                    '{distro}',
                    '{distro_version}',
                    '{image_size}',
                    '{layer_count}',
                    '{registry}',
                    '{repo}',
                    '{dockerfile}'
                )'''
                .format(
                    uid=image['uid'],
                    image_b64=image['image_b64'],
                    report_uid=report_uid, 
                    anchore_imageid=image.get('anchore_imageid', ''),
                    analyzed_at=image.get('analyzed_at', '01.01.1970'),
                    created_at=image.get('created_at', '01.01.1970'),
                    fulltag=image['fulltag'],
                    image_digest=image.get('image_digest', ''),
                    arch=image.get('arch', ''),
                    distro=image.get('distro', ''),
                    distro_version=image.get('distro_version'),
                    image_size=image.get('image_size', 0),
                    layer_count=image.get('layer_count', 0),
                    registry=image.get('registry', ''),
                    repo=image.get('repo', ''),
                    dockerfile=image.get('dockerfile', '')
            ))

    def saveVulnsummary(self, report_uid, vulnSummary):
        for image_uid, imageSummary in vulnSummary.items():
            for severity, values in imageSummary.items():
                imagesummaryUid = str(uuid.uuid4())
                self.__cursor.execute('''INSERT INTO k_vulnsummary(
                        uid,
                        image_uid, 
                        report_uid, 
                        severity,
                        total,
                        fixed
                    ) VALUES (
                        '{imagesummaryUid}',
                        '{image_uid}',
                        '{report_uid}',
                        '{severity}',
                        '{total}',
                        '{fixed}'
                    )'''
                    .format(
                        imagesummaryUid=imagesummaryUid,
                        image_uid=image_uid,
                        report_uid=report_uid, 
                        severity=severity,
                        total=values['total'],
                        fixed=values['fixed']
                ))


    def saveVulnAnchore(self, report_uid, imageVulnList):
        for image_uid, vulnList in imageVulnList.items():
            for vuln in vulnList:
                vulnUid = str(uuid.uuid4())
                try:
                    nvd_data = vuln['nvd_data'][0]
                except IndexError:
                    nvd_data = {'id': '', 'cvss_v3': {'base_score':0,'exploitability_score':0,'impact_score':0,}}

                self.__cursor.execute('''INSERT INTO k_vuln_anchore(
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
                        '{vulnUid}',
                        '{image_uid}',
                        '{report_uid}',
                        '{feed}',
                        '{feed_group}',
                        '{fix}',
                        '{nvd_id}',
                        {nvd_base_score},
                        {nvd_exploitability_score},
                        {nvd_impact_score},
                        '{package}',
                        '{package_cpe}',
                        '{package_cpe23}',
                        '{package_name}',
                        '{package_path}',
                        '{package_type}',
                        '{package_version}',
                        '{severity}',
                        '{url}',
                        '{19}'
                    )'''
                    .format(
                        vulnUid=vulnUid,
                        image_uid=image_uid,
                        report_uid=report_uid, 
                        feed=vuln['feed'],
                        feed_group=vuln['feed_group'],
                        fix=vuln['fix'],
                        nvd_id=nvd_data['id'],
                        nvd_base_score=nvd_data['cvss_v3']['base_score'],
                        nvd_exploitability_score=nvd_data['cvss_v3']['exploitability_score'],
                        nvd_impact_score=nvd_data['cvss_v3']['impact_score'],
                        package=vuln['package'],
                        package_cpe=vuln['package_cpe'],
                        package_cpe23=vuln['package_cpe23'],
                        package_name=vuln['package_name'],
                        package_path=vuln['package_path'],
                        package_type=vuln['package_type'],
                        package_version=vuln['package_version'],
                        severity=vuln['severity'],
                        url=vuln['url'],
                        vuln=vuln['vuln']
                ))

    def saveVulnTrivy(self, report_uid, imageVulnList):
        for image_uid, vulnList in imageVulnList.items():
            for target in vulnList:
                #pprint.pprint(target)
                for vuln in target['Vulnerabilities']:
                    vulnUid = str(uuid.uuid4())
                    
                    self.__cursor.execute('''INSERT INTO k_vuln_trivy(
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
                            report_uid=report_uid, 
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


    def saveContainersHasImage(self, report_uid, containersHasImage):
        for item in containersHasImage:
            self.__cursor.execute('''INSERT INTO k_container_has_images (
                    report_uid,
                    container_uid,
                    image_uid
                ) VALUES (
                    '{report_uid}',
                    '{container_uid}',
                    '{image_uid}'
                )'''
                .format(
                    report_uid=report_uid, 
                    container_uid=item['container_uid'], 
                    image_uid=item['image_uid']
            ))


    def saveReportsSummaries(self, report_uid, reportsummary):
        self.__cursor.execute('''INSERT INTO k_reports_summaries(
                uid,
                report_uid, 
                namespaces_checked,
                namespaces_total,
                vuln_total,
                vuln_critical,
                vuln_high,
                vuln_medium,
                vuln_low,
                vuln_unknown,
                vuln_fixed,
                pods,
                images
            ) VALUES (
                '{uid}', 
                '{report_uid}', 
                {namespaces_checked},
                {namespaces_total},
                {vuln_total},
                {vuln_critical},
                {vuln_high},
                {vuln_medium},
                {vuln_low},
                {vuln_unknown},
                {vuln_fixed},
                {pods},
                {images}
            )'''
            .format(
                uid=reportsummary['uid'],
                report_uid=report_uid, 
                namespaces_checked=reportsummary.get('namespaces_checked', 0),
                namespaces_total=reportsummary.get('namespaces_total', 0),
                vuln_total=reportsummary.get('vuln_total', 0),
                vuln_critical=reportsummary.get('vuln_critical', 0),
                vuln_medium=reportsummary.get('vuln_medium', 0),
                vuln_high=reportsummary.get('vuln_high', 0),
                vuln_low=reportsummary.get('vuln_low', 0),
                vuln_unknown=reportsummary.get('vuln_unknown', 0),
                vuln_fixed=reportsummary.get('vuln_fixed', 0),
                pods=reportsummary.get('pods', 0),
                images=reportsummary.get('images', 0)
            ))