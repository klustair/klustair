import os
import requests
import logging as log
import pprint
from datetime import datetime, timedelta


class Api: 
    def __init__(self, url='', personal_access_token=''):
        print("INFO: Save data to API")
        self.__url = os.getenv('KLUSTAIR_URL', url)
        personal_access_token = os.getenv('KLUSTAIR_PERSONAL_ACCESS_TOKEN', personal_access_token)
        self.headers = {'Authorization': f'Bearer {personal_access_token}'}

    def getRunnerConfig(self, config):
        config = '0d56e018-53e3-474a-a402-f5bc50bfd97a'
        r = requests.get(url=f'{self.__url}/api/v1/pac/config/runner/get/{config}', headers=self.headers)
        pprint.pprint(r.json())
    
    def saveReport(self, report):
        r = requests.post(url=f'{self.__url}/api/v1/pac/report/create', data=report, headers=self.headers)
        if (r.status_code > 299):
            pprint.pprint(r.status_code)
            pprint.pprint(r.text)
    
    def saveNamespaces(self, report_uid, nsList):
        r = requests.post(url=f'{self.__url}/api/v1/pac/report/{report_uid}/namespace/create', json=nsList, headers=self.headers)
        if (r.status_code > 299):
            pprint.pprint(r.status_code)
            pprint.pprint(r.text)

    def saveNamespaceAudits(self, report_uid, namespaceAudits):
        r = requests.post(url=f'{self.__url}/api/v1/pac/report/{report_uid}/audit/create', json=namespaceAudits, headers=self.headers)
        if (r.status_code > 299):
            pprint.pprint(r.status_code)
            pprint.pprint(r.text)

    def savePods(self, report_uid, podsList):
        r = requests.post(url=f'{self.__url}/api/v1/pac/report/{report_uid}/pod/create', json=podsList, headers=self.headers)
        if (r.status_code > 299):
            pprint.pprint(r.status_code)
            pprint.pprint(r.text)

    def saveContainers(self, report_uid, containersList):
        r = requests.post(url=f'{self.__url}/api/v1/pac/report/{report_uid}/container/create', json=containersList, headers=self.headers)
        if (r.status_code > 299):
            pprint.pprint(r.status_code)
            pprint.pprint(r.text)

    def saveImages(self, report_uid, uniqueImagesList):
        r = requests.post(url=f'{self.__url}/api/v1/pac/report/{report_uid}/image/create', json=uniqueImagesList, headers=self.headers)
        if (r.status_code > 299):
            pprint.pprint(r.status_code)
            pprint.pprint(r.text)

    def saveVulnTrivy(self, report_uid, imageVulnListTrivy):
        r = requests.post(url=f'{self.__url}/api/v1/pac/report/{report_uid}/vuln/create', json=imageVulnListTrivy, headers=self.headers)
        if (r.status_code > 299):
            pprint.pprint(r.status_code)
            pprint.pprint(r.text)

    def saveVulnsummary(self, report_uid, imageVulnSummary):
        r = requests.post(url=f'{self.__url}/api/v1/pac/report/{report_uid}/vuln/summary/create', json=imageVulnSummary, headers=self.headers)
        if (r.status_code > 299):
            pprint.pprint(r.status_code)
            pprint.pprint(r.text)

    def saveContainersHasImage(self, report_uid, containersHasImage):
        r = requests.post(url=f'{self.__url}/api/v1/pac/report/{report_uid}/containerhasimage/create', json=containersHasImage, headers=self.headers)
        if (r.status_code > 299):
            pprint.pprint(r.status_code)
            pprint.pprint(r.text)

    def saveReportsSummaries(self, report_uid, reportsummary):
        r = requests.post(url=f'{self.__url}/api/v1/pac/report/{report_uid}/summary/create', json=reportsummary, headers=self.headers)
        if (r.status_code > 299):
            pprint.pprint(r.status_code)
            pprint.pprint(r.text)

    def cleanupDB(self, limitDate=False, limitNr=False ):

        if limitDate is not False:
            now = datetime.now()
            d = timedelta(days = int(limitDate))
            checktimeLimit = now - d
        else:
            checktimeLimit = False

        cleanup = {"limitNr": limitNr, "limitDate": limitDate}

        log.debug(f'CLEANUP: keep {limitNr} reports, Timelimit {checktimeLimit}')

        r = requests.post(url=f'{self.__url}/api/v1/pac/report/cleanup', json=cleanup, headers=self.headers)
        if (r.status_code > 299):
            pprint.pprint(r.status_code)
            pprint.pprint(r.text)

