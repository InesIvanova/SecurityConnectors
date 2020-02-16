from core_ines.helpers.base_connector import ConnectorResult, BaseConnector
from core_ines.handler import SubProcessorInputOutputHandler
from core_ines.common.exceptions import ResponseNotInCorrectFormatException, MaximRequestsExceededException
import requests
import time
import os


VIRUSTOTAL_API_KEY = os.environ.get('VT_API_KEY')
HIBP_APII_KEY = os.environ.get('HIBP_API_KEY')


class VirusTotalConnector(BaseConnector):
    request_counter = 0
    def __init__(self, path, max_request_per_minute=4) -> None:
        self.api_key = os.environ.get('VT_API_KEY')
        self.scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
        self.report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
        self.handler = SubProcessorInputOutputHandler(path=path, connector='virustotal')
        self.headers = {'Accept': 'application/json'}
        self.max_request_per_minute = max_request_per_minute

    def analyze(self):
        for urls in self.handler.list_urls_from_file():
            if urls:
                [self._scan_url(url) if self.request_counter <= self.max_request_per_minute else self.wait() for url in urls]

    def _scan_url(self, url):
        params = {'apikey': self.api_key, 'url': url}
        if self.request_counter == self.max_request_per_minute:
            self.wait()
        response = requests.post(self.scan_url, data=params)

        self.request_counter += 1
        if response.status_code == 204:
            print("Maximum requests exceeded")
            raise MaximRequestsExceededException(message="Request limit error")
        else:
            try:
                scan_id = response.json()['scan_id']
            except KeyError as ex:
                raise ResponseNotInCorrectFormatException(message="Response format error")
            result_obj = self._get_url_report(scan_id=scan_id, url=url)
            self.handler.write_to_file(result=result_obj.result)

    def _get_url_report(self, scan_id, url):
        url = url
        params = {'apikey': self.api_key, 'resource': url, 'scan': scan_id}
        try:
            response = requests.get(self.report_url, params=params).json()
            self.request_counter += 1
        except ValueError as ex:
            raise ResponseNotInCorrectFormatException(message="Decoding response unsuccessful - check api documentation response")

        counter = 0
        for scan, values in response['scans'].items():
            if values['detected']:
                counter += 1

        if counter:
            return ConnectorResult({url: f"{counter} problems found"})
        return ConnectorResult({url: "Not Suspicious"})

    def wait(self):
        time.sleep(60)
        print("Waiting for requests limit...")
        self.request_counter = 0


class HIBPConnector(BaseConnector):
    def __init__(self, path):
        self.path = path
        self.hibp_api_key = os.environ.get('HIBP_API_KEY')
        self.handler = SubProcessorInputOutputHandler(path=path, connector='hibp')
        self.headers = {'hibp-api-key': self.hibp_api_key}
        self.url = 'https://haveibeenpwned.com/api/v3/breachedaccount/'

    def analyze(self):
        for mails in self.handler.list_urls_from_file():
            if mails:
                [self._scan_mail(mail) for mail in mails]

    def _scan_mail(self, mail):
        response = requests.get(self.url + mail, headers=self.headers)
        if response.content:
            res_obj = ConnectorResult({mail: "Vulnerable"})
        else:
            res_obj = ConnectorResult({mail: "Secured"})
        self.handler.write_to_file(result=res_obj.result)
