import os
import json

connectors_hash = {
    'virustotal': os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'analysis')),
    'hibp': os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'analysis_mails'))
}


class SubProcessorInputOutputHandler:
    def __init__(self, path: str, connector: str=None):
        self.path = path
        self.write_to_file_path = connectors_hash[connector]

    def list_urls_from_file(self):
        return self._get_urls()

    def _get_files(self):
        return os.listdir(self.path)

    def _get_urls(self):
        files = self._get_files()
        for file in files:
            with open(self.path + "/" + file, 'r') as file:
                current_file_urls = [el.replace('\n', '') for el in file.readlines() if el]
                yield current_file_urls

    def write_to_file(self, result):
        with open(self.write_to_file_path+ "/" +'analysis.json', 'a') as file:
            json.dump(result, file)



