from core.connectors import VirusTotalConnector, HIBPConnector
import os

"""
If you are using a premium api key you can
specify max_request_per_minute=6000 in the instantiation the of object
default will be 4
"""
path_vt = os.path.abspath(os.path.join(os.path.dirname( __file__ ), 'source_files'))
path_hibp = os.path.abspath(os.path.join(os.path.dirname( __file__ ), 'source_files_mails'))

connectors = [VirusTotalConnector(path=path_vt), HIBPConnector(path=path_hibp)]

for connector in connectors:
    try:
        connector.analyze()
        print("Successfully analyzed")
    except Exception as ex:
        print(f"Something went wrong :( {ex}")
