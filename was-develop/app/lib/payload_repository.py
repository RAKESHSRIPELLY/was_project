__author__='JG'

import json
from lib import utility as util


class CMS:

    def __init__(self):
        self.log=util.Log()

    @staticmethod
    def login(username,password):
        message={'username':username,'password':password,'grant_type':'password','client_id':'cms-web-client'}
        payload=json.loads(json.dumps(message))
        return payload

    @staticmethod
    def logout():
        message=f""
        payload=json.dumps(message)
        return payload

    @staticmethod
    def applications():
        message=f""
        payload=json.dumps(message)
        return payload

    @staticmethod
    def get_application_details():
        message=f""
        payload=json.dumps(message)
        return payload

    @staticmethod
    def application_status(application_id):
        message={'points':'10','applications':[f'{application_id}']}
        payload=json.dumps(message)
        return payload

    @staticmethod
    def application_services():
        message=f""
        payload=json.dumps(message)
        return payload

    @staticmethod
    def application_analysis_engine():
        message=f""
        payload=json.dumps(message)
        return payload

    @staticmethod
    def application_instances():
        message=f""
        payload=json.dumps(message)
        return payload

    @staticmethod
    def get_all_incidents():
        message=f""
        payload=json.dumps(message)
        return payload

    @staticmethod
    def get_incident_details():
        message=f""
        payload=json.dumps(message)
        return payload

    @staticmethod
    def search_application_details(body=""):
        payload=json.dumps(body)
        return payload