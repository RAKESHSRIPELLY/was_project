__author__='JG'

from lib import utility as util


class CMS:

    def __init__(self,address):
        self.address=address
        self.log=util.Log()

    def base_url(self):
        base_url=f"https://{self.address}/"
        return base_url

    def login(self):
        api=f'services/oauth/token'
        uri=f"{self.base_url()}{api}"
        return uri

    def logout(self):
        api=f"/services/api/logout"
        uri=f"{self.base_url()}{api}"
        return uri

    def applications(self):
        api=f'services/application'
        uri=f"{self.base_url()}{api}"
        return uri

    def application_details(self,app_id):
        api=f'services/application/{app_id}/detail'
        uri=f"{self.base_url()}{api}"
        return uri

    def application_status(self):
        api=f"/services/dashboard/widgets/WIDGET_INSTANCE_STATUS/H12"
        uri=f"{self.base_url()}{api}"
        return uri

    def application_services(self,application_id):
        api=f"services/application/{application_id}/services"
        uri=f"{self.base_url()}{api}"
        return uri

    def application_analysis_engine(self,application_id):
        api=f"services/application/{application_id}/analysisEngines"
        uri=f"{self.base_url()}{api}"
        return uri

    def application_instances(self,application_id):
        api=f"services/application/{application_id}/instances"
        uri=f"{self.base_url()}{api}"
        return uri

    def get_incidents(self):
        api=f'/services/incidents?order=desc&source=application&sort=timestamp'
        uri=f"{self.base_url()}{api}"
        return uri

    def get_all_incidents(self):
        api=f'services/incidents'
        uri=f"{self.base_url()}{api}"
        return uri

    def get_incident_details(self,incident_id):
        api=f'services/incidents/{incident_id}'
        uri=f"{self.base_url()}{api}"
        return uri

    def search_application_details(self):
        api=f'services/incidents/search?term='
        uri=f"{self.base_url()}{api}"
        return uri

    def search_archived_details_for_application(self,app_id):
        api=f'services/incidents/archived?appid={app_id}'
        uri=f"{self.base_url()}{api}"
        return uri

    def get_archived_incident_details(self,incident_id):
        api=f'services/incidents/archived/{incident_id}'
        uri=f"{self.base_url()}{api}"
        return uri

    def cms_version(self):
        api=f'services/system/version'
        uri=f"{self.base_url()}{api}"
        return uri


class ZAP:

    def __init__(self,address):
        self.address=address
        self.log=util.Log()

    def base_url(self):
        base_url=f"https://{self.address}/"
        return base_url
