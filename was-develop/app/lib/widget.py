from lib import utility as util
from config import was, cms, environment as env
from pymongo import MongoClient
from datetime import datetime
import pymongo



class Dashboard:
    def __init__(self):
        self.log = util.Log()
        self.redis = util.Database().Redis()
        self.mongo = util.Database().Mongo()
        self.display = {}


    def application_present_in_CMS(self):
        try:
            cache_channel=self.redis.connect(host=was.was['cache'])
            db_channel=self.mongo.connect(host=was.was['database'])
            db=self.mongo.create_database(db_channel,'was_db')
            coll=self.mongo.create_collection(db,'reports')
            app_coll=self.mongo.create_collection(db,'applications')
            current_application= self.mongo.find_documents(app_coll, {'app_present': True})
            current_app_ids = []
           
            db_apps= set()
            if cache_channel.exists('cms'):
                self.log.info("In dashboard: getting current CMS IP address")
                cms=util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
                if isinstance(cms,dict):
                    current_CMS=cms['ipv4_address'].replace('.','_')
                    
            if current_application!='documents_not_found':        
                for app_id in current_application:
                    current_app_ids.append(app_id['application_id'])
                    
            docs=self.mongo.find_all_documents(coll)
            if docs!='documents_not_found':
                self.log.info(f"{len(docs)} available in database")
               
                for doc in docs:
                    if doc['application_details']['application_id'] in current_app_ids:
                        db_apps.add(doc['application_details']['application_id'])
            self.log.info(f"Application id's of current CMS: {db_apps}")           
            return db_apps,current_CMS
        
        except Exception as e:
           self.log.critical("Exception occured while checking current CMS applications:",e)
            
    def total_count(self, applicationId):
        try:
            self.dashboard_data = {
                "severity": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                },
                "total": 0
            }
            self.val_Details = {}
            self.critical = 0
            self.high = 0
            self.low = 0
            self.medium = 0

            # get all documents from db
            db_channel = self.mongo.connect(host=was.was['database'])
          
            db = self.mongo.create_database(db_channel, 'was_db')
            self.log.info(f"Fetching reports from database")
            
            coll_i = self.mongo.create_collection(db, 'dashboard')
            self.client = MongoClient(host=was.was["database"])
            self.mydatabase = self.client['was_db']
            self.letest_report = self.mydatabase['reports']
            self.applications = {}
            application_set = set()
            application_list = []
            
            application_set,current_Ip = self.application_present_in_CMS()
            
            for i in application_set:
                all_rows = self.letest_report.find_one({"application_id": i}, sort=[('_id', pymongo.DESCENDING)])
                application_list.append(all_rows)
                
            if len(application_list) != 0:
                for i in application_list:
                    self.val_Details = i['vulnerability_distribution']['severity']
                    details = self.val_Details

                    for i in details:
                        if i == 'critical':
                            self.critical = self.critical + details[i]
                        elif i == 'high':
                            self.high = self.high + details[i]
                        elif i == 'low':
                            self.low = self.low + details[i]
                        elif i == 'medium':
                            self.medium = self.medium + details[i]
            else:
                self.log.debug("No documents found in reports table for current CMS")
                return self.dashboard_data
            
            self.log.info(f"Calculating Total vulnerability_distribution for applications")
            
            self.dashboard_data['severity']['critical'] = self.critical
            self.dashboard_data['severity']['high'] = self.high
            self.dashboard_data['severity']['medium'] = self.medium
            self.dashboard_data['severity']['low'] = self.low
            total = self.critical + self.high + self.medium + self.low
            self.dashboard_data['total'] = total

            doc = self.mongo.update_document(coll_i,
                                             {'$set': {f'dashboard.{current_Ip}.vulnerabilities_count': self.dashboard_data, }},
                                             {'application_id': 'all'}, upsert=True)

            if doc !='documents_not_found':
                self.log.info("sucess")
                
        except Exception as e:
            self.log.critical(f"Exception occured while calculating total vulnerabilities_count {e}")

    def application_count(self, applicationId):
        try:
            self.dashboard_data = {
                "severity": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                },
                "total": 0
            }
            self.val_Details = {}
            self.critical = 0
            self.high = 0
            self.low = 0
            self.medium = 0
            # get one document for application_id
            client = MongoClient(host=was.was["database"])
           
            mydatabase = client['was_db']
            self.reportTable = mydatabase['reports']
            db_channel = self.mongo.connect(host=was.was['database'])
            db = self.mongo.create_database(db_channel, 'was_db')
            self.log.info(f"Fetching reports from database")
            all_rows = self.reportTable.find_one({"application_id": applicationId}, sort=[('_id', pymongo.DESCENDING)])
            if 'vulnerability_distribution' in all_rows.keys():
                self.val_Details = all_rows['vulnerability_distribution']['severity']
            else:
                self.log.debug(" Document dont have key vulnerability_distribution")
                
            one_application = self.val_Details
            if len(one_application) != 0:
                self.dashboard_data['severity']['critical'] = one_application['critical']
                self.dashboard_data['severity']['high'] = one_application['high']
                self.dashboard_data['severity']['medium'] = one_application['medium']
                self.dashboard_data['severity']['low'] = one_application['low']
                total = one_application['critical'] + one_application['high'] + one_application['medium'] + one_application[
                    'low']
                self.dashboard_data['total'] = total
            else:
                self.log.debug(" Document dont have key vulnerability_distribution")

            coll_i = self.mongo.create_collection(db, 'dashboard')
            # dash_doc = self.mongo.find_document(coll_i, {'application_id': 'all'})
            doc = self.mongo.update_document(coll_i,
                                             {'$set': {'dashboard.vulnerabilities_count': self.dashboard_data, }},
                                             {'application_id': applicationId}, upsert=True)
            if doc !='documents_not_found':
                self.log.info("sucess")
                
        except Exception as e:
            self.log.critical(f"Exception occured while calculating vulnerabilities_count{e}")

    def vulnerableApplications(self, applicationId):
        try:

            
            application_id = applicationId
            vulnerable_applications = {'applications':{}}
            db_channel = self.mongo.connect(host=was.was['database'])
            db = self.mongo.create_database(db_channel, 'was_db')
            self.log.info(f"Fetching reports from database")
            coll_i = self.mongo.create_collection(db, 'dashboard')
        
            self.client = MongoClient(host=was.was["database"])
            
            self.mydatabase = self.client['was_db']
            self.letest_report = self.mydatabase['reports']
            self.dashboardTable = self.mydatabase['dashboard']
            
            self.applications = {}
            application_set = set()
            application_list = []
            
            application_set,current_Ip = self.application_present_in_CMS()
            
            for i in application_set:
                all_rows = self.letest_report.find_one({"application_id": i}, sort=[('_id', pymongo.DESCENDING)])
                application_list.append(all_rows)

            # cursor = reportTable.find().sort(
            #     [('vulnerability_distribution.severity.critical', -1), ('vulnerability_distribution.severity.high', -1),
            #     ('vulnerability_distribution.severity.medium', -1), ('vulnerability_distribution.severity.low', -1)]).limit(5)

            severity_list = []
            application_ids = []
            application_name = []
            critical = []
            high = []
            low = []
            medium = []
            
            if len(application_list) != 0:
                self.sortedData = sorted(application_list,
                                        key=lambda i: i['vulnerability_distribution']['severity']['critical'],
                                        reverse=True)
                for i in self.sortedData:
                    # self.sortedData = sorted(tempDictOne, key=lambda i: i['frequency'],reverse=True)
                    application_ids.append(i['application_id'])
                    application_name.append(i['application_details']['application_name'])
                    severity_list.append(i['vulnerability_distribution']['severity'])
                    critical.append(i['vulnerability_distribution']['severity']['critical'])
                    high.append(i['vulnerability_distribution']['severity']['high'])
                    low.append(i['vulnerability_distribution']['severity']['low'])
                    medium.append(i['vulnerability_distribution']['severity']['medium'])

                for i in range(0, len(application_name)):
                    vulnerable_applications['applications'][application_name[i]] = {}
                    vulnerable_applications['applications'][application_name[i]]['application_id'] = application_ids[i]
                    vulnerable_applications['applications'][application_name[i]]['application_name'] = application_name[i]
                    vulnerable_applications['applications'][application_name[i]]['total'] = critical[i] + high[i] + medium[
                        i] + low[i]
                    vulnerable_applications['applications'][application_name[i]]['severity'] = severity_list[i]
            else:
                self.log.warning("reports not found for current CMS")
                
            coll_i = self.mongo.create_collection(db, 'dashboard')
           
            if application_id != 'all':
                doc = self.mongo.update_document(coll_i, {
                    '$set': {'dashboard.vulnerable_applications': vulnerable_applications, }},
                                                 {'application_id': application_id}, upsert=True)
                if doc !='documents_not_found':
                    self.log.info("vulnerable application updated sucessfully")
            else:
                doc = self.mongo.update_document(coll_i, {
                    '$set': {f'dashboard.{current_Ip}.vulnerable_applications': vulnerable_applications, }},
                                                 {'application_id': 'all'}, upsert=True)
                if doc !='documents_not_found':
                    self.log.info("vulnerable applications updated sucessfully")
                    
        except Exception as e:
           self.log.error(f"Exception occured while calulating vulnerable applications widget {e}")

    def scanAgingHistory(self, applicationId):

        try:
            self.client = MongoClient(host=was.was["database"])
            application_id = applicationId
            
            # get the report and sort them with last scan time
            db_channel = self.mongo.connect(host=was.was['database'])
          
            db = self.mongo.create_database(db_channel, 'was_db')
            self.log.info(f"Fetching reports from database")
            coll_i = self.mongo.create_collection(db, 'dashboard')
          
            self.mydatabase = self.client['was_db']
            self.letest_report = self.mydatabase['reports']
            self.applications = {}
            application_set = set()
            application_list = []
          
            application_set,current_Ip = self.application_present_in_CMS()
            
            for i in application_set:
                all_rows = self.letest_report.find_one({"application_id": i}, sort=[('_id', pymongo.DESCENDING)])
                application_list.append(all_rows)
            if len(application_list) != 0:
                # cursor=self.reportTable.find({},{'_id':0}).sort([('application_details.scan_end_time', -1),('vulnerability_distribution.severity.critical', -1), ('vulnerability_distribution.severity.high', -1)])
                scan_report = sorted(application_list, key=lambda i: i['application_details']['scan_end_time'],
                                    reverse=True)

                self.dashboard_data = {"applications": {}}

                for i in scan_report:
                    # dt_object = datetime.fromtimestamp(i['application_details']['scan_end_time']).strftime('%d-%m-%y %H:%M:%S')
                    app_name = i['application_details']['application_name']
                    self.dashboard_data['applications'][app_name] = {}
                    self.dashboard_data['applications'][app_name]['application_id'] = i['application_id']
                    self.dashboard_data['applications'][app_name]['application_name'] = i['application_details'][
                        'application_name']
                    self.dashboard_data['applications'][app_name]['scanned'] = i['application_details']['scan_end_time']
                    total = i['vulnerability_distribution']['severity']['critical'] + \
                            i['vulnerability_distribution']['severity']['high'] + \
                            i['vulnerability_distribution']['severity']['medium'] + \
                            i['vulnerability_distribution']['severity']['low']
                    self.dashboard_data['applications'][app_name]['total'] = total

                    self.dashboard_data['applications'][app_name]['severity'] = {}
                    self.dashboard_data['applications'][app_name]['severity']['critical'] = \
                    i['vulnerability_distribution']['severity']['critical']
                    self.dashboard_data['applications'][app_name]['severity']['high'] = \
                    i['vulnerability_distribution']['severity']['high']
                    self.dashboard_data['applications'][app_name]['severity']['medium'] = \
                    i['vulnerability_distribution']['severity']['medium']
                    self.dashboard_data['applications'][app_name]['severity']['low'] = \
                    i['vulnerability_distribution']['severity']['low']
            else:
                self.log.warning("No reports found for current CMS")
                
            coll_i = self.mongo.create_collection(db, 'dashboard')
           
            if application_id != 'all':
                doc = self.mongo.update_document(coll_i, {
                    '$set': {'dashboard.applications_not_scanned': self.dashboard_data, }},
                                                 {'application_id': application_id}, upsert=True)
                if doc !='documents_not_found':
                        self.log.info("applications_not_scanned widget updated sucessfully")
            else:
                doc = self.mongo.update_document(coll_i, {
                    '$set': {f'dashboard.{current_Ip}.applications_not_scanned': self.dashboard_data, }},
                                                 {'application_id': 'all'}, upsert=True)
                if doc !='documents_not_found':
                        self.log.info("applications_not_scanned widget updated sucessfully")

        except Exception as e:
            self.log.error(f"Exception occured while calculating applications_not_scanned {e}")

    def oneApllication(self, applicationId, cwe_dict):
        try:
            # get one document for application_id
            cwe_frequency = cwe_dict
            self.client = MongoClient(host=was.was["database"])
           
            self.mydatabase = self.client['was_db']
            self.reportTable = self.mydatabase['reports']
            portInfo = self.reportTable.find_one({"application_id": applicationId}, sort=[('_id', pymongo.DESCENDING)])
            vulnarability_id = []
            vulnerability_name = []
            services = ''
            services_count = []
            self.cwe_count = []
            cwe = []
            cvss_score = []
            tempDictOne = []
            cvss = []
            if 'services' in portInfo.keys():
                services = portInfo['services']
                
            for i in services:
                services_count.append(i)

            for k in services_count:
                res = None
                if all(k in sub for sub in [services, services_count]):
                    res = services[k]
                    vulnarability = res['vulnerabilities']

                    for v in vulnarability:

                        if all(v in val for val in [res['vulnerabilities'], vulnarability]):
                            r = res['vulnerabilities'][v]
                            vulnarability_id.append(r['vulnerabilility_id'])
                            vulnerability_name.append(r['vulnerability_name'])

                            self.cwe_count.append((r['vulnerability_classification']['cwe']))
                            cvss_score.append(r['vulnerability_classification']['cvss'])

            self.display['vulnerabilities'] = {}
            res = {}
            for i in cvss_score:
                for k, v in i.items():
                    cvss.append(v['cvss_score'])
            for i in self.cwe_count:
                for k, v in i.items():
                    cwe.append(k)
            for j in range(len(cwe)):
                self.display['vulnerabilities'][vulnerability_name[j]] = {}
                self.display['vulnerabilities'][vulnerability_name[j]]['vulnerability_id'] = vulnarability_id[j]
                self.display['vulnerabilities'][vulnerability_name[j]]['vulnerability_name'] = vulnerability_name[j]
                self.display['vulnerabilities'][vulnerability_name[j]]['frequency'] = cwe_frequency[
                    vulnerability_name[j]]
                self.display['vulnerabilities'][vulnerability_name[j]]['cvss_score'] = cvss[j]
                self.display['vulnerabilities'][vulnerability_name[j]]['cwe_id'] = cwe[j]


                tempDictOne.append(self.display['vulnerabilities'][vulnerability_name[j]])

            self.sortedData = sorted(tempDictOne, key=lambda i: i['frequency'], reverse=True)

            tempDict = {"vulnerabilities": {}}
            i = 1
            for data in self.sortedData:

                tempDict['vulnerabilities'][data['vulnerability_name']] = {}
                tempDict['vulnerabilities'][data['vulnerability_name']] = data
                if i == 5:
                    break
                i = i + 1

            db_channel = self.mongo.connect(host=was.was['database'])
            
            db = self.mongo.create_database(db_channel, 'was_db')
            coll_i = self.mongo.create_collection(db, 'dashboard')
            
            doc = self.mongo.update_document(coll_i, {'$set': {'dashboard.top_vulnerabilities': tempDict, }},
                                             {'application_id': applicationId}, upsert=True)
            if doc !='documents_not_found':
                self.log.info("top_vulnerabilities widget updated sucessfully")
                         
            return self.sortedData

        except Exception as e:
            self.log.error(f"Exception occured top_vulnerabilities widget:{e}")

    #########################change required
    def allApllication(self):
        try:
            db_channel = self.mongo.connect(host=was.was['database'])
            
            db = self.mongo.create_database(db_channel, 'was_db')
            self.client = MongoClient(host=was.was["database"])
            self.mydatabase = self.client['was_db']
            self.reportTable = self.mydatabase['reports']
            # this is for all application
          
            self.edit = []
            # get the data from database
            self.client = MongoClient(host=was.was["database"])
            
            self.mydatabase = self.client['was_db']
            self.letest_report = self.mydatabase['reports']
            self.dashboardTable = self.mydatabase['dashboard']
            # app_coll = self.mongo.create_collection(db, 'applications')
            # db_applications = self.mongo.find_all_documents(coll)
            db_applications = self.dashboardTable.find()
            current_application_id,current_Ip = self.application_present_in_CMS()
            
            self.applications = {}
            application_list = []
            vulnarability_list = []
            for i in db_applications:
                if i['application_id'] != 'all' and i['application_id'] in current_application_id:
                    application_list.append(i['dashboard']['top_vulnerabilities']['vulnerabilities'])

            vulnarability_list_check = {}
            if len(application_list) != 0 :
                for i in application_list:
                    for k, v in i.items():
                        if k in vulnarability_list_check.keys():
                            vulnarability_list_check[k]['frequency'] = vulnarability_list_check[k]['frequency'] + v[
                                'frequency']
                        else:
                            vulnarability_list_check[k] = v

                for i in vulnarability_list_check.values():
                    vulnarability_list.append(i)

                sortedData = sorted(vulnarability_list, key=lambda i: i['frequency'], reverse=True)
                tempDict = {"vulnerabilities": {}}
                i = 1
                sorted_vulnarability = []
                for i in sortedData:
                    if i['vulnerability_name'] not in sorted_vulnarability:
                        sorted_vulnarability.append(i)
                j = 1
                for data in sorted_vulnarability:
                    vulnerability = 'vulnerability_' + str(j)
                    tempDict['vulnerabilities'][vulnerability] = {}
                    tempDict['vulnerabilities'][vulnerability] = data

                    j = j + 1

            db_channel = self.mongo.connect(host=was.was['database'])
            db = self.mongo.create_database(db_channel, 'was_db')
            coll_i = self.mongo.create_collection(db, 'dashboard')
            # dash_doc = self.mongo.find_document(coll_i, {'application_id': 'all'})
            doc = self.mongo.update_document(coll_i, {'$set': {f'dashboard.{current_Ip}.top_vulnerabilities': tempDict, }},
                                             {'application_id': 'all'}, upsert=True)
            if doc !='documents_not_found':
                self.log.info("top_vulnerabilities widget updated sucessfully")
                         
           

        except Exception as e:
            self.log.error(f"Exception occured top_vulnerabilities widget:{e}")

    def Heatmap_oneApplication(self, applicationId):
        # ths is for 1 application
        try:
            self.client = MongoClient(host=was.was["database"])
            self.mydatabase = self.client['was_db']
            self.letest_report = self.mydatabase['reports']
            self.dashboardTable = self.mydatabase['dashboard']
            old_open = 0
            old_scan = self.dashboardTable.find({"application_id": applicationId})
            # old_scan = self.reportTable.find_one({"application_id": applicationId}, sort=[( '_id', pymongo.DESCENDING )])
            self.old_list = []
            oldscan1 = ''
            for i in old_scan:

                if 'vulnarability_combination' in i:
                    oldscan1 = i['dashboard']['vulnerabilities_by_scan']
                    self.old_list.append(i['vulnarability_combination'])
                else:
                    old_open = 0
                    
            if len(oldscan1) >= 1:
                for k, v in oldscan1.items():
                    for i in v:
                        for key, value in i.items():
                            old_open = value['vulnerability_status']['open']
            scanned = 0
            application_name = ''
            new_services = ''
            new_services_count = []
            self.compare_list = []

            vulnarability_combination = {}
            updated_combination = []
            # letest_scan =self.letest_report.find({"application_id": applicationId})
            letest_scan = self.letest_report.find_one({"application_id": applicationId},
                                                      sort=[('_id', pymongo.DESCENDING)])

            new_services = letest_scan['services']
            applicationId = letest_scan['application_id']
            application_name = letest_scan['application_details']['application_name']
            scanned = letest_scan['application_details']['scan_end_time']

            for i in new_services:
                new_services_count.append(i)

            for k in new_services_count:
                res = None

                if all(k in sub for sub in [new_services, new_services_count]):
                    res = new_services[k]
                    vulnarability = res['vulnerabilities']

                    for v in vulnarability:

                        if all(v in val for val in [res['vulnerabilities'], vulnarability]):
                            r = res['vulnerabilities'][v]
                            self.compare_list.append(r)
            # take data from old report

            # check if record present
            ret = []
            old_v = 0
            check_old_combination = ''
            check_new_combination = []
            resolved_url = 0
            dt_object = datetime.fromtimestamp(scanned).strftime('%Y-%m-%d')
            tempDict = {}
            tempDict[application_name] = {}
            tempDict[application_name]['application_name'] = application_name
            tempDict[application_name]['scanned'] = dt_object
            newly_open = 0
            for new in self.compare_list:
                for k, v in new['urls'].items():
                    new_combination = new['vulnerability_name'] + "_" + v['url'] + "_" + v['parameter'][
                        'parameter_name']
                    check_new_combination.append(new_combination)

            try:
                if len(self.old_list) != 0:

                    for old in self.old_list:
                        for k, v in old.items():
                            # old_combination=old['vulnerability_name'] + "_" + old['urls'][f'url_{i}']['url']
                            check_old_combination = v
                            updated_combination = v
                    #     i = i + 1
                    # if (new['vulnerability_name'] not in old['vulnerability_name']) and (new['urls'][f'url_{i}']['url'] not in old['urls'][f'url_{i}']['url'] ) :

                    for i in check_new_combination:
                        # for newly_open combination
                        if i not in check_old_combination:
                            newly_open += 1
                            ret
                            updated_combination.append(i)
                        else:
                            old_v += 1
                            updated_combination.append(i)

                    for j in check_old_combination:
                        if j not in check_new_combination:
                            resolved_url += 1
                            # updated_combination.pop(j)
                            updated_combination.remove(j)

                    vulnarability_combination['vulnarability_combination'] = updated_combination
                else:
                    vulnarability_combination['vulnarability_combination'] = check_new_combination

                    newly_open = len(check_new_combination)

            except Exception as e:
               self.log.error(f"Exception occured in widget scan again history {e}")

            newlyOpened = newly_open
            resolved = resolved_url
            totalOpen = (old_open + newly_open) - resolved
            if totalOpen <= -1:
                totalOpen = 0

            dt_object = datetime.fromtimestamp(scanned).strftime('%Y-%m-%d')

            finalDict = {'application': {}}
            application = []
            tempDict = {}
            tempDict[application_name] = {}
            tempDict[application_name]['application_name'] = application_name
            tempDict[application_name]['scanned'] = dt_object
            tempDict[application_name]['vulnerability_status'] = {}
            tempDict[application_name]['vulnerability_status']['open'] = totalOpen
            tempDict[application_name]['vulnerability_status']['resolved'] = resolved
            tempDict[application_name]['vulnerability_status']['new'] = newlyOpened
            tempDict[application_name]['application_id'] = applicationId
            application.append(tempDict)
            finalDict['application'] = application

        
            db_channel = self.mongo.connect(host=was.was['database'])
            db = self.mongo.create_database(db_channel, 'was_db')
            coll_i = self.mongo.create_collection(db, 'dashboard')
            # dash_doc = self.mongo.find_document(coll_i, {'application_id': 'all'})
            doc = self.mongo.update_document(coll_i, {'$set': {'dashboard.vulnerabilities_by_scan': finalDict, }},
                                             {'application_id': applicationId}, upsert=True)

            doc = self.mongo.update_document(coll_i,
                                             {'$set': {'vulnarability_combination': vulnarability_combination, }},
                                             {'application_id': applicationId}, upsert=True)
            
            if doc !='documents_not_found':
                self.log.info("Widget vulnerabilities_by_scan updated sucessfully")

            return tempDict

        except Exception as e:
            self.log.error(f"Exception occured in widget vulnerabilities_by_scan {e}")

    # def heatmapFor_all(self,applicationId):
    #    #ths is for 1 application
    #     try:
    #         self.client = MongoClient(host=was.was["database"])
    #         self.mydatabase = self.client['was_db']
    #         self.letest_report = self.mydatabase['reports']
    #         self.dashboardTable = self.mydatabase['dashboard']
    #         old_open=0
    #         old_scan=self.dashboardTable.find({"application_id": applicationId})
    #         #old_scan = self.reportTable.find_one({"application_id": applicationId}, sort=[( '_id', pymongo.DESCENDING )])
    #         self.old_list=[]
    #         oldscan1=''
    #         for i in old_scan:

    #             if 'vulnarability_combination' in i:
    #                 oldscan1=i['dashboard']['vulnerabilities_by_scan']
    #                 self.old_list.append(i['vulnarability_combination'])
    #             else:
    #                  old_open = 0
    #         if len(oldscan1)>=1:
    #             for k,v in oldscan1.items():
    #                 for i in v:
    #                     for key, value in i.items():
    #                         old_open=value['vulnerability_status']['open']
    #         scanned=0
    #         application_name=''
    #         new_services =''
    #         new_services_count=[]
    #         self.compare_list=[]

    #         vulnarability_combination={}
    #         updated_combination=[]
    #         #letest_scan =self.letest_report.find({"application_id": applicationId})
    #         letest_scan = self.letest_report.find_one({"application_id": applicationId}, sort=[( '_id', pymongo.DESCENDING )])

    #         new_services=letest_scan['services']
    #         applicationId=letest_scan['application_id']
    #         application_name=letest_scan['application_details']['application_name']
    #         scanned=letest_scan['application_details']['scan_end_time']

    #         for i in new_services:
    #             new_services_count.append(i)

    #         for k in new_services_count:
    #             res = None

    #             if all(k in sub for sub in [new_services, new_services_count]):
    #                 res = new_services[k]
    #                 vulnarability = res['vulnerabilities']

    #                 for v in vulnarability:

    #                     if all(v in val for val in [res['vulnerabilities'], vulnarability]):
    #                         r = res['vulnerabilities'][v]
    #                         self.compare_list.append(r)
    #         #take data from old report

    #         #check if record present
    #         ret=[]
    #         old_v = 0
    #         check_old_combination=''
    #         check_new_combination=[]
    #         resolved_url=0
    #         dt_object = datetime.fromtimestamp(scanned).strftime('%Y-%m-%d')
    #         tempDict={}
    #         tempDict[application_name]={}
    #         tempDict[application_name]['application_name']=application_name
    #         tempDict[application_name]['scanned']=dt_object
    #         newly_open=0
    #         for new in self.compare_list:
    #             for k,v in new['urls'].items():

    #                     new_combination=new['vulnerability_name'] + "_" + v['url']
    #                     check_new_combination.append(new_combination)

    #         try:
    #             if len(self.old_list) != 0:

    #                 for old in self.old_list:
    #                    for k,v in old.items():
    #                     #old_combination=old['vulnerability_name'] + "_" + old['urls'][f'url_{i}']['url']
    #                         check_old_combination = v
    #                         updated_combination = v
    #                 #     i = i + 1
    #                 #if (new['vulnerability_name'] not in old['vulnerability_name']) and (new['urls'][f'url_{i}']['url'] not in old['urls'][f'url_{i}']['url'] ) :

    #                 for i in check_new_combination:
    #                     #for newly_open combination
    #                     if i not in check_old_combination:
    #                         newly_open +=1
    #                         ret
    #                         updated_combination.append(i)
    #                     else:
    #                         old_v +=1
    #                         updated_combination.append(i)

    #                 for j in check_old_combination:
    #                     if j not in check_new_combination :
    #                         resolved_url +=1
    #                         #updated_combination.pop(j)
    #                         updated_combination.remove(j)

    #                 vulnarability_combination ['vulnarability_combination']=updated_combination
    #             else:
    #                 vulnarability_combination ['vulnarability_combination'] =check_new_combination

    #                 newly_open=len(check_new_combination)

    #         except Exception as e:
    #             print("Key should present", "Exception:", e)

    #         newlyOpened=newly_open
    #         resolved=resolved_url
    #         totalOpen = (old_open + newly_open)-resolved

    #         dt_object = datetime.fromtimestamp(scanned).strftime('%Y-%m-%d')

    #         finalDict = {'application':{}}
    #         application=[]
    #         tempDict={}
    #         tempDict[application_name]={}
    #         tempDict[application_name]['application_name']=application_name
    #         tempDict[application_name]['scanned']=dt_object
    #         tempDict[application_name]['vulnerability_status']={}
    #         tempDict[application_name]['vulnerability_status']['open']=totalOpen
    #         tempDict[application_name]['vulnerability_status']['resolved']=resolved
    #         tempDict[application_name]['vulnerability_status']['new']=newlyOpened
    #         tempDict[application_name]['application_id']=applicationId
    #         application.append(tempDict)
    #         finalDict['application']=application

    #         return tempDict

    #     except Exception as e:
    #         print("Unable to estabilish connection", "Exception:", e)

    def Heatmap_allApplication(self):
        # this is for all application
        try:
            self.client = MongoClient(host=was.was["database"])
            self.mydatabase = self.client['was_db']
            self.letest_report = self.mydatabase['reports']
            db_channel = self.mongo.connect(host=was.was['database'])
            db = self.mongo.create_database(db_channel, 'was_db')
            coll_i = self.mongo.create_collection(db, 'dashboard')
            
            self.client = MongoClient(host=was.was["database"])
           
            self.mydatabase = self.client['was_db']
            self.dashboardTable = self.mydatabase['dashboard']
            # app_coll = self.mongo.create_collection(db, 'applications')
            db_applications = self.dashboardTable.find()
            self.applications = {}
            application_list = []
            all_application_list = []
            # for i in db_applications:
            #     application_set.append(i['application_details']['application_id'])

            
            current_application_id,current_Ip = self.application_present_in_CMS()
            
            for i in db_applications:
                if i['application_id'] != 'all' and i['application_id'] in current_application_id:
                    application_list.append(i['dashboard']['vulnerabilities_by_scan']['application'])
                    
            # for appName in application_set:
            #     all_application_list.append(self.heatmapFor_all(appName))
            # all_application_list.append(self.dashboardTable.find({'application_id':appName}))

            # apps = sorted(all_application_list, key=lambda i: (i['application_name']))
            # for i in range(len(apps)):
            #     application_by_scan=apps[i]
            if len(application_list) != 0:
                for i in application_list:
                    for j in i:
                        all_application_list.append(j)

            finalDict = {'application': {}}

            
            finalDict['application'] = all_application_list

            db_channel = self.mongo.connect(host=was.was['database'])
            db = self.mongo.create_database(db_channel, 'was_db')
            coll_i = self.mongo.create_collection(db, 'dashboard')
          
            doc = self.mongo.update_document(coll_i, {'$set': {f'dashboard.{current_Ip}.vulnerabilities_by_scan': finalDict}},
                                             {'application_id': 'all'}, upsert=True)
            if doc !='documents_not_found':
                self.log.info("Widget vulnerabilities_by_scan updated sucessfully")
                
            
        except Exception as e:
            self.log.error(f"Exception occured in widget vulnerabilities_by_scan {e}")