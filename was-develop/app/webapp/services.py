__author__='JG'

from lib import utility as util
from lib import framework as fw
import re,datetime
from config import was
import time


class WAS:

    def __init__(self):
        self.log=util.Log()
        self.redis=util.Database().Redis()
        self.mongo=util.Database().Mongo()

    def authorization(self,token,address):
        status=fw.WAS().authorization(token,address)
        return status

    def system_authorization(self,token,address):
        status=fw.WAS().system_authorization(token,address)
        return status

    def create_user(self,authorization_token,remote_address,user_input):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            user_input=util.ConvertData(user_input).payload_to_json()
            status=fw.WAS().create_user(user=user_input['user'])
            return status
        else:
            return 'unauthorized'

    def validate_user(self,visitor_address,user_input):
        user_input=util.ConvertData(user_input).payload_to_json()
        status,user_details=fw.WAS().validate_user(visitor_address,user=user_input['user'])
        return status,user_details

    def change_login_credentials(self,authorization_token,remote_address,user_input):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            user_input=util.ConvertData(user_input).payload_to_json()
            status,state=fw.WAS().change_login_credentials(user=user_input['user'])
            return status,state
        else:
            return 'unauthorized',None

    def logout(self,authorization_token,remote_address):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            status=fw.WAS().logout(authorization_token)
            return status
        else:
            return 'unauthorized'

    def dashboard(self,authorization_token,remote_address,user_input):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            filters,return_map=dict(),dict()
            return_map['dashboard']=dict()

            cache_channel=util.Database().Redis().connect(was.was['cache'])
            if user_input['filter'] is not None and user_input['filter'].lower()=='true':
                if cache_channel.exists('dashboard'):
                    data=cache_channel.hgetall('dashboard')
                    for k,v in data.items():
                        filters.update({k.decode('utf-8'):util.ConvertData(v.decode('utf-8')).framework_compatible()})
                else:
                    filters=None

                return 'success',filters

            # Widget 1
            if user_input['widget']=='vulnerabilities_count':
                filters['application']=user_input['application']
                cache_channel.hset('dashboard','vulnerabilities_count',str(filters))

                board=fw.WAS().dashboard(dashboard=user_input)
                if isinstance(board,dict):
                    return_map['applications']=board['applications']
                    return_map['dashboard']['vulnerability_count']=board['dashboard']['vulnerabilities_count']
                    return_map['dashboard']['filters']=util.ConvertData(
                        cache_channel.hget('dashboard','vulnerabilities_count').decode('utf-8')).framework_compatible()
                    return 'success',return_map
                else:
                    return board,None
            # Widget 2
            if user_input['widget']=='applications_not_scanned':
                filters['applications_not_scanned_age']=user_input['applications_not_scanned_age']
                filters['applications_not_scanned_buffer']=user_input['applications_not_scanned_buffer']
                cache_channel.hset('dashboard','applications_not_scanned',str(filters))

                board=fw.WAS().dashboard(dashboard=user_input)
                if isinstance(board,dict):
                    apps=list()
                    for k,v in board['dashboard']['applications_not_scanned']['applications'].items():
                        apps.append(v)
                    apps=sorted(apps,key=lambda i:i['scanned'],reverse=False)
                    return_map['applications']=board['applications']
                    return_map['dashboard']['applications_not_scanned']=apps
                    return_map['dashboard']['filters']=util.ConvertData(
                        cache_channel.hget('dashboard','applications_not_scanned').decode(
                            'utf-8')).framework_compatible()
                    return 'success',return_map
                else:
                    return board,None
            # Widget 3
            if user_input['widget']=='vulnerabilities_by_scan':
                filters['application']=user_input['application']
                filters['vulnerabilities_by_scan_from']=user_input['vulnerabilities_by_scan_from']
                filters['vulnerabilities_by_scan_to']=user_input['vulnerabilities_by_scan_to']
                cache_channel.hset('dashboard','vulnerabilities_by_scan',str(filters))

                stime=datetime.datetime.strptime(user_input['vulnerabilities_by_scan_from'],'%Y-%m-%d')
                etime=datetime.datetime.strptime(user_input['vulnerabilities_by_scan_to'],'%Y-%m-%d')
                # Original data
                # board = fw.WAS().dashboard(dashboard=user_input)
                # apps = list()
                # cache_channel = self.redis.connect(host=was.was['cache'])
                # db_channel = self.mongo.connect(host=was.was['database'])
                # db = self.mongo.create_database(db_channel, 'was_db')
                # coll = self.mongo.create_collection(db, 'dashboard')
                # docs = self.mongo.find_all_documents(coll)
                # for doc in docs:
                #     record_created_time = doc['_id'].generation_time
                #     if stime <= record_created_time <= etime:
                #         apps.append(doc)
                #     # Only to compute dummy data
                board=fw.WAS().dashboard(dashboard=user_input)
                if isinstance(board,dict):
                    apps,timestamp=list(),list()
                    for app in board['dashboard']['vulnerabilities_by_scan']['application']:
                        for k,v in app.items():
                            v1=datetime.datetime.strptime(v['scanned'],'%Y-%m-%d')
                            if stime<=v1<=etime:
                                if user_input['application']=='all':
                                    timestamp.append(v1.date())
                                    apps.append(v)
                                else:
                                    if user_input['application']==v['application_id']:
                                        timestamp.append(v1.date())
                                        apps.append(v)
                            else:
                                print("no application scanned")
                    apps=sorted(apps,key=lambda i:i['scanned'],reverse=False)
                    return_map['applications']=board['applications']
                    return_map['dashboard']['vulnerabilities_by_scan']=apps
                    return_map['dashboard']['filters']=util.ConvertData(
                        cache_channel.hget('dashboard','vulnerabilities_by_scan').decode(
                            'utf-8')).framework_compatible()
                    #return_map['dashboard']['filters']['age'] = board['threshold']
                    return 'success',return_map
                else:
                    return board,None

            # Widget 4
            if user_input['widget']=='top_vulnerabilities':
                filters['application']=user_input['application']
                cache_channel.hset('dashboard','top_vulnerabilities',str(filters))

                board=fw.WAS().dashboard(dashboard=user_input)
                value_sort={}
                if isinstance(board,dict):
                    vuls=list()
                    for k,v in board['dashboard']['top_vulnerabilities'].items():
                        vuls=[value for key,value in v.items()]

                    vuls=sorted(vuls,key=lambda i:i['cvss_score'],reverse=True)
                    value_sort={}
                    for i in vuls:
                        value_sort[i['vulnerability_name']]=i
                    #return_map['dashboard']['cvss_score']=5.0
                    return_map['applications']=board['applications']
                    return_map['dashboard']['top_vulnerabilities']=value_sort
                    return_map['dashboard']['filters']=util.ConvertData(
                        cache_channel.hget('dashboard','top_vulnerabilities').decode('utf-8')).framework_compatible()
                    return 'success',return_map
                else:
                    return board,None

            # Widget 5
            if user_input['widget']=='vulnerable_applications':
                board=fw.WAS().dashboard(dashboard=user_input)
                if isinstance(board,dict):
                    apps=list()
                    for k,v in board['dashboard']['vulnerable_applications']['applications'].items():
                        apps.append(v)
                    apps=sorted(apps,key=lambda i:i['total'],reverse=True)
                    return_map['applications']=board['applications']
                    return_map['dashboard']['vulnerable_applications']=apps
                    return 'success',return_map
                else:
                    return board,None
            # All
            if user_input['widget'] is None:
                board=fw.WAS().dashboard(dashboard=user_input)
                if isinstance(board,dict):
                    return_map['applications']=board['applications']
                    filters=dict()
                    if 'applications_not_scanned_age' in user_input:
                        filters['applications_not_scanned']=dict()
                        filters['applications_not_scanned']['age']=user_input['applications_not_scanned_age']
                        filters['applications_not_scanned']['buffer']=user_input['applications_not_scanned_buffer']
                    if 'vulnerabilities_by_scan_from' in user_input:
                        filters['vulnerabilities_by_scan']=dict()
                        filters['vulnerabilities_by_scan']['vulnerabilities_by_scan_from']=user_input[
                            'vulnerabilities_by_scan_from']
                        filters['vulnerabilities_by_scan']['vulnerabilities_by_scan_from']=user_input[
                            'vulnerabilities_by_scan_to']

                    # Widget 1
                    return_map['dashboard']['vulnerability_count']=board['dashboard']['vulnerability_count']

                    # Widget 2
                    apps=list()
                    for k,v in board['dashboard']['applications_not_scanned']['applications'].items():
                        apps.append(v)
                    apps=sorted(apps,key=lambda i:i['scanned'],reverse=False)
                    applications_not_scanned=dict()
                    applications_not_scanned['applications']=apps
                    return_map['dashboard']['applications_not_scanned']=applications_not_scanned
                    return_map['dashboard']['applications_not_scanned']['filters']=filters['applications_not_scanned']

                    # Widget 3
                    # stime = datetime.datetime.strptime(user_input['vulnerabilities_by_scan_from'], '%Y-%m-%d')
                    # etime = datetime.datetime.strptime(user_input['vulnerabilities_by_scan_to'], '%Y-%m-%d')
                    # Original data
                    # apps = list()
                    # coll = self.mongo.create_collection(db, 'dashboard')
                    # docs = self.mongo.find_all_documents(coll)
                    # for doc in docs:
                    #     record_created_time = doc['_id'].generation_time
                    #     if stime <= record_created_time <= etime:
                    #         apps.append(doc)
                    # Only to compute dummy data

                    # apps, timestamp = list(), list()
                    # for app in board['dashboard']['vulnerabilities_by_scan']['applications']:
                    #     for k, v in app.items():
                    #         if stime <= v['scanned'] <= etime:
                    #             if user_input['application'] == 'all':
                    #                 timestamp.append(v['scanned'].date())
                    #                 apps.append(v)
                    #             else:
                    #                 if user_input['application'] == v['application_id']:
                    #                     timestamp.append(v['scanned'].date())
                    #                     apps.append(v)
                    # apps = sorted(apps, key=lambda i: i['scanned'], reverse=False)

                    # vulnerabilities_by_scan = dict()
                    # vulnerabilities_by_scan['applications'] = apps
                    # return_map['dashboard']['vulnerabilities_by_scan'] = vulnerabilities_by_scan
                    # return_map['dashboard']['vulnerabilities_by_scan']['filters'] = filters['vulnerabilities_by_scan']
                    # return_map['dashboard']['vulnerabilities_by_scan']['filters']['age'] = board['threshold']

                    # Widget 4
                    vuls=list()
                    for k,v in board['dashboard']['top_vulnerabilities']['vulnerabilities'].items():
                        vuls.append(v)
                    vuls=sorted(vuls,key=lambda i:i['cvss_score'],reverse=True)

                    return_map['dashboard']['top_vulnerabilities']=vuls

                    # Widget 5
                    apps=list()
                    for k,v in board['dashboard']['vulnerable_applications']['applications'].items():
                        apps.append(v)
                    apps=sorted(apps,key=lambda i:i['total'],reverse=True)

                    return_map['dashboard']['vulnerable_applications']=apps
                    return 'success',return_map
                else:
                    return board,None


        else:
            return status,None

    def applications(self,authorization_token,remote_address,user_input):
        status=self.authorization(token=authorization_token,address=remote_address)
        #chg
        print("addresss value : ",remote_address)
        print("authorization_token value : ",authorization_token)
        print("status value : ",status)
        if status=='authorized':
            applications=fw.WAS().applications()
            if isinstance(applications,list):
                apps=list()
                for app in applications:
                    if 'application_id' in app:
                        app.pop('application_id')
                        apps.append(app['detail'])
                    else:
                        apps.append(app)
            else:
                return applications,None

            return_map=dict()
            if user_input['sort_by']:
                if user_input['sort_order'].upper()=='ASC':
                    self.log.info(f"Sorting application by {user_input['sort_by']}")
                    apps=sorted(apps,key=lambda i:i[user_input['sort_by']],reverse=False)
                elif user_input['sort_order'].upper()=='DESC':
                    self.log.info(f"Sorting application by {user_input['sort_by']}")
                    apps=sorted(apps,key=lambda i:i[user_input['sort_by']],reverse=True)

                if user_input['filter_text']:
                    self.log.info(f"Filtering application state by {user_input['filter_text']}")
                    #apps = list(lambda app :app['state']==user_input['filter_text'] if user_input['filter_text']!='not_instrumented' else: app['state']==user_input['filter_text'] )
                    if user_input['filter_text'] != 'not_instrumented':
                        apps=list(filter(lambda app: app['state']==user_input['filter_text'],apps))
                    else:
                        
                        apps=list(filter(lambda app: app['instrumentation'] == False,apps))

                if user_input['search_text']:
                    self.log.info(f"Searching {user_input['search_text']} in application name")
                    apps=list(filter(lambda app:re.search(f"{user_input['search_text']}",app['name'],re.I),apps))

                if apps:
                    apps_chunk=[apps[i*user_input['page_size']:(i+1)*user_input['page_size']] for i in
                        range((len(apps)+user_input['page_size']-1)//user_input['page_size'])]
                    return_map['total']=len(apps)
                    return_map['applications']=apps_chunk[user_input['page_number']]
                    return 'success',return_map
                else:
                    return 'success',None
        else:
            return status,None

    def application_authentication(self,authorization_token,remote_address,application_id,method='',user_input=''):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            if method.upper()=='GET':
                authentication=fw.WAS().application_authentication(application_id,method)

                if authentication!='field_not_found' and authentication!='document_not_found' and authentication!='connection_error':
                    return 'success',authentication
                elif authentication!='field_not_found' or authentication!='document_not_found' or authentication!='connection_error':
                    return authentication,None
                elif authentication is None:
                    return None,None
            elif method.upper()=='POST':
                user_input=util.ConvertData(user_input).payload_to_json()
                authentication=fw.WAS().application_authentication(application_id,method,
                    authentication=user_input['authentication'])
                return authentication,None
        else:
            return status,None

    def application_authentication_user(self,authorization_token,remote_address,method,application_id,user_id):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            authentication=fw.WAS().application_authentication_user(method,application_id,user_id)
            return authentication,None
        else:
            return status,None

    def application_authentication_test(self,authorization_token,remote_address,application_id,user_input):
        user_input=util.ConvertData(user_input).payload_to_json()
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            status=fw.WAS().application_authentication_test(application_id,
                authentication=user_input['authentication'])
            return status
        else:
            return status

    def application_authentication_automated(self,authorization_token,remote_address,application_id,user_id,user_input):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            status=fw.WAS().application_authentication_automated(application_id=application_id,user_id=user_id,
                authentication=user_input)
            if 'filename' in status:
                return 'success',status
        else:
            return status,None

    def application_authentication_automated_test(self,authorization_token,remote_address,application_id,user_id):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            status=fw.WAS().application_authentication_automated_test(application_id=application_id,user_id=user_id)
            return status
        else:
            return status

    # def application_authentication_interactive(self, authorization_token, remote_address, method, application_id, user_id, user_input=''):
    #     if method == 'GET':
    #         status = self.authorization(token=authorization_token, address=remote_address)
    #         if status == 'authorized':
    #                 authentication_path = fw.WAS().application_authentication_interactive(method=method,
    #                                                                                       application_id=application_id,
    #                                                                                       user_id=user_id,
    #                                                                                       authentication=user_input)
    #                 return_map = dict()
    #                 return_map['authentication_file'] = authentication_path
    #                 return 'success', return_map
    #         else:
    #             return status, None
    #     elif method == 'POST':
    #         user_input = util.ConvertData(user_input).payload_to_json()
    #         status = fw.WAS().application_authentication_interactive(method=method, application_id=application_id,
    #                                                                  user_id=user_id, authentication=user_input['authentication'])
    #         return status, None

    def application_services(self,authorization_token,remote_address,application_id,method='',user_input=''):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            if method.upper()=='GET':
                services=fw.WAS().application_services(application_id,method)
                if 'services' in services:
                    return 'success',services
                else:
                    return services,None
            elif method.upper()=='POST':
                user_input=util.ConvertData(user_input).payload_to_json()
                status=fw.WAS().application_services(application_id,method,services=user_input['services'])
                return status,None
        else:
            return status,None

    def application_pre_crawl(self,authorization_token,remote_address,application_id,method='',user_input=''):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            if method.upper()=='GET':
                time.sleep(5)
                status=fw.WAS().application_pre_crawl(application_id,method,pre_crawl=user_input)
                if isinstance(status,dict):
                    return_map=dict()

                    if 'burp_xml' in status:
                        file_chunk=[status['burp_xml']['files'][i*user_input['page_size']:(i+1)*user_input['page_size']]
                            for i in
                            range(
                                (len(status['burp_xml']['files'])+user_input['page_size']-1)//user_input['page_size'])]
                        return_map['burp_xml']=dict()
                        return_map['burp_xml']['state']=status['burp_xml']['state']
                        if 'generated' in status['burp_xml']:
                            return_map['burp_xml']['generated']=status['burp_xml']['generated']
                            return_map['burp_xml']['total']=len(status['burp_xml']['files'])
                            return_map['burp_xml']['files']=file_chunk[user_input['page_number']]
                    if 'manual' in status:
                        # urls_list= list(status['manual']['urls'].values())
                        # file_chunk = [urls_list[i * user_input['page_size']:(i + 1) * user_input['page_size']] for i in
                        #               range((len(urls_list) + user_input['page_size'] - 1) // user_input['page_size'])]
                        return_map['manual']=dict()
                        return_map['manual']['state']=status['manual']['state']
                        if 'generated' in status['manual']:
                            return_map['manual']['generated']=status['manual']['generated']
                            return_map['manual']['total']=" "  #len(status['manual']['urls'])
                            #return_map['manual']['urls'] = file_chunk[user_input['page_number']]
                            return_map['manual']['state']=status['manual']['state']
                    return 'success',return_map
                else:
                    return status,None
            elif method.upper()=='POST':
                status=fw.WAS().application_pre_crawl(application_id,method,pre_crawl=user_input)
                if isinstance(status,dict):
                    return_map=status
                    return_map['pre_crawl']['refresh']=30
                    return 'success',return_map
                elif status=='terminate_success':
                    return status,None
                else:
                    return status,None
            elif method.upper()=='PUT':
                user_input=util.ConvertData(user_input).payload_to_json()
                status=fw.WAS().application_pre_crawl(application_id,method,pre_crawl=user_input)
                if isinstance(status,list):
                    if len(status)>=1:
                        return status[0],None
                    else:
                        return 'update_failure',None

        else:
            return status,None

    def application_pre_crawl_view(self,authorization_token,remote_address,application_id,user_input=''):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            status=fw.WAS().application_pre_crawl_view(application_id)
            if len(status)>0:
                status=status=[v for v in status]
                if isinstance(status,list):
                    file_chunk=[status[i*user_input['page_size']:(i+1)*user_input['page_size']] for i in
                        range((len(status)+user_input['page_size']-1)//user_input['page_size'])]

                    return_map=dict()
                    return_map['total']=len(status)
                    return_map['urls']=file_chunk[user_input['page_number']]
                    return 'success',return_map
            # status = [v for k, v in status.items()]
            # if isinstance(status, list):
            #     file_chunk = [status[i * user_input['page_size']:(i + 1) * user_input['page_size']] for i in
            #                   range((len(status) + user_input['page_size'] - 1) // user_input['page_size'])]

            #     return_map = dict()
            #     return_map['total'] = len(status)
            #     return_map['urls'] = file_chunk[user_input['page_number']]
            #     return 'success', return_map
            else:
                return status,None
        else:
            return status,None

    def application_payload_policy(self,authorization_token,remote_address,application_id,method='',user_input=''):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            if method.upper()=='GET':
                policy=fw.WAS().application_payload_policy(application_id,method)
                if 'payload_policy' in policy:
                    return_map=dict()
                    return_map['application']=dict()
                    return_map['application']['payload_policy']=policy['payload_policy']
                    return 'success',return_map
                else:
                    return policy,None
            elif method.upper()=='POST':
                user_input=util.ConvertData(user_input).payload_to_json()
                status=fw.WAS().application_payload_policy(application_id,method,
                    application=user_input['application'])
                return status,None
        else:
            return status,None

    def application_transactions(self,authorization_token,remote_address,application_id,transaction_id='',url_id='',
                                 method='',user_input=''):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            if method.upper()=='GET':
                transactions=fw.WAS().application_transactions(application_id=application_id,
                    method=method,
                    application=user_input)
                if 'transactions' in transactions:
                    search_map,return_map=list(),dict()
                    if user_input['search_text']:
                        self.log.info(f"Searching {user_input['search_text']} in transaction name")
                        for k,v in transactions['transactions'].items():
                            txn=dict()
                            if re.search(f"{user_input['search_text']}",v['transaction_name'],re.I):
                                txn[k]=v
                                search_map.append(txn)
                            else:
                                pass
                        if search_map:
                            txn_chunk=[search_map[i*user_input['page_size']:(i+1)*user_input['page_size']] for i in
                                range((len(search_map)+user_input['page_size']-1)//user_input['page_size'])]
                            return_map['total']=len(search_map)
                            return_map['transactions']=txn_chunk[user_input['page_number']]
                            return 'success',return_map
                        else:
                            return 'success',search_map
                    else:
                        txns=list()
                        for k,v in transactions['transactions'].items():
                            txn=dict()
                            txn[k]=v
                            txns.append(txn)
                        if len(txns)>=1:
                            txn_chunk=[txns[i*user_input['page_size']:(i+1)*user_input['page_size']] for i in
                                range((len(txns)+user_input['page_size']-1)//user_input['page_size'])]
                            return_map['total']=len(txns)
                            return_map['transactions']=txn_chunk[user_input['page_number']]
                            return 'success',return_map
                        else:
                            return_map['total']=0
                            return_map['transactions']=[]
                            return 'success',return_map
                else:
                    return transactions,None

            elif method.upper()=='POST':
                status=fw.WAS().application_transactions(application_id=application_id,method=method,
                    transaction=user_input)
                return status,None

            elif method.upper()=='DELETE':
                status=fw.WAS().application_transactions(application_id,transaction_id,url_id,method=method)
                return status,None
        else:
            return status,None

    def application_transaction_test(self,authorization_token,remote_address,application_id):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            status=fw.WAS().application_transaction_test(application_id=application_id)
            return status
        else:
            return status

    def crawl(self,authorization_token,remote_address,application_id='',method='',user_input='',request_state=None,
              address=None):
        user_auth=self.authorization(token=authorization_token,address=remote_address)
        system_auth=self.system_authorization(authorization_token,address)
        if user_auth=='authorized' or system_auth=='token_valid':
            if method.upper()=='GET':
                if request_state is None:
                    status=fw.WAS().crawl(method=method)
                    if status:
                        if isinstance(status,list):
                            return_map=dict()

                            if user_input['sort_by']:
                                if 'crawl' in user_input['sort_by']:
                                    if user_input['sort_order'].upper()=='ASC':
                                        self.log.info(f"Sorting application by {user_input['sort_by']}")
                                        apps=sorted(status,key=lambda i:i['crawl'][user_input['sort_by']],reverse=False)
                                    elif user_input['sort_order'].upper()=='DESC':
                                        self.log.info(f"Sorting application by {user_input['sort_by']}")
                                        apps=sorted(status,key=lambda i:i['crawl'][user_input['sort_by']],reverse=True)
                                else:
                                    if user_input['sort_order'].upper()=='ASC':
                                        self.log.info(f"Sorting application by {user_input['sort_by']}")
                                        apps=sorted(status,key=lambda i:i[user_input['sort_by']],reverse=False)
                                    elif user_input['sort_order'].upper()=='DESC':
                                        self.log.info(f"Sorting application by {user_input['sort_by']}")
                                        apps=sorted(status,key=lambda i:i[user_input['sort_by']],reverse=True)

                            if user_input['filter_text']:
                                self.log.info(f"Filtering application by {user_input['filter_text']}")
                                apps=list(
                                    filter(lambda app:app['crawl']['crawl_state']==user_input['filter_text'],apps))

                            if user_input['search_text']:
                                self.log.info(f"Searching {user_input['search_text']} in application name")
                                apps=list(
                                    filter(lambda app:re.search(f"{user_input['search_text']}",app['name'],re.I),apps))

                            if apps:
                                app_chunk=[apps[i*user_input['page_size']:(i+1)*user_input['page_size']] for i in
                                    range((len(apps)+user_input['page_size']-1)//user_input['page_size'])]

                                return_map['total']=len(apps)
                                return_map['applications']=app_chunk[user_input['page_number']]
                                return_map['refresh']=2
                            return 'success',return_map
                        else:
                            return status,None
                    else:
                        return None,None
                elif request_state=='status':
                    status=fw.WAS().crawl(application_id,method=method,request_state=request_state)
                    if status['crawl_state'] in ['in_progress','paused','terminated','completed']:
                        return_map=dict()
                        return_map['crawl']=status
                        return 'success',return_map
                elif request_state=='progress':
                    status=fw.WAS().crawl(application_id,method=method,request_state=request_state)
                    return_map=dict()
                    return_map['crawl']=dict()
                    return_map['crawl']['crawl_progress']=status
                    return 'success',return_map
                elif request_state=='status_progress':
                    crawl_status=fw.WAS().crawl(application_id,method=method,request_state=request_state)
                    if isinstance(crawl_status,list):
                        return 'status_progress_success',crawl_status
                    else:
                        self.log.critical(f"Crawl states: {crawl_status}")
                        return crawl_status,None
                elif request_state=='logs':
                    logs=fw.WAS().crawl(application_id,method=method,crawl=user_input,request_state=request_state)
                    return_map=dict()
                    return_map['logs']=logs
                    return 'success',return_map
            elif method.upper()=='POST':
                user_input=util.ConvertData(user_input).payload_to_json()
                if request_state in ['instantiate','terminate','aborted']:
                    status=fw.WAS().crawl(application_id,method=method,crawl=user_input,request_state=request_state)
                    if status=='instantiated':
                        return status,None
                    elif status=='update_success' and user_input['crawl']['url_store']=='create':
                        return 'create_success',None
                    elif status=='url_store_update_success' and user_input['crawl']['url_store']=='update':
                        return 'url_store_update_success',None
                    elif status=='url_store_update_success' and user_input['crawl']['url_store']=='replace':
                        return 'url_store_replace_success',None
                    elif status == 'document_not_found':
                        return 'document_not_found',None
                elif request_state=='pause':
                    status=fw.WAS().crawl(application_id,method=method,crawl=user_input,request_state=request_state)
                    return status,None
                elif request_state=='resume':
                    status=fw.WAS().crawl(application_id,method=method,crawl=user_input,request_state=request_state)
                    return status,None
                elif request_state=='terminate':
                    status=fw.WAS().crawl(application_id,method=method,crawl=user_input,request_state=request_state)
                    return status,None
        else:
            return user_auth,None

    def crawl_verify_authentication(self,authorization_token,remote_address,application_id,user_input):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            user_input=util.ConvertData(user_input).payload_to_json()
            status=fw.WAS().crawl_verify_authentication(application_id=application_id,crawl=user_input)
            return status,None
        else:
            return status,None

    def crawl_url_store(self,authorization_token,remote_address,application_id='',method='',user_input='',
                        request_state=None):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            if method.upper()=='GET':
                urls=list()
                status=fw.WAS().crawl_url_store(application_id=application_id,method=method)
                if status == 'document_not_found':
                    return status, None
                check=[v for k,v in status['urls'].items()]
                for i in check:
                    for k,v in i.items():
                        for k1,v1 in v.items():
                            urls.append(v1)

                if isinstance(urls,list):
                    url_chunk=[urls[i*user_input['page_size']:(i+1)*user_input['page_size']] for i in
                        range((len(urls)+user_input['page_size']-1)//user_input['page_size'])]
                    return_map=dict()
                    return_map['total']=len(urls)
                    return_map['urls']=url_chunk[user_input['page_number']]
                    return_map['authentication']=status['authentication']
                    return 'success',return_map
                else:
                    return status,None
        else:
            return status,None

    def attack(self,authorization_token,remote_address,application_id='',method='',user_input='',request_state=None,
               address=None):
        user_auth=self.authorization(token=authorization_token,address=remote_address)
        self.log.info(f"chk user auth value : {user_auth}")
        system_auth=self.system_authorization(authorization_token,address)
        self.log.info(f"chk system auth value : {system_auth}")
        if user_auth=='authorized' or system_auth=='token_valid':
            if method.upper()=='GET':
                if request_state is None:
                    status=fw.WAS().attack(method=method,request_state=request_state)  # chgaj
                    if status:
                        if isinstance(status,list):
                            return_map=dict()

                            if user_input['sort_by']:
                                if 'attack' in user_input['sort_by']:
                                    if user_input['sort_order'].upper()=='ASC':
                                        self.log.info(f"Sorting application by {user_input['sort_by']}")
                                        apps=sorted(status,key=lambda i:i['attack'][user_input['sort_by']],
                                            reverse=False)
                                    elif user_input['sort_order'].upper()=='DESC':
                                        self.log.info(f"Sorting application by {user_input['sort_by']}")
                                        apps=sorted(status,key=lambda i:i['attack'][user_input['sort_by']],reverse=True)
                                else:
                                    if user_input['sort_order'].upper()=='ASC':
                                        self.log.info(f"Sorting application by {user_input['sort_by']}")
                                        apps=sorted(status,key=lambda i:i[user_input['sort_by']],reverse=False)
                                    elif user_input['sort_order'].upper()=='DESC':
                                        self.log.info(f"Sorting application by {user_input['sort_by']}")
                                        apps=sorted(status,key=lambda i:i[user_input['sort_by']],reverse=True)

                            if user_input['filter_text']:
                                self.log.info(f"Filtering application by {user_input['filter_text']}")
                                apps=list(
                                    filter(lambda app:app['attack']['attack_state']==user_input['filter_text'],apps))

                            if user_input['search_text']:
                                self.log.info(f"Searching {user_input['search_text']} in application name")
                                apps=list(
                                    filter(lambda app:re.search(f"{user_input['search_text']}",app['name'],re.I),apps))

                            if apps:
                                app_chunk=[apps[i*user_input['page_size']:(i+1)*user_input['page_size']] for i in
                                    range((len(apps)+user_input['page_size']-1)//user_input['page_size'])]

                                return_map['total']=len(apps)
                                return_map['applications']=app_chunk[user_input['page_number']]
                                return_map['refresh']=2
                            return 'success',return_map
                        else:
                            return status,None
                    else:
                        return None,None
                elif request_state=='status':
                    status=fw.WAS().attack(application_id,method=method,request_state=request_state)
                    # if status['attack_state'] in ['instantiated', 'in_progress', 'paused', 'terminated', 'completed', 'aborted']:
                    if status['attack_state']:
                        return_map=dict()
                        return_map['attack']=status
                        return 'success',return_map
                    else:
                        return status,None
                elif request_state=='progress':
                    status=fw.WAS().attack(application_id,method=method,request_state=request_state)
                    return_map=dict()
                    return_map['attack']=dict()
                    return_map['attack']['attack_progress']=status
                    return 'success',return_map
                elif request_state=='status_progress':
                    attack_status=fw.WAS().attack(method=method,request_state=request_state)
                    if isinstance(attack_status,list):
                        return 'status_progress_success',attack_status
                    else:
                        self.log.critical(f"Attack states: {attack_status}")
                        return attack_status,None
                elif request_state=='logs':
                    logs=fw.WAS().attack(application_id,method=method,attack=user_input,request_state=request_state)
                    return_map=dict()
                    return_map['logs']=logs
                    return 'success',return_map
            elif method.upper()=='POST':
                # user_input = util.ConvertData(user_input).payload_to_json()
                if request_state=='instantiate':
                    status=fw.WAS().attack(application_id,method=method,crawl=user_input,request_state=request_state)
                    return status,None
                elif request_state=='pause':
                    status=fw.WAS().attack(application_id,method=method,crawl=user_input,request_state=request_state)
                    return status,None
                elif request_state=='terminate':
                    status,state=fw.WAS().attack(application_id,method=method,crawl=user_input,
                        request_state=request_state)
                    return status,state
                elif request_state=='resume':
                    status,state=fw.WAS().attack(application_id,method=method,crawl=user_input,
                        request_state=request_state)
                    return status,state

        else:
            return user_auth,None

    def attack_application(self,authorization_token,remote_address,application_id,user_input):
        self.log.info(f"App.ID value {application_id}")
        self.log.info(f"remote_address value {remote_address}")
        self.log.info(f"authorization_token value {authorization_token}")

        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            user_input=util.ConvertData(user_input).payload_to_json()
            status=fw.WAS().attack_application(application_id=application_id,attack=user_input)
            return status,None
        else:
            return status,None

    def attack_verify_authentication(self,authorization_token,remote_address,application_id,user_input):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            user_input=util.ConvertData(user_input).payload_to_json()
            status=fw.WAS().attack_verify_authentication(application_id=application_id,attack=user_input)
            return status,None
        else:
            return status,None

    def attack_store(self,authorization_token,remote_address,application_id='',method='',user_input='',
                     request_state=None):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            if method.upper()=='GET':
                if request_state=='url_store':
                    status=fw.WAS().attack_store(application_id=application_id,method=method,
                        request_state='url_store')
                    if status!='document_not_found':
                        urls=list()
                        check=[v for k,v in status['urls'].items()]
                        for i in check:
                            for k,v in i.items():
                                for k1,v1 in v.items():
                                    urls.append(v1)
                        #urls = [v for k, v in status['urls'].items()]
                        if isinstance(urls,list):
                            url_chunk=[urls[i*user_input['page_size']:(i+1)*user_input['page_size']] for i in
                                range((len(urls)+user_input['page_size']-1)//user_input['page_size'])]
                            return_map=dict()
                            return_map['total']=len(urls)
                            return_map['urls']=url_chunk[user_input['page_number']]
                            return_map['authentication']=status['authentication']
                            return 'success',return_map
                    else:
                        return status,None
                elif request_state=='transaction_store':
                    status=fw.WAS().attack_store(application_id=application_id,method=method,
                        request_state='transaction_store')
                    if status!='document_not_found':
                        txn=[v for k,v in status['transactions'].items()]
                        return_map=dict()
                        txn_chunk=[txn[i*user_input['page_size']:(i+1)*user_input['page_size']] for i in
                            range((len(status['transactions'])+user_input['page_size']-1)//user_input['page_size'])]
                        return_map['total']=len(txn)
                        return_map['transactions']=txn_chunk[user_input['page_number']]
                        return 'success',return_map
                    else:
                        return status,None
        else:
            return status,None

    def attack_policy(self,authorization_token,remote_address,policy_name='',method='',user_input=''):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            if method.upper()=='GET':
                status=fw.WAS().attack_policy(method=method,policy_name=policy_name)
                if isinstance(status,dict):
                    return_map=dict()
                    return_map['attack_policy']=status
                    return 'success',return_map
                else:
                    return status,None
            elif method.upper()=='POST':
                user_input=util.ConvertData(user_input).payload_to_json()
                status=fw.WAS().attack_policy(method=method,attack_policy=user_input)
                return status,None
        else:
            return status,None

    def reports(self,authorization_token,remote_address,user_input):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            reports=fw.WAS().reports()
            if isinstance(reports,list):
                return_map=dict()
                if user_input['sort_by']:
                    if user_input['sort_order'].upper()=='ASC':
                        self.log.info(f"Sorting application by {user_input['sort_by']}")
                        reports=sorted(reports,key=lambda i:i[user_input['sort_by']],reverse=False)
                    elif user_input['sort_order'].upper()=='DESC':
                        self.log.info(f"Sorting application by {user_input['sort_by']}")
                        reports=sorted(reports,key=lambda i:i[user_input['sort_by']],reverse=True)

                    if user_input['search_text']:
                        self.log.info(f"Searching {user_input['search_text']} in application name")
                        reports=list(
                            filter(lambda report:re.search(f"{user_input['search_text']}",report['report_name'],re.I),
                                reports))

                    if reports:
                        apps_chunk=[reports[i*user_input['page_size']:(i+1)*user_input['page_size']] for i in
                            range((len(reports)+user_input['page_size']-1)//user_input['page_size'])]
                        return_map['total']=len(reports)
                        return_map['reports']=apps_chunk[user_input['page_number']]
                        return 'success',return_map
                    else:
                        return 'success',None
            else:
                return reports,None
        else:
            return status,None

    def report_download(self,authorization_token,remote_address,report_id):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            report=fw.WAS().report_download(report_id)
            if isinstance(report,dict):
                return 'success',report
            else:
                return report,None
        else:
            return status,None

    def report_compensating_control(self,authorization_token,remote_address,report_id,method,user_input=''):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            if method.upper()=='GET':
                cc=fw.WAS().report_compensating_control(report_id,method=method)

                if isinstance(cc,dict):
                    return_map=dict()
                    cc_chunk=[cc['compensating_control']['vulnerabilities'][
                    i*user_input['page_size']:(i+1)*user_input['page_size']] for i in
                        range(
                            (len(cc['compensating_control']['vulnerabilities'])+user_input['page_size']-1)//user_input[
                                'page_size'])]
                    return_map['total']=len(cc['compensating_control']['vulnerabilities'])
                    return_map['compentating_control']=cc_chunk[user_input['page_number']]
                    return 'success',return_map
                else:
                    return cc,None
            elif method.upper()=='POST':
                user_input=util.ConvertData(user_input).payload_to_json()
                cc=fw.WAS().report_compensating_control(report_id,method=method,compensating_control=user_input)
                if cc=='report_not_found':
                    return cc,None
                else:
                    return 'success',cc
        else:
            return status,None

    def configuration(self,authorization_token,remote_address,method,user_input=''):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            if method.upper()=='GET':
                return_map=dict()
                return_map['configuration']=dict()

                user_selection=set()
                for k,v in user_input.items():
                    if v is not None:
                        user_selection.update(v)

                if len(user_selection)==0:
                    config=fw.WAS().configuration(method=method,request_type=None)
                    return_map['configuration']=config
                    return 'success',return_map
                elif user_input['cms'] is not None and user_input['cms'].lower()=='true':
                    config=fw.WAS().configuration(method=method,request_type='cms')
                    if 'cms' in config:
                        return_map['configuration']['cms']=config['cms']
                    else:
                        return_map['configuration']['cms']=None
                    return 'success',return_map
                elif user_input['integration'] is not None and user_input['integration'].lower()=='true':
                    config=fw.WAS().configuration(method=method,request_type='integration')
                    if 'integration' in config:
                        return_map['configuration']['integration']=dict()
                        keys=sorted(config['integration']['keys'],key=lambda i:i['issued'],reverse=True)
                        return_map['configuration']['integration']['configuration']=config['integration'][
                            'configuration']
                        return_map['configuration']['integration']['keys']=keys
                    else:
                        return_map['configuration']['integration']=None
                    return 'success',return_map
                elif user_input['syslog'] is not None and user_input['syslog'].lower()=='true':
                    config=fw.WAS().configuration(method=method,request_type='syslog')
                    if 'syslog' in config:
                        return_map['configuration']['syslog']=config['syslog']
                    else:
                        return_map['configuration']['syslog']=None
                    return 'success',return_map
                elif user_input['email'] is not None and user_input['email'].lower()=='true':
                    config=fw.WAS().configuration(method=method,request_type='email')
                    if 'email' in config:
                        return_map['configuration']['email']=config['email']
                    else:
                        return_map['configuration']['email']=None
                    return 'success',return_map
                elif user_input['database_policy'] is not None and user_input['database_policy'].lower()=='true':
                    config=fw.WAS().configuration(method=method,request_type='database_policy')
                    if 'database_policy' in config:
                        return_map['configuration']['database_policy']=config['database_policy']
                    else:
                        return_map['configuration']['database_policy']=None
                    return 'success',return_map
                elif user_input['logging_policy'] is not None and user_input['logging_policy'].lower()=='true':
                    config=fw.WAS().configuration(method=method,request_type='logging_policy')
                    if 'logging_policy' in config:
                        return_map['configuration']['logging_policy']=config['logging_policy']
                    else:
                        return_map['configuration']['logging_policy']=None
                    return 'success',return_map
                elif user_input['file_upload_policy'] is not None and user_input['file_upload_policy'].lower()=='true':
                    config=fw.WAS().configuration(method=method,request_type='file_upload_policy')
                    if 'file_upload_policy' in config:
                        return_map['configuration']['file_upload_policy']=config['file_upload_policy']
                    else:
                        return_map['configuration']['file_upload_policy']=None
                    return 'success',return_map
                elif user_input['attack_policy'] is not None and user_input['attack_policy'].lower()=='true':
                    config=fw.WAS().configuration(method=method,request_type='attack_policy')
                    if 'attack_policy' in config:
                        return_map['configuration']['attack_policy']=config['attack_policy']
                    else:
                        return_map['configuration']['attack_policy']=None
                    return 'success',return_map
                elif user_input['api_version'] is not None and user_input['api_version'].lower()=='true':
                    config=fw.WAS().configuration(method=method,request_type='api_version')
                    if 'api_version' in config:
                        return_map['configuration']['api_version']=config['api_version']
                    else:
                        return_map['configuration']['api_version']=None
                    return 'success',return_map
                # else:
                #     return_map['configuration'] = config
                #     return 'success', return_map
                # if 'cms' in status:
                #     status['cms'].pop('authorization_token')
                #     return_map['configuration']['cms'] = status['cms']
                # if 'vsp' in status:
                #     return_map['configuration']['vsp'] = status['vsp']
                # if 'proxy' in status:
                #     return_map['configuration']['proxy'] = status['proxy']
                # if 'syslog' in status:
                #     return_map['configuration']['syslog'] = status['syslog']
                # if 'integration' in status:
                #     return_map['configuration']['integration'] = status['integration']
                # if 'file_size' in status:
                #     return_map['configuration']['file_size'] = status['file_size']
                # if 'database_policy' in status:
                #     return_map['configuration']['database_policy'] = status['database_policy']
                # if 'logging_policy' in status:
                #     return_map['configuration']['logging_policy'] = status['logging_policy']
                # for k, v in return_map['configuration'].items():
                #     if 'password' in return_map['configuration'][k]:
                #         return_map['configuration'][k].pop('password')
                # return 'success', return_map

            elif method.upper()=='PUT':
                user_input=util.ConvertData(user_input).payload_to_json()
                state,config=fw.WAS().configuration(method=method,configuration=user_input['configuration'])
                return state,config
        else:
            return status,None

    def configuration_integration(self,authorization_token,remote_address,method,user_input=''):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            if method.upper()=='POST':
                user_input=util.ConvertData(user_input).payload_to_json()
                token=fw.WAS().configuration_integration(method=method,configuration=user_input['configuration'])
                if isinstance(token,dict):
                    return 'token_generated',token
                else:
                    return token,None
        else:
            return status,None

    def configuration_integration_check(self,authorization_token,remote_address,user_input=''):
        status=self.system_authorization(token=authorization_token,address=remote_address)
        return status

    def configuration_check(self,authorization_token,remote_address,user_input):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            user_input=util.ConvertData(user_input).payload_to_json()
            status,error=fw.WAS().configuration_check(configuration=user_input['configuration'])
            return status,error
        else:
            return status,None

    def notification(self,authorization_token,remote_address,method,user_input=''):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            if method=='GET':
                notify=fw.WAS().notification(method,notifications=user_input)
                # notify = fw.WAS().notification(method)
                if isinstance(notify,dict):
                    notify['refresh']=15
                    return 'available',notify
                else:
                    return notify,None
            elif method=='POST':
                user_input=util.ConvertData(user_input).payload_to_json()
                response=fw.WAS().notification(method,notifications=user_input)
                return response,None
            elif method=='DELETE':
                user_input=util.ConvertData(user_input).payload_to_json()
                response=fw.WAS().notification(method,notifications=user_input)
                return response,None
        else:
            return status,None

    def application_status(self,authorization_token,remote_address,method,request_state):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            if method.upper()=="GET":
                if (request_state=="application_status"):
                    return fw.WAS().get_all_application_status()
        else:
            return 401,status

    def clear_application_data(self,authorization_token,remote_address,method,application_id):
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            authentication=fw.WAS().clear_application_data(method,application_id)
            return authentication,None
        else:
            return status,None
    
    def attack_application_status(self,authorization_token,remote_address,application_id):
        
        status=self.authorization(token=authorization_token,address=remote_address)
        if status=='authorized':
            response=fw.WAS().cms_application_status(application_id)
            return response
        else:
            response_dict ={}
            response_dict['status'] = status
            return response_dict
