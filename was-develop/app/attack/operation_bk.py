__author__ = 'JG'

from lib import utility as util, framework as fw
from config import was, environment as env
import time
import requests
from urllib.parse import quote
import os
import traceback
from json import loads, dumps
# from requests.utils import quote
from multiprocessing import Process, Pipe
from multiprocessing.pool import ThreadPool
"""
execution_manager.py // Generate test cases
    segregate_test_cases // Segregate test cases from list of TCs
    schedule_test_apps // Check application on CMS, fetch probe details/service details
    schedule_tests  // forwarding request to testcase_execution
    testcase_execution // forwarding request to execution_engine
    execution_engine.py   // 
        execute_testcase    // forwarding request to execute_test_steps
        execute_test_steps  // Check probe status and forward request to generate_attack
            generate_attack // Create CVE/PVE/FSM attack generator
                            // Pull URL store, performs authentication, create process with target- url_multip
            url_multip      //  Based on URLs in URL store, pull payloads from payload store based on vulnerabilities
                            // ** not we do not have vulnerability flag in new attack flow
                            // Performs cve_attack for each type of vulnerabilities A1 - A9
                invoke_cve_attack   // Read payload file and forward payloads to execute_payload_using_requests
                execute_payload_using_requests  // Grouping CapedID list and send it to execute_payloads
                execute_payloads    // Main attack script
    app_config_json_with_rtt
    
"""


class Attack:

    def __init__(self, application_id):
        self.application_id = application_id

        self.log = util.Log()
        self.redis = util.Database().Redis()
        self.mongo = util.Database().Mongo()

        self.count = 1

    def initiate(self):
        try:
            cache_channel = self.redis.connect(host=was.was['cache'])
            db_channel = self.mongo.connect(host=was.was['database'])
            db = self.mongo.create_database(db_channel, 'was_db')

            self.log.info(f"Validating if application instance(s) is in appropriate state")

            coll = self.mongo.create_collection(db, 'url_store')
            application_services = self.mongo.find_document(coll, {'application_id': self.application_id},
                                                            {'services': True})
            if 'services' in application_services:
                application_instances = set()
                for k, v in application_services['services'].items():
                    for instance in v['instances']:
                        application_instances.add(instance)

                cms = util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
                access_token = fw.CMS(cms['ipv4_address']).token_status()
                cms_services_header = util.Authentication().create_http_header('services', access_token, cms['ipv4_address'])

                cms_application_instances = fw.CMS(cms['ipv4_address']).application_instances(self.application_id,
                                                                                           cms_services_header)
                attack_ready = False
                for instance in application_instances:
                    for app_instance in cms_application_instances:
                        if instance == app_instance['serverNetworkInfo']['ipAddress'] and app_instance['status'] == 'NORMAL':
                            attack_ready = True
                            self.log.info(f"Application {self.application_id} has service instance {instance} in {app_instance['status']} state")
                        else:
                            attack_ready = False
                            self.log.info(f"Application {self.application_id} has service instance {instance} in {app_instance['status']} state")

                if attack_ready == True:
                    self.log.info(f"Validating application authentication for application- {self.application_id}")

                    coll = self.mongo.create_collection(db, 'url_store')
                    application_authentication = self.mongo.find_document(coll, {'application_id': self.application_id},
                                                                          {'authentication': True})
                    coll = self.mongo.create_collection(db, 'applications')
                    attack_users = self.mongo.find_document(coll, {'application_id': self.application_id},
                                                             {'attack.users': True})

                    fw_auth = 'not_applicable'
                    if application_authentication['authentication']['framework_authentication']['login'] == True:
                        self.log.info(f"Verifying framework-authentication for application- {self.application_id}")

                        auth_status = fw.WAS().application_authentication_test(self.application_id,
                                                                               authentication=application_authentication['authentication'])
                        if auth_status == 'basic_authentication_success' or auth_status == 'digest_authentication_success' or auth_status == 'ntlm_authentication_success':
                            fw_auth = 'success'
                        else:
                            fw_auth = 'failure'

                    app_auth = 'not_applicable'
                    if application_authentication['authentication']['application_authentication']['login'] == True:
                        validation_state = set()
                        for k, v in attack_users['attack']['users'].items():
                            if v['type'] == 'interactive':
                                auth_status, session = fw.WAS().application_authentication_interactive_test(self.application_id, k)
                            if v['type'] == 'automated':
                                auth_status = fw.WAS().application_authentication_automated_test(self.application_id, k)
                            validation_state.add(auth_status)
                        if [state for state in validation_state][0] == 'success':
                            app_auth = 'success'
                        else:
                            app_auth = 'failure'

                    self.log.info(f"Fetching crawled URLs for user(s) {attack_users['attack']['users']} with application {self.application_id}")

                    db_field = dict()
                    for k, v in attack_users['attack']['users'].items():
                        db_field[f'urls.{k}'] = True

                    self.log.info(f"Creating complete list of URLs with parameters")
                    urls = list()
                    coll = self.mongo.create_collection(db, 'url_store')
                    url_store = self.mongo.find_document(coll, {'application_id': self.application_id}, db_field)
                    for k1, v1 in url_store['urls'].items():
                        for k2, v2 in v1.items():
                            for k3, v3 in v2.items():
                                if v3['exercisable_parameters']:
                                    urls.append(v3)

                    attack_coll = self.mongo.create_collection(db, 'applications')
                    attack_detail = self.mongo.find_document(attack_coll, {'application_id': self.application_id}, {'attack': True})

                    if attack_detail['attack']['payload_policy'].lower() in ['low', 'medium', 'high']:
                        self.log.info(f"Creating complete list of Payloads with intensity- low")
                        pls = list()
                        coll = self.mongo.create_collection(db, 'payload_store')
                        url_store = self.mongo.find_all_documents(coll)
                        for vul in url_store:
                            vul.pop('_id')
                            for vulnerability, payload in vul.items():
                                if vulnerability in was.was['supported_vulnerabilities']:
                                    payload_data = list()
                                    for data in payload:
                                        if data['payload_data']:
                                            payload_data.append({data['capec_id']: data['payload_data']})
                                    pls.append(payload_data)
                    payloads = [i for i in zip(was.was['supported_vulnerabilities'], pls)]
                    # self.log.info(f"Creating a HTTP session")
                    # http_session = requests.session()
                    # http_session = session
                    # for p in payloads:
                    #     try:
                    #         for url in urls:
                    #             try:
                    #                 if url['request_type'].upper() == 'GET' and url['parameters']:
                    #
                    #                     attack_map = dict()
                    #                     attack_map['session'] = http_session
                    #                     attack_map['method'] = url['request_type'].upper()
                    #                     attack_map['url'] = list()
                    #                     attack_map['url_id'] = url['url_id']
                    #                     attack_map['payload'] = None
                    #                     attack_map['vulnerability'] = p[0]
                    #
                    #                     parent_url = f"{application_authentication['authentication']['homepage_url']}{url['attack_url']}?"
                    #                     for k, v in url['parameters'].items():
                    #                         for data in p[1][2:5]:
                    #                             for capec_id, payload in data.items():
                    #                                 if len(url['parameters']) == 1:
                    #                                     attack_map['url'].append({capec_id: f"{parent_url}{k}={payload}"})
                    #                                 elif len(url['parameters']) > 1:
                    #                                     param = str()
                    #                                     for k1, v1 in url['parameters'].items():
                    #                                         if k1 != k:
                    #                                             param = f"&{param}{k1}={v1}&"
                    #                                     attack_map['url'].append({capec_id: f"{parent_url}{k}={payload}{param}"[:-1]})
                    #
                    #                     self.attacker(request=attack_map)
                    #
                    #                 elif url['request_type'].upper() == 'POST' and url['parameters']:
                    #
                    #                     attack_map = dict()
                    #                     attack_map['session'] = http_session
                    #                     attack_map['method'] = url['request_type'].upper()
                    #                     attack_map['url'] = f"{application_authentication['authentication']['homepage_url']}{url['attack_url']}"
                    #                     attack_map['url_id'] = url['url_id']
                    #                     attack_map['payload'] = list()
                    #                     attack_map['vulnerability'] = p[0]
                    #
                    #                     for k, v in url['parameters'].items():
                    #                         for data in p[1][2:5]:
                    #                             for capec_id, payload in data.items():
                    #                                 if len(url['parameters']) == 1:
                    #                                     attack_map['payload'].append({capec_id: {k: payload}})
                    #                                 elif len(url['parameters']) > 1:
                    #                                     param = dict()
                    #                                     for k1, v1 in url['parameters'].items():
                    #                                         if k1 != k:
                    #                                             param[k1] = v1
                    #                                         else:
                    #                                             param[k] = payload
                    #                                     attack_map['payload'].append({capec_id: param})
                    #
                    #                     self.attacker(request=attack_map)
                    #             except Exception as err:
                    #                 self.log.error(err)
                    #                 traceback.print_stack(err)
                    #     except Exception as err:
                    #         self.log.error(err)
                    #         traceback.print_stack()

                    end_time = time.time()
                    cache_channel.hset(self.application_id, 'attack_state', 'completing')
                    coll = self.mongo.create_collection(db, 'applications')
                    self.mongo.update_document(coll, {'$set': {'attack.attack_state': 'completing',
                                                               'attack.attack_completed': end_time}},
                                               {'application_id': self.application_id}, upsert=True)
                    self.mongo.update_document(coll, {'$set': {'detail.state': 'attack_completing'}},
                                               {'application_id': self.application_id}, upsert=True)
                    # self.log.info(f"All the payloads been fired. Cooling for 300 seconds")
                    # time.sleep(300)
                    self.log.info(f"Investigating incidents")
                    status = self.investigate()
                    # status = 'investigation_success'
                    # if status == 'investigation_success':
                    #     self.log.info(f"Generating report")
                    #     self.reporting()
                    # else:
                    #     self.log.error(status)
                    #     return status

                else:
                    self.log.critical(f"Aborting attack operation! None of the instance(s) are in Normal state")

                    end_time = time.time()
                    cache_channel.hset(self.application_id, 'attack_state', 'aborted: instances_not_normal')
                    coll = self.mongo.create_collection(db, 'applications')
                    self.mongo.update_document(coll, {'$set': {'attack.attack_state': 'aborted: instances_not_normal',
                                                               'attack.attack_aborted': end_time}},
                                               {'application_id': self.application_id}, upsert=True)
                    self.mongo.update_document(coll, {'$set': {'detail.state': 'attack_aborted'}},
                                               {'application_id': self.application_id}, upsert=True)
                    return 'instances_not_normal'
            else:
                self.log.warning(f'Application services not available in database')

                self.log.critical(f"Aborting attack operation! None of the instance(s) are in Normal state")

                end_time = time.time()
                cache_channel.hset(self.application_id, 'attack_state', 'aborted: services_not_found')
                coll = self.mongo.create_collection(db, 'applications')
                self.mongo.update_document(coll, {'$set': {'attack.attack_state': 'aborted: services_not_found',
                                                           'attack.attack_aborted': end_time}},
                                           {'application_id': self.application_id}, upsert=True)
                self.mongo.update_document(coll, {'$set': {'detail.state': 'attack_aborted'}},
                                           {'application_id': self.application_id}, upsert=True)

                return 'services_not_found'
        finally:
            if cache_channel:
                cache_channel.close()
            if db_channel:
                db_channel.close()

    def attacker(self, **kwargs):
        http_request = kwargs.get('request')
        cache_channel = self.redis.connect(host=was.was['cache'])

        try:
            header, http_snippet = dict(), list()
            if http_request['method'] == 'GET':
                self.log.info(f"Firing URLs {http_request['url']} with vulnerability {http_request['vulnerability']}")
                for url in http_request['url']:
                    for capec_id, furl in url.items():
                        self.log.info(f"Generating WAS header for {furl} | request{self.count}")
                        header['virsec_uid'] = f"was-{self.application_id}-{http_request['url_id']}-{http_request['vulnerability']}-{capec_id}-request{self.count}"

                        # response = http_request['session'].request(method=http_request['url'], url=furl, data=http_request['payload'], headers=header, cookies=None, verify=False)

                        cache_map = dict()
                        cache_map['request_id'] = f"request{self.count}"
                        cache_map['uid'] = header['was_uid']
                        cache_map['method'] = http_request['method']
                        cache_map['url'] = furl
                        cache_map['vulnerability'] = http_request['vulnerability']
                        cache_map['response'] = 'test'
                        cache_channel.hset(self.application_id, f"request{self.count}", str(cache_map))
                        cache_channel.hset(self.application_id, f"request{self.count}_payload", str(http_request['payload']))
                        # cache_channel.hset(self.application_id, f"request{self.count}_response", str(response.text[:200]))
                        self.count += 1

            elif http_request['method'] == 'POST':
                self.log.info(f"Firing payload {http_request['payload']} from {http_request['vulnerability']} to URL {http_request['url']}")
                for payload in http_request['payload']:
                    for capec_id, data in payload.items():
                        self.log.info(f"Generating WAS header for url {http_request['url']} | request{self.count}")
                        header['was_uid'] = f"was-{self.application_id}-{http_request['url_id']}-{http_request['vulnerability']}-{capec_id}-request{self.count}"

                        # response = http_request['session'].request(method=http_request['url'], url=http_request['url'], data=data, headers=header, cookies=None, verify=False)

                        cache_map = dict()
                        cache_map['request_id'] = f"request{self.count}"
                        cache_map['uid'] = header['was_uid']
                        cache_map['method'] = http_request['method']
                        cache_map['url'] = http_request['url']
                        cache_map['vulnerability'] = http_request['vulnerability']
                        cache_map['response'] = 'test'
                        cache_channel.hset(self.application_id, f"request{self.count}", str(cache_map))
                        cache_channel.hset(self.application_id, f"request{self.count}_payload", str(data))
                        # cache_channel.hset(self.application_id, f"request{self.count}_response", str(response.text[:200]))
                        self.count += 1
        finally:
            if cache_channel:
                cache_channel.close()

    def investigate(self):
        try:
            cache_channel = self.redis.connect(host=was.was['cache'])
            db_channel = self.mongo.connect(host=was.was['database'])
            db = self.mongo.create_database(db_channel, 'was_db')

            cms = util.ConvertData((cache_channel.get('cms')).decode('utf-8')).framework_compatible()
            access_token = fw.CMS(cms['ipv4_address']).token_status()
            cms_services_header = util.Authentication().create_http_header('services', access_token, cms['ipv4_address'])

            application_ae = fw.CMS(cms['ipv4_address']).application_analysis_engine(self.application_id, cms_services_header)
            application_ae_address = application_ae[0]['serverNetworkInfo']['ipAddress']
            if application_ae_address:
                # coll = self.mongo.create_collection(db, 'vault')
                # doc = self.mongo.find_document(coll, {'username': cms['username']})
                # password = util.Authentication().decrypt_password(key=doc['key'], encrypted_password=doc['password'])

                client, channel = util.Connect().SSH(cms['ipv4_address']).connect(username='virsec', password='P@ssword1',
                                                                                  transport=True,
                                                                                  destination_host=application_ae_address,
                                                                                  destination_username='virsec',
                                                                                  destination_password='P@ssword1')

                cmd1 = ["sudo bash", "cd /var/virsec/log"]
                cmd2 = ["echo '' > emejson.log", "chown virsec:virsec temp.txt"]
                cmd3 = ["sed -n '/^ActiveMQ_Mgr::send: JSON: (MsgSeq# [0-9]*, Dest: \(DBI-CMS-QUEUE\|SW-EXC-LOG-QUEUE\)): {/,/^$/p' emejson.log > test.txt && echo 'success'",
                        "sed '/^$/d' test.txt > temp.txt && echo 'success'"]
                for cmd in cmd1:
                    output = util.Connect.SSH(application_ae_address).execute(channel=channel, command=cmd)
                for cmd in cmd3:
                    util.Connect.SSH(application_ae_address).execute_wait(channel=channel, command=cmd, expect='success')
                for cmd in cmd2:
                    output = util.Connect.SSH(application_ae_address).execute(channel=channel, command=cmd)

                local_dir = f"{env.workspace}/artefacts/traces/ae/{self.application_id}.log"
                remote_dir = f"/var/virsec/log/temp.txt"
                util.Connect.SSH(application_ae_address).secure_copy_files(client=client, local_directory=local_dir,
                                                                           remote_directory=remote_dir, operation='pull')

                # local_dir = os.getcwd() + '\\artefacts\\traces\\ae\\test.log'
                if os.path.exists(local_dir):
                    incident_uuid, virsec_uid = list(), list()
                    # file = os.getcwd() + '\\artefacts\\traces\\ae\\test.log'

                    with open(local_dir, "r") as outfile:
                        for line in outfile.readlines():
                            if 'uuid' in line:
                                print(line.strip().split(':')[1].strip(','))
                                incident_uuid.append(line.strip().split(':')[1].strip(',').split('"')[1])
                            if 'virsec-uid' in line:
                                virsec_uid.append(line.strip().split(':')[1].split('"')[1])

                    # incident_uuid = ["dd7a6860-0c6e-4b", "cde5e4a2-da65-4b", "9d0c3906-f4c7-4f"]
                    # virsec_uid = ["was-12345-URL_4-sqli-42-request1", "was-12345-URL_4-sqli-42-request2", "was-12345-URL_4-sqli-42-request3"]
                    uid_map = (dict(zip(incident_uuid, virsec_uid)))

                    cms_incidents = fw.CMS(cms['ipv4_address']).application_incidents(self.application_id,
                                                                                      cms_services_header)
                    cms_incident_id = list()
                    for incident in cms_incidents:
                        cms_incident_id.append(incident['id'])

                    known_incidents = dict()
                    for incident in cms_incident_id:
                        for incident_uid, virsec_uid in uid_map.items():
                            incident_detail = fw.CMS(cms['ipv4_address']).application_incident_detail(self.application_id,
                                                                                                      cms_services_header, incident)
                            if incident_detail['detail']['attributes']['Threat Level'] in ['ATTACK', 'THREAT'] and incident_detail['detail']['attributes']['UUID'] == incident_uid:
                                incident_map = dict()
                                incident_map[incident_uid] = dict()
                                incident_map[incident_uid]['uid'] = incident_uid
                                if 'GET' in incident_detail['detail']['attributes']['HTTP Request']:
                                    incident_map[incident_uid]['method'] = 'GET'
                                elif 'POST' in incident_detail['detail']['attributes']['HTTP Request']:
                                    incident_map[incident_uid]['method'] = 'POST'
                                incident_map[incident_uid]['uri'] = incident_detail['detail']['attributes']['HTTP Request'].split(' ')[1]
                                incident_map[incident_uid]['url_id'] = virsec_uid.split('-')[2]
                                incident_map[incident_uid]['request_id'] = virsec_uid.split('-')[5]
                                incident_map[incident_uid]['vulnerability'] = virsec_uid.split('-')[3]
                                incident_map[incident_uid]['capec_id'] = virsec_uid.split('-')[4]

                                known_incidents.update(incident_map)
                            else:
                                self.log.warning(f"Incident {incident_detail['detail']['attributes']['UUID']} is not a known incident")
                                continue

                    status = cache_channel.hset(self.application_id, 'known_incidents', str(known_incidents))
                    if status == 0:
                        return 'investigation_success'
                else:
                    self.log.critical(f"Analysis Engine logs not available")
                    return 'ae_logs_not_found'
            else:
                self.log.critical("Unable to find analysis engine address")
                return 'analysis_engine_not_available'

        finally:
            if cache_channel:
                cache_channel.close()

    def reporting(self):
        try:
            cache_channel = self.redis.connect(host=was.was['cache'])
            db_channel = self.mongo.connect(host=was.was['database'])
            db = self.mongo.create_database(db_channel, 'was_db')

            app_coll = self.mongo.create_collection(db, 'applications')
            app_doc = self.mongo.find_document(app_coll, {'application_id': self.application_id})

            url_store_coll = self.mongo.create_collection(db, 'url_store')
            url_store = self.mongo.find_document(url_store_coll, {'application_id': self.application_id})
            import json
            incidents = util.ConvertData(cache_channel.hget(self.application_id, 'known_incidents').decode('utf-8')).framework_compatible()

            final = dict()
            for incident_uid, incident_details in incidents.items():
                request_details = util.ConvertData(cache_channel.hget(self.application_id, incident_details['request_id']).decode('utf-8')).framework_compatible()
                request_payload = cache_channel.hget(self.application_id, f"{incident_details['request_id']}_payload").decode('utf-8')

                vulnerabilities = dict()
                vulnerabilities[request_details['request_id']] = dict()
                vulnerabilities[request_details['request_id']]['request_id'] = request_details['request_id']
                vulnerabilities[request_details['request_id']]['uid'] = request_details['uid']
                vulnerabilities[request_details['request_id']]['method'] = request_details['method']
                vulnerabilities[request_details['request_id']]['url'] = request_details['url']
                vulnerabilities[request_details['request_id']]['payload'] = request_payload
                vulnerabilities[request_details['request_id']]['response'] = request_details['response']
                vulnerabilities[request_details['request_id']]['vulnerability'] = request_details['vulnerability']
                vulnerabilities[request_details['request_id']]['url_id'] = incident_details['url_id']
                vulnerabilities[request_details['request_id']]['capec_id'] = incident_details['capec_id']
                final.update(vulnerabilities)

            report = dict()
            report['report_id'] = util.Authentication().generate_uuid('uuid4')
            report['report_name'] = f"{app_doc['detail']['name']}_{app_doc['detail']['version']}"
            report['report_version'] = "1.0.0"

            report['application_id'] = self.application_id
            report['application_details'] = dict()
            report['application_details']['application_id'] = self.application_id
            report['application_details']['application_name'] = app_doc['detail']['name']
            report['application_details']['application_version'] = app_doc['detail']['version']
            report['application_details']['application_url'] = url_store['authentication']['homepage_url']
            report['application_details']['application_user'] = ''
            report['application_details']['scan_start_time'] = app_doc['attack']['attack_instantiated']
            report['application_details']['scan_complete_time'] = app_doc['attack']['attack_completed']
            report['application_details']['user_email'] = 'was_admin@virsec.com'
            report['application_details']['was_isntance'] = util.Network().get_ipv4()

            report['services'] = dict()
            for k, v in url_store['services'].items():
                report['services'][k] = dict()
                report['services'][k]['vulnerabilities'] = dict()
                for rid, rdetails in final.items():
                    if rdetails['vulnerability'] == 'capec_a1_command_injection':
                        temp = list()
                        temp.append(rdetails)
                        report['services'][k]['vulnerabilities'][rdetails['vulnerability']] = dict()
                        report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['vulnerability_id'] = rdetails['vulnerability']
                        report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['vulnerability_name'] = 'Command Injection'
                        report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['affected_items'] = len(temp)
                        report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['recommendations'] = dict()
                        report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['references'] = dict()
                        report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['risk_factor'] = 'critical'
                        report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['urls'] = dict()
                        # report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['urls'][rdetails['url_id']] = rdetails
                        report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['vulnerability_classifications'] = dict()
                        report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['vulnerability_classifications']['capec'] = dict()
                        for i in temp:
                            report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['urls'][i['url_id']] = i
                            report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['vulnerability_classifications']['capec'][i['capec_id']] = dict()
                            report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['vulnerability_classifications']['capec'][i['capec_id']]['capec_id'] = i['capec_id']
                            report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['vulnerability_classifications']['capec'][i['capec_id']]['capec_description'] = ''
                        report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['vulnerability_classifications']['cwe'] = dict()
                        report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['vulnerability_classifications']['owasp'] = dict()
                        report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['vulnerability_classifications']['sans'] = dict()
                        report['services'][k]['vulnerabilities'][rdetails['vulnerability']]['vulnerability_classifications']['cvss'] = dict()
                break
            report_coll = self.mongo.create_collection(db, 'reports')
            status = self.mongo.update_document(report_coll, {'$set': {self.application_id: report}},
                                                {'application_id': self.application_id}, upsert=True)
            if status == 'update_success':
                self.log.info(f"Report successfully generated")

                cache_channel.hset(self.application_id, 'attack_state', 'completed')
                coll = self.mongo.create_collection(db, 'applications')
                self.mongo.update_document(coll, {'$set': {'attack.attack_state': 'completed'}},
                                           {'application_id': self.application_id}, upsert=True)
                self.mongo.update_document(coll, {'$set': {'detail.state': 'report_ready'}},
                                           {'application_id': self.application_id}, upsert=True)
                return 'attack_complete_successful'
            else:
                self.log.critical(f"Report could not successfully generated")
                return status
        finally:
            if cache_channel:
                cache_channel.close()
            if db_channel:
                db_channel.close()