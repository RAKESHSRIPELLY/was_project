import time
from zapv2 import ZAPv2
from urllib import parse
import urllib.parse as urlparse
from urllib.parse import parse_qs
import requests
import sys
import subprocess

ZapAPIKey = "12345"
ZapDirectory = '/home/virsec/ZAP_2.10.0/zap-2.10.0.jar'
ZapIP = '0.0.0.0'
ZapPort = '2031'
# target = 'http://test.com'
target = 'https://public-firing-range.appspot.com'


# ZAPHeaders = {'Accept': 'application/json', 'X-ZAP-API-Key': '{0}'.format(apiKey)}

# zap = ZAPv2(apikey=apiKey)

def setProxy(self):
    try:
        # self.ZapAPIKey = '60a5f8e18315bdbdd248e93b'
        # self.ZapIP = '127.0.0.1'
        # self.ZapPort = 2031
        self.ZAPHeaders = {'Accept': 'application/json', 'X-ZAP-API-Key': '{0}'.format(self.ZapAPIKey)}
        print(f"Enabling ZAP proxy for {self.ZapIP} on port {self.ZapPort}")
        forwardURL = ("http://{0}:{1}/JSON/core/action/setOptionProxyChainName/").format(self.ZapIP, self.ZapPort)
        print(f"Sending {forwardURL} with APG {self.APGIP} and {self.ZAPHeaders}")
        F_IP = requests.get(forwardURL, params={'String': self.APGIP}, headers=self.ZAPHeaders)
        print(F_IP)
        forwardPort = ("http://{0}:{1}/JSON/core/action/setOptionProxyChainPort/").format(self.ZapIP, self.ZapPort)
        F_PORT = requests.get(forwardPort, params={'Integer': '8080'}, headers=self.ZAPHeaders)
        print(F_PORT)
        forwardSet = ("http://{0}:{1}/JSON/core/action/setOptionUseProxyChain/").format(self.ZapIP, self.ZapPort)
        F_SET = requests.get(forwardSet, params={'Boolean': 'True'}, headers=self.ZAPHeaders)
        print(F_SET)
        if (F_IP.status_code == 200) and (F_PORT.status_code == 200) and (F_SET.status_code == 200):
            print("Success: ZAP Proxy Enabled")
        else:
            print("Error: ZAP Proxy Failed")
    except Exception as e:
        print(e)
        print('Unable to Process setProxy.')
        sys.exit(2029)


def fetchZAPProcessId(ZapAPIKey):
    try:
        print(f"Fetching ZAP process ID with key {ZapAPIKey}")
        zapDataCmd = ("ps -aux | grep ZAP | grep -v grep")
        execGrep = subprocess.Popen(zapDataCmd, shell=True, stdout=subprocess.PIPE)
        z = execGrep.communicate()[0].decode('utf-8')
        print(z)
        if z:
            print(f"ZAP process ID: {(z.split())[1]}")
            return (z.split())[1]
        else:
            return None
    except Exception as e:
        print(e)
        print('Unable to Process fetchZAPProcessId .')
        sys.exit(2029)


def startZAP():
    try:
        # self.log.info(f"Starting ZAP with key: {self.ZapAPIKey}")

        portNumRaw = fetchZAPProcessId(ZapAPIKey)
        if portNumRaw is None:
            zapTrigger = (
                "java -jar {0} -daemon -host {1} -port {2} -config api.key='{3}' -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true > zap.txt ").format(
                ZapDirectory, ZapIP, ZapPort, ZapAPIKey)
            subprocess.Popen([zapTrigger], shell=True)
            print("ZAP started successfully for the first time")
        elif len(portNumRaw) >= 1:
            zapKillTrigger = ("kill {0}").format(portNumRaw)
            subprocess.Popen([zapKillTrigger], shell=True)

            zapTrigger = (
                "java -jar {0} -daemon -host {1} -port {2} -config api.key={3} > zap.txt ").format(
                ZapDirectory, ZapIP, ZapPort, ZapAPIKey)
            subprocess.Popen([zapTrigger], shell=True)
            print("ZAP started successfully")
    except Exception as e:
        return jsonify({'data': {'code': 2030, 'status': 'error', 'message': 'Unable to Process Crawl : StartZAP.',
                                 'exception': e}})


def validateZAPAPI():
    try:
        print("validateZAPAPI")
        tempURL = ("http://{0}:{1}/JSON/context/view/contextList/").format(ZapIP, ZapPort)
        print(tempURL)
        tempResponse = requests.get(tempURL)
        print(tempResponse)
        if tempResponse.status_code == 200:
            print("Success: Valid ZAP API Key.")
        else:
            return ({'data': {'code': 2039, 'status': 'error',
                              'message': 'Unable to Process Crawl : Invalid ZAP API Key.'}})

    except Exception as e:
        print({'data': {'code': 2038, 'status': 'error',
                        'message': 'Unable to Process Crawl : Error in Validating ZAP API Key.',
                        'exception': e}})


def get_query_params(url):
    dict = {
        "exercisable_parameters": [],
        "parameters": {}
    }
    parsed = urlparse.urlparse(url)
    query_obj = parse_qs(parsed.query)
    for d in query_obj:
        dict['exercisable_parameters'].append(d)
        dict['parameters'][d] = "".join(query_obj[d])
    return dict


#############################################################3
startZAP()
time.sleep(30)
print('Spidering target {}'.format(target))
# The scan returns a scan id to support concurrent scanning
# zap.spider.set_option_user_agent("xzasdad")
# validateZAPAPI()

zap = ZAPv2(apikey=ZapAPIKey, proxies={
    'http': f'http://{ZapIP}:{ZapPort}',  # 'http': f'http://{ZapIP}:{ZapPort}',
    'https': f'http://{ZapIP}:{ZapPort}'
})
# zap.spider.set_option_user_agent("Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",ZapAPIKey)

scanID = zap.spider.scan(target, apikey=ZapAPIKey)

while int(zap.spider.status(scanID)) < 100:
    # Poll the status until it completes
    print('Spider progress %: {}'.format(zap.spider.status(scanID)))
    time.sleep(1)

print(zap.spider.results(scanID))
header_list = []
result = {
    "user-agent": None,  # "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "requestType": None,
    "attack_url": None,
    "exercisable_parameters": [],
    "parameters": {},
    "hostname": None

}
user_agent = zap.session.headers._store['user-agent'][1]
for data in zap.spider.full_results(scanID)[0]["urlsInScope"]:
    dict = get_query_params(data['url'])
    header_list.append({
        "user-agent": user_agent,  # "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "requestType": data['method'],
        "attack_url": parse.urlparse(data['url']).path,
        "exercisable_parameters": dict["exercisable_parameters"],
        "parameters": dict['parameters'],
        "hostname": parse.urlparse(data['url']).netloc

    })
print(zap.session.headers)
# print(zap.spider.option_user_agent)
# print(zap.spider.results(scanID))
# print('Traditional Spider has completed!')
#
# # set1_list=[]
# # for i in header_list:
# #     set1_list.append(i["attack_url"])
# #
# # import collections
# # print([item for item, count in collections.Counter(set1_list).items() if count > 1])
#
# self.mongoClient = MongoClient(host=was.was["database"])
# self.dbConn = self.mongoClient["was_db"]
# self.urlStoreTempTable = self.dbConn['temp_url_store']
# with open("finalURLData.json", "r") as finallog:
#     json_data = json.load(finallog)
#     for i in json_data:
#         cursor = self.urlStoreTempTable.find({"attack_url": i['attack_url']})
#         count = cursor.count()
# ########################################################################
# def get_zap_object():
#     return ZAPv2(
#         apikey=self.ZapAPIKey,
#         proxies={
#             'http': f'http://{self.ZapAPIKey}:{self.ZapPort}',
#             'https': f'http://{self.ZapAPIKey}:{self.ZapPort}'
#         }
#     )
# def get_scan_id():
#     target=self.applicationURL
#     zap_obj=get_zap_object()
#     return zap_obj.spider.scan(target)
#
# def get_user_agent(zap_obj):
#     if zap_obj is not None:
#         return zap.session.headers._store['user-agent'][1]
#     raise ValueError("Zap object cannot be None")
#
# def get_query_params(url):
#     dict = {
#         "exercisable_parameters": [],
#         "parameters": {}
#     }
#     parsed = urlparse.urlparse(url)
#     query_obj = parse_qs(parsed.query)
#     for d in query_obj:
#         dict['exercisable_parameters'].append(d)
#         dict['parameters'][d] = "".join(query_obj[d])
#     return dict
#
# def get_header_list():
#     header_list = []
#     result = {
#         "user-agent": None,  # "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
#         "requestType": None,
#         "attack_url": None,
#         "exercisable_parameters": [],
#         "parameters": {},
#         "hostname": None
#
#     }
#     for data in zap.spider.full_results(scanID)[0]["urlsInScope"]:
#         dict = get_query_params(data['url'])
#         header_list.append({
#             "user-agent": user_agent,  # "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
#             "requestType": data['method'],
#             "attack_url": parse.urlparse(data['url']).path,
#             "exercisable_parameters": dict["exercisable_parameters"],
#             "parameters": dict['parameters'],
#             "hostname": parse.urlparse(data['url']).netloc
#
#         })
