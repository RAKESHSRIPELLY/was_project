import pymongo

payload_dict = [
    {
    "CAPEC-A1-SQLi": [{
        "capec_id": "7",
        "capec_description": "Blind SQL Injection24",
        "payload_id": "Capec-SQLi-7-013",
        "payload_data": "JyBvciBhc2NpaShTVUJTVFJJTkcoJ3Jvb3QnLDEsMSkpPTExNC0tIA==",
        "payload_info": "SQL Injection is a variant of Injection attacks. It allows an attacker to execute malicious SQL queries on the database associated with the application. An attacker can carry out dangerous activities such as bypass authentication of a web application, dump the contents of an entire database. The attacker can add, modify or delete database records.",
        "solution": {
            "recommendation_1": {
                "recommendation_description": "Do not include untrusted input from user in the SQL query without performing basic sanitization. It is preferrable to use parametrized queries or dynamic queries instead of stored procedures",
                "recommendation_id": "recommendation_1"
            }
        },
        "reference": {
            "link_1": {
                "link": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "link_id": "link_1"
            }
        }
    }]
},
    {
    "CAPEC-A7-ReflectiveXSS": [{
        "capec_id": "18",
        "capec_description": "XSS Targeting Non-Script Elements",
        "payload_id": "Capec-XSS-18-001",
        "payload_data": "PjxpbWcgaWQ9WFNTIFNSQz14IG9uZXJyb3I9YWxlcnQoWFNTKTs+",
        "payload_info": "Reflected XSS is a variant of XSS attacks where java script is a non-persistent and malicious script gets added to the link that a victim clicks.It allows an attacker to inject a malicious java script into a webpage. When a victim visits the infected page, the malicious java script is executed on the victim’s browser. The attacker can perform any malicious action such as stealing cookies, performing sensitive transactions on the application and other impersonation attacks.",
        "solution": {
            "recommendation_1": {
                "recommendation_description": "Input validation and output sanitization are basic and mandatory implementations. But these may get bypassed, based on the location where the input is reflected in the document of the web page.OWASP has proposed 8 rules for defending XSS attacks. Refer the below document for the guidelines:https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "recommendation_id": "recommendation_1"
            }
        },
        "reference": {
            "link_1": {
                "link": "https://owasp.org/www-community/xss-filter-evasion-cheatsheet",
                "link_id": "link_1"
            }
        }
    }]
    },
    {
    "CAPEC-A5-RFI": [{
        "capec_id": "274",
        "capec_description": "RFI",
        "payload_id": "Capec-RFI-V1-001",
        "payload_data": "aHR0cDovL3d3dy52aXJzZWMuY29t",
        "payload_info": "The File Inclusion vulnerability enables an attacker to include a file, usually exploiting a “dynamic file inclusion” mechanism implemented in the target application. The vulnerability occurs due to the usage of user input without validation.An attacker can include a webshell and can carry out code execution attacks on the application server",
        "solution": {
            "recommendation_1": {
                "recommendation_description": "Do not include user supplied files in the application. If this is a business requirement, maintain an allowed list of URLs to be included.",
                "recommendation_id": "recommendation_1"
            }
        },
        "reference": {
            "link_1": {
                "link": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion",
                "link_id": "link_1"
            },
            "link_3": {
                "link": "http://projects.webappsec.org/w/page/13246955/Remote%20File%20Inclusion",
                "link_id": "link_3"
            }
        }
    }]
},
    {
    "CAPEC-A5-PathTraversal": [{
        "capec_id": "126",
        "capec_description": "Relative Path Traversal",
        "payload_id": "Capec-PT-139-001",
        "payload_data": "Li4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vdmlyc2VjLnR4dA==",
        "payload_info": "Path Traversal vulnerability allows an attacker to trick the web      server and read the files outside of the webroot directory. The attacker can traverse back from the webroot using '../' sequence",
        "solution": {
            "recommendation_1": {
                "recommendation_description": "The most effective way to defend Path traversal attack is to not allow the dynamic file reading based on the user input. If it is a business requirement, follow the below steps:1. Enforce strong input validation to not allow special characters such as ''../''.2. Maintain a list of allowed files to be accessed from the Application. Alternatively, restrict the access to a specific directory. Do not store any business logic code or sensitive files in that directory.3. Append directory and file extensions to the user input.4. Start web server with a low privileged user account so that OS ACLs also provide additional security",
                "recommendation_id": "recommendation_1"
            }
        },
        "reference": {
            "link_1": {
                "link": "https://cwe.mitre.org/data/definitions/22.html",
                "link_id": "link_1"
            },
            "link_2": {
                "link": "http://projects.webappsec.org/w/page/13246952/Path%20Traversal",
                "link_id": "link_2"
            },
            "link_3": {
                "link": "http://projects.webappsec.org/w/page/13246952/Path%20Traversal",
                "link_id": "link_3"
            }
        }
    }]
},
    {
    "CAPEC-A1-CMDi": [{
        "capec_id": "248",
        "capec_description": "Command Injection",
        "payload_id": "Capec-CMDi-248-001",
        "payload_data": "JTNCY2F0JTIwL2V0Yy9wYXNzd2Q=",
        "payload_info": "OS Command Injection is a variant of Injection attacks. It occurs when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell without validation. The attacker-supplied operating system commands are executed with the privileges of the vulnerable application. Command injection attacks are possible largely due to insufficient input validation.",
        "solution": {
            "recommendation_1": {
                "recommendation_description": "Do not execute OS commands from the application layer based on the user inputs. If this requirement is necessary then follow OWASP guidelines to prevent commad injection vulnerability.https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                "recommendation_id": "recommendation_1"
            }
        },
        "reference": {
            "link_1": {
                "link": "https://owasp.org/www-community/attacks/Command_Injectionl",
                "link_id": "link_1"
            },
            "link_2": {
                "link": "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                "link_id": "link_2"
            },
            "link_3": {
                "link": "https://cwe.mitre.org/data/definitions/77.html",
                "link_id": "link_3"
            }
        }
    }]
}
]

user_dict = {
    "username": "was_admin@virsec.com",
    "first_name": "Administrator",
    "last_name": "Administrator",
    "email_address": "admin@JGLab.in",
    "phone_number": "0123456789",
    "type": "was",
    "roles": ["root"],
    "user_id": "31f7370a-ae36-11eb-9c73-bf966054b7ce"
}

vault_dict = {
    "user_id": "31f7370a-ae36-11eb-9c73-bf966054b7ce",
    "type": "was",
    "password": "$5$rounds=535000$0YVBQ4Y3W9d2ZsDl$2Q6AsUV2HkGsNo7xqBFfvmEiuXRE0tSkmxYIte7Ei0/"
}

zap_port_dict = {
    "zapIP": "0.0.0.0",
    "zapPort": '',
    "portStatus": "active",
    "applicationName": " ",
    "applicationId": " ",
    "applicationAPIKey": " ",
    "applicationURL": " ",
    "scanId": "",
    "processId": "",
    "created_dt": "",
    "updated_dt": "",
    "userInfo": "",
    "sacnId": ""
}

zap_ports = [2030, 2031, 2032, 2033, 2034, 2035, 2036, 2037, 2038, 2039]

# parser = argparse.ArgumentParser()
# try:
#     parser.add_argument('--MONGO_DB_HOST', type=str, help='Enter Mongodb Host ', default='localhost')
# except Exception as e:
#     print(str(e))
#     traceback.print_stack()
#
# data = parser.parse_args()
# localhost = data.MONGO_DB_HOST

localhost = input("Enter Mongodb Host Address: ")


class ValidatingConnection:
    def check(self):
        mongoClient = pymongo.MongoClient(host=localhost)
        dbConn = mongoClient["was_db"]
        try:
            list_count = dbConn.list_collection_names()
            return True
        except:
            return False


class DefaultMongodb:
    def __init__(self):
        self.mongoClient = pymongo.MongoClient(host=localhost)
        self.dbConn = self.mongoClient["was_db"]

    def default_user(self):
        # adding Default user documents
        count = self.dbConn.get_collection('users').count_documents({})
        if int(count) == 0:
            status = self.dbConn.get_collection('users').insert_one(user_dict)
            print('user added')

    def default_vault(self):
        # adding Default vault documents
        count = self.dbConn.get_collection('vault').count_documents({})
        if int(count) == 0:
            self.dbConn.get_collection('vault').insert_one(vault_dict)
            print('vault added')

    def default_zap(self):
        count = self.dbConn.get_collection('zap_ports').count_documents({})
        if int(count) == 0:
            for zap_port_id in zap_ports:
                zap_port_dict['zapPort'] = zap_port_id
                try:
                    zap_port_dict.pop('_id')
                except:
                    pass
                self.dbConn.get_collection('zap_ports').insert_one(zap_port_dict)
            print('zap_ports added')

    def default_payload(self):
        count = self.dbConn.get_collection('payload_store_low').count_documents({})
        if int(count) == 0:
            # adding Default payload stores documents
            self.dbConn.get_collection('payload_store_low').insert_many(payload_dict)
            print('payload_store_low added')
        count = self.dbConn.get_collection('payload_store_high').count_documents({})
        if int(count) == 0:
            # adding Default payload stores documents
            self.dbConn.get_collection('payload_store_high').insert_many(payload_dict)
            print('payload_store_high added')
        count = self.dbConn.get_collection('payload_store_medium').count_documents({})
        if int(count) == 0:
            # adding Default payload stores documents
            self.dbConn.get_collection('payload_store_medium').insert_many(payload_dict)
            print('payload_store_medium added')


vc_object = ValidatingConnection()
db_status = vc_object.check()

if db_status:
    dm_object = DefaultMongodb()

    dm_object.default_user()
    dm_object.default_vault()

    dm_object.default_payload()

    dm_object.default_zap()
else:
    print("invalid Mongodb Host")

