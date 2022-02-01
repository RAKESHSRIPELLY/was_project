import os
import logging
from dotenv import load_dotenv
import json
import os.path

#from config import was_config
#dotenv_path = os.path.join(os.path.realpath(os.getcwd()),"was.env")
dotenv_path='../../was.env'
load_dotenv(dotenv_path=dotenv_path)
#os.environ["DB_NAME"]="was_db"
__version__='2.0.21_27122021'
# "supported_vulnerabilities": ['capec_a1_command_injection', 'capec_a1_sql_injection', 'capec_a5_path_traversal', 'capec_a7_reflected_xss', 'capec_a7_stored_xss'],

was={
    "cache": os.environ['REDIS_CACHE_HOST'],
    "database": os.environ['MONGO_DB_HOST'],
    "host_ip": os.environ['BASE_HOST_IP'],
    "syslog": os.environ['BASE_HOST_IP'],
    "zap":os.path.join(os.path.realpath(os.getcwd()),"ZAP_2.11.0","zap-2.11.0.jar"),
    "supported_content_types":{
        'exe':['application/x-msdos-program','application/x-msdownload','application/x-msdownloads',
            'application/x-ms-dos-executable'],
        'xml':['application/xml','text/xml']},
    "supported_vulnerabilities":['capec_a1_command_injection','capec_a1_sql_injection','capec_a5_path_traversal',
        'capec_a7_reflected_xss','capec_a7_stored_xss','CAPEC-A1-CMDi','CAPEC-A1-SQLi',
        'CAPEC-A4-XXE','CAPEC-A5-PathTraversal','CAPEC-A5-RFI','CAPEC-A7-ReflectiveXSS',
        'CAPEC-A7-StoredXSS'],
    "attack_processes":10,
    "attack_threads":20,
    "cwe_id_desc":{
        74:"Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
        89:"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        80:"Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)",
        444:"Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')",
        113:"Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')",
        209:"Generation of Error Message Containing Sensitive Information",
        384:"Session Fixation",
        79:"Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        176:"Improper Handling of Unicode Encoding",
        177:"Improper Handling of URL Encoding (Hex Encoding)",
        173:"Improper Handling of Alternate Encoding",
        78:"Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        200:"Exposure of Sensitive Information to an Unauthorized Actor",
        22:"Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        424:"Improper Protection of Alternate Path",
        90:"Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
        20:"Improper Input Validation",
        829:"Inclusion of Functionality from Untrusted Control Sphere",
        94:"Improper Control of Generation of Code ('Code Injection')",
        77:"Improper Neutralization of Special Elements used in a Command ('Command Injection')",
        91:"XML Injection (aka Blind XPath Injection)",
        98:"Improper Control of Filename for Include / Require Statement in PHP Program ('PHP Remote File Inclusion')",
        707:"Improper Neutralization",
        302:"Authentication Bypass by Assumed-Immutable Data",
        88:"Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')"
    },

    "capec_cwe_mapping":{
        6:74,
        7:89,
        18:80,
        33:444,
        34:113,
        54:209,
        61:384,
        63:79,
        66:89,
        71:176,
        72:177,
        79:74,
        80:173,
        88:78,
        116:200,
        120:173,
        126:22,
        127:424,
        136:90,
        153:20,
        214:209,
        228:829,
        242:94,
        243:83,
        244:83,
        248:77,
        250:91,
        253:98,
        272:707,
        273:74,
        274:302,
        460:88,
        108:74
    },

    "cvss_base_score_dict":{
        "Attack Vector":"AV:N",
        "Attack Complexity":"AC:L",
        "Privileges Required":"PR:L",
        "User Interaction":"UI:N",
        "Scope":"S:C",
        "Confidentiality Impact":"C:H",
        "Integrity Impact":"I:H",
        "Availability Impact":"A:H"
    },
    "email":{
        "server":"10.20.12.54",
        "port":{
            "NONE":25,
            "SSL":465,
            "TLS":000
        },
        "sender_address":"automail@wasmail.local",
        "sender_password":"Testing@123",
        "protocol":"none"
    },
    "CAPEC-A1-SQLi":"SecRule REQUEST_URI 'VULN-URL' 'id': 'RULE_ID',phase:2,drop,capture,t:none,t:urlDecode,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,msg:'SQL injection Attack Detected',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',tag:'custom-rule-attack-sqli',tag:'OWASP_CRS/WEB_ATTACK/SQLi', tag:'OWASP_TOP_10/A1',ctl:auditLogParts=+E, severity:'CRITICAL', setvar:'tx.msg=%{rule.msg}'setvar:'tx.sqli_score=+%{tx.critical_anomaly_score}',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}',chain' \nSecRule ARGS_NAMES 'ARGUMENT-NAME' 'chain'\n SecRule ARGS '@detectSQLi'",
    "CAPEC-A1-CMDi":"SecRule REQUEST_URI 'VULN-URL' 'id': 'RULE_ID',phase:2,drop, capture,t:none,t:urlDecode,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,msg:'Command injection Attack Detected',  logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',tag:'custom-rule-attack-rce',   tag:'attack-rce',ctl:auditLogParts=+E, severity:'CRITICAL',setvar:'tx.msg=%{rule.msg}',setvar:'tx.rce_score=+%{tx.critical_anomaly_score}',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}','chain'\n SecRule ARGS_NAMES 'ARGUMENT-NAME' 'chain' \nSecRule ARGS '@rx (?:;|\{|\||\|\||&|&&|\n|\r|\$\(|\$\(\(|`|\${|<\(|>\(|\(\s*\))\s*(?:{|\s*\(\s*|\w+=(?:[^\s]*|\$.*|\$.*|<.*|>.*|\'.*\'|\".*\")\s+|!\s*|\$)*\s*(?:'|\")*(?:[\?\*\[\]\(\)\-\|+\w'\"\./\\\\]+/)?[\\\\'\"]*(?:s[\\\\'\"]*(?:e[\\\\'\"]*(?:t[\\\\'\"]*(?:(?:f[\\\\'\"]*a[\\\\'\"]*c[\\\\'\"]*l[\\\\'\"]*)?(?:\s|<|>).*|e[\\\\'\"]*n[\\\\'\"]*v|s[\\\\'\"]*i[\\\\'\"]*d)|n[\\\\'\"]*d[\\\\'\"]*m[\\\\'\"]*a[\\\\'\"]*i[\\\\'\"]*l|d[\\\\'\"]*(?:\s|<|>).*)|h[\\\\'\"]*(?:\.[\\\\'\"]*d[\\\\'\"]*i[\\\\'\"]*s[\\\\'\"]*t[\\\\'\"]*r[\\\\'\"]*i[\\\\'\"]*b|u[\\\\'\"]*t[\\\\'\"]*d[\\\\'\"]*o[\\\\'\"]*w[\\\\'\"]*n|(?:\s|<|>).*)|o[\\\\'\"]*(?:(?:u[\\\\'\"]*r[\\\\'\"]*c[\\\\'\"]*e|r[\\\\'\"]*t)[\\\\'\"]*(?:\s|<|>).*|c[\\\\'\"]*a[\\\\'\"]*t)|c[\\\\'\"]*(?:h[\\\\'\"]*e[\\\\'\"]*d|p[\\\\'\"]*(?:\s|<|>).*)|t[\\\\'\"]*r[\\\\'\"]*i[\\\\'\"]*n[\\\\'\"]*g[\\\\'\"]*s|(?:l[\\\\'\"]*e[\\\\'\"]*e|f[\\\\'\"]*t)[\\\\'\"]*p|y[\\\\'\"]*s[\\\\'\"]*c[\\\\'\"]*t[\\\\'\"]*l|u[\\\\'\"]*(?:(?:\s|<|>).*|d[\\\\'\"]*o)|d[\\\\'\"]*i[\\\\'\"]*f[\\\\'\"]*f|s[\\\\'\"]*h|v[\\\\'\"]*n)|p[\\\\'\"]*(?:k[\\\\'\"]*(?:g(?:(?:[\\\\'\"]*_)?[\\\\'\"]*i[\\\\'\"]*n[\\\\'\"]*f[\\\\'\"]*o)?|e[\\\\'\"]*x[\\\\'\"]*e[\\\\'\"]*c|i[\\\\'\"]*l[\\\\'\"]*l)|t[\\\\'\"]*a[\\\\'\"]*r(?:[\\\\'\"]*(?:d[\\\\'\"]*i[\\\\'\"]*f[\\\\'\"]*f|g[\\\\'\"]*r[\\\\'\"]*e[\\\\'\"]*p))?|a[\\\\'\"]*(?:t[\\\\'\"]*c[\\\\'\"]*h[\\\\'\"]*(?:\s|<|>).*|s[\\\\'\"]*s[\\\\'\"]*w[\\\\'\"]*d)|r[\\\\'\"]*i[\\\\'\"]*n[\\\\'\"]*t[\\\\'\"]*(?:e[\\\\'\"]*n[\\\\'\"]*v|f[\\\\'\"]*(?:\s|<|>).*)|y[\\\\'\"]*t[\\\\'\"]*h[\\\\'\"]*o[\\\\'\"]*n(?:[\\\\'\"]*(?:3(?:[\\\\'\"]*m)?|2))?|e[\\\\'\"]*r[\\\\'\"]*(?:l(?:[\\\\'\"]*(?:s[\\\\'\"]*h|5))?|m[\\\\'\"]*s)|(?:g[\\\\'\"]*r[\\\\'\"]*e|f[\\\\'\"]*t)[\\\\'\"]*p|(?:u[\\\\'\"]*s[\\\\'\"]*h|o[\\\\'\"]*p)[\\\\'\"]*d|h[\\\\'\"]*p(?:[\\\\'\"]*[57])?|i[\\\\'\"]*n[\\\\'\"]*g|s[\\\\'\"]*(?:\s|<|>).*)|n[\\\\'\"]*(?:c[\\\\'\"]*(?:\.[\\\\'\"]*(?:t[\\\\'\"]*r[\\\\'\"]*a[\\\\'\"]*d[\\\\'\"]*i[\\\\'\"]*t[\\\\'\"]*i[\\\\'\"]*o[\\\\'\"]*n[\\\\'\"]*a[\\\\'\"]*l|o[\\\\'\"]*p[\\\\'\"]*e[\\\\'\"]*n[\\\\'\"]*b[\\\\'\"]*s[\\\\'\"]*d)|(?:\s|<|>).*|a[\\\\'\"]*t)|e[\\\\'\"]*t[\\\\'\"]*(?:k[\\\\'\"]*i[\\\\'\"]*t[\\\\'\"]*-[\\\\'\"]*f[\\\\'\"]*t[\\\\'\"]*p|(?:s[\\\\'\"]*t|c)[\\\\'\"]*a[\\\\'\"]*t|(?:\s|<|>).*)|s[\\\\'\"]*(?:l[\\\\'\"]*o[\\\\'\"]*o[\\\\'\"]*k[\\\\'\"]*u[\\\\'\"]*p|t[\\\\'\"]*a[\\\\'\"]*t)|(?:a[\\\\'\"]*n[\\\\'\"]*o|i[\\\\'\"]*c[\\\\'\"]*e)[\\\\'\"]*(?:\s|<|>).*|(?:o[\\\\'\"]*h[\\\\'\"]*u|m[\\\\'\"]*a)[\\\\'\"]*p|p[\\\\'\"]*i[\\\\'\"]*n[\\\\'\"]*g)|r[\\\\'\"]*(?:e[\\\\'\"]*(?:(?:p[\\\\'\"]*(?:l[\\\\'\"]*a[\\\\'\"]*c[\\\\'\"]*e|e[\\\\'\"]*a[\\\\'\"]*t)|n[\\\\'\"]*a[\\\\'\"]*m[\\\\'\"]*e)[\\\\'\"]*(?:\s|<|>).*|a[\\\\'\"]*l[\\\\'\"]*p[\\\\'\"]*a[\\\\'\"]*t[\\\\'\"]*h)|m[\\\\'\"]*(?:(?:d[\\\\'\"]*i[\\\\'\"]*r[\\\\'\"]*)?(?:\s|<|>).*|u[\\\\'\"]*s[\\\\'\"]*e[\\\\'\"]*r)|u[\\\\'\"]*b[\\\\'\"]*y(?:[\\\\'\"]*(?:1(?:[\\\\'\"]*[89])?|2[\\\\'\"]*[012]))?|(?:a[\\\\'\"]*r|c[\\\\'\"]*p|p[\\\\'\"]*m)[\\\\'\"]*(?:\s|<|>).*|n[\\\\'\"]*a[\\\\'\"]*n[\\\\'\"]*o|o[\\\\'\"]*u[\\\\'\"]*t[\\\\'\"]*e|s[\\\\'\"]*y[\\\\'\"]*n[\\\\'\"]*c)|t[\\\\'\"]*(?:c[\\\\'\"]*(?:p[\\\\'\"]*(?:t[\\\\'\"]*r[\\\\'\"]*a[\\\\'\"]*c[\\\\'\"]*e[\\\\'\"]*r[\\\\'\"]*o[\\\\'\"]*u[\\\\'\"]*t[\\\\'\"]*e|i[\\\\'\"]*n[\\\\'\"]*g)|s[\\\\'\"]*h)|r[\\\\'\"]*a[\\\\'\"]*c[\\\\'\"]*e[\\\\'\"]*r[\\\\'\"]*o[\\\\'\"]*u[\\\\'\"]*t[\\\\'\"]*e(?:[\\\\'\"]*6)?|e[\\\\'\"]*(?:l[\\\\'\"]*n[\\\\'\"]*e[\\\\'\"]*t|e[\\\\'\"]*(?:\s|<|>).*)|i[\\\\'\"]*m[\\\\'\"]*e[\\\\'\"]*(?:o[\\\\'\"]*u[\\\\'\"]*t|(?:\s|<|>).*)|a[\\\\'\"]*(?:i[\\\\'\"]*l(?:[\\\\'\"]*f)?|r[\\\\'\"]*(?:\s|<|>).*)|o[\\\\'\"]*(?:u[\\\\'\"]*c[\\\\'\"]*h[\\\\'\"]*(?:\s|<|>).*|p))|u[\\\\'\"]*(?:n[\\\\'\"]*(?:l[\\\\'\"]*(?:i[\\\\'\"]*n[\\\\'\"]*k[\\\\'\"]*(?:\s|<|>).*|z[\\\\'\"]*m[\\\\'\"]*a)|c[\\\\'\"]*o[\\\\'\"]*m[\\\\'\"]*p[\\\\'\"]*r[\\\\'\"]*e[\\\\'\"]*s[\\\\'\"]*s|a[\\\\'\"]*m[\\\\'\"]*e|r[\\\\'\"]*a[\\\\'\"]*r|s[\\\\'\"]*e[\\\\'\"]*t|z[\\\\'\"]*i[\\\\'\"]*p|x[\\\\'\"]*z)|s[\\\\'\"]*e[\\\\'\"]*r[\\\\'\"]*(?:(?:a[\\\\'\"]*d|m[\\\\'\"]*o)[\\\\'\"]*d|d[\\\\'\"]*e[\\\\'\"]*l)|l[\\\\'\"]*i[\\\\'\"]*m[\\\\'\"]*i[\\\\'\"]*t[\\\\'\"]*(?:\s|<|>).*)|m[\\\\'\"]*(?:y[\\\\'\"]*s[\\\\'\"]*q[\\\\'\"]*l(?:[\\\\'\"]*(?:d[\\\\'\"]*u[\\\\'\"]*m[\\\\'\"]*p(?:[\\\\'\"]*s[\\\\'\"]*l[\\\\'\"]*o[\\\\'\"]*w)?|h[\\\\'\"]*o[\\\\'\"]*t[\\\\'\"]*c[\\\\'\"]*o[\\\\'\"]*p[\\\\'\"]*y|a[\\\\'\"]*d[\\\\'\"]*m[\\\\'\"]*i[\\\\'\"]*n|s[\\\\'\"]*h[\\\\'\"]*o[\\\\'\"]*w))?|(?:(?:o[\\\\'\"]*u[\\\\'\"]*n|u[\\\\'\"]*t)[\\\\'\"]*t|v)[\\\\'\"]*(?:\s|<|>).*)|x[\\\\'\"]*(?:z[\\\\'\"]*(?:(?:[ef][\\\\'\"]*)?g[\\\\'\"]*r[\\\\'\"]*e[\\\\'\"]*p|d[\\\\'\"]*(?:i[\\\\'\"]*f[\\\\'\"]*f|e[\\\\'\"]*c)|c[\\\\'\"]*(?:a[\\\\'\"]*t|m[\\\\'\"]*p)|l[\\\\'\"]*e[\\\\'\"]*s[\\\\'\"]*s|m[\\\\'\"]*o[\\\\'\"]*r[\\\\'\"]*e|(?:\s|<|>).*)|a[\\\\'\"]*r[\\\\'\"]*g[\\\\'\"]*s|t[\\\\'\"]*e[\\\\'\"]*r[\\\\'\"]*m|x[\\\\'\"]*d[\\\\'\"]*(?:\s|<|>).*)|z[\\\\'\"]*(?:(?:[ef][\\\\'\"]*)?g[\\\\'\"]*r[\\\\'\"]*e[\\\\'\"]*p|c[\\\\'\"]*(?:a[\\\\'\"]*t|m[\\\\'\"]*p)|d[\\\\'\"]*i[\\\\'\"]*f[\\\\'\"]*f|i[\\\\'\"]*p[\\\\'\"]*(?:\s|<|>).*|l[\\\\'\"]*e[\\\\'\"]*s[\\\\'\"]*s|m[\\\\'\"]*o[\\\\'\"]*r[\\\\'\"]*e|r[\\\\'\"]*u[\\\\'\"]*n|s[\\\\'\"]*h)|o[\\\\'\"]*(?:p[\\\\'\"]*e[\\\\'\"]*n[\\\\'\"]*s[\\\\'\"]*s[\\\\'\"]*l|n[\\\\'\"]*i[\\\\'\"]*n[\\\\'\"]*t[\\\\'\"]*r)|w[\\\\'\"]*(?:h[\\\\'\"]*o[\\\\'\"]*(?:a[\\\\'\"]*m[\\\\'\"]*i|(?:\s|<|>).*)|g[\\\\'\"]*e[\\\\'\"]*t|3[\\\\'\"]*m)|v[\\\\'\"]*i[\\\\'\"]*(?:m[\\\\'\"]*(?:\s|<|>).*|g[\\\\'\"]*r|p[\\\\'\"]*w)|y[\\\\'\"]*u[\\\\'\"]*m)\b",
    "CAPEC-A5-PathTraversal":"SecRule REQUEST_URI 'VULN-URL' 'id': 'RULE_ID',phase:2,drop,capture, t:none,t:urlDecode,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,  msg:'Path Traversal Attack Detected(/../)',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',    tag:'custom-rule-attack-lfi', tag:'attack-lfi',ctl:auditLogParts=+E,severity:'CRITICAL',setvar:'tx.msg=%{rule.msg}',setvar:'tx.lfi_score=+%{tx.critical_anomaly_score}',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}',chain \n SecRule ARGS_NAMES 'ARGUMENT-NAME' 'chain'\n SecRule ARGS '@rx (?:^|[\\/])\.\.(?:[\\/]|$)'",
    "CAPEC-A7-ReflectiveXSS":"SecRule REQUEST_URI 'VULN-URL' 'id': 'RULE_ID',phase:2,drop,capture, t:none,t:urlDecode,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls, msg:'Cross Site Scripting(XSS) Attack Detected',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}', tag:'custom-rule-attack-xss',tag:'OWASP_CRS/WEB_ATTACK/XSS', tag:'OWASP_TOP_10/A3', ctl:auditLogParts=+E, severity:'CRITICAL', setvar:'tx.msg=%{rule.msg}',setvar:'tx.xss_score=+%{tx.critical_anomaly_score}', setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}',chain \n SecRule ARGS_NAMES 'ARGUMENT-NAME' 'chain'\n SecRule ARGS '@detectXSS'",
    "CAPEC-A5-RFI":"SecRule REQUEST_URI 'VULN-URL' 'id': 'RULE_ID', phase:2,drop,capture,t:none,t:urlDecode,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,msg:'Remote File Inclusion (RFI) Attack',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',tag:'custom-rule-attack-rfi',tag:'OWASP_CRS/WEB_ATTACK/RFI',ctl:auditLogParts=+E,severity:'CRITICAL',setvar:'tx.rfi_score=+%{tx.critical_anomaly_score}',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}','chain'\n SecRule ARGS_NAMES 'ARGUMENT-NAME' 'chain'\nSecRule ARGS '@rx ^(?i:file|ftps?|https?)'",
    "CMS":{
        "acceptable_app_status":["attack","normal","threat"]
    }

}

user={
    "username":"was_admin@virsec.com",
    "password":"Password@12345",
    "first_name":"Administrator",
    "last_name":"Administrator",
    "email_address":"admin@JGLab.in",
    "phone_number":"0123456789",
    "type":"was",
    "roles":["root"]
}

configuration={
    "configuration":{
        "file_upload_policy":{
            "authentication_automated":50,
            "pre_crawl":50,
            "transaction_store":50
        },
        "database_policy":{
            "archive":90,
            "backup":30
        },
        "logging_policy":{
            "rotation":250,
            "archive":30
        },
        "integration":{
            "minimum":1,
            "maximum":45,
            "default":30
        },
        "syslog":{
            "ipv4_address":"127.0.0.1",
            "port":514
        },
        "attack_policy":{
            "default":{
                "policy_name":"default",
                "policy_description":"WAS default attack policy",
                "peak_hour_stime":1234,
                "peak_hour_etime":4321,
                "threads":2,
                "delay":3,
                "retry":4,
                "notification":True,
                "fuzz":["url_parameters","body_parameters","headers"],
                "custom_script":False,
                "vulnerabilities":["sql_injection","command_injection","path_traversal"]
            }
        },
        "api_version":"1.0"
    },
    "manual_crawl":{
        "mitm_executor":"mitmdump",
        "mitm_process_py":"uploadLog.py",
        "mitm_location":os.path.abspath(os.getcwd()),
        "upload_json_name":"mitm_temp.json",
        "final_url":"finalURLData.json"
    },
    "exclusion_ext":['apng','avif','gif','jpg','jpeg','jfif','pjpeg','pjp','png','svg','webp','bmp','ico',
        'cur','tif','tiff','cgi','pl','shtml','txt','pdf','xml','css'],
    "payload_policy":{
        "low":"payload_store_low",
        "medium":"payload_store_medium",
        "high":"payload_store_high"
    },
    "attack":{
        "attack_timeout":5
    },
    "report":{

        "inclusion_status_codes":[100,101,102,103,200,201,202,203,204,205,206,207,208,226,300,301,302,303,304,305,306,
            307,308],
        "error_codes":[400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,422,425,426,428,429,
            431,451,500,501,502,503,504,505,506,507,508,510,511]
    },
    "crawl":{
        "default_service_tag":"default_tag"
    },
    "timeout":10
}

environment={
    "logging":{
        "level":logging.DEBUG,
        "log_location":os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))),"artefacts",
            "traces"),
        "execution_log":{
            "name":"execution.log",
            "backup_count":3,
            "size_limit":15  # Size in Mb
        },
        "crawl_log":{
            "name":"crawl.log",
            "backup_count":3,
            "size_limit":15  # Size in Mb
        }
    }

}
