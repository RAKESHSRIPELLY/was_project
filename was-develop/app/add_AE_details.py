from pymongo.common import validate
from config.was import was
from lib.utility import Database, Authentication
from getpass import getpass
import re 

class Add_AE():
    
    def __init__(self):
        self.mongo=Database().Mongo()
        self.db_channel=self.mongo.connect(host=was['database'])
        self.db1=self.mongo.create_database(self.db_channel,'was_db')
    
    def user_input(self, **kwargs):
        
        ae_ip = kwargs.get('ae_ip')
        cms_ip = kwargs.get('cms_ip')
        
        vm_username = kwargs.get('vm_username')
        vm_password = kwargs.get('vm_password')
        
        ae_user = kwargs.get('ae_user')
        ae_password = kwargs.get('ae_password') 

        coll=self.mongo.create_collection(self.db1,'configuration')
        config=self.mongo.find_document(coll,{'api_version':'1.0'})
        ip_ae=ae_ip.replace('.','_')
        ip_cms=cms_ip.replace(".","_")
        
        # config_details={}
        if not isinstance(config,dict):
            config={'api_version':'1.0'}
        if "cms" not in config:
            config["cms"]={}
        
        if ip_cms not in config["cms"]:    
            config["cms"][ip_cms]={
                "ipv4_address":"",
                "username":"",
                "authorization_token":"",
                "vm_username":"",
                "ae":[]
            }
        
        
        if "ae" not in config["cms"][ip_cms]:
            config["cms"][ip_cms]["ae"]=[]
        
        if len(config["cms"][ip_cms]["ae"])==0:
            config["cms"][ip_cms]["ae"].append({ip_ae:{}})
        if ip_ae not in config['cms'][ip_cms]["ae"][0].keys():
            config["cms"][ip_cms]["ae"]=[]
            config["cms"][ip_cms]["ae"].append({ip_ae:{}})
        config['cms'][ip_cms]['vm_username'] = vm_username
        config['cms'][ip_cms]["ae"][0][ip_ae]["ip_address"]=ae_ip
        config['cms'][ip_cms]["ae"][0][ip_ae]["user_name"]=ae_user
        config['cms'][ip_cms]["ae"][0][ip_ae]["type"]="ae"
        config['cms'][ip_cms]["ae"][0][ip_ae]["log_path"]=""


        status=self.mongo.update_document(coll,{'$set':config},
                            {'api_version':'1.0'},
                            upsert=True)
        
        # < ---- vault document operations ---- >
        self.vault_operations(psw=vm_password,ip_address=cms_ip,vault_type='vm_password')
        
        self.vault_operations(psw=ae_password,ip_address=ae_ip,vault_type='ae')
    
    def vault_operations(self, psw, ip_address, vault_type):
        """
        This method used to create/update the vault document of type ( vm_Password and ae )

        Args:
            psw ([type]): str
            ip_address ([type]): str
            vault_type ([type]): str

        Returns:
            [type]: bool
        """
        try:
            # mongo=Database().Mongo()
            # db_channel=mongo.connect(host=was['database'])
            # db1=mongo.create_database(db_channel,'was_db')
            coll=self.mongo.create_collection(self.db1,'vault')
            
            encrypted_password,key = Authentication().encrypt_password(password=psw)
            
            # Getting the exiting document from Vault collection
            vault_dict = self.mongo.find_document(coll,{'type':str(vault_type),'ipv4_address':str(ip_address)})
            if not isinstance(vault_dict,dict):
                vault_dict={
                    "password": encrypted_password,
                    "type": vault_type,
                    "ipv4_address":ip_address,
                    "key":key
                }
            else:    
                vault_dict['password'] = encrypted_password  
                vault_dict['type'] = vault_type 
                vault_dict['ipv4_address'] = ip_address
                vault_dict['key'] = key
            
            status= self.mongo.update_document(coll,{'$set':vault_dict},
                            {'type':str(vault_type),'ipv4_address':str(ip_address)},
                            upsert=True)
            return True
        except:
            return False
        

def is_valid_ip(ip_str):
    #ip_regex=re.compile("^[0-9]{,3}.[0-9]{,3}.[0-9]{,3}.[0-9]{,3}$")
    return bool(re.match('^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$',ip_str))

cnt=0
valid_info=True
while valid_info:
    if cnt < 3:
        ae_ip=input("Please enter AE IP Address  : ")
        valid_info = not is_valid_ip(ae_ip)
        if valid_info:
            cnt+=1
    else:
        print("Attempts threshhold reached; exiting")
        valid_info=False
if cnt < 3 and not valid_info:
    ae_user=input("Please enter AE Username  : ")
    ae_password=getpass("Please enter AE Password  : ")
    cnt=0
    valid_info=True
    while valid_info:
        if cnt < 3:
            cms_ip=input("Please enter coresponding CMS IP Address  : ")
            valid_info = not is_valid_ip(cms_ip)
            if valid_info:
                cnt+=1
        else:
            print("Attempts threshhold reached; exiting")
            valid_info=False
    if cnt < 3 and not valid_info:
        vm_username=input(f"Please enter VM Username for CMS IP {cms_ip}  : ")
        vm_password=getpass(f"Please enter VM Password for CMS IP {cms_ip} : ")
        Add_AE().user_input(ae_ip=ae_ip, cms_ip=cms_ip, vm_password = vm_password, 
                     vm_username=vm_username, ae_user=ae_user, ae_password=ae_password)