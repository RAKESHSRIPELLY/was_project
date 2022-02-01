import ipaddress
from pathlib import Path
import os
import dotenv
import platform
import subprocess

default_dict = {}

# < --- Getting Was.env File Path From Terminal --- >
# was_path = str(input("Enter Was.Env File Path: "))
# print("Entered Path:", was_path)
# path_env = Path(was_path)
path_env = Path('was.env')


def validate_fun(id_port):
    """
    Desc: Validating IP Address & Ping the status, if it is Valid Then return True
    :param id_port: host
    :return: Bool (True/False)
    """
    try:
        ipaddress.ip_address(id_port)
        status = checking_ping(id_port)
        if status:
            return True
        else:
            return False
    except:
        return False


def checking_ping(host, retry_packets=3):
    """
    Desc: Returns Bool (True) if ping host/server status responds to a ping request.
    :param host: ip Address
    :param retry_packets: Numbers of times to Ping
    :return:
    """

    # Option for the number of packets as a function of
    param = '-n' if platform.system().lower() == 'windows' else '-c'

    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, str(retry_packets), host]
    ping_res = subprocess.call(command)
    return ping_res == 0


def env_set_key(_input, key):
    """
    Desc: Updated the Input Value (host) into Was.env File using set_key function.
    :param _input: host
    :param key: was.env Variable
    :return: none
    """
    try:
        yes_no_resp = input("Please confirm {} is the IP address for {}, if [yes/no]".format(_input, key))
        if yes_no_resp in ['yes', 'YES', 'y', 'Y']:
            os.environ[key] = str(_input)
            dotenv.set_key(path_env, str(key), os.environ[key], quote_mode="never")
    except Exception as e:
        print(str(e))


# < --- Operation For getting & Updating Mongo DB Host Address From Terminal --- >
mongo_user_input = input("Enter Mongodb Address: ")
if mongo_user_input == 'localhost':
    env_set_key(_input=mongo_user_input, key='MONGO_DB_HOST')
else:
    res = validate_fun(mongo_user_input)
    if res:
        env_set_key(_input=mongo_user_input, key='MONGO_DB_HOST')

# < --- Operation For getting & Updating Redis Cache Address From Terminal --- >
redis_user_input = input("Enter Redis cache Address: ")
if redis_user_input == 'localhost':
    env_set_key(_input=redis_user_input, key='REDIS_CACHE_HOST')
else:
    res = validate_fun(redis_user_input)
    if res:
        env_set_key(_input=redis_user_input, key='REDIS_CACHE_HOST')

# < --- Operation For getting & Updating Base Host Address From Terminal --- >
base_user_input = input("Enter the Base Host Address: ")
if base_user_input == 'localhost':
    env_set_key(_input=base_user_input, key='BASE_HOST_IP')
else:
    res = validate_fun(base_user_input)
    if res:
        env_set_key(_input=base_user_input, key='BASE_HOST_IP')
