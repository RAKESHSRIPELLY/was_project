__author__ = 'JG'

from lib import utility as util
from config import was
from config import payloads as pl

log = util.Log()

redis = util.Database().Redis()
cache_channel = redis.connect(host=was.was['cache'])

mongo = util.Database().Mongo()
channel = mongo.connect(host=was.was['database'])
db = mongo.create_database(channel, 'was_db')


def prerequisite():

    # Flushing cache & database
    status = cache_channel.flushall()
    log.info(f"Cache flushed: {status}")
    channel.drop_database('was_db')
    log.info(f"Database flushed")
    db = mongo.create_database(channel, 'was_db')
    log.info(f"Database recreated")

    # Adding default configuration
    config_map = was.configuration
    coll = mongo.create_collection(db, 'configuration')
    doc = mongo.insert_document(coll, config_map['configuration'])
    if doc == 'insert_success':
        # test = {"custom": {"policy_name": "test1"}}
        # mongo.update_document(coll, {'$set': {'attack_policy.custom': test['custom']}}, {'api_version': '1.0'})
        # print("-"*100)
        # print(mongo.find_document(coll, {'api_version': '1.0'}))
        # print("-" * 100)
        log.info(f"Default configuration added successfully")

    log.info(f"Configuring default threshold value for dashboard widgets")
    cache_channel.hset('dashboard', 'threshold', 90)

    user = was.user
    uid = util.Authentication().generate_uuid('uuid1')
    user['user_id'] = uid
    log.info(f"Updating user {uid}")

    # Adding default user
    coll = mongo.create_collection(db, 'vault')
    log.info(f"Updating vault for user {uid}")
    vault_map = dict()
    vault_map['user_id'] = uid
    vault_map['type'] = user['type']
    vault_map['password'] = util.Authentication().hash_password(user['password'])
    status = mongo.insert_document(coll, vault_map)
    if status == 'insert_success':

        user_map = user
        user_map.pop('password')
        coll = mongo.create_collection(db, 'users')
        status = mongo.insert_document(coll, user_map)
        log.info(f"User update status: {status}")
        log.info(f"Default user detail {coll.find_one({'user_id': uid})}")
        if status == 'insert_success':
            log.info(f"User {uid} created successfully")

    # Start ZAP

    for k, v in pl.payload_data.items():
        mongo.insert_document(coll, {k: v})

    return 'success'
