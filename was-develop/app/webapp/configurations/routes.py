__author__ = 'JG'

from flask_cors import cross_origin
from flask import Blueprint, request, abort, make_response, jsonify
from webapp import services as svc

configurations = Blueprint('configurations', __name__)


@configurations.route("/api/configuration/was", methods=['GET', 'PUT'])
@cross_origin(supports_credentials=True)
def configuration():
    user_input = dict()
    user_input['cms'] = request.args.get('cms')
    user_input['integration'] = request.args.get('integration')
    user_input['syslog'] = request.args.get('syslog')
    user_input['email'] = request.args.get('email')
    user_input['database_policy'] = request.args.get('database_policy')
    user_input['logging_policy'] = request.args.get('logging_policy')
    user_input['file_upload_policy'] = request.args.get('file_upload_policy')
    user_input['attack_policy'] = request.args.get('attack_policy')
    user_input['api_version'] = request.args.get('api_version')
    if request.method.upper() == 'GET':
        status, config = svc.WAS().configuration(authorization_token=request.headers['Authorization'],
                                                 remote_address=request.remote_addr,
                                                 method=request.method, user_input=user_input)
    elif request.method.upper() == 'PUT':
        status, config = svc.WAS().configuration(authorization_token=request.headers['Authorization'],
                                                 remote_address=request.remote_addr,
                                                 method=request.method, user_input=request.json) #chg
    if status == 'unauthorized' or status == 'token_invalid':
        abort(401, description=status)
    elif status == 'success':
        return make_response(jsonify({'status_code': 200, 'status': 'success',
                                      'data': config,
                                      'isShowToaster': False, 'message': None}), 200)
    elif status == 'cms_update_success':
        return make_response(jsonify({'status_code': 201, 'status': status,
                                      'data': None,
                                      'isShowToaster': True, 'message': 'WAS configuration updated successfully'}), 201)
    elif status == 'syslog_update_success':
        return make_response(jsonify({'status_code': 201, 'status': status,
                                      'data': None,
                                      'isShowToaster': True, 'message': 'WAS configuration updated successfully'}), 201)
    elif status == 'email_update_success':
        return make_response(jsonify({'status_code': 201, 'status': status,
                                      'data': None,
                                      'isShowToaster': True, 'message': 'WAS configuration updated successfully'}), 201)
    elif status == 'database_update_success':
        return make_response(jsonify({'status_code': 201, 'status': status,
                                      'data': None,
                                      'isShowToaster': True, 'message': 'WAS configuration updated successfully'}), 201)
    elif status == 'update_success':
        return make_response(jsonify({'status_code': 201, 'status': status,
                                      'data': None,
                                      'isShowToaster': True, 'message': 'WAS configuration updated successfully'}), 201)
    elif status == 'cms_connection_error':
        return make_response(jsonify({'status_code': 10004, 'status': status,
                                      'data': None,
                                      'isShowToaster': True,
                                      'message': 'CMS connectivity error'}), 502)
    elif status == 'cms_authentication_error':
        return make_response(jsonify({'status_code': 10002, 'status': status,
                                      'data': None,
                                      'isShowToaster': True, 'message': config}), 401)

    elif status == 'insert_failure' or status == 'update_failure':
        return make_response(jsonify({'status_code': 202, 'status': status,
                                      'data': None,
                                      'isShowToaster': True, 'message': 'Configuration could not update successfully'}), 202)
    elif status == 'document_not_found':
        return make_response(jsonify({'status_code': 200, 'status': None,
                                      'data': None,
                                      'isShowToaster': False, 'message': None}), 200)
    elif status == 'connection_error':
        return make_response(jsonify({'status_code': 1001, 'status': status,
                                      'data': None,
                                      'isShowToaster': True, 'message': 'Connectivity to database got broken'}), 1001)
    elif status == 'smtp_authentication_error':
        return make_response(jsonify({'status_code': 10051, 'status': status,
                                      'data': None,
                                      'isShowToaster': True, 'message': 'SMTP username and password not accepted'}), 403)
    elif status == 'smtp_not_supported_error':
        return make_response(jsonify({'status_code': 10052, 'status': status,
                                      'data': None,
                                      'isShowToaster': True, 'message': 'SMTP protocol not supported'}), 406)
    elif status == 'connection_reset_error':
        return make_response(jsonify({'status_code': 10053, 'status': status,
                                      'data': None,
                                      'isShowToaster': True, 'message': 'Connection reset by SMTP server'}), 502)
    else:
        abort(403, description=config)


@configurations.route("/api/configuration/was/integration/key", methods=['POST'])
def configuration_integration():
    status, data = svc.WAS().configuration_integration(authorization_token=request.headers['Authorization'],
                                                       remote_address=request.remote_addr,
                                                       method=request.method, user_input=request.args)
    if status == 'unauthorized' or status == 'token_invalid':
        abort(401, description=status)
    elif status == 'token_generated':
        return make_response(jsonify({'status_code': 201, 'status': status,
                                      'data': data,
                                      'isShowToaster': True, 'message': 'Authorization key generated'}), 201)
    elif status == 'token_renewed':
        return make_response(jsonify({'status_code': 201, 'status': status,
                                      'data': None,
                                      'isShowToaster': True, 'message': 'Authorization key renewed'}), 201)
    elif status == 'token_revoked':
        return make_response(jsonify({'status_code': 201, 'status': status,
                                      'data': None,
                                      'isShowToaster': True, 'message': 'Authorization key revoked'}), 201)


@configurations.route("/api/configuration/was/integration/check", methods=['GET'])
def configuration_integration_check():
    status = svc.WAS().configuration_integration_check(authorization_token=request.headers['Authorization'],
                                                       remote_address=request.remote_addr)
    if status == 'unauthorized' or status == 'token_invalid':
        abort(401, description=status)
    elif status == 'authorized':
        return make_response(jsonify({'status_code': 200, 'status': status,
                                      'data': None,
                                      'isShowToaster': True, 'message': 'System is authorized to access APIs'}), 200)
    else:
        abort(401, description=status)


@configurations.route("/api/configuration/check", methods=['POST'])
def configuration_check():
    status, error = svc.WAS().configuration_check(authorization_token=request.headers['Authorization'],
                                                  remote_address=request.remote_addr,
                                                  user_input=request.args)
    if status == 'unauthorized' or status == 'token_invalid':
        abort(401, description=status)
    elif status == 'success':
        return make_response(jsonify({'status_code': 200, 'status': 'success',
                                      'data': None,
                                      'isShowToaster': True, 'message': 'Validated successfully'}), 200)
    elif status == 'connection_error':
        abort(502, description=status)
    else:
        abort(401, description=error)

