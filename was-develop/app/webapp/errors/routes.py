__author__ = 'JG'

from flask import Blueprint, make_response, jsonify
from flask import Flask
from lib import utility as util
from flask_cors import cross_origin

errors = Blueprint('errors', __name__)

log = util.Log()
app = Flask(__name__)


@errors.app_errorhandler(400)
def error_400(err):
    log.error(f"{err.description}")
    return make_response(jsonify({'status_code': 400, 'status': 'failure',
                                  'data': None,
                                  'isShowToaster': True, 'message': err.description}), 400)


@errors.app_errorhandler(401)
@cross_origin(supports_credentials=True)
def error_401(err):
    log.error(f"{err.description}")
    return make_response(jsonify({'status_code': 401, 'status': err.description,
                                  'data': None,
                                  'isShowToaster': True, 'message': err.description}), 401)


# @errors.app_errorhandler(402)
# def error_402(err):
#     log.error(f"{err.description}")
#     return make_response(jsonify({'status_code': 402, 'status': 'failure,
#                                   'data': None,
#                                   'isShowToaster': True, 'message': err.description}), 402)


@errors.app_errorhandler(403)
def error_403(err):
    log.error(f"{err.description}")
    return make_response(jsonify({'status_code': 403, 'status': 'failure',
                                  'data': None,
                                  'isShowToaster': True, 'message': err.description}), 403)


@errors.app_errorhandler(404)
def error_404(err):
    log.error(f"API: {err.description}")
    return make_response(jsonify({'status_code': 404, 'status': 'failure',
                                  'data': None,
                                  'isShowToaster': True, 'message': err.description}), 404)


@errors.app_errorhandler(405)
def error_405(err):
    log.error(f"API: {err.description}")
    return make_response(jsonify({'status_code': 405, 'status': 'failure',
                                  'data': None,
                                  'isShowToaster': True, 'message': err.description}), 405)


@errors.app_errorhandler(406)
def error_406(err):
    log.error(f"API: {err.description}")
    return make_response(jsonify({'status_code': 406, 'status': 'failure',
                                  'data': None,
                                  'isShowToaster': True, 'message': err.description}), 406)


@errors.app_errorhandler(411)
def error_411(err):
    log.error(f"{err.description}")
    return make_response(jsonify({'status_code': 411, 'status': 'failure',
                                  'data': None,
                                  'isShowToaster': True, 'message': err.description}), 411)


@errors.app_errorhandler(412)
def error_412(err):
    return make_response(jsonify({'status_code': 412, 'status': 'failure',
                                  'data': None,
                                  'isShowToaster': True, 'message': err.description}), 412)


@errors.app_errorhandler(417)
def error_417(err):
    return make_response(jsonify({'status_code': 417, 'status': 'failure',
                                  'data': None,
                                  'isShowToaster': True, 'message': err.description}), 417)


@errors.app_errorhandler(500)
def error_500(err):
    log.error(f"API: {err.description}")
    return make_response(jsonify({'status_code': 500, 'status': 'failure',
                                  'data': None,
                                  'isShowToaster': True, 'message': err.description}), 500)


@errors.app_errorhandler(502)
def error_502(err):
    log.error(f"{err.description}")
    return make_response(jsonify({'status_code': 502, 'status': 'failure',
                                  'data': None,
                                  'isShowToaster': True, 'message': err.description}), 502)


@errors.app_errorhandler(504)
def error_502(err):
    log.error(f"{err.description}")
    return make_response(jsonify({'status_code': 504, 'status': 'failure',
                                  'data': None,
                                  'isShowToaster': True, 'message': err.description}), 504)


