__author__='JG'

from flask import Blueprint,request,abort,make_response,jsonify,send_file
from flask_cors import cross_origin
from webapp import services as svc

operations=Blueprint('operations',__name__)


@operations.route("/api/operations/validate_user",methods=['POST'])
@cross_origin(supports_credentials=True)
def validate_user():
    status,user_details=svc.WAS().validate_user(visitor_address=request.remote_addr,user_input=request.args)
    if status=='username_not_found' or status=='password_do_not_match' or status=='unauthorized' or status=='token_invalid' or status=='invalid':
        abort(401,description=status)
    elif status=='database_connection_error':
        abort(502,description=status)
    if status=='user_validated':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':user_details,
            'isShowToaster':True,'message':f"User validated successfully"}),200)
    if status=='valid' or status=='success' or status=='insert_success' or status=='update_success':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':user_details,
            'isShowToaster':True,'message':'User validated successfully'}),200)
    if status=='unauthorized_user' or 'unauthorized':
        return make_response(jsonify({'status_code':401,'status':status,
            'data':None,
            'isShowToaster':True,'message':user_details}),401)
    elif status=='invalid_user_type':
        abort(400)
    elif status=='document_not_found':
        abort(500,description=status)


@operations.route("/api/operations/change_login_credentials",methods=['POST'])
@cross_origin(supports_credentials=True)
def change_login_credentials():
    status,credentials=svc.WAS().change_login_credentials(authorization_token=request.headers['authorization'],
        remote_address=request.remote_addr,
        user_input=request.args)

    if status=='new_password_updated':
        return make_response(jsonify({'status_code':200,'status':status,
            'isShowToaster':True,'message':'Password changed successfully'}),200)
    if status=='same_as_old_password':
        return make_response(jsonify({'status_code':200,'status':'same_as_old_password',
            'isShowToaster':True,'message':'New password cannot be same as old'}),200)
    else:
        return make_response(jsonify({'status_code':200,'status':'current_password_invalid',
            'data':credentials,
            'isShowToaster':True,'message':'Current password is not valid'}),200)


@operations.route("/api/operations/applications",methods=['GET'])
@cross_origin(supports_credentials=True)
def applications():
    user_input=dict()
    user_input['sort_by']=request.args.get('sort_by')
    user_input['sort_order']=request.args.get('sort_order')
    user_input['search_text']=request.args.get('search_text')
    user_input['filter_text']=request.args.get('filter_text')
    user_input['page_number']=int(request.args.get('page_number'))
    user_input['page_size']=int(request.args.get('page_size'))
    status,apps=svc.WAS().applications(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,user_input=user_input)

    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='success':
        if apps is not None:
            for num,value in enumerate(apps['applications']):
                try:
                    temp_progress=apps['applications'][num]['progress']
                    apps['applications'][num]['progress']={y.decode('utf8'):temp_progress.get(y).decode('utf8') for y in
                        temp_progress.keys()}
                except KeyError:
                    continue

        return make_response(jsonify({'status_code':200,'status':status,
            'data':apps,
            'isShowToaster':False,'message':None}),200)
    elif status=='cms_not_configured':
        return make_response(jsonify({'status_code':10001,'status':status,
            'data':None,
            'isShowToaster':True,'message':'CMS is not configured to fetch applications'}),421)
    elif status=='cms_authentication_error':
        return make_response(jsonify({'status_code':10002,'status':status,
            'data':None,
            'isShowToaster':True,'message':'CMS is not authenticated to fetch applications'}),421)
    elif status=='cms_captcha_error':
        return make_response(jsonify({'status_code':10003,'status':status,
            'data':None,
            'isShowToaster':True,'message':'CMS needs captcha to authenticate and fetch applications'}),421)
    elif status=='cms_connection_error':
        return make_response(jsonify({'status_code':10004,'status':status,
            'data':None,
            'isShowToaster':True,
            'message':'CMS connectivity error'}),502)


@operations.route("/api/operations/application/<application_id>/authentication",methods=['GET','POST'])
@cross_origin(supports_credentials=True)
def application_authentication(application_id):
    status,authentication=svc.WAS().application_authentication(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,
        method=request.method,user_input=request.args)
    if status=='field_not_found' and authentication is None:
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':authentication,
            'isShowToaster':False,'message':None}))
    if status=='document_not_found' and authentication is None:
        abort(500,description=status)

    if status=='insert_success' or status=='update_success':
        return make_response(jsonify({'status_code':201,'status':'success',
            'data':authentication,
            'isShowToaster':True,'message':"Application authentication details updated successfully"}),201)

    elif status=='success' and authentication is not None:
        return make_response(jsonify({'status_code':200,'status':status,
            'data':authentication,
            'isShowToaster':False,'message':None}))
    elif 'authentication' in status:
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':authentication,
            'isShowToaster':False,'message':None}))

    elif status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)


@operations.route("/api/operations/application/<application_id>/authentication/<user_id>",methods=['POST','DELETE'])
@cross_origin(supports_credentials=True)
def application_authentication_user(application_id,user_id):
    status,authentication=svc.WAS().application_authentication_user(
        authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,method=request.method,
        application_id=application_id,user_id=user_id)
    if status=='url_store_available':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':authentication,
            'isShowToaster':True,'message':'URL store already generated by this user'}),200)
    elif status=='url_store_not_available':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':authentication,
            'isShowToaster':True,'message':'URL store is not generated by this user'}),200)
    elif status=='user_delete_success':
        return make_response(jsonify({'status_code':201,'status':status,
            'data':authentication,
            'isShowToaster':True,'message':"Application authentication details updated successfully"}),201)
    else:
        abort(404,description=status)


@operations.route("/api/operations/application/<application_id>/authentication/test",methods=['POST'])
@cross_origin(supports_credentials=True)
def application_authentication_test(application_id):
    status=svc.WAS().application_authentication_test(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,
        user_input=request.args)
    if status=='success':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':None,
            'isShowToaster':True,'message':'Framework authentication successful'}),200)
    elif status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='basic_authentication_failure':
        abort(403)
    elif status=='decode_error' or status=='failure':
        return make_response(jsonify({'status_code':417,'status':status,
            'data':None,
            'isShowToaster':True,'message':'Framework authentication unsuccessful'}),417)
    elif status=='connection_error':
        return make_response(jsonify({'status_code':10061,'status':status,
            'data':None,
            'isShowToaster':True,'message':'Remote machine is not reachable'}),502)
    elif status=='base_exception':
        return make_response(jsonify({'status_code':10069,'status':status,
            'data':None,
            'isShowToaster':True,'message':'An exception occurred'}),503)


@operations.route("/api/operations/application/<application_id>/authentication/<user_id>/automated",methods=['POST'])
@cross_origin(supports_credentials=True)
def application_authentication_automated(application_id,user_id):
    user_input=dict()
    user_input['file']=request.files['file']
    user_input['parameters']=request.form['parameters']
    user_input['message']=request.form['message']

    status,result=svc.WAS().application_authentication_automated(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,
        application_id=application_id,user_id=user_id,
        user_input=request.files['file'])
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='success':
        return make_response(jsonify({'status_code':201,'status':'success',
            'data':result,
            'isShowToaster':True,'message':'Binary upload successful'}),201)
    elif status=='file_not_supported':
        abort(406,description=status)
    elif status=='file_not_found':
        abort(412,description=status)


@operations.route("/api/operations/application/<application_id>/authentication/<user_id>/automated/test",
    methods=['POST'])
@cross_origin(supports_credentials=True)
def application_authentication_automated_test(application_id,user_id):
    status=svc.WAS().application_authentication_automated_test(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,
        application_id=application_id,user_id=user_id)
    if status=='success':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'Test successful'}),200)

    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)

    elif status=='file_not_found':
        abort(412,description=status)


# @operations.route("/api/operations/application/<application_id>/authentication/<user_id>/interactive", methods=['GET', 'POST'])
# @cross_origin(supports_credentials=True)
# def application_authentication_interactive(application_id, user_id):

#     if request.method == 'GET':
#         status, location = svc.WAS().application_authentication_interactive(authorization_token=request.headers['Authorization'],
#                                                                             remote_address=request.remote_addr, method=request.method,
#                                                                             application_id=application_id, user_id=user_id)
#     elif request.method == 'POST':
#         status, location = svc.WAS().application_authentication_interactive(authorization_token=None, remote_address=None,
#                                                                             method=request.method, application_id=application_id,
#                                                                             user_id=user_id)
#     if status == 'unauthorized' or status == 'token_invalid':
#         abort(401, description=status)
#     elif status == 'success':
#         return send_file(location['authentication_file'], attachment_filename='authentication.zip')
#     elif status == 'interactive_authentication_update_success':
#         return make_response(jsonify({'status_code': 200, 'status': status,
#                                       'data': None,
#                                       'isShowToaster': True, 'message': 'HTTP stream update successful'}), 200)
#     elif status == 'authentication_success':
#         return make_response(jsonify({'status_code': 200, 'status': status,
#                                       'data': None,
#                                       'isShowToaster': True, 'message': 'Authentication successful'}), 200)
#     elif status == 'authentication_unsuccess':
#         return make_response(jsonify({'status_code': 200, 'status': status,
#                                       'data': None,
#                                       'isShowToaster': True, 'message': 'Authentication unsuccessful'}), 200)
#     elif status == 'interactive_authentication_update_success':
#         return make_response(jsonify({'status_code': 201, 'status': status,
#                                       'data': None,
#                                       'isShowToaster': True, 'message': 'Recording updated successfully'}), 201)


@operations.route("/api/operations/application/<application_id>/services",methods=['GET','POST'])
@cross_origin(supports_credentials=True)
def application_services(application_id):
    status,services=svc.WAS().application_services(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,
        method=request.method,user_input=request.args)
    if status=='success':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':services,
            'isShowToaster':False,'message':None}),200)
    elif status=='services_update_success':
        return make_response(jsonify({'status_code':201,'status':'success',
            'data':services,
            'isShowToaster':True,'message':'Service URIs updated successfully'}),201)
    if status=='cms_not_configured':
        return make_response(jsonify({'status_code':10001,'status':status,
            'data':services,
            'isShowToaster':True,'message':'CMS is not configured to fetch applications'}),421)
    elif status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='connection_error':
        abort(500)


@operations.route("/api/operations/application/<application_id>/pre_crawl",methods=['GET','POST','PUT'],
    strict_slashes=False)
@cross_origin(supports_credentials=True)
def application_pre_crawl(application_id):
    if request.method.upper()=='GET':
        user_input=dict()
        user_input['page_number']=int(request.args.get('page_number'))
        user_input['page_size']=int(request.args.get('page_size'))
        status,pre_crawl=svc.WAS().application_pre_crawl(authorization_token=request.headers['Authorization'],
            remote_address=request.remote_addr,application_id=application_id,
            method=request.method,user_input=user_input)
        if status=='document_not_found':
            return make_response(jsonify({'status_code':200,'status':'success',
                'data':None,
                'isShowToaster':False,'message':None}),200)
        elif status=='success':
            return make_response(jsonify({'status_code':200,'status':'success',
                'data':pre_crawl,
                'isShowToaster':False,'message':None}),200)
    elif request.method.upper()=='POST':
        user_input=dict()
        user_input['store_type']=request.form['store_type']
        if request.form['store_type']=='burp_xml':
            user_input['file']=request.files['file']
        elif request.form['store_type']=='manual':
            user_input['state']=request.form['state']

        status,pre_crawl=svc.WAS().application_pre_crawl(authorization_token=request.headers['Authorization'],
            remote_address=request.remote_addr,application_id=application_id,
            method=request.method,user_input=user_input)
    elif request.method.upper()=='PUT':
        status,pre_crawl=svc.WAS().application_pre_crawl(authorization_token=request.headers['Authorization'],
            remote_address=request.remote_addr,application_id=application_id,
            method=request.method,user_input=request.args)
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='success':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':pre_crawl,
            'isShowToaster':False,'message':None}),200)
    elif status=='insert_success' or status=='update_success':
        return make_response(jsonify({'status_code':201,'status':'success',
            'data':None,
            'isShowToaster':False,'message':'Application pre-crawl store updated successfully'}),201)
    elif status=='burp_xml_instantiated':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':pre_crawl,
            'isShowToaster':True,'message':'Burp-XML pre-crawl instantiated successfully'}),200)
    elif status=='manual_instantiated':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':pre_crawl,
            'isShowToaster':True,'message':'Manual pre-crawl instantiated successfully'}),200)
    elif status=='terminate_success':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':None,
            'isShowToaster':True,'message':'Manual pre-crawl terminated successfully'}),200)
    elif status=='updates_not_available':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'No new URLs found'}),200)
    elif status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='file_not_found':
        abort(412,description=status)
    elif status=='file_not_supported':
        abort(417,description=status)
    else:
        return make_response(jsonify({'status_code':200,'status':status,
            'data':None,
            'isShowToaster':False,'message':None}),200)


@operations.route("/api/operations/application/<application_id>/pre_crawl/view",methods=['GET'],strict_slashes=False)
@cross_origin(supports_credentials=True)
def application_pre_crawl_view(application_id):
    user_input=dict()
    user_input['page_number']=int(request.args.get('page_number'))
    user_input['page_size']=int(request.args.get('page_size'))

    status,pre_crawl=svc.WAS().application_pre_crawl_view(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,user_input=user_input)
    # pre_crawl={"total":2,"urls":[{"attack_url":"/benchmark/0","exercisable_parameters":["test0_a","test0_b"],"parameters":{},"request_type":"POST","url_id":"url_0","user_agent":"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv"},
    #     {"attack_url":"/benchmark/6","exercisable_parameters":["test6_a","test6_b"],"parameters":{},"request_type":"POST","url_id":"url_6","user_agent":"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv"},{"attack_url":"/benchmark/9","exercisable_parameters":["test9_a","test9_b"],"parameters":{},"request_type":"POST","url_id":"url_9","user_agent":"Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv"}]}
    # status='success'
    if status=='success' or status==[]:
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':pre_crawl,
            'isShowToaster':False,'message':None}),200)
    else:
        abort(500,description=status)


@operations.route("/api/operations/application/<application_id>/payload_policy",methods=['GET','POST'])
@cross_origin(supports_credentials=True)
def application_payload_policy(application_id):
    status,policy=svc.WAS().application_payload_policy(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,
        method=request.method,user_input=request.args)
    if status=='success' and policy:
        if policy:
            return make_response(jsonify({'status_code':200,'status':status,
                'data':policy,
                'isShowToaster':False,'message':None}),200)
    elif status=='insert_success' or status=='update_success':
        return make_response(jsonify({'status_code':201,'status':'success',
            'data':None,
            'isShowToaster':False,'message':'Application payload policy updated successfully'}),201)
    elif status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='field_not_found' and policy is None:
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':None,
            'isShowToaster':False,'message':policy}),200)
    elif status=='document_not_found' and policy is None:
        return make_response(jsonify({'status_code':202,'status':status,
            'data':None,
            'isShowToaster':False,'message':policy}),202)
    elif status=='connection_error':
        abort(500)


@operations.route("/api/operations/crawl",methods=['GET'])
@cross_origin(supports_credentials=True)
def crawl():
    user_input=dict()
    user_input['sort_by']=request.args.get('sort_by')
    user_input['sort_order']=request.args.get('sort_order')
    user_input['search_text']=request.args.get('search_text')
    user_input['filter_text']=request.args.get('filter_text')
    user_input['page_number']=int(request.args.get('page_number'))
    user_input['page_size']=int(request.args.get('page_size'))

    status,apps=svc.WAS().crawl(authorization_token=request.headers['Authorization'],remote_address=request.remote_addr,
        method=request.method,user_input=user_input,address=request.remote_addr)

    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='applications_not_found':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':{},
            'isShowToaster':True,'message':'Applications not found in database'}),200)
    elif status=='success':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':apps,
            'isShowToaster':False,'message':None}),200)
    elif status is None:
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':None,
            'isShowToaster':False,'message':None}),200)


@operations.route("/api/operations/crawl/<application_id>/instantiate",methods=['POST'])
@cross_origin(supports_credentials=True)
def crawl_instantiate(application_id):
    status,state=svc.WAS().crawl(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,method=request.method,user_input=request.args,
        request_state='instantiate')
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='instantiated':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'Application crawl instantiated successfully'}),200)
    elif status=='create_success':
        return make_response(jsonify({'status_code':201,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'URL store created successfully'}),201)
    elif status=='url_store_update_success':
        return make_response(jsonify({'status_code':201,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'URL store updated successfully'}),201)
    elif status=='url_store_replace_success':
        return make_response(jsonify({'status_code':201,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'URL store replaced successfully'}),201)
    elif status=='document_not_found':
        return make_response(jsonify({'status_code':400,'status':'failure',
            'data':None,
            'isShowToaster':True,'message':'Applications not available in Was database'}),400)


@operations.route("/api/operations/crawl/<application_id>/pause",methods=['POST'])
@cross_origin(supports_credentials=True)
def crawl_pause(application_id):
    status,state=svc.WAS().crawl(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,method=request.method,request_state='pause')
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='paused':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'Application crawl paused successfully'}),200)
    elif status=='update_success' or status=='insert_success':
        return make_response(jsonify({'status_code':201,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'URL store generated successfully'}),201)


@operations.route("/api/operations/crawl/<application_id>/resume",methods=['POST'])
@cross_origin(supports_credentials=True)
def crawl_resume(application_id):
    status,state=svc.WAS().crawl(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,method=request.method,request_state='resume')
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='resume':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'Application crawl resumed successfully'}),200)
    elif status=='update_success' or status=='insert_success':
        return make_response(jsonify({'status_code':201,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'URL store generated successfully'}),201)


@operations.route("/api/operations/crawl/<application_id>/terminate",methods=['POST'])
@cross_origin(supports_credentials=True)
def crawl_terminate(application_id):
    status,state=svc.WAS().crawl(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,method=request.method,
        request_state='terminate')
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='terminated':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'Application crawl terminated successfully'}),200)
    elif status=='update_success' or status=='insert_success':
        return make_response(jsonify({'status_code':201,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'URL store generated successfully'}),201)


@operations.route("/api/operations/crawl/<application_id>/status",methods=['GET'])
@cross_origin(supports_credentials=True)
def crawl_status(application_id):
    status,state=svc.WAS().crawl(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,method=request.method,request_state='status')
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='success':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':state,
            'isShowToaster':False,'message':None}),200)
    elif status=='update_success' or status=='insert_success':
        return make_response(jsonify({'status_code':201,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'URL store generated successfully'}),201)


@operations.route("/api/operations/crawl/<application_id>/progress",methods=['GET'])
@cross_origin(supports_credentials=True)
def crawl_progress(application_id):
    status,state=svc.WAS().crawl(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,method=request.method,request_state='progress')

    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='success':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':state,
            'isShowToaster':False,'message':None}),200)


@operations.route("/api/operations/crawl/status_progress",methods=['GET'])
@cross_origin(supports_credentials=True)
def crawl_status_progress():
    status,progress=svc.WAS().crawl(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,method=request.method,request_state='status_progress')
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)

    elif status=='status_progress_success':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':progress,
            'isShowToaster':False,'message':None}),200)
    elif status=='applications_not_available':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':{},
            'isShowToaster':True,'message':'Applications not getting crawled'}),200)


@operations.route("/api/operations/crawl/<application_id>/verify_authentication",methods=['POST'])
@cross_origin(supports_credentials=True)
def crawl_application_authentication(application_id):
    status,crawl=svc.WAS().crawl_verify_authentication(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,user_input=request.args)
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description='WAS user authorization token is invalid')
    elif status=='application_authentication_revalidated':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':crawl,
            'isShowToaster':True,'message':'Application authentication successfully revalidated'}),200)


@operations.route("/api/operations/crawl/<application_id>/logs",methods=['GET'])
@cross_origin(supports_credentials=True)
def crawl_log(application_id):
    user_input=dict()
    user_input['lines']=request.args.get('lines')
    user_input['level']=request.args.get('level')
    user_input['download']=request.args.get('download')
    status,log=svc.WAS().crawl(authorization_token=request.headers['Authorization'],remote_address=request.remote_addr,
        application_id=application_id,method=request.method,user_input=user_input,
        request_state='logs')

    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='success' and not user_input['download']:
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':log,
            'isShowToaster':False,'message':None}),200)
    elif status=='success' and user_input['download']:
        return send_file(log['logs'],attachment_filename='attack.log')


@operations.route("/api/operations/crawl/<application_id>/url_store",methods=['GET'],strict_slashes=False)
@cross_origin(supports_credentials=True)
def crawl_url_store(application_id):
    user_input=dict()
    user_input['page_number']=int(request.args.get('page_number'))
    user_input['page_size']=int(request.args.get('page_size'))

    status,url_store=svc.WAS().crawl_url_store(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,
        method=request.method,user_input=user_input)
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='success':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':url_store,
            'isShowToaster':False,'message':None}),200)
    elif status=='document_not_found':
        return make_response(jsonify({'status_code':400,'status':'failure',
            'data':None,
            'isShowToaster':True,'message':'Applications not available in Was database'}),400)

@operations.route("/api/operations/attack",methods=['GET'])
@cross_origin(supports_credentials=True)
def attack():
    user_input=dict()
    user_input['sort_by']=request.args.get('sort_by')
    user_input['sort_order']=request.args.get('sort_order')
    user_input['search_text']=request.args.get('search_text')
    user_input['filter_text']=request.args.get('filter_text')
    user_input['page_number']=int(request.args.get('page_number'))
    user_input['page_size']=int(request.args.get('page_size'))

    status,apps=svc.WAS().attack(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,method=request.method,user_input=user_input,address=request.remote_addr)
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='applications_not_found':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':{},
            'isShowToaster':True,'message':'Applications not found in database'}),200)
    elif status=='success':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':apps,
            'isShowToaster':False,'message':None}),200)
    elif status is None:
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':None,
            'isShowToaster':False,'message':None}),200)
    elif status=='application_not_attacked':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':None,
            'isShowToaster':False,'message':None}),200)
    elif status=='application_not_available':
        return make_response(jsonify({'status_code':10002,'status':status,
            'data':None,
            'isShowToaster':True,'message':'Application not available in CMS'}),404)
    elif status=='services_not_found':
        return make_response(jsonify({'status_code':10003,'status':status,
            'data':None,
            'isShowToaster':True,'message':'Application services not available in database'}),404)


@operations.route("/api/operations/attack/<application_id>",methods=['POST'])
@cross_origin(supports_credentials=True)
def attack_application(application_id):
    status,attack=svc.WAS().attack_application(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,
        user_input=request.args)
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description='WAS user authorization token is invalid')
    elif status=='application_updated':
        return make_response(jsonify({'status_code':201,'status':'success',
            'data':attack,
            'isShowToaster':True,'message':'Attack configurations updated successfully'}),201)


@operations.route("/api/operations/attack/<application_id>/verify_authentication",methods=['POST'])
@cross_origin(supports_credentials=True)
def attack_application_authentication(application_id):
    status,attack=svc.WAS().attack_verify_authentication(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,user_input=request.args)
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description='WAS user authorization token is invalid')
    elif status=='application_authentication_revalidated':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':attack,
            'isShowToaster':True,'message':'Application authentication successfully revalidated'}),200)


@operations.route("/api/operations/attack/<application_id>/url_store",methods=['GET'],strict_slashes=False)
@cross_origin(supports_credentials=True)
def attack_url_store(application_id):
    user_input=dict()
    user_input['page_number']=int(request.args.get('page_number'))
    user_input['page_size']=int(request.args.get('page_size'))

    status,url_store=svc.WAS().attack_store(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,
        method=request.method,user_input=user_input,
        request_state='url_store')
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description='WAS user authorization token is invalid')
    elif status=='success':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':url_store,
            'isShowToaster':False,'message':None}),200)
    elif status=='document_not_found':
        return make_response(jsonify({'status_code':400,'status':'failure',
            'data':None,
            'isShowToaster':True,'message':'Applications not available in Was database'}),400)

@operations.route("/api/operations/attack/<application_id>/instantiate",methods=['POST'])
@cross_origin(supports_credentials=True)
def attack_instantiate(application_id):
    status,state=svc.WAS().attack(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,method=request.method,
        request_state='instantiate')
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='instantiated':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'Application attack instantiated successfully'}),200)
    elif status == 'crawl_not_instantiated':
        return make_response(jsonify({'status_code':200,'status':'success','data':None,
              'isShowToaster':True,'message':"Attack Can't be instantiate as crawl is in progress"
           }),200)
    elif status=='update_success' or status=='insert_success':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'Application attack completed successfully'}),200)
    elif status=='document_not_found':
        return make_response(jsonify({'status_code':400,'status':'failure',
        'data':None,
        'isShowToaster':True,'message':'Applications not available in Was database'}),400)


@operations.route("/api/operations/attack/<application_id>/pause",methods=['POST'])
@cross_origin(supports_credentials=True)
def attack_pause(application_id):
    status,state=svc.WAS().attack(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,method=request.method,request_state='pause')
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='paused':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'Application attack paused successfully'}),200)


@operations.route("/api/operations/attack/<application_id>/resume",methods=['POST'])
@cross_origin(supports_credentials=True)
def attack_resume(application_id):
    status,state=svc.WAS().attack(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,method=request.method,request_state='resume')
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='resumed':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':None,
            'isShowToaster':True,'message':'Application attack resumed successfully'}),200)


@operations.route("/api/operations/attack/<application_id>/terminate",methods=['POST'])
@cross_origin(supports_credentials=True)
def attack_terminate(application_id):
    status,state=svc.WAS().attack(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,method=request.method,
        request_state='terminate')
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='terminated':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':state,
            'isShowToaster':True,'message':'Application attack terminated successfully'}),200)


@operations.route("/api/operations/attack/<application_id>/status",methods=['GET'])
@cross_origin(supports_credentials=True)
def attack_status(application_id):
    status,state=svc.WAS().attack(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,
        method=request.method,request_state='status')
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='success':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':state,
            'isShowToaster':False,'message':None}),200)


@operations.route("/api/operations/attack/<application_id>/progress",methods=['GET'])
@cross_origin(supports_credentials=True)
def attack_progress(application_id):
    status,state=svc.WAS().attack(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,application_id=application_id,method=request.method,request_state='progress')

    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='success':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':state,
            'isShowToaster':False,'message':None}),200)


@operations.route("/api/operations/attack/status_progress",methods=['GET'])
@cross_origin(supports_credentials=True)
def attack_status_progress():
    status,progress=svc.WAS().attack(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,method=request.method,request_state='status_progress')
    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='status_progress_success':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':progress,
            'isShowToaster':False,'message':None}),200)
    elif status=='applications_not_available':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':{},
            'isShowToaster':True,'message':'Applications not getting attacked'}),200)


@operations.route("/api/operations/attack/<application_id>/logs",methods=['GET'])
@cross_origin(supports_credentials=True)
def attack_log(application_id):
    user_input=dict()
    user_input['lines']=request.args.get('lines')
    user_input['level']=request.args.get('level')
    user_input['download']=request.args.get('download')
    status,log=svc.WAS().attack(authorization_token=request.headers['Authorization'],remote_address=request.remote_addr,
        application_id=application_id,method=request.method,user_input=user_input,
        request_state='logs')

    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='success' and not user_input['download']:
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':log,
            'isShowToaster':False,'message':None}),200)
    elif status=='success' and user_input['download']:
        return send_file(log['logs'],attachment_filename='attack.log')


@operations.route("/api/application/attack/<application_id>/status",methods=['GET'])
@cross_origin(supports_credentials=True)
def application_cms_status_api(application_id):
    status=svc.WAS().attack_application_status(authorization_token=request.headers['Authorization'],
                                               remote_address=request.remote_addr,
                                               application_id=application_id)
    if isinstance(status, dict):
        if status['status'] in ['unauthorized','token_invalid']:
            abort(401,description=status['status'])
        elif status['status'] == 'success':
            return make_response(jsonify({'status_code':200,'status':'success',
                'data':status['message'],
                'isShowToaster':False,'message':''}),200)
        else:
            return make_response(jsonify({'status_code':400,'status':status['status'],
                'data':None,
                'isShowToaster':False,'message':status['message']}),400)
               
@operations.route("/api/operations/report/<report_id>",methods=['GET'])  #ajchg
@cross_origin(supports_credentials=True)
def report_download(report_id):
    # user_input = dict()
    # user_input['page_number'] = request.args.get('page_number')
    # user_input['page_size'] = request.args.get('page_size')
    # if len(user_input['page_number'])>0 :
    #     status, apps = svc.WAS().report_compensating_control(authorization_token=request.headers['Authorization'],
    #                                       remote_address=request.remote_addr, report_id=report_id,method=request.method, user_input=user_input)
    # else:
    status,apps=svc.WAS().report_download(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,report_id=report_id)

    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='success':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':apps,
            'isShowToaster':False,'message':None}),200)
    elif status=='report_not_found':
        return make_response(jsonify({'status_code':400,'status':'failure',
        'data':None,
        'isShowToaster':True,'message':'Report is not available to be downloaded'}),400)

@operations.route("/api/operations/reports",methods=['GET'])  #ajchg
@cross_origin(supports_credentials=True)
def reports():
    user_input=dict()
    user_input['sort_by']=request.args.get('sort_by')
    user_input['sort_order']=request.args.get('sort_order')
    user_input['search_text']=request.args.get('search_text')
    user_input['filter_text']=request.args.get('filter_text')
    user_input['page_number']=int(request.args.get('page_number'))
    user_input['page_size']=int(request.args.get('page_size'))
    status,apps=svc.WAS().reports(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,user_input=user_input)

    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=="documents_not_found":
        #abort(500, description="Reports not found")
        return make_response(jsonify({'status_code':200,'status':status,
            'data':"documents_not_found",
            'isShowToaster':False,'message':"documents_not_found"}),200)
    elif status=='success':
        # if apps is None:
        #     return make_response(jsonify({'status_code': 200, 'status': status,
        #                                 'data': None,
        #                                 'isShowToaster': False, 'message': None}), 200)
        return make_response(jsonify({'status_code':200,'status':status,
            'data':apps,
            'isShowToaster':False,'message':None}),200)


@operations.route("/api/operations/report/<report_id>/cc",methods=['GET'])
@cross_origin(supports_credentials=True)
def report_compensating_control(report_id):
    user_input=dict()
    user_input['page_number']=int(request.args.get('page_number'))
    user_input['page_size']=int(request.args.get('page_size'))
    status,apps=svc.WAS().report_compensating_control(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,report_id=report_id,method=request.method,user_input=user_input)

    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='success':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':apps,
            'isShowToaster':False,'message':None}),200)


@operations.route("/api/operations/report/<report_id>/cc",methods=['POST'])
@cross_origin(supports_credentials=True)
def download_report_compensating_control(report_id):
    user_input=dict()
    user_input=request.args.get('compensating_control')
    status,apps=svc.WAS().report_compensating_control(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,report_id=report_id,method=request.method,user_input=user_input)

    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='success':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':apps,
            'isShowToaster':False,'message':None}),200)


@operations.route("/api/operations/logout",methods=['POST'])
@cross_origin(supports_credentials=True)
def logout():
    status=svc.WAS().logout(authorization_token=request.headers['Authorization'],remote_address=request.remote_addr)
    if status=='success':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':None,
            'isShowToaster':True,'message':'User logout successful'}))
    elif status is None:
        abort(204)

    elif status=='unauthorized':
        abort(401)

    elif status=='failure':
        return make_response(jsonify({'status_code':202,'status':status,
            'data':None,
            'isShowToaster':True,'message':'User could not create successfully'}),202)

    elif status=='connection_error':
        return 1001


@operations.route("/api/operations/applications_status_check",methods=['GET'])
@cross_origin(supports_credentials=True)
def pool_application_status():
    content=None
    data=[]
    status,progress=svc.WAS().application_status(
        authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,
        method=request.method,
        request_state='application_status')
    if isinstance(progress,list):
        data=progress
    else:
        content=progress
    return make_response(jsonify({'status_code':status,'status':None,
        'data':data,
        'isShowToaster':True,'message':content}),status)


@operations.route("/api/operations/application/<application_id>/clear_data",methods=['DELETE'])
@cross_origin(supports_credentials=True)
def clear_application(application_id):
    status,authentication=svc.WAS().clear_application_data(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,method=request.method,
        application_id=application_id)
    if status=='url_store_available':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':authentication,
            'isShowToaster':True,'message':'URL store already generated by this user'}),200)
    elif status=='url_store_not_available':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':authentication,
            'isShowToaster':True,'message':'URL store is not generated by this user'}),200)
    elif status=='application_data_reseted':
        return make_response(jsonify({'status_code':201,'status':status,
            'data':authentication,
            'isShowToaster':True,'message':"Application details deleted successfully"}),201)
    else:
        abort(404,description=status)