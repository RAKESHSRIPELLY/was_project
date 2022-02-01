__author__='JG'

from flask import Blueprint,request,abort,make_response,jsonify
from webapp import services as svc
from flask_cors import CORS,cross_origin

dashboard=Blueprint('dashboard',__name__)


@dashboard.route("/api/dashboard",methods=['GET'])
@cross_origin(supports_credentials=True)
def board():
    user_input=dict()
    user_input['widget']=request.args.get('widget')
    user_input['application']=request.args.get('application')
    user_input['applications_not_scanned_age']=request.args.get('applications_not_scanned_age')
    user_input['applications_not_scanned_buffer']=request.args.get('applications_not_scanned_buffer')
    user_input['vulnerabilities_by_scan_from']=request.args.get('vulnerabilities_by_scan_from')
    user_input['vulnerabilities_by_scan_to']=request.args.get('vulnerabilities_by_scan_to')
    user_input['filter']=request.args.get('filter')
    status,detail=svc.WAS().dashboard(authorization_token=request.headers['Authorization'],
        remote_address=request.remote_addr,
        user_input=user_input)

    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    if status=='data_not_available':
        return make_response(jsonify({'status_code':404,'status':'failure',
            'data':None,
            'isShowToaster':True,'message':'Data not found'}),404)
    if status=='success':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':detail,
            'isShowToaster':False,'message':None}),200)


@dashboard.route("/api/notification",methods=['GET','POST','DELETE'])
@cross_origin(supports_credentials=True)
def notify():
    if request.method=='GET':
        user_input=dict()
        user_input['check']=request.args.get('check')
        status,data=svc.WAS().notification(authorization_token=request.headers['Authorization'],
            remote_address=request.remote_addr,
            method=request.method,user_input=user_input)
    elif request.method=='POST' or request.method=='DELETE':
        status,data=svc.WAS().notification(authorization_token=request.headers['Authorization'],
            remote_address=request.remote_addr,
            method=request.method,user_input=request.args)

    if status=='unauthorized' or status=='token_invalid':
        abort(401,description=status)
    elif status=='success':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':data,
            'isShowToaster':True,'message':'Notifications sent successfully'}),200)
    elif status=='available':
        return make_response(jsonify({'status_code':200,'status':status,
            'data':data,
            'isShowToaster':True,'message':'Notifications available'}),200)
    elif status=='notification_read':
        return make_response(jsonify({'status_code':201,'status':status,
            'data':data,
            'isShowToaster':True,'message':'Notification read successfully'}),201)
    elif status=='notifications_read':
        return make_response(jsonify({'status_code':201,'status':status,
            'data':data,
            'isShowToaster':True,'message':'Notifications read successfully'}),201)
    elif status=='notification_deleted':
        return make_response(jsonify({'status_code':201,'status':status,
            'data':data,
            'isShowToaster':True,'message':'Notification deleted successfully'}),201)
    elif status=='notifications_deleted':
        return make_response(jsonify({'status_code':201,'status':status,
            'data':data,
            'isShowToaster':True,'message':'Notifications deleted successfully'}),201)
    elif status=='notifications_not_available':
        return make_response(jsonify({'status_code':200,'status':'success',
            'data':data,
            'isShowToaster':True,'message':'Notifications not available'}),200)