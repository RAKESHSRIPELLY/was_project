__author__ = 'JG'

from flask import Blueprint, request, abort, make_response, jsonify, Response
from webapp import services as svc

notification = Blueprint('notification', __name__)

@notification.route("/notification")
def notify():
    pass