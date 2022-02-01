__author__='JG'

from flask import Flask
from lib import utility as util
import traceback
import os
from dotenv import load_dotenv

#env_path = join(dirname(__file__) + '/..', 'was.env')
env_path='../was.env'
load_dotenv(env_path)

log=util.Log()


def initiate_webapp(host,deployment):
    try:
        app=Flask(__name__)

        from webapp.operations.routes import operations
        from webapp.configurations.routes import configurations
        from webapp.dashboard.routes import dashboard
        from webapp.notification.routes import notification
        from webapp.errors.routes import errors
        from flask_cors import CORS

        app.register_blueprint(operations)
        app.register_blueprint(configurations)
        app.register_blueprint(dashboard)
        app.register_blueprint(notification)
        app.register_blueprint(errors)

        if deployment=='development':
            log.debug(f"Initializing WAS application program interface service in development environment on {host}")
            # try:
            #     os.system('./mitmdump -s /home/virsec/uploadLog.py') #os. ./mitmdump -s uploaderLog.py
            # except Exception as err:
            #     log.debug(f"{err}")

            app.run(host=host,port=int(os.environ['PORT']),debug=True,threaded=True,use_reloader=False)

    except Exception as err:
        print(err)
    except RuntimeError as err:
        log.error(err)
        traceback.print_stack()
        return 'runtime_error'





