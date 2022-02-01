__author__ = 'JG'

import os
from config import was, environment as env
env.workspace = os.getcwd()
import execWAS
import logging
import argparse
import traceback
import tracemalloc


parser = argparse.ArgumentParser()
parser.add_argument('--executor', type=str, help='Test-suite executor', default='JG')
parser.add_argument('--was_app', type=str, help='Enable/Disable WAS web application', default='True')
parser.add_argument('--was', type=str, help='Enable/Disable WAS application', nargs='?')
parser.add_argument('--auto_deployment', type=str, help='Enable/Disable Auto Deployment', nargs='?')
parser.add_argument('--cache', type=str, help='Cache address', default='localhost')
parser.add_argument('--database', type=str, help='Database address', default='localhost')
parser.add_argument('--log', type=str, help='Set logging level', default='INFO')
parser.add_argument('--deployment', type=str, help='Enable/Disable Production/Development service', default='development')
parser.add_argument('--flush', type=str, help='Enable/Disable cache & database flush', default='False')
args = parser.parse_args()

logging.basicConfig(filename='artefacts/traces/execution.log',
                    format='%(asctime)s | %(levelname)s | %(name)s | %(message)s',
                    level=args.log.upper())
from lib import utility as util
log = util.Log()

if args.executor:
    log.debug(f"Service requested by {args.executor} for WAS-API: {args.was_app} with cache: {args.cache} & database: {args.database} and log-level: {args.log}")
    # was.was['cache'] = args.cache
    # was.was['database'] = args.database

    if args.was_app.lower() == 'true':
        try:
            if args.flush.lower() == 'true':
                from config import prerequisite
                prerequisite.prerequisite()

            ipv4_address = util.Network().get_ipv4()
            #ipv4_address = "0.0.0.0"

            try:
                # tracemalloc.start(10)
                status = execWAS.initiate_webapp(host='0.0.0.0', deployment=args.deployment)
                if status == 'runtime_error':
                    log.critical(f"WAS application program interface service encountered with errors")
            except:
                # snapshot = tracemalloc.take_snapshot()
                pass
        except EnvironmentError as err:
            log.error(err)
            traceback.print_stack()
    else:
        log.warning(f"Please enable 'WAS-App' with boolean value")
else:
    log.warning(f"Please enter the 'executor' to initiate the suite")
