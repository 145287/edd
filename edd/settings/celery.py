# -*- coding: utf-8 -*-
""" Celery-specific settings saved here. """

from datetime import timedelta
from edd_utils.parsers.json_encoders import EXTENDED_JSON_CONTENT_TYPE

from .base import env

# Defines whether or not EDD uses Celery.
USE_CELERY = False

###################################################################################################
# Configure email notifications for task errors
###################################################################################################

# controls initial retry warning email & subsequent failure/resolution message
CELERY_SEND_TASK_ERROR_EMAILS = True


####################################################################################################
# General settings for celery.
####################################################################################################
# Broker Settings
BROKER_URL = env('BROKER_URL')

CELERY_TASK_SERIALIZER = EXTENDED_JSON_CONTENT_TYPE
CELERY_RESULT_SERIALIZER = EXTENDED_JSON_CONTENT_TYPE

# CELERY_TIMEZONE='America/Los_Angeles' # Use UTC time to work around a Celery 3.1.18 bug
# that causes flower charts to always be blank -- see https://github.com/celery/celery/issues/2482

# Remove pickle from the transport list for forward-compatibility with Celery 3.2 (upcoming). Also
# avoids an error message in 3.1 mentioning this issue.
# Pickle transport is known to be insecure.
CELERY_ACCEPT_CONTENT = [EXTENDED_JSON_CONTENT_TYPE, 'json', 'msgpack', 'yaml']


####################################################################################################
# Routers and queues for EDD.
####################################################################################################

# A simplistic router that routes all Celery messages into the "edd" exchange, and from there onto
# the "edd" queue. This is essentially just allowing us flexibility to use the same RabbitMQ server
# to support multiple applications at JBEI. If needed, we can use more complex routing later to
# improve throughput for EDD.
class SingleQueueRouter(object):
    def route_for_task(self, task, args=None, kwargs=None):
        return {
            'exchange': 'edd',
            'exchange_type': 'fanout',
            'routing_key': 'edd',
        }


CELERY_ROUTES = (SingleQueueRouter(),)

# route all tasks to the edd queue unless specifically
# called out by CELERY_QUEUES
CELERY_DEFAULT_EXCHANGE = 'edd'
CELERY_DEFAULT_QUEUE = 'edd'
CELERY_DEFAULT_ROUTING_KEY = 'edd'


####################################################################################################
# Task configuration
####################################################################################################
# seconds after which a task is notified that it'll be killed soon (5 min)
CELERYD_TASK_SOFT_TIME_LIMIT = 270
# upper limit in seconds a run can take before host process is terminated (5 min 30 sec)
CELERYD_TASK_TIME_LIMIT = 300

# List of modules to import when celery worker starts.
# Note: alternatively, we could have Celery auto-discover all
# tasks in each reusable Django app, but at the cost of following
# the less descriptive naming convention 'tasks.py'
CELERY_IMPORTS = ('edd.remote_tasks',)


####################################################################################################
# Configure database backend to store task state and results
####################################################################################################
CELERY_RESULT_BACKEND = env('CELERY_RESULT_BACKEND')

# prevent errors due to database connection timeouts while traffic is relatively low.
# remove to drastically improve performance when throughput is higher
CELERY_RESULT_DB_SHORT_LIVED_SESSIONS = True

# initially keep task results for 30 days to enable some history inspection while load is low
CELERY_TASK_RESULT_EXPIRES = timedelta(days=30)


###################################################################################################
# EDD-specific configuration for Celery (NOT Celery-defined constants as in the rest of the file
###################################################################################################
# buffer around the final retry during which no warning emails will be sent
CELERY_MIN_WARNING_GRACE_PERIOD_MIN = 30

# Shared defaults for Celery communication with ICE. May be overridden on a task-by-task basis,
# depending on the processing being performed. These defaults are appropriate for simple ICE
# queries or data pushes that don't do a significant amount of processing, and execute quickly
# with each retry attempt. For help in configuring new defaults, run time_until_retry() or
# compute_exp_retry_delay() in celery_utils.py from the command line.

# seconds before first retry attempt. assumption is exponential backoff.
CELERY_INITIAL_ICE_RETRY_DELAY = 2
# ~= 14 seconds total wait after initial failure (execution+timeout are extra)
CELERY_WARN_AFTER_RETRY_NUM_FOR_ICE = 3
# ~= 2 weeks total wait...plenty of overhead for outages without intervention/data loss
CELERY_MAX_ICE_RETRIES = 19
