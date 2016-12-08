# coding: utf-8
"""
Defines the client-side Celery "app" (API instance) used by EDD to asynchronously execute tasks on
the Celery cluster.
"""

from __future__ import absolute_import, unicode_literals

import os

from celery import Celery
from kombu.serialization import register

from . import utilities

# Ensure that there is at least a default settings module configured, using EDD settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'edd.settings')

from django.conf import settings  # noqa


###################################################################################################
# Register custom serialization code to allow us to serialize datetime objects as JSON (just
# datetimes, for starters). Used by Celery tasks to serialize dates.
###################################################################################################
EDD_SERIALIZE_NAME = 'edd-json'
register(
    name=EDD_SERIALIZE_NAME,
    encoder=utilities.JSONEncoder.dumps,
    decoder=utilities.JSONDecoder.loads,
    content_type='application/x-edd-json',
    content_encoding='UTF-8',
)

# set up a Celery "app" for use by EDD. A Celery "app" is just an unfortunately-named instance of
# the Celery API,
# This instance defines EDD's interface with Celery.
task_exchange = Celery('edd', broker=settings.BROKER_URL)
task_exchange.config_from_object(settings)


if __name__ == '__main__':
    task_exchange.start()
