# -*- coding: utf-8 -*-
# Generated by Django 1.9.11 on 2016-11-29 00:28
from __future__ import unicode_literals

import environ

from django.core.management import call_command
from django.core.serializers import base, python
from django.db import migrations


def load_bootstrap_fixture(apps, schema_editor):
    """
    Loads the bootstrap fixture, using models generated from the migration state, rather than from
    current model code.
    """
    # re-define the _get_model function, using argument apps in closure
    # code copied verbatim from django.core.serializers.python
    def _get_model(model_identifier):
        try:
            return apps.get_model(model_identifier)
        except (LookupError, TypeError):
            raise base.DeserializationError("Invalid model identifier: '%s'" % model_identifier)
    # save function we are going to monkey-patch
    backup = python._get_model
    # monkey-patch
    python._get_model = _get_model
    # load bootstrap fixture
    call_command('loaddata', 'bootstrap.json', app_label='main')
    # revert monkey-patch
    python._get_model = backup


def set_default_site(apps, schema_editor):
    """
    Changes the default site from example.com to whatever is in VIRTUAL_HOST environment.
    """
    Site = apps.get_model('sites', 'Site')
    env = environ.Env()
    domain = env('VIRTUAL_HOST', default='localhost')
    domain = domain.split(',')[-1]  # use the last if a comma-delimited list
    Site.objects.create(domain=domain, name='EDD')


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0001_edd-schema-init'),
        ('profile', '0002_auto_20150729_1523'),
        ('sites', '0002_alter_domain_unique'),
    ]

    operations = [
        migrations.RunPython(code=load_bootstrap_fixture, reverse_code=migrations.RunPython.noop),
        migrations.RunPython(code=set_default_site, reverse_code=migrations.RunPython.noop),
    ]
