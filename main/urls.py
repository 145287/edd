# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf.urls import include, url
from django.contrib.auth.decorators import login_required
from django.contrib.staticfiles.storage import staticfiles_storage
from django.http import HttpResponse
from django.views.generic.base import RedirectView
from django.contrib.flatpages import views
from edd.branding.views import favicon

from main import autocomplete, views


# These are the URL endpoints nested under a link to a specific Study, for use with include() in
#   the two URL paths for study below. Because this list is included twice, there should be no
#   URL with the name kwarg here, as that will result in conflicts looking up URLs by name.
study_url_patterns = [
    url(r'^assaydata/$', login_required(views.study_assay_table_data)),
    url(r'^edddata/$', login_required(views.study_edddata)),
    url(
        # NOTE: leaving off the $ end-of-string regex is important! Further matching in include()
        r'^measurements/(?P<protocol>\d+)/',
        include([
            url(r'^$', login_required(views.study_measurements)),
            url(r'^(?P<assay>\d+)/$', login_required(views.study_assay_measurements)),
        ])
    ),
    url(r'^map/$', login_required(views.study_map)),
    url(r'^permissions/$', login_required(views.StudyPermissionJSONView.as_view())),
    url(r'^define/$', login_required(views.study_define)),
    url(
        # NOTE: leaving off the $ end-of-string regex is important! Further matching in include()
        r'^import/',
        include([
            url(r'^$', login_required(views.study_import_table)),
            # TODO these should be folded into the main import page at some point
            url(r'^rnaseq/$', login_required(views.study_import_rnaseq)),
            url(r'^rnaseq/parse/$', login_required(views.study_import_rnaseq_parse)),
            url(r'^rnaseq/process/$', login_required(views.study_import_rnaseq_process)),
            url(r'^rnaseq/edgepro/$', login_required(views.study_import_rnaseq_edgepro)),
        ])
    ),
    url(r'^experiment-description/$', login_required(autocomplete.search_study_lines)),
    url(r'^rename/$',
        login_required(views.StudyUpdateView.as_view(update_action='rename'))),
    url(r'^setdescription/$',
        login_required(views.StudyUpdateView.as_view(update_action='setdescription'))),
    url(r'^setcontact/$',
        login_required(views.StudyUpdateView.as_view(update_action='setcontact'))),
]

urlpatterns = [
    # "homepage" URLs
    url(r'^$', login_required(views.StudyIndexView.as_view()), name='index'),
    url(
        r'^study/$',
        login_required(views.StudyCreateView.as_view()),
        name='create_study'
    ),
    url(r'^study/study-search/$', login_required(views.study_search)),

    # Individual study-specific pages loaded by primary key
    url(
        # NOTE: leaving off the $ end-of-string regex is important! Further matching in include()
        r'^study/(?P<pk>\d+)/',
        include(
            [
                url(r'^$', login_required(views.StudyDetailView.as_view()), name='detail_by_pk', ),
                url(r'^experiment-description/$', login_required(views.StudyLinesView.as_view()), name='lines_by_pk', ),
                url(r'^overview/$', login_required(views.StudyOverviewView.as_view()), name='overview_by_pk', ),
            ] + study_url_patterns)
    ),
    # Individual study-specific pages loaded by slug
    url(
        # NOTE: leaving off the $ end-of-string regex is important! Further matching in include()
        r'^study/(?P<slug>[-\w]+)/',
        include(
            [url(r'^$', login_required(views.StudyDetailView.as_view()), name='detail', ),
             url(r'^experiment-description/$', login_required(views.StudyLinesView.as_view()), name='lines', ),
             url(r'^overview/$', login_required(views.StudyOverviewView.as_view()), name='overview', ),
             ] +
            study_url_patterns
        )
    ),

    # Individual study-specific pages loaded by slug
    url(
        # NOTE: leaving off the $ end-of-string regex is important! Further matching in include()
        r'^study/(?P<slug>[-\w]+)/overview',
        include(
            [url(r'^$', login_required(views.StudyOverviewView.as_view()), name='overview', )] +
            study_url_patterns
        )
    ),
    # "export" URLs
    url(r'^export/$', login_required(views.ExportView.as_view()), name='export'),
    url(r'^worklist/$', login_required(views.WorklistView.as_view()), name='worklist'),
    url(r'^sbml/$', login_required(views.SbmlView.as_view()), name='sbml'),

    # Miscellaneous URLs; most/all of these should eventually be delegated to REST API
    url(r'^file/download/(?P<file_id>\d+)/$', login_required(views.download)),
    # url(r'^file/delete/(?P<file_id>\d+)/$', login_required(views.delete_file)),
    url(r'^utilities/parsefile/$', login_required(views.utilities_parse_import_file)),
    url(r'^data/carbonsources/$', login_required(views.data_carbonsources)),
    url(r'^data/measurements/$', login_required(views.data_measurements)),
    url(r'^data/metadata/$', login_required(views.data_metadata)),
    url(r'^data/misc/$', login_required(views.data_misc)),
    url(r'^data/sbml/$', login_required(views.data_sbml)),
    url(r'^data/sbml/(?P<sbml_id>\d+)/$', login_required(views.data_sbml_info)),
    url(r'^data/sbml/(?P<sbml_id>\d+)/reactions/$', login_required(views.data_sbml_reactions)),
    url(r'^data/sbml/(?P<sbml_id>\d+)/reactions/(?P<rxn_id>.+)/$',
        login_required(views.data_sbml_reaction_species)),
    url(r'^data/strains/$', login_required(views.data_strains)),
    url(r'^data/users/$', login_required(views.data_users)),
    url(r'help/experiment_description/$', login_required(views.ExperimentDescriptionHelp.as_view()),
        name='experiment_description_help', ),
    url(r'^search/$', login_required(views.search)),
    url(r'^search/(?P<model>\w+)/$', login_required(views.model_search)),

    url(r'^health/$', lambda request: HttpResponse()),

    # Call-out for the favicon, which would normally only be accessible via a URL like:
    #   https://edd.example.org/static/favicon.ico
    # This way, browsers can load the favicon from the standard link.
    url(
        r'^favicon\.ico$',
        favicon,
        name='favicon'
    ),
    url(r'^pages/', include('django.contrib.flatpages.urls'))
]
