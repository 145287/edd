
import rest_framework.routers as rest_routers
import rest_framework_nested.routers as nested_routers
from django.conf.urls import include, url

from jbei.rest.clients.edd.constants import (LINES_RESOURCE_NAME, MEASUREMENTS_RESOURCE_NAME,
                                             METADATA_GROUPS_RESOURCE_NAME,
                                             METADATA_TYPES_RESOURCE_NAME, SEARCH_RESOURCE_NAME,
                                             STRAINS_RESOURCE_NAME, STUDIES_RESOURCE_NAME,
                                             VALUES_RESOURCE_NAME)
from views import schema_view
from .views import (AssaysViewSet, LinesView, MeasurementUnitViewSet, MeasurementsViewSet,
                    MeasurementValuesViewSet, MetadataGroupViewSet, MetadataTypeViewSet,
                    ProtocolViewSet, SearchViewSet, StrainStudiesView,
                    StrainViewSet, StudyViewSet, _STRAIN_NESTED_RESOURCE_PARENT_PREFIX)

###################################################################################################
# Define a router for base REST API methods & views
###################################################################################################
base_rest_api_router = rest_routers.DefaultRouter()
base_rest_api_router.register(SEARCH_RESOURCE_NAME, SearchViewSet, 'search')
# base_rest_api_router.register(LINES_RESOURCE_NAME, SearchLinesViewSet)
base_rest_api_router.register(STUDIES_RESOURCE_NAME, StudyViewSet, STUDIES_RESOURCE_NAME)
base_rest_api_router.register(STRAINS_RESOURCE_NAME, StrainViewSet, STRAINS_RESOURCE_NAME)
base_rest_api_router.register(r'measurement_units', MeasurementUnitViewSet, 'measurement_units')
base_rest_api_router.register(METADATA_TYPES_RESOURCE_NAME, MetadataTypeViewSet, 'metadata_type')
base_rest_api_router.register(METADATA_GROUPS_RESOURCE_NAME, MetadataGroupViewSet)
base_rest_api_router.register(r'protocols', ProtocolViewSet)

###################################################################################################
# /rest/studies nested routers
###################################################################################################
study_router = nested_routers.NestedSimpleRouter(base_rest_api_router,
                                                 STUDIES_RESOURCE_NAME, lookup='study')
study_router.register(LINES_RESOURCE_NAME, LinesView, base_name='study-lines')
# study_nested_resources_router.register(STRAINS_RESOURCE_NAME, StudyStrainsView,
#                                        base_name='study-strains')

study_lines_router = nested_routers.NestedSimpleRouter(study_router,
                                                       LINES_RESOURCE_NAME, lookup='line')
study_lines_router.register(r'assays', AssaysViewSet, base_name='assay')

study_assays_router = nested_routers.NestedSimpleRouter(study_lines_router, 'assays',
    lookup='assay')
study_assays_router.register(MEASUREMENTS_RESOURCE_NAME, MeasurementsViewSet,
                             base_name='measurements')

study_measurements_router = nested_routers.NestedSimpleRouter(study_assays_router,
                                                              MEASUREMENTS_RESOURCE_NAME,
                                                              lookup='measurement')
study_measurements_router.register(VALUES_RESOURCE_NAME, MeasurementValuesViewSet,
                                   base_name='values')

# measurements_router = nested_routers.NestedSimpleRouter(study_assays_router, 'values',
#     lookup='values')

###################################################################################################
# /rest/strains nested router
###################################################################################################
strain_nested_resources_router = (
    nested_routers.NestedSimpleRouter(base_rest_api_router, _STRAIN_NESTED_RESOURCE_PARENT_PREFIX,
                                      lookup='strains'))
strain_nested_resources_router.register(STUDIES_RESOURCE_NAME, StrainStudiesView,
                                        base_name='strain-studies')

###################################################################################################
# Use routers & supporting frameworks to construct URL patterns
###################################################################################################
urlpatterns = [
    # url(r'docs/$', include('rest_framework_swagger.urls')),

    url(r'^', include(base_rest_api_router.urls)),
    url(r'^', include(study_router.urls)),
    url(r'', include(study_lines_router.urls)),
    url(r'', include(study_assays_router.urls)),
    url(r'', include(study_measurements_router.urls)),
    url(r'^', include(strain_nested_resources_router.urls)),
    url(r'^', include('rest_framework.urls', namespace='rest_framework')),
    url(r'docs/', schema_view),


]
