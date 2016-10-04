
from django.conf.urls import include, url
import rest_framework.routers as rest_routers

from jbei.rest.clients.edd.constants import (STRAINS_RESOURCE_NAME, STUDIES_RESOURCE_NAME,
    METADATA_TYPES_RESOURCE_NAME, METADATA_GROUPS_RESOURCE_NAME, LINES_RESOURCE_NAME)
from .views import (LineViewSet, MetadataGroupViewSet, MetadataTypeViewSet,
                    STRAIN_NESTED_RESOURCE_PARENT_PREFIX, StrainStudiesView, StrainViewSet,
                    StudyLineView, StudyStrainsView, StudyViewSet)
import rest_framework_nested.routers as nested_routers
from views import schema_view



####################################################################################################
# Define a router for base REST API methods & views
####################################################################################################
base_rest_api_router = rest_routers.DefaultRouter()
base_rest_api_router.register(LINES_RESOURCE_NAME, LineViewSet)
base_rest_api_router.register(STUDIES_RESOURCE_NAME, StudyViewSet, STUDIES_RESOURCE_NAME)
base_rest_api_router.register(STRAINS_RESOURCE_NAME, StrainViewSet, STRAINS_RESOURCE_NAME)
base_rest_api_router.register(METADATA_TYPES_RESOURCE_NAME, MetadataTypeViewSet)
base_rest_api_router.register(METADATA_GROUPS_RESOURCE_NAME, MetadataGroupViewSet)

####################################################################################################
# /rest/studies nested router
####################################################################################################
study_nested_resources_router = nested_routers.NestedSimpleRouter(base_rest_api_router,
                                                                  STUDIES_RESOURCE_NAME,
                                                                  lookup='studies')
study_nested_resources_router.register(LINES_RESOURCE_NAME, StudyLineView,
                                       base_name='study-lines')
study_nested_resources_router.register(STRAINS_RESOURCE_NAME, StudyStrainsView,
                                       base_name='study-strains')

####################################################################################################
# /rest/strains nested router
####################################################################################################
strain_nested_resources_router = (
    nested_routers.NestedSimpleRouter(base_rest_api_router, STRAIN_NESTED_RESOURCE_PARENT_PREFIX,
                                      lookup='strains'))
strain_nested_resources_router.register(STUDIES_RESOURCE_NAME, StrainStudiesView,
                                        base_name='strain-studies')

####################################################################################################
# Use routers & supporting frameworks to construct URL patterns
####################################################################################################
urlpatterns = [
    url(r'', include(base_rest_api_router.urls)),
    url(r'', include(study_nested_resources_router.urls)),
    url(r'', include(strain_nested_resources_router.urls)),
    url(r'', include('rest_framework.urls', namespace='rest_framework')),
    url(r'docs/', schema_view),
]
