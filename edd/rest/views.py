"""
Defines the supported views and browseable API endpoint documentation for EDD's REST framework.

Assuming Django REST Framework (DRF) will be adopted in EDD, new and existing views should be
ported to this class over time. Many potential REST resources are currently defined in
main/views.py, but are not making use of DRF.
"""
from __future__ import unicode_literals

import json
import logging
import numbers
import re
from uuid import UUID

from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from rest_framework import mixins, response, schemas, status, viewsets
from rest_framework.decorators import api_view, renderer_classes
from rest_framework.exceptions import (APIException, NotAuthenticated, NotFound, ParseError,
                                       ValidationError)
from rest_framework.permissions import DjangoModelPermissions, IsAuthenticated
from rest_framework.relations import StringRelatedField
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet
from rest_framework_swagger.renderers import OpenAPIRenderer, SwaggerUIRenderer

from jbei.rest.clients.edd.constants import (ACTIVE_STATUS_DEFAULT, ACTIVE_STATUS_PARAM,
                                             ALT_NAMES_PARAM, CASE_SENSITIVE_PARAM,
                                             CREATED_AFTER_PARAM, CREATED_BEFORE_PARAM,
                                             DESCRIPTION_REGEX_PARAM, LOCALE_PARAM,
                                             METADATA_TYPE_CONTEXT, METADATA_TYPE_GROUP,
                                             METADATA_TYPE_I18N, METADATA_TYPE_LOCALE,
                                             METADATA_TYPE_NAME_REGEX, META_SEARCH_PARAM,
                                             NAME_REGEX_PARAM,
                                             QUERY_ACTIVE_OBJECTS_ONLY, QUERY_ANY_ACTIVE_STATUS,
                                             QUERY_INACTIVE_OBJECTS_ONLY,
                                             SEARCH_TYPE_PARAM,
                                             STRAIN_CASE_SENSITIVE,
                                             STRAIN_NAME, STRAIN_NAME_REGEX, STRAIN_REGISTRY_ID,
                                             STRAIN_REGISTRY_URL_REGEX, STUDIES_RESOURCE_NAME,
                                             TYPE_GROUP_PARAM, UNIT_NAME_PARAM,
                                             UPDATED_AFTER_PARAM, UPDATED_BEFORE_PARAM)
from jbei.rest.utils import is_numeric_pk
from main.models import (Assay, Line, Measurement, MeasurementType,
                         MeasurementUnit, MeasurementValue, MetadataGroup, MetadataType, Protocol,
                         Strain, Study,
                         StudyPermission, User)
from .permissions import (ImpliedPermissions, StudyResourcePermissions,
                          user_has_admin_or_manage_perm)
from .serializers import (AssaySerializer, GeneIdSerializer, LineSerializer, MeasurementSerializer,
                          MeasurementTypeSerializer, MeasurementUnitSerializer,
                          MeasurementValueSerializer,
                          MetaboliteSerializer, MetadataGroupSerializer, MetadataTypeSerializer,
                          PhosphorSerializer,
                          ProteinIdSerializer, ProtocolSerializer, StrainSerializer,
                          StudySerializer, UserSerializer)

logger = logging.getLogger(__name__)

_QUERYSET_LOG_MESSAGE = '%(class)s.%(cls_method)s(). %(http_method)s %(url)s: kwargs=%(kwargs)s'

_STRAIN_NESTED_RESOURCE_PARENT_PREFIX = r'strains'
_STUDY_NESTED_ID_KWARG = 'study_id'
_LINE_NESTED_ID_KWARG = 'line_id'
_ASSAY_NESTED_ID_KWARG = 'assay_id'
_MEASUREMENT_NESTED_ID_KWARG = 'measurement_id'


BASE_STRAIN_URL_KWARG = 'id'  # NOTE: value impacts url kwarg names for nested resources
HTTP_MUTATOR_METHODS = ('POST', 'PUT', 'PATCH', 'UPDATE', 'DELETE')
EXISTING_RECORD_MUTATOR_METHODS = ('PUT', 'PATCH', 'UPDATE', 'DELETE')

SORT_PARAM = 'sort_order'
FORWARD_SORT_VALUE = 'ascending'
REVERSE_SORT_VALUE = 'descending'

USE_STANDARD_PERMISSIONS = None

# Subset of Django 1.11-supported HStoreField operators that don't require a key name in
# order to use them. Note: 'contains'/'contained_by' work both with and without a key
NON_KEY_DJANGO_HSTORE_COMPARISONS = ('contains', 'contained_by', 'has_key',
                                     'has_any_keys', 'has_keys', 'keys', 'values')

_NON_KEY_LOOKUP_REGEX = r'(?P<operator>(?:%s)(?:__[\w_]+)?)=(?P<test>.+)$' % ('|'.join(
        NON_KEY_DJANGO_HSTORE_COMPARISONS))
_NON_KEY_LOOKUP_PATTERN = re.compile(_NON_KEY_LOOKUP_REGEX)

_KEY_LOOKUP_REGEX = r'(?P<key>[0-9]+)(?P<operator>=|(?:__[\w_]+))=?(?P<test>.+)$'
_KEY_LOOKUP_PATTERN = re.compile(_KEY_LOOKUP_REGEX)


def permission_denied_handler(request):
    # same as DRF provides in /rest/
    return response.HttpResponse('{"detail":"Authentication credentials were not provided."}',
                                 status.HTTP_403_FORBIDDEN)


@api_view()
@renderer_classes([OpenAPIRenderer, SwaggerUIRenderer])
def schema_view(request):
    generator = schemas.SchemaGenerator(title='Experiment Data Depot')
    return response.Response(generator.get_schema(request=request))


class CustomPermFilteringMixin(object):
    """
    A mixin for DRF views that do their own permissions enforcement via queryset result filtering
    (e.g. based on StudyPermissions)
    """

    def get_object(self):
        """
        Overrides the default implementation to provide flexible ID lookup (
        either based on local numeric primary key, UUID, or slug when appropriate)
        """
        queryset = self.get_queryset()

        # unlike the DRF example code: for consistency in permissions enforcement, just do all the
        # filtering in get_queryset() and pass empty filters here
        filters = {}
        obj = get_object_or_404(queryset, **filters)
        self.check_object_permissions(self.request, obj)
        return obj


class StudyAssaysViewSet(CustomPermFilteringMixin, mixins.ListModelMixin, GenericViewSet):
    permission_classes = [ImpliedPermissions]
    serializer_class = AssaySerializer

    def get_queryset(self):
        logger.debug(_QUERYSET_LOG_MESSAGE % {
            'class': AssaysViewSet.__name__,
            'cls_method': self.get_queryset.__name__,
            'http_method': self.request.method,
            'url': self.request.path,
            'kwargs': self.kwargs
        })

        study_id = self.kwargs.get(_STUDY_NESTED_ID_KWARG)
        assay_id = self.kwargs.get(self.lookup_url_kwarg, None)

        return build_assays_query(self.request, self.request.query_params,
                                  identifier_override=assay_id, study_id=study_id)


class AssaysViewSet(CustomPermFilteringMixin, viewsets.ReadOnlyModelViewSet):
    permission_classes = [ImpliedPermissions]
    serializer_class = AssaySerializer
    lookup_url_kwarg = 'id'

    def get_queryset(self):
        logger.debug((_QUERYSET_LOG_MESSAGE + ' query_params: %(query_params)s') % {
            'class': AssaysViewSet.__name__,
            'cls_method': self.get_queryset.__name__,
            'http_method': self.request.method,
            'url': self.request.path,
            'kwargs': self.kwargs,
            'query_params': self.request.query_params,
        })

        assay_id = self.kwargs.get(self.lookup_url_kwarg, None)

        return build_assays_query(self.request, self.request.query_params,
                                  identifier_override=assay_id)

    def get_serializer_class(self):
        # TODO: override to support optional bulk measurement / data requests for the study rather
        # than returning just assays
        return super(AssaysViewSet, self).get_serializer_class()


def build_assays_query(request, query_params, identifier_override=None, study_id=None):

    ###################################################################################
    # Build the query based on assay-specific search parameters, but don't execute yet
    ##################################################################################
    query = Assay.objects.all()
    query = optional_edd_object_filtering(query_params,
                                          query,
                                          id_override=identifier_override)
    # optional filtering by protocol
    _PROTOCOL_REQUEST_PARAM = 'protocol'
    protocol_filter = query_params.get(_PROTOCOL_REQUEST_PARAM, None)
    query = filter_id_list(query, 'protocol', 'protocol', protocol_filter)

    ###############################################################################
    # Add in context-specific permissions checks for the enclosing study/studies
    ###############################################################################

    # if we a study ID is provided, first check study permissions and raise a 404 if the study
    # doesn't exist or isn't accessible. This helps allows us to distinguish between 404 for
    # non-existent / inaccessible studies, return a 200 empty list for valid studies with no
    # assays, and also to avoid multi-table joins that include more than a single study.
    if study_id:
        study_pk = study_internals_initial_query(request, study_id, Assay)
        logger.debug('Filtering results to those in study %s' % study_id)
        query = query.filter(line__study_id=study_pk)

    # otherwise, build study permission checks into the query itself
    else:
        logger.debug('No %s identifier found for filtering' % _STUDY_NESTED_ID_KWARG)
        query = filter_for_study_permission(request, query, Assay, 'line__study__')

    return query


def study_internals_initial_query(request, study_id, result_model_class):
    """
    A helper method to simplify REST API queries for studies and study internals.  If this
    method returns without raising an Exception, the user is authenticated and has permission
    to access the study and its internals based on the HTTP request method used.

    The first step of querying for any study-specific data via REST should be to run this method
    to verify user access to the study. Checks user authentication status, superuser status,
    and study-specific user/group permissions.  Note that class-level django.contrib.auth
    permissions are purposefully NOT checked on the study internals (e.g. Assay), since those
    are currently not in use in EDD and would add complexity / hurt efficiency for no benefit.

    Note that this method is very similar in purpose to main.views.load_study(), but includes
    some specific conveniences for use in the DRF REST context, as well as removing the need for
    client code to distinguish which study identifier is in use.
    :param request: the REST API request
    :param kwargs: a dict of URI keyword arguments
    :param study_uri_kwarg: the string used to identify the study identifier read from the
    request URI
    :return: the integer primary key of the study, even if the client provided a different valid
    identifier (e.g. UUID or slug).
    :raises NotAuthenticated: if the user isn't authenticated
    :raises NotFound: if the no study identifier is provided
    """
    user = request.user
    if not user.is_authenticated():
        raise NotAuthenticated()

    # special-case workaround for the DRF browseable API.  It appears to directly call the views'
    # get_queryset() methods during inspection. When implemented, removing this check would cause
    # the browseable API to fail to load, although clearly under normal conditions study nested
    # resources shouldn't be reachable without the study id used to enforce access controls
    if not study_id:
        raise NotFound('No study identifier was provided')

    # load / check enclosing study permissions first
    study_query = Study.objects.filter(build_study_id_q('', study_id))
    study_query = filter_for_study_permission(request, study_query, result_model_class, '')
    study_query = study_query.values_list('pk', flat=True)

    if len(study_query) != 1:
        raise NotFound('Study "%s" not found' % study_id)

    return study_query.get()


def build_study_id_q(prefix, identifier):
    """
    Helper method for constructing a query that includes a unique study identifier whose type is
    determine dynimically (could be a pk, slug, or UUID).
    :param prefix:
    :param identifier:
    :return:
    """
    ############################
    # integer primary key
    ############################
    try:
        id_keyword = '%spk' % prefix
        return Q(**{id_keyword: int(identifier)})
    except ValueError:
        pass

    ############################
    # UUID
    ############################
    try:
        id_keyword = '%suuid' % prefix
        return Q(**{id_keyword: UUID(identifier)})
    except ValueError:
        pass

    ############################
    # Assume it's a slug
    ############################
    id_keyword = '%sslug' % prefix
    return Q(**{id_keyword: identifier})


def build_id_q(prefix, identifier):
    """
    Helper method for simplifying repetitive/flexible ID lookup of multiple Django models.
    :raise: ParseError if identifier isn't a valid integer primary key or UUID
    """
    # TODO: optimize by trying data_member_id first if it's an integer
    try:
        id_keyword = '%spk' % prefix
        return Q(**{id_keyword: int(identifier)})
    except ValueError:
        pass

    try:
        id_keyword = '%suuid' % prefix
        return Q(**{id_keyword: UUID(identifier)})
    except ValueError:
        raise ParseError('Invalid identifier "%(id)s" is not an integer primary key or UUID' % {
            'id': identifier
        })


def filter_id_list(query, filter_param_name, model_field_name, requested_filter_values):
    """
    Helper method for filtering a query to only results that contain an identifier that falls
    within the given list
    """
    if not requested_filter_values:
        return query

    filter_kwarg = '%s__in' % model_field_name

    # if query params came from URL query params, parse them into a form usable in an ORM query
    if isinstance(requested_filter_values, basestring):
        tokens = requested_filter_values.split(',')
        if len(tokens) == 1:
            return query.filter(build_id_q('%s__' % model_field_name, tokens[0].strip()))
        else:
            pks = []
            for index, token in enumerate(tokens):
                try:
                    pks.append(int(token))
                    continue
                except ValueError:
                    raise ParseError('Invalid value "%(invalid)s" in %(param)s was not a valid '
                                     'integer primary key' % {
                                         'invalid': token,
                                         'param': filter_param_name, })
            logger.debug('filter_id_list() %s: %s' % (model_field_name, {filter_kwarg: pks}))
            return query.filter(**{filter_kwarg: pks})

    elif isinstance(requested_filter_values, list):
        # TODO: remove debug stmt
        logger.debug('filter_id_list() %s: %s' % (model_field_name,
                                                  {filter_kwarg: requested_filter_values}))
        return query.filter(**{filter_kwarg: requested_filter_values})
    elif isinstance(requested_filter_values, int):
        logger.debug('filter_id_list() %s: %s' % (model_field_name,
                                                  {model_field_name: requested_filter_values}))
        return query.filter(**{model_field_name: requested_filter_values})

    raise ParseError('Unsupported %(param)s value "%(value)s"' % {
        'param': filter_param_name,
        'value': requested_filter_values
    })


class MeasurementsViewSet(CustomPermFilteringMixin, viewsets.ReadOnlyModelViewSet):
    permission_classes = [ImpliedPermissions]
    serializer_class = MeasurementSerializer
    lookup_url_kwarg = 'id'

    def get_queryset(self):

        logger.debug((_QUERYSET_LOG_MESSAGE + ' query_params=%(query_params)s') % {
            'class': MeasurementsViewSet.__name__,
            'url': self.request.path,
            'cls_method': self.get_queryset.__name__,
            'http_method': self.request.method,
            'kwargs': self.kwargs,
            'query_params': self.request.query_params,
        })

        logger.debug('query_params: %s' % self.request.query_params)

        measurement_id = self.kwargs.get(self.lookup_url_kwarg)
        return build_measurements_query(self.request, self.request.query_params,
                                        id_override=measurement_id)


class StudyMeasurementsViewSet(CustomPermFilteringMixin, mixins.ListModelMixin, GenericViewSet):
    permission_classes = [ImpliedPermissions]
    serializer_class = MeasurementSerializer
    lookup_url_kwarg = 'id'

    def get_queryset(self):

        logger.debug((_QUERYSET_LOG_MESSAGE + ' query_params=%(query_params)s') % {
            'class': MeasurementsViewSet.__name__,
            'url': self.request.path,
            'cls_method': self.get_queryset.__name__,
            'http_method': self.request.method,
            'kwargs': self.kwargs,
            'query_params': self.request.query_params,
        })

        logger.debug('query_params: %s' % self.request.query_params)

        study_id = self.kwargs.get(_STUDY_NESTED_ID_KWARG)
        measurement_id = self.kwargs.get(self.lookup_url_kwarg)
        return build_measurements_query(self.request, self.request.query_params,
                                        id_override=measurement_id, study_id=study_id)


def build_measurements_query(request, query_params, id_override=None, study_id=None):

    ###########################################################################################
    # Build the query based on measurement-specific search parameters, but don't execute yet
    ###########################################################################################

    query_params = request.query_params
    meas_query = Measurement.objects.all()

    # type
    measurement_type_filter = query_params.get('measurement_type')
    meas_query = filter_id_list(meas_query, 'measurement_type', 'measurement_type_id',
                                measurement_type_filter)

    # x-units
    x_units_filter = query_params.get('x_units')
    meas_query = filter_id_list(meas_query, 'x_units', 'x_units_id', x_units_filter)

    # y-units
    y_units_filter = query_params.get('y_units')
    meas_query = filter_id_list(meas_query, 'y_units', 'y_units_id', y_units_filter)

    # cellular compartment
    compartment_filter = query_params.get('compartment')
    if compartment_filter:
        meas_query = meas_query.filter(compartment=compartment_filter)

    # format
    format_filter = query_params.get('meas_format')  # NOTE: "format" is reserved by DRF
    if format_filter:
        logger.debug('MEASUREMENT FORMAT filter: %s' % format_filter)
        meas_query = meas_query.filter(measurement_format=format_filter)

    # use standard filtering code to perform ID and metadata-based filtering
    meas_query = optional_edd_object_filtering(query_params,
                                               meas_query,
                                               id_override=id_override)

    ###############################################################################
    # Add in context-specific permissions checks for the enclosing study/studies
    ###############################################################################

    # if we a study ID is provided, first check study permissions and raise a 404 if the study
    # doesn't exist or isn't accessible. This helps allows us to distinguish between 404 for
    # non-existent / inaccessible studies, return a 200 empty list for valid studies with no
    # assays, and also to avoid multi-table joins that include more than a single study.
    if study_id:
        study_pk = study_internals_initial_query(request, study_id, Measurement)
        logger.debug('Filtering results to those in study %s' % study_id)
        meas_query = meas_query.filter(assay__line__study_id=study_pk)

    # otherwise, build study permission checks into the query itself
    else:
        logger.debug('No %s identifier found for filtering' % _STUDY_NESTED_ID_KWARG)
        meas_query = filter_for_study_permission(request, meas_query, Measurement,
                                                 'assay__line__study__')

    return meas_query


class MeasurementValuesViewSet(CustomPermFilteringMixin, viewsets.ReadOnlyModelViewSet):
    permission_classes = [ImpliedPermissions]
    serializer_class = MeasurementValueSerializer
    lookup_url_kwarg = 'id'

    def get_queryset(self):

        logger.debug((_QUERYSET_LOG_MESSAGE + ' query_params=%(query_params)s') % {
            'class': MeasurementsViewSet.__name__,
            'url': self.request.path,
            'cls_method': self.get_queryset.__name__,
            'http_method': self.request.method,
            'kwargs': self.kwargs,
            'query_params': self.request.query_params,
        })

        logger.debug('query_params: %s' % self.request.query_params)

        value_id = self.kwargs.get(self.lookup_url_kwarg)
        return build_values_query(self.request,
                                  self.request.query_params,
                                  id_override=value_id)


class StudyValuesViewSet(CustomPermFilteringMixin, mixins.ListModelMixin, GenericViewSet):
    permission_classes = [ImpliedPermissions]
    serializer_class = MeasurementValueSerializer
    lookup_url_kwarg = 'id'

    def get_queryset(self):

        logger.debug((_QUERYSET_LOG_MESSAGE + ' query_params=%(query_params)s') % {
            'class': MeasurementsViewSet.__name__,
            'url': self.request.path,
            'cls_method': self.get_queryset.__name__,
            'http_method': self.request.method,
            'kwargs': self.kwargs,
            'query_params': self.request.query_params,
        })

        logger.debug('query_params: %s' % self.request.query_params)

        study_id = self.kwargs.get(_STUDY_NESTED_ID_KWARG)
        value_id = self.kwargs.get(self.lookup_url_kwarg)
        return build_values_query(self.request,
                                  self.request.query_params,
                                  study_id=study_id,
                                  id_override=value_id)


def build_values_query(request, query_params, id_override=None, study_id=None,
                       enabling_manage_perms=USE_STANDARD_PERMISSIONS,
                       requested_study_perm_override=None):

    ###################################################################################
    # Build the query based on value-specific search parameters, but don't execute yet
    ##################################################################################
    query = MeasurementValue.objects.all()
    if id_override:
        query = query.filter(pk=id_override)
    else:
        identifier = query_params.get('id')
        if identifier:
            query = query.filter(pk=identifier)
    query = _optional_updated_filter(query, query_params)

    ###############################################################################
    # Add in context-specific permissions checks for the enclosing study/studies
    ###############################################################################

    # if we a study ID is provided, first check study permissions and raise a 404 if the study
    # doesn't exist or isn't accessible. This helps allows us to distinguish between 404 for
    # non-existent / inaccessible studies, return a 200 empty list for valid studies with no
    # assays, and also to avoid multi-table joins that include more than a single study.
    if study_id:
        study_pk = study_internals_initial_query(request, study_id, MeasurementValue)
        logger.debug('Filtering results to those in study %s' % study_id)
        query = query.filter(measurement__assay__line__study_id=study_pk)

    # otherwise, build study permission checks into the query itself
    else:
        logger.debug('No %s identifier found for filtering' % _STUDY_NESTED_ID_KWARG)
        query = filter_for_study_permission(request, query, MeasurementValue,
                                            'measurement__assay__line__study__')

    return query


def opt_foreign_key_filter(model_field_name, queryset, request_params, request_param_name):
    filter_value = request_params.get(request_param_name)
    if not filter_value:
        return queryset

    try:
        return queryset.filter(**{model_field_name: int(filter_value)})
    except ValueError:
        raise ParseError('%(request_param)s value "%(value)s" is not a valid integer primary '
                         'key' % {
                            'request_param': request_param_name,
                            'value': filter_value, })


class MeasurementTypesViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [ImpliedPermissions]
    serializer_class = MeasurementTypeSerializer
    lookup_url_kwarg = 'id'

    serializer_lookup = {
        MeasurementType.Group.GENERIC: MeasurementTypeSerializer,
        MeasurementType.Group.METABOLITE: MetaboliteSerializer,
        MeasurementType.Group.GENEID: GeneIdSerializer,
        MeasurementType.Group.PROTEINID: ProteinIdSerializer,
        MeasurementType.Group.PHOSPHOR: PhosphorSerializer,
    }

    def get_queryset(self):
        identifier = self.kwargs.get('pk', None)

        return build_measurement_type_query(self.request, self.request.query_params,
                                            identifier=identifier)

    def get_serializer_class(self):
        """
        Overrides the parent implementation to provide serialization that's dynamically determined
        by the requested result type
        """
        # TODO: investigate whether there's a way to test whether there's a single query result,
        # then to test its type and return the correct data even though group wasn't specified
        group = self.request.query_params.get(TYPE_GROUP_PARAM)

        if not group:
            return MeasurementTypeSerializer

        serializer = self.serializer_lookup.get(group, None)
        if not serializer:
            raise NotImplementedError('No serializer is defined for %(param)s "%(value)s"' % {
                'param': SEARCH_TYPE_PARAM,
                'value': self.search_type,
            })

        return serializer


def build_measurement_type_query(request, query_params, identifier=None):

    # if client has provided a group filter, look up and use the appropriate model object
    # to provide the full level of available detail
    group_filter = query_params.get(TYPE_GROUP_PARAM)

    model_class = MeasurementType
    if group_filter:
        model_class = MeasurementType.get_model_class(group_filter)

        if not model_class:
            raise ValidationError('%(param)s value "%(val)s" is invalid or unsupported' % {
                              'param': TYPE_GROUP_PARAM,
                              'val': group_filter, })

    query = model_class.objects.all()
    if identifier:
        query = query.filter(build_id_q(identifier))

    if request.method in HTTP_MUTATOR_METHODS:
        require_auth_perm(request, model_class)

    if not query_params:
        return query

    _TYPE_NAME_PROPERTY = 'type_name'
    query = _optional_regex_filter(query_params, query, _TYPE_NAME_PROPERTY, NAME_REGEX_PARAM,
                                   LOCALE_PARAM)

    if group_filter:
        query = query.filter(type_group=group_filter)

    # sort
    sort = query_params.get(SORT_PARAM)

    if sort is not None:
        query = query.order_by(_TYPE_NAME_PROPERTY)

        if sort == REVERSE_SORT_VALUE:
            query = query.reverse()

    return query


class MetadataTypeViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint that supports viewing and searching .EDD's metadata types
    TODO: implement/confirm access controls for unsafe methods, then make writable
    """

    # Note: queryset must be defined for DjangoModelPermissions in addition to get_queryset(). See
    # related  comment/URL above
    permission_classes = [ImpliedPermissions]
    serializer_class = MetadataTypeSerializer

    def get_queryset(self):
        identifier = self.kwargs.get('pk', None)

        queryset = MetadataType.objects.all()
        return build_metadata_type_query(queryset, self.request.query_params,
                                         identifier=identifier)


def build_metadata_type_query(queryset, query_params, identifier=None):
    if identifier:
        try:
            queryset = queryset.filter(pk=identifier)
        except ValueError:
            try:
                queryset = queryset.filter(uuid=UUID(identifier))
            except ValueError:
                raise ValidationError('Invalid identifier "%(id)s"' % {
                    'id': identifier
                })

    if not query_params:
        return queryset

    # group id
    group_id = query_params.get(METADATA_TYPE_GROUP)
    if group_id:
        if is_numeric_pk(group_id):
            queryset = queryset.filter(group=group_id)
        else:
            queryset = queryset.filter(group__group_name=group_id)

    # for context
    for_context = query_params.get(METADATA_TYPE_CONTEXT)
    if for_context:
        queryset = queryset.filter(for_context=for_context)

    # type I18N
    type_i18n = query_params.get(METADATA_TYPE_I18N)
    if type_i18n:
        queryset = queryset.filter(type_i18n=type_i18n)

    # sort
    sort = query_params.get(SORT_PARAM)

    TYPE_NAME_PROPERTY = 'type_name'

    if sort is not None:
        queryset = queryset.order_by(TYPE_NAME_PROPERTY)

        if sort == REVERSE_SORT_VALUE:
            queryset = queryset.reverse()

    queryset = _optional_regex_filter(query_params, queryset, TYPE_NAME_PROPERTY,
                                      METADATA_TYPE_NAME_REGEX, METADATA_TYPE_LOCALE, )

    return queryset


OWNED_BY = 'owned_by'
VARIANT_OF = 'variant_of'
DEFAULT_UNITS_QUERY_PARAM = 'default_units'
CATEGORIZATION_QUERY_PARAM = 'categorization'


class MeasurementUnitViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = MeasurementUnit.objects.all()  # must be defined for DjangoModelPermissions
    serializer_class = MeasurementUnitSerializer

    def get_queryset(self):

        queryset = MeasurementUnit.objects.all()

        # Note: at the time of writing, MeasurementUnit doesn't support a UUID
        pk = self.kwargs.get('pk', None)

        return build_measurement_units_query(self.request.query_params, queryset, pk)


def build_measurement_units_query(query_params, queryset, identifier=None):
    # Note: at the time of writing, MeasurementUnit doesn't support a UUID
    if identifier:
        queryset = queryset.filter(pk=identifier)

    i18n_placeholder = ''

    queryset = _optional_regex_filter(query_params, queryset, 'unit_name', UNIT_NAME_PARAM,
                                      i18n_placeholder)

    queryset = _optional_regex_filter(query_params, queryset, 'alternate_names',
                                      ALT_NAMES_PARAM, i18n_placeholder)

    queryset = _optional_regex_filter(query_params, queryset, 'type_group', TYPE_GROUP_PARAM,
                                      i18n_placeholder)

    return queryset


class ProtocolViewSet(CustomPermFilteringMixin, viewsets.ReadOnlyModelViewSet):
    queryset = Protocol.objects.all()  # must be defined for DjangoModelPermissions
    serializer_class = ProtocolSerializer
    lookup_url_kwarg = 'id'

    # Django model object property (used several times)
    NAME_PROPERTY = 'name'

    # API query parameter names...may diverge from Django Model field names over time
    NAME_QUERY_PARAM = 'name'
    OWNED_BY_QUERY_PARAM = 'owned_by'
    CATEGORIZATION_PROPERTY = 'categorization'
    DEFAULT_UNITS_PROPERTY = 'default_units'

    def get_queryset(self):

        queryset = Protocol.objects.all()
        identifier = self.kwargs.get(self.lookup_url_kwarg)
        if identifier:
            queryset = queryset.filter(build_id_q('', identifier))

        i18n_placeholder = ''  # TODO: implement if I18N implemented for Protocol model

        params = self.request.query_params
        if params:
            # owned by
            owned_by_id = params.get(OWNED_BY)
            if owned_by_id:
                queryset = queryset.filter(owned_by=owned_by_id)

            # variant of
            variant_of = params.get(VARIANT_OF)
            if variant_of:
                queryset = queryset.filter(variant_of=variant_of)

            # default units
            default_units = params.get(DEFAULT_UNITS_QUERY_PARAM)
            if default_units:
                queryset = queryset.filter(build_id_q('default_units__', default_units))

            # categorization
            queryset = _optional_regex_filter(params, queryset, 'categorization',
                                              CATEGORIZATION_QUERY_PARAM, i18n_placeholder)

            # sort (based on name)
            sort = params.get(SORT_PARAM)
            if sort is not None:
                queryset = queryset.order_by(self.NAME_PROPERTY)

                if sort == REVERSE_SORT_VALUE:
                    queryset = queryset.reverse()

            queryset = _optional_regex_filter(params, queryset, self.NAME_PROPERTY,
                                              self.NAME_QUERY_PARAM, i18n_placeholder)

            queryset = _optional_timestamp_filter(queryset, self.request.query_params)

        return queryset


def _optional_regex_filter(query_params_dict, queryset, data_member_name, regex_param_name,
                           locale_param_name):
    """
    Implements consistent regular expression matching behavior for EDD's REST API. Applies
    default behaviors re: case-sensitivity to all regex-based searches in the REST API.
    :param queryset: the queryset to filter based on the regular expression parameter
    :param data_member_name the django model data member name to be filtered according to the
        regex, if present
    :param regex_param_name: the query parameter name REST API clients use to pass the regular
        expression used for the search
    :param locale_param_name: the query parameter name REST API clients use to pass the locale used
        to determine which strings the regular expression is tested against
    :return: the queryset, filtered using the regex, if available
    """
    # TODO: do something with locale, which we've at least forced clients to provide to simplify
    # future full i18n support

    regex_value = query_params_dict.get(regex_param_name)
    if not regex_value:
        return queryset

    case_sensitive_search = CASE_SENSITIVE_PARAM in query_params_dict
    search_type = 'regex' if case_sensitive_search else 'iregex'
    filter_param = '%(data_member_name)s__%(search_type)s' % {
        'data_member_name': data_member_name,
        'search_type': search_type
    }

    return queryset.filter(**{filter_param: regex_value})


class MetadataGroupViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint that supports view-only access to EDD's metadata groups.
    TODO: implement/confirm access controls for unsafe methods, then make this writable
    """
    queryset = MetadataGroup.objects.all()  # must be defined for DjangoModelPermissions
    serializer_class = MetadataGroupSerializer

    def list(self, request, *args, **kwargs):
        """
        Lists the metadata groups in EDD's database
        """


class UserViewSet(viewsets.ReadOnlyModelViewSet):
    # TODO: allows unrestricted read access
    permission_classes = [IsAuthenticated, DjangoModelPermissions]
    """
    API endpoint that allows privileged users to get read-only information on the current set of
    EDD user accounts.
    """
    serializer_class = UserSerializer

    def get_queryset(self):
        return User.objects.filter(self.kwargs['user'])


PAGING_PARAMETER_DESCRIPTIONS = """
            parameters:
               - name: page
                 type: integer
                 description: the number of the results page to return (starting with 1)


            responseMessages:
               - code: 401
                 message: Not authenticated
               - code: 403
                 message: Insufficient rights to call this procedure
               - code: 500 internal server error
    """


class StrainViewSet(mixins.CreateModelMixin,
                    mixins.RetrieveModelMixin,
                    mixins.UpdateModelMixin,
                    # mixins.DestroyModelMixin,  TODO: implement & test later as a low priority
                    mixins.ListModelMixin,
                    GenericViewSet):
    """
    Defines the set of REST API views available for the base /rest/strain/ resource. Nested views
    are defined elsewhere (e.g. StrainStudiesView).
    """
    permission_classes = [ImpliedPermissions]

    # Note: queryset must be defined for DjangoModelPermissions in addition to get_queryset(). See
    # related  comment/URL above
    queryset = Strain.objects.none()

    serializer_class = StrainSerializer
    lookup_url_kwarg = BASE_STRAIN_URL_KWARG

    def get_object(self):
        """
        Overrides the default implementation to provide flexible lookup for Strain detail
        views (either based on local numeric primary key, or based on the strain UUID from ICE
        """
        queryset = self.get_queryset()

        # unlike the DRF example code: for consistency in permissions enforcement, just do all the
        # filtering in get_queryset() and pass empty filters here
        filters = {}
        obj = get_object_or_404(queryset, **filters)
        self.check_object_permissions(self.request, obj)
        return obj

    def get_queryset(self):
        """
        Overrides the default implementation to provide:
        * flexible list view filtering based on a number of useful input parameters
        * flexible strain detail lookup by local numeric pk OR by UUID from ICE
        """

        logger.debug(_QUERYSET_LOG_MESSAGE % {
            'class': self.__class__.__name__,
            'cls_method': self.get_queryset.__name__,
            'http_method': self.request.method,
            'url': self.request.path,
            'kwargs': self.kwargs})

        # build a query, filtering by the provided user inputs (starting out unfiltered).
        # TODO: Strain has been recently updated to be an EDDObject.  We can reuse more code here
        # than before, and also likely take advantage of newer/more standard search features in
        # optional_edd_object_filtering().
        # However, there are now two UUID's for a strain...
        query = Strain.objects.all()

        # if a strain UUID or local numeric pk was provided via the URL, get it
        identifier = None
        if self.kwargs:
            identifier = self.kwargs.get(self.lookup_url_kwarg)

            try:
                if is_numeric_pk(identifier):
                    query = query.filter(pk=int(identifier))
                else:
                    query = query.filter(registry_id=UUID(identifier))
            except ValueError:
                raise ParseError('URL identifier "%s" is neither a valid integer nor UUID' %
                                 identifier)
        # otherwise, we're searching strains, so filter them according to the provided params
        else:
            # parse optional query parameters
            query_params = self.request.query_params
            identifier = query_params.get(self.lookup_url_kwarg)
            local_pk_filter = query_params.get('pk')
            registry_id_filter = query_params.get(STRAIN_REGISTRY_ID)
            registry_url_regex_filter = query_params.get(STRAIN_REGISTRY_URL_REGEX)
            case_sensitive = query_params.get(STRAIN_CASE_SENSITIVE)
            name_filter = query_params.get(STRAIN_NAME)

            try:
                # if provided an ambiguously-defined unique ID for the strain, apply it based
                # on the format of the provided value
                if identifier:
                    if is_numeric_pk(identifier):
                        query = query.filter(pk=identifier)
                    else:
                        query = query.filter(registry_id=UUID(identifier))

                if local_pk_filter:
                    identifier = local_pk_filter
                    query = query.filter(pk=local_pk_filter)

                if registry_id_filter:
                    identifier = registry_id_filter
                    query = query.filter(registry_id=UUID(registry_id_filter))
            except ValueError:
                raise ParseError('Identifier %s is not a valid integer nor UUID' % identifier)

            if registry_url_regex_filter:
                if case_sensitive:
                    query = query.filter(registry_url__regex=registry_url_regex_filter)
                else:
                    query = query.filter(registry_url__iregex=registry_url_regex_filter)

            if name_filter:
                if case_sensitive:
                    query = query.filter(name__contains=name_filter)
                else:
                    query = query.filter(name__icontains=name_filter)

            query = _optional_regex_filter(query_params, query, 'name', STRAIN_NAME_REGEX, None)
            query = _optional_timestamp_filter(query, query_params)

        # filter results to ONLY the strains accessible by this user. Note that this may
        # prevent some users from accessing strains, depending on how EDD's permissions are set up,
        # but the present alternative is to create a potential leak of experimental strain names /
        # descriptions to potentially competing researchers that use the same EDD instance

        # if user is requesting to add / modify / delete strains, apply django.auth permissions
        # to determine access
        user = self.request.user
        http_method = self.request.method
        if http_method in HTTP_MUTATOR_METHODS:
            if not user.is_authenticated():
                logger.debug('User is not authenticated. Returning zero results')
                return Strain.objects.none()
            if user_has_admin_or_manage_perm(self.request, query):
                logger.debug('User %s has manage permissions for ')
                return query
            return Strain.objects.none()

        # if user is requesting to view one or more strains, allow either django auth permissions
        # or study permissions to determine whether or not the strain is visible to this user. If
        # the user has access to this study, they'll be able to view strain details in the UI.
        query = filter_for_study_permission(self.request, query, Strain, 'line__study__')
        return query

    def list(self, request, *args, **kwargs):
        """
            List strains the requesting user has access to.

            Strain access is defined by:

            1.  Study read access. A user has read access to strains in any study s/he has read
            access to.

            2.  Explicit strain permissions. Any user who has the add/update/delete permission to
            the strain class will have that level of access to strains, as well as implied read
            access to all of them.

            3.  Administrative access. System administrators always have full access to strains.

            ---
            responseMessages:
               - code: 400
                 message: Bad client request
               - code: 401
                 message: Unauthenticated
               - code: 403
                 message: Forbidden. User is authenticated but lacks the required permissions.
               - code: 500
                 message: Internal server error
            parameters:
               - name: page
                 paramType: query  # work django-rest-swagger breaking this in override
                 type: integer
                 description: The number of the results page to return (starting with 1)
               - name: page_size
                 paramType: query  # work django-rest-swagger breaking this in override
                 type: integer
                 description: "The requested maximum page size for results. May not be respected
                 by EDD if this value exceeds the server's maximum supported page size."
            """
        return super(StrainViewSet, self).list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        """
        View details of a single strain

        ---
            responseMessages:
               - code: 400
                 message: Bad client request
               - code: 401
                 message: Unauthenticated
               - code: 403
                 message: Forbidden. User is authenticated but lacks the required permissions.
               - code: 500
                 message: Internal server error
        """
        return super(StrainViewSet, self).retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        """
        Create a new strain.
        ---
            responseMessages:
               - code: 400
                 message: Bad client request
               - code: 401
                 message: Unauthenticated
               - code: 403
                 message: Forbidden. User is authenticated but lacks the required permissions.
               - code: 500
                 message: Internal server error
        """
        # TODO: as a future improvement, limit strain creation input to only ICE part identifier
        #  (part ID, local pk, or UUID), except by apps with additional privileges (e.g. those
        # granted to ICE itself to update strain data for ICE-72).  For now, we can just limit
        # strain creation privileges to control consistency of newly-created strains (which
        # should be created via the UI in most cases anyway).
        return super(StrainViewSet, self).create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        """
        Update all fields of an existing strain.
        ---
            responseMessages:
               - code: 400
                 message: Bad client request
               - code: 401
                 message: Unauthenticated
               - code: 403
                 message: Forbidden. User is authenticated but lacks the required permissions.
               - code: 404
                 message: Strain doesn't exist
               - code: 500
                 message: Internal server error
        """
        return super(StrainViewSet, self).update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        """
            Update only the provided fields of an existing strain.
            ---
                responseMessages:
                   - code: 400
                     message: Bad client request
                   - code: 401
                     message: Unauthenticated
                   - code: 403
                     message: Forbidden. User is authenticated but lacks the required permissions.
                   - code: 404
                     message: Strain doesn't exist
                   - code: 500
                     message: Internal server error
            """


HTTP_TO_STUDY_PERMISSION_MAP = {
    'POST': StudyPermission.WRITE,
    'PUT': StudyPermission.WRITE,
    'DELETE': StudyPermission.WRITE,
    'PATCH': StudyPermission.WRITE,
    'OPTIONS': StudyPermission.NONE,
    'HEAD': StudyPermission.READ,
    'GET': StudyPermission.READ,
}


def get_requested_study_permission(http_method):
    return HTTP_TO_STUDY_PERMISSION_MAP.get(http_method.upper())


def filter_by_active_status(queryset, active_status=QUERY_ACTIVE_OBJECTS_ONLY, query_prefix=''):
    """
    A helper method for queryset filtering based on a standard set of HTTP request
    parameter values that indicate whether EddObjects should be considered in the query based on
    their 'active' status.

    For a single object class A related to the ORM model class B returned from the query, a call to
    filter_by_active_status() will filter the query according to A's 'active' status. Note
    that this filtering by active status will result in the queryset returning one row for each
    relations of A to B, so clients will often want to use distinct() to limit the returned
    results.  A typical use of this method is to control which lines are considered
    in a query.

    Example 1 : Finding only active Lines. This is slightly more code than to just filter the
                query directly, but that wouldn't be standard across REST resource implementations.

    queryset = Line.objects.all()
    queryset = filter_by_active_status(queryset, active_status=ACTIVE_ONLY,
                                       query_prefix='').distinct()

    Example 2: Finding Strains associated with a Study by active lines

    queryset = Strain.objects.filter(line__study__pk=study_id)
    queryset = filter_by_active_status(queryset, active_status=ACTIVE_ONLY,
                                       query_prefix=('line__')).distinct()

    :param queryset: the base queryset to apply filtering to
    :param active_status: the HTTP request query parameter whose value implies the type of
    filtering to apply based on active status. If this isn't one of the recognized values,
    the default behavior is applied, filtering out inactive objects. See
    constants.ACTIVE_STATUS_OPTIONS.
    :param query_prefix: an optional keyword prefix indicating the relationship of the filtered
    class to the model we're querying (see examples above)
    :return: the input query, filtered according to the parameters
    """
    active_status = active_status.lower()

    # just return the parameter if no extra filtering is required
    if active_status == QUERY_ANY_ACTIVE_STATUS:
        return queryset

    # construct an ORM query keyword based on the relationship of the filtered model class to the
    # Django model class being queried. For example 1 above, when querying Line.objects.all(),
    # we prepend '' and come up with Q(active=True). For example 2, when querying
    # Strain, we prepend 'line__' and get Q(line__active=True)
    orm_query_keyword = '%sactive' % query_prefix
    # return requested status, or active objects only if input was bad
    active_value = (active_status != QUERY_INACTIVE_OBJECTS_ONLY)

    active_criterion = Q(**{orm_query_keyword: active_value})
    return queryset.filter(active_criterion)


class StudyViewSet(mixins.CreateModelMixin,
                   mixins.RetrieveModelMixin,
                   mixins.UpdateModelMixin,
                   # TODO: implement & test later as a low priority...study deletion via the
                   # API should maybe only mark studies as "disabled" if they have data (or maybe
                   # should require an override parameter to actually delete.
                   # mixins.DestroyModelMixin,
                   mixins.ListModelMixin,
                   GenericViewSet):
    """
    API endpoint that provides access to studies, subject to user/role read access
    controls. Note that some privileged 'manager' users may have access to the base study name,
    description, etc, but not to the contained experiment description or data.
    """
    serializer_class = StudySerializer
    contact = StringRelatedField(many=False)
    permission_classes = [StudyResourcePermissions]
    lookup_url_kwarg = 'id'

    def get_object(self):
        """
        Overrides the default implementation to provide flexible lookup for Study detail
        views (either based on local numeric primary key, slug, or UUID
        """
        queryset = self.get_queryset()

        # unlike the DRF example code: for consistency in permissions enforcement, just do all the
        # filtering in get_queryset() and pass empty filters here
        filters = {}
        obj = get_object_or_404(queryset, **filters)
        self.check_object_permissions(self.request, obj)
        return obj

    def get_queryset(self):

        params = self.request.query_params
        study_id = self.kwargs.get(self.lookup_url_kwarg, None)
        return build_study_query(self.request, params, identifier=study_id)

    def create(self, request, *args, **kwargs):
        if not request.user.is_authenticated():
            return Response(status=status.HTTP_404_NOT_FOUND)

        if not Study.user_can_create(request.user):
            return Response(status=status.HTTP_403_FORBIDDEN)

        return super(StudyViewSet, self).create(request, *args, **kwargs)


def build_study_query(request, query_params, identifier=None, skip_study_auth_perms=False,
                      skip_non_id_filtering=False):
    """
    A helper method for constructing a Study QuerySet while consistently applying Study permissions
    :param skip_study_auth_perms: True to disallow access to the study based on class-level
    django.util.auth permissions that only grant permission to the base study details (e.g.
    name, description, contact) rather than the contained data.  Use False to apply only
    Study-specific user permissions, e.g. when accessing nested study resources like Lines,
    Measurements, etc.
    """
    study_query = Study.objects.all()

    # if client provided any identifier, filter based on it. Note that since studies have a slug
    # that most other EddObjects don't have, we do our id filtering up front rather than using
    # EddObject filtering. We also use int/UUID constructors to guarantee that input format
    # checking is performed up front at queryset construction time (400 error) rather than
    # evaluation time (500 error)
    if identifier:
        study_query = study_query.filter(build_study_id_q('', identifier))

    # apply standard filtering options, but skip ID-based filtering we've just finished
    if not skip_non_id_filtering:
        study_query = optional_edd_object_filtering(query_params, study_query,
                                                    skip_id_filtering=True)

    # apply study permissions
    study_query = filter_for_study_permission(request, study_query, Study, '')

    return study_query


def optional_edd_object_filtering(params, query, skip_id_filtering=False, id_override=None):
    """
    A helper method to perform filtering on standard EDDObject fields
    """
    # filter results based on the provided ID (can take multiple forms). Note: we purposefully use
    # int/UUID constructors here to force errors to occur at query *construction* time rather
    # than *evaluation* time. format checks deferred until evaluation will result in 500 errors
    # rather than more appropriate 400's
    if not skip_id_filtering:
        # if an identifier came from another source (e.g. query URL) use that one
        if id_override:
            logger.debug('Filtering query for overridden identifier "%s"' % id_override)
            query = query.filter(build_id_q('', id_override))

        # otherwise, look for identifiers in the search params
        else:
            identifier = params.get('id')
            if identifier:
                query = query.filter(build_id_q('', identifier))

    # apply optional name-based filtering
    query = _optional_regex_filter(params, query, 'name', NAME_REGEX_PARAM, None, )

    # apply optional description-based filtering
    query = _optional_regex_filter(params, query, 'description', DESCRIPTION_REGEX_PARAM,
                                   None, )

    # filter for active status, or apply the default of only returning active objects.
    # if accessing a detail view, default to returning the result regardless of active status since
    # it was specifically requested
    active_status = params.get(ACTIVE_STATUS_PARAM, QUERY_ANY_ACTIVE_STATUS if id_override
                               else ACTIVE_STATUS_DEFAULT)
    query = filter_by_active_status(query, active_status=active_status)

    # apply timestamp_based filtering
    query = _optional_timestamp_filter(query, params)

    # apply optional metadata lookups supported by Django's HStoreField.  Since we trust
    # django to apply security checks, for starters we'll expose the HStoreField query
    # parameters to clients more-or-less directly.  This is necessary to help support
    # comparisons that our current lack of metadata validation makes difficult, e.g. growth
    #  temp > X.  See EDD-771, and possibly other tickets linked to EDD-438. If needed,
    # we can add in abstractions later to help with this....e.g. expose an
    # artificially-added 'lt' operator.
    meta_comparisons = params.get(META_SEARCH_PARAM)

    if not meta_comparisons:
        return query

    if isinstance(meta_comparisons, list):
        comparison_count = len(meta_comparisons)
        for index, comparison in enumerate(meta_comparisons):
            query = _filter_for_metadata(query, comparison, index+1, comparison_count)
    else:
        query = _filter_for_metadata(query, meta_comparisons, 1, 1)

    return query


def _filter_for_metadata(query, meta_comparison, comparison_num, comparison_count):
    def keep_as_str(s):
        return s

    match = _KEY_LOOKUP_PATTERN.match(meta_comparison)
    if match:
        meta_key = match.group('key')
        meta_operator = match.group('operator')
        meta_test = match.group('test')
        logger.debug('Meta comparison %(num)d of %(total)d matches key-based pattern! '
                     'key="%(key)s", op="%(op)s", test="%(test)s"' % {
                         'num': comparison_num,
                         'total': comparison_count,
                         'key': meta_key,
                         'op': meta_operator,
                         'test': meta_test})
    else:
        match = _NON_KEY_LOOKUP_PATTERN.match(meta_comparison)
        if not match:
            logger.debug('URL input "%(input)s" did not match non-key regex "%(regex)s"' % {
                             'input': meta_comparison,
                             'regex': _NON_KEY_LOOKUP_REGEX,
            })
            raise ValidationError('Invalid metadata comparison "%s"' % meta_comparison)

        meta_key = None
        meta_operator = match.group('operator')
        meta_test = match.group('test')
        logger.debug('Meta comparison %(num)d of %(total)d matches non-key pattern! '
                     'op="%(op)s", test="%(test)s"' % {
                         'num': comparison_num,
                         'total': comparison_count,
                         'op': meta_operator,
                         'test': meta_test})

    # tolerate numeric values used for comparison.  They must be converted to strings to work
    # for comparison against Postgres' HStoreField. Note that keys will automatically be converted
    # to strings by JSON serialization, regardless of what clients specify. Alternative is to raise
    # or work around a ProgrammingError at query evaluation time
    if isinstance(meta_test, numbers.Number):
        meta_test = str(meta_test)
    elif isinstance(meta_test, basestring) and (('[' in meta_test) or ('{' in meta_test)):
        # convert from URL-derived string to list/dict, but leave numbers as strings so they
        # can be passed directly as kwargs to QuerySet.filter() below
        meta_test = json.loads(meta_test, parse_float=keep_as_str, parse_int=keep_as_str)

    prefix = 'meta_store__'
    comparison = meta_operator
    if meta_key:
        prefix = 'meta_store__%s' % meta_key
        comparison = meta_operator if meta_operator != '=' else ''

    filter_key = '%(prefix)s%(comparison)s' % {
        'prefix': prefix,
        'comparison': comparison,
    }
    filter_dict = {filter_key: meta_test}

    logger.debug('Metadata filter %d of %d: %s' % (comparison_num, comparison_count,
                                                   str(filter_dict)))
    return query.filter(**filter_dict)


def filter_for_study_permission(request, query, result_model_class, study_keyword_prefix):
    """
        A helper method that filters a Queryset to return only results that the requesting user
        should have access to, based on class-level django.auth permissions and on
        study-specific main.models.StudyPermissions. Note the assumption that the
        requested resource is unique to the study (e.g. Lines).
        :param request: the HttpRequest to access a study-related resource
        :param query: the queryset as defined by the request (with permissions not yet enforced)
        :result_model_class: the Django model class returned by the QuerySet. If the user has
        class-level django.contrib.auth appropriate permissions to view/modify/create objects of
        this type, access will be granted regardless of configured Study-level permissions.
        that optionally overrides the default set of permissions that would otherwise determine
        class-level access to all of the results based on request.method. If None, the default
        permissions will be applied, or django.contrib.auth permissions will be ignored if an empty
        list is provided.
     """

    # never show anything to un-authenticated users
    user = request.user
    if (not user) or not user.is_authenticated():
        logger.debug('User %s is not authenticated' % user)
        raise NotAuthenticated()

    requested_permission = get_requested_study_permission(request.method)

    # if user role (e.g. admin) grants access to all Studies, we can expose all objects
    # without additional queries
    has_role_based_permission = (requested_permission == StudyPermission.READ and
                                 Study.user_role_can_read(user))
    if has_role_based_permission:
        return query

    has_auth_permission = require_auth_perm(request, result_model_class, suppress_exception=True)
    if has_auth_permission:
        return query

    # if user has no class-level permissions that grant access to all results , filter
    # results to only those exposed in studies the user has read/write
    # access to. This is significantly more expensive, but exposes the same data available
    # via the UI. Where possible, we should encourage clients to access nested study
    # resources via /rest/studies/X/Y to avoid these joins.

    # if user is only requesting read access, construct a query that will infer read permission
    # from the existing of either read or write permission
    if requested_permission == StudyPermission.READ:
        requested_permission = StudyPermission.CAN_VIEW

    logger.debug('Filtering query for study permissions')
    user_permission_q = Study.user_permission_q(user, requested_permission,
                                                keyword_prefix=study_keyword_prefix)
    return query.filter(user_permission_q).distinct()


NUMERIC_PK_PATTERN = re.compile('^\d+$')


def require_auth_perm(request, result_model_class,
                      suppress_exception=False,
                      enabling_perms_override=USE_STANDARD_PERMISSIONS):
    """
    A helper method to enforce class-level django.contrib.auth permissions. If this method
    returns without raising an Exception, the user has the required permission.
    """

    # test whether explicit django.contrib.auth permissions allow user to access all results
    # without having to drill down into case-by-case study or nested relationships that would
    # grant access to a subset of results
    if enabling_perms_override is USE_STANDARD_PERMISSIONS:
        enabling_perms = (
            ImpliedPermissions.get_standard_enabling_permissions(
                request.method, result_model_class))
    else:
        enabling_perms = enabling_perms_override

    user = request.user
    requested_drf_perm = get_requested_study_permission(request.method)
    for auth_perm in enabling_perms:

        if user.has_perm(auth_perm):
            logger.debug('User %(user)s has DRF permission "%(requested_perm)s" for '
                         'all %(model_class)s objects, implied via the "%(auth_perm)s" '
                         'auth permission' % {
                             'user': user.username,
                             'model_class': result_model_class.__name__,
                             'requested_perm': requested_drf_perm,
                             'auth_perm': auth_perm,
                         })
            return True

    logger.debug('User %(user)s has does NOT have DRF permission "%(requested_perm)s" for '
                 'all %(model_class)s objects. Granting django.contrib.auth permissions would '
                 'be the any of (%(auth_perm)s)' % {
                     'user': user.username,
                     'model_class': result_model_class.__name__,
                     'requested_perm': requested_drf_perm,
                     'auth_perm': ', '.join(['"%s"' % perm for perm in enabling_perms])})

    if suppress_exception:
        return False

    raise PermissionDenied('User %(user)s does not have required permission to access '
                           '%(method) %(uri)' % {
                               'user': user,
                               'method': request.method,
                               'uri': request.path, })

# Notes on DRF nested views:
# lookup_url_kwargs doesn't seem to be used/respected by nested routers in the same way as plain
# DRF - see StrainStudiesView for an example that works, but isn't clearly the most clear yet


class StrainStudiesView(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint that allows read-only access to the studies a given strain is used in (subject to
    user/role read access privileges on the studies).
    """
    serializer_class = StudySerializer
    lookup_url_kwarg = 'study_pk'

    def get_object(self):
        """
        Overrides the default implementation to provide flexible lookup for nested strain
        views (either based on local numeric primary key, or based on the strain UUID from ICE
        """
        # unlike the example, just do all the filtering in get_queryset() for consistency
        filters = {}
        queryset = self.get_queryset()

        obj = get_object_or_404(queryset, **filters)
        # verify class-level strain access. study permissions are enforced in get_queryset()
        self.check_object_permissions(self.request, obj)
        return obj

    def get_queryset(self):
        kwarg = '%s_%s' % (_STRAIN_NESTED_RESOURCE_PARENT_PREFIX, BASE_STRAIN_URL_KWARG)
        # get the strain identifier, which could be either a numeric (local) primary key, or a UUID
        strain_id = self.kwargs.get(kwarg)

        # figure out which it is
        strain_pk = strain_id if is_numeric_pk(strain_id) else None
        strain_uuid = strain_id if not strain_pk else None

        params = self.request.query_params

        line_active_status = self.request.query_params.get(
            ACTIVE_STATUS_PARAM, ACTIVE_STATUS_DEFAULT
        )
        user = self.request.user

        # only allow superusers through, since this is strain-related data that should only be
        # accessible to sysadmins. Also allows us to potentially avoid expensive joins to check for
        # per-study user/group permissions (though we've included below for the moment for safety)
        if not user.is_superuser:
            #  TODO: user group / merge in recent changes / throw PermissionsError or whatever
            return Response(status=status.HTTP_403_FORBIDDEN)

        study_pks_query = None
        if strain_pk:
            study_pks_query = Line.objects.filter(strains__pk=strain_pk)
        else:
            study_pks_query = Line.objects.filter(strains__registry_id=strain_uuid)
        study_pks_query = filter_by_active_status(
                study_pks_query, active_status=line_active_status).values_list(
                'study__pk').distinct()  # distict() needed bc of line active status filtering
        studies_query = Study.objects.filter(pk__in=study_pks_query)

        study_pk = self.kwargs.get(self.lookup_url_kwarg)
        if study_pk:
            studies_query = studies_query.filter(pk=study_pk)

        studies_query = _optional_timestamp_filter(studies_query, params)

        # enforce EDD's custom access controls for readability of the associated studies. Note:
        # at present this isn't strictly necessary because of the sysadmin check above but best
        # to enforce programatically in case the implementation of Study's access controls
        # changes later on
        if not Study.user_role_can_read(user):
            study_user_permission_q = Study.user_permission_q(user, StudyPermission.READ,
                                                              keyword_prefix='line__study__')
            studies_query = studies_query.filter(study_user_permission_q)
        # required by both line activity and studies permissions queries
        studies_query = studies_query.distinct()

        return studies_query


class StudyStrainsView(viewsets.ReadOnlyModelViewSet):
    """
        API endpoint that allows read-only viewing the unique strains used within a specific study
    """
    serializer_class = StrainSerializer
    STUDY_URL_KWARG = '%s_pk' % STUDIES_RESOURCE_NAME
    lookup_url_kwarg = 'strain_pk'

    # override

    def get_object(self):
        """
            Overrides the default implementation to provide flexible lookup for nested strain
            views (either based on local numeric primary key, or based on the strain UUID from ICE
            """
        filters = {}  # unlike the example, just do all the filtering in get_queryset() for
        # consistency
        queryset = self.get_queryset()
        obj = get_object_or_404(queryset, **filters)
        self.check_object_permissions(self.request, obj)
        return obj

    def get_queryset(self):
        # TODO: this query takes way too long to complete (at least in
        # local tests on a laptop) for users who are granted read
        # permission on a single study, but have no superuser basis for accessing it . Performance
        # problem appears to be related to study_user_permission_q and related joins. Consider
        # using Solr to index in addition to optimizing the query.
        logger.debug('%(class)s.%(method)s: kwargs = %(kwargs)s' % {
            'class':  StudyStrainsView.__name__,
            'method': self.get_queryset.__name__,
            'kwargs': self.kwargs
        })

        # extract URL keyword arguments
        study_id = self.kwargs[self.STUDY_URL_KWARG]

        study_id_is_pk = is_numeric_pk(study_id)
        line_active_status = self.request.query_params.get(ACTIVE_STATUS_PARAM,
                                                           ACTIVE_STATUS_DEFAULT)
        user = self.request.user

        # build the query, enforcing EDD's custom study access controls. Normally we'd require
        # sysadmin access to view strains, but the names/descriptions of strains in the study
        # should be visible to users with read access to a study that measures them
        study_user_permission_q = Study.user_permission_q(user, StudyPermission.READ,
                                                          keyword_prefix='line__study__')
        if study_id_is_pk:
            strain_query = Strain.objects.filter(study_user_permission_q, line__study__pk=study_id)
        else:
            logger.error("Non-numeric study IDs aren't supported.")
            return Strain.objects.none()

        strain_id = self.kwargs.get(self.lookup_url_kwarg)
        if strain_id:
            strain_id_is_pk = is_numeric_pk(strain_id)

            if strain_id_is_pk:
                strain_query = strain_query.filter(pk=strain_id)
            else:
                strain_query = strain_query.filter(registry_id=strain_id)

        # filter by line active status, applying the default (only active lines)
        strain_query = filter_by_active_status(strain_query, line_active_status,
                                               query_prefix='line__')
        # required by both study permission query and line active filters above
        strain_query = strain_query.distinct()

        return strain_query


class LinesViewSet(CustomPermFilteringMixin, viewsets.ReadOnlyModelViewSet):
    """
            API endpoint that allows to be searched, viewed, and edited.
        """
    permission_classes = [ImpliedPermissions]
    serializer_class = LineSerializer
    lookup_url_kwarg = 'id'

    def get_queryset(self):
        logger.debug('in %(class)s.%(method)s. kwargs=%(kwargs)s, query_params = '
                     '%(query_params)s' % {
                         'class': LinesViewSet.__name__,
                         'method': self.get_queryset.__name__,
                         'kwargs': self.kwargs,
                         'query_params': self.request.query_params,
                     })
        line_id = self.kwargs.get(self.lookup_url_kwarg, None)
        return build_lines_query(self.request, self.request.query_params, id_override=line_id)


class StudyLinesView(CustomPermFilteringMixin, mixins.ListModelMixin, GenericViewSet):
    """
        API endpoint that allows lines within a study to be searched, viewed, and edited.
    """
    permissions_classes = [ImpliedPermissions]
    serializer_class = LineSerializer
    lookup_url_kwarg = 'id'

    def get_queryset(self):
        logger.debug('in %(class)s.%(method)s. kwargs=%(kwargs)s' % {
            'class': StudyLinesView.__name__,
            'method': self.get_queryset.__name__,
            'kwargs': self.kwargs
        })
        line_id = self.kwargs.get(self.lookup_url_kwarg, None)
        study_id = self.kwargs.get(_STUDY_NESTED_ID_KWARG, None)
        return build_lines_query(self.request, self.request.query_params, study_id=study_id,
                                 id_override=line_id)

    # def create(self, request, *args, **kwargs):
    #     ##############################################################
    #     # enforce study write privileges
    #     ##############################################################
    #     study_pk = self.kwargs[self.STUDY_URL_KWARG]
    #     user = self.request.user
    #     StudyLinesView._test_user_write_access(user, study_pk)
    #     # if user has write privileges for the study, use parent implementation
    #     return super(StudyLinesView, self).create(request, *args, **kwargs)
    #
    # def update(self, request, *args, **kwargs):
    #     ##############################################################
    #     # enforce study write privileges
    #     ##############################################################
    #     study_pk = self.kwargs[self.STUDY_URL_KWARG]
    #     user = self.request.user
    #     StudyLinesView._test_user_write_access(user, study_pk)
    #     # if user has write privileges for the study, use parent implementation
    #     return super(StudyLinesView, self).update(request, *args, **kwargs)
    #
    # def destroy(self, request, *args, **kwargs):
    #     ##############################################################
    #     # enforce study write privileges
    #     ##############################################################
    #     study_pk = self.kwargs[self.STUDY_URL_KWARG]
    #     user = self.request.user
    #     StudyLinesView._test_user_write_access(user, study_pk)
    #     # if user has write privileges for the study, use parent implementation
    #     return super(StudyLinesView, self).destroy(request, *args, **kwargs)


class NotImplementedException(APIException):
    status_code = 500
    default_detail = 'Not yet implemented'


def _optional_timestamp_filter(queryset, query_params):
    """
    For any EddObject-derived model object, creates and returns an updated queryset that's
    optionally filtered by creation or update timestamp. Note that in both cases the start bound
    is inclusive and the end is exclusive.
    @:raise ParseError if the one of the related query parameters was provided, but was
    improperly formatted
    """
    query_param_name, value = None, None
    try:
        # filter by creation timestamp
        created_after_value = query_params.get(CREATED_AFTER_PARAM, None)
        created_before_value = query_params.get(CREATED_BEFORE_PARAM, None)
        if created_after_value:
            query_param_name, value = CREATED_AFTER_PARAM, created_after_value
            queryset = queryset.filter(created__mod_time__gte=created_after_value)
        if created_before_value:
            query_param_name, value = CREATED_BEFORE_PARAM, created_before_value
            queryset = queryset.filter(created__mod_time__lt=created_before_value)

        # filter by last update timestamp
        queryset = _optional_updated_filter(queryset, query_params)

    # if user provided a date in a format Django doesn't understand,
    # re-raise in a way that makes the client error apparent
    except TypeError:
        raise ParseError(detail='%(param)s %(value)s is not a valid date/time.' % {
            'param': query_param_name,
            'value': value,
        })

    return queryset


def _optional_updated_filter(queryset, query_params):
    updated_after = query_params.get(UPDATED_AFTER_PARAM, None)
    updated_before = query_params.get(UPDATED_BEFORE_PARAM, None)
    if updated_after:
        queryset = queryset.filter(updated__mod_time__gte=updated_after)
    if updated_before:
        queryset = queryset.filter(updated__mod_time__lt=updated_before)

    return queryset


def build_lines_query(request, query_params, study_id=None, id_override=None):

    ###############################################################################################
    # Build the query based on line-specific search parameters, but don't execute yet
    ###############################################################################################
    query = Line.objects.all()

    # filter by common EDDObject characteristics
    query = optional_edd_object_filtering(query_params, query,
                                          id_override=id_override)

    if study_id:
        study_pk = study_internals_initial_query(request, study_id, Line)
        query = query.filter(study_id=study_pk)
    else:
        query = filter_for_study_permission(request, query, Line, 'study__')

    return query


@api_view()
def search_test_view(request):
    msg = '%s %s Query params: %s ' % (request.method, request.path, request.query_params)
    logger.debug(msg)
    meta_comparisons = request.query_params.get(META_SEARCH_PARAM)

    query = Line.objects.all()

    if not meta_comparisons:  # TODO: security! merge in with existing lines search
        return query

    if isinstance(meta_comparisons, list):
        comparison_count = len(meta_comparisons)
        for index, comparison in enumerate(meta_comparisons):
            query = _filter_for_metadata(query, comparison, index + 1, comparison_count)
    else:
        query = _filter_for_metadata(query, meta_comparisons, 1, 1)
    return JsonResponse({'msg': msg})


@api_view()
def not_found_view(request):
    return JsonResponse({'error': 'Requested resource "%s" was not found'
                                  % request.build_absolute_uri()}, status=404)
