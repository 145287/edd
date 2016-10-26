"""
Defines the supported views and browsable API endpoint documentation for EDD's REST framework.
This class is a work in progress.

Assuming Django REST Framework (DRF) will be adopted in EDD, new and existing views should be
ported to this class over time. Many REST resources are currently defined in main/views.py,
but are not making use of DRF.

Note that many of the docstrings in this module use specific YAML formatting to define API
endpoint documentation viewable in the browser. See
http://django-rest-swagger.readthedocs.io/en/latest/yaml.html
"""

import logging
import re

from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework.permissions import DjangoModelPermissions, IsAuthenticated, BasePermission
from rest_framework.status import HTTP_403_FORBIDDEN

from edd.rest.serializers import (LineSerializer, MetadataGroupSerializer, MetadataTypeSerializer,
                                  StrainSerializer, StudySerializer, UserSerializer)
from jbei.rest.clients.edd.constants import (
    CASE_SENSITIVE_PARAM, LINE_ACTIVE_STATUS_PARAM, LINES_ACTIVE_DEFAULT, METADATA_TYPE_CONTEXT,
    METADATA_TYPE_GROUP, METADATA_TYPE_I18N, METADATA_TYPE_LOCALE, METADATA_TYPE_NAME_REGEX,
    QUERY_ACTIVE_OBJECTS_ONLY, QUERY_ALL_OBJECTS, QUERY_INACTIVE_OBJECTS_ONLY,
    STRAIN_CASE_SENSITIVE, STRAIN_NAME, STRAIN_NAME_REGEX, STRAIN_REGISTRY_ID,
    STRAIN_REGISTRY_URL_REGEX, STUDIES_RESOURCE_NAME,
)
from jbei.rest.utils import is_numeric_pk
from jbei.utils import PK_OR_TYPICAL_UUID_PATTERN, PK_OR_TYPICAL_UUID_REGEX
from main.models import Line, MetadataType, Strain, Study, StudyPermission, User, MetadataGroup
from rest_framework import (response, schemas, status, viewsets)
from rest_framework.decorators import api_view, renderer_classes
from rest_framework.exceptions import APIException
from rest_framework.relations import StringRelatedField
from rest_framework.response import Response
from rest_framework_swagger.renderers import OpenAPIRenderer, SwaggerUIRenderer



logger = logging.getLogger(__name__)

# Note on REST resource permissions:
# Many important resources below require some cludgy code to work with DjangoModelPermissions (a
# placeholder QuerySet in addition to overriding get_queryset()). See
# http://www.django-rest-framework.org/api-guide/permissions/#djangomodelpermissions

# class IsStudyReadable(permissions.BasePermission):
#     """
#     Custom permission to only allow owners of an object to edit it.
#     """
#
#     def has_object_permission(self, request, view, study):
#
#         # studies are only available to users who have read permissions on them
#         return study.user_can_read(request.user)

STRAIN_NESTED_RESOURCE_PARENT_PREFIX = r'strains'

STUDY_URL_KWARG = 'study'
BASE_STRAIN_URL_KWARG = 'id'  # NOTE: value impacts url kwarg names for nested resources
HTTP_MUTATOR_METHODS = ('POST', 'PUT', 'PATCH', 'UPDATE', 'DELETE')

# TODO: consider for all models below:
#   # Required for DjangoModelPermissions bc of get_queryset() override.
#   # See http://www.django-rest-framework.org/api-guide/permissions/#djangomodelpermissions
#   queryset = Strain.objects.none()
#   permissionClasses = (IsAuthenticated,) for views dependent on custom Study permissions


def permission_denied_handler(request):
    from django.http import HttpResponse
    # same as DRF provides in /rest/
    return HttpResponse('{"detail":"Authentication credentials were not provided."}',
                        HTTP_403_FORBIDDEN)


class DjangoModelImplicitViewPermissions(DjangoModelPermissions):
    # TODO allow superusers access
    """
    Extends DjangoModelPermissions to allow view access to only users who have the
    add/change/delete permission on models of the specified class.
    """
    _ADD_PERMISSION = '%(app_label)s.add_%(model_name)s'
    _CHANGE_PERMISSION = '%(app_label)s.change_%(model_name)s'
    _DELETE_PERMISSION = '%(app_label)s.delete_%(model_name)s'
    _IMPLICIT_VIEW_PERMISSION = [_ADD_PERMISSION, _CHANGE_PERMISSION, _DELETE_PERMISSION]
    perms_map = {
        'GET': _IMPLICIT_VIEW_PERMISSION,
        'HEAD': _IMPLICIT_VIEW_PERMISSION,
        'OPTIONS': [],  # only require user to be authenticated
        'POST': [_ADD_PERMISSION],
        'PUT': [_CHANGE_PERMISSION],
        'PATCH': [_CHANGE_PERMISSION],
        'DELETE': [_DELETE_PERMISSION],
    }


class ModelImplicitViewOrResultImpliedPermissions(BasePermission):
    """
    A custom permissions class similar DjangoModelPermissions that allows permissions to a REST
    resource based on the following:
     1) Unauthenticated users are always denied access
     2) A user who has class-level add/change/delete permissions explicitly granted
     django.contrib.auth permissions may exercise those capabilities
     2) A user who has any add/change/delete class-level permission explicitly granted also has
     implied class-level view access (though view isn't explicitly defined as an auth permission)
     3) If the inferred_permissions property is defined / non-empty, the existence of one or more
     results  in the queryset implies that the user has a level of inferred permission only on
     the objects returned by queryset. This inference should align with DRF's pattern of queryset
     filtering based on only the objects a user has access to. In most cases, this feature will
     probably only be used to infer view access to queryset results while avoiding a separate DB
     query in this class to check user permissions that are already checked as part of queryset
     result filtering.
    """

    # django.contrib.auth permissions explicitly respected or used as the basis for interring view
    # permission. See similar (though distinct) logic in DRF's DjangoModelPermissions class.
    _AUTH_ADD_PERMISSION = '%(app_label)s.add_%(model_name)s'
    _AUTH_CHANGE_PERMISSION = '%(app_label)s.change_%(model_name)s'
    _AUTH_DELETE_PERMISSION = '%(app_label)s.delete_%(model_name)s'
    _AUTH_IMPLICIT_VIEW_PERMISSION = [_AUTH_ADD_PERMISSION, _AUTH_CHANGE_PERMISSION,
                                      _AUTH_DELETE_PERMISSION]
    django_auth_perms_map = {
        'GET': _AUTH_IMPLICIT_VIEW_PERMISSION,
        'HEAD': _AUTH_IMPLICIT_VIEW_PERMISSION,
        'OPTIONS': [],  # only require user to be authenticated
        'POST': [_AUTH_ADD_PERMISSION],
        'PUT': [_AUTH_CHANGE_PERMISSION],
        'PATCH': [_AUTH_CHANGE_PERMISSION],
        'DELETE': [_AUTH_DELETE_PERMISSION],
    }

    """
    The list of permissions to infer on the specific ORM query result objects returned by the
    queryset. Accepted values are defined by QS_INFERRED_* constants attached to this class
    """
    QS_INFERRED_VIEW_PERMISSION = 'qs_view'
    QS_INFERRED_CHANGE_PERMISSION = 'qs_change'
    QS_INFERRED_DELETE_PERMISSION = 'qs_delete'
    QS_INFERRED_ADD_PERMISSION = 'qs_add'
    method_to_inferred_perm_map = {
        'GET': QS_INFERRED_VIEW_PERMISSION,
        'HEAD': QS_INFERRED_VIEW_PERMISSION,
        'OPTIONS': QS_INFERRED_VIEW_PERMISSION,
        'POST': QS_INFERRED_ADD_PERMISSION,
        'PUT': QS_INFERRED_CHANGE_PERMISSION,
        'PATCH': QS_INFERRED_CHANGE_PERMISSION,
        'DELETE': QS_INFERRED_DELETE_PERMISSION,
    }

    # optional implied add/change/view permissions on the specific objects returned by the queryset
    queryset_inferred_permissions = [QS_INFERRED_VIEW_PERMISSION]

    def get_enabling_permissions(self, http_method, orm_model_cls):
        """
        Given a model class and an HTTP method, return the list of permission
        codes that enable the user to access this resource (having any of them will permit access)
        """
        kwargs = {
            'app_label': orm_model_cls._meta.app_label, 'model_name': orm_model_cls._meta.model_name
        }
        return [perm % kwargs for perm in self.django_auth_perms_map[http_method]]

    def has_permission(self, request, view):  # TODO: adjust logging level after testing complete
        # Workaround to ensure DjangoModelPermissions are not applied
        # to the root view when using DefaultRouter.
        if getattr(view, '_ignore_model_permissions', False):
            return True

        # get the queryset, depending on how the view defines it
        if hasattr(view, 'get_queryset'):
            queryset = view.get_queryset()
        else:
            queryset = getattr(view, 'queryset', None)

        assert queryset is not None, ('Cannot apply permissions on a view that '
                                      'does not set `.queryset` or have a `.get_queryset()` '
                                      'method.')
        #########################################################

        http_method = request.method
        enabling_perms = self.get_enabling_permissions(http_method, queryset.model)
        user = request.user

        # unauthenticated users never have permission
        if not (user and user.is_authenticated()):
            logger.debug('User %(username)s is not authenticated. Denying access to %(url)s' % {
                            'username': user.username,
                            'url': request.path,
                        })
            return False

        # superusers users always have permission
        if user.is_superuser:
            logger.debug('User %(username)s is a superuser.  Allowing access to %(method)s '
                         '%(url)s' % {
                            'username': user.username,
                            'method': request.method,
                            'url': request.path,
                        })
            return True

        # if user has been explicitly granted any of the class-level permissions that enable
        # access, allow access
        for permission in enabling_perms:
            if user.has_perm(permission):
                logger.debug('User %(username)s has explicitly-granted permission %(permission)s on'
                             ' resource %(method)s %(url)s' % {
                                'username': user.username,
                                'permission': permission,
                                'method': request.method,
                                'url': request.path, })
                return True

        # if we can't infer permission and don't have any explicitly permission is DENIED
        if not self.queryset_inferred_permissions:
            logger.debug('User %(username)s has no explicitly-granted permissions on '
                         'resource %(url)s. Denying access since no inferred permissions are '
                         'defined.' % {
                            'username': user.username,
                            'method': request.method,
                            'url': request.path,
                        })
            return False

        # note: we'll just return an empty resultset, but still tell the user they have access to
        # the resource since it would be confusing for the return code to change based solely on
        # the addition of an item
        requested_permission = self.method_to_inferred_perm_map[http_method]
        has_permission = requested_permission in self.queryset_inferred_permissions

        has = 'has' if has_permission else "doesn't have"
        logger.debug('User %(username)s %(has)s inferred permission %(permission)s on resource '
                     '%(method)s %(url)s' % {
                        'username': user.username,
                        'has': has,
                        'permission': requested_permission,
                        'method': request.method,
                        'url': request.path, })
        return has_permission

@api_view()
@renderer_classes([OpenAPIRenderer, SwaggerUIRenderer])
def schema_view(request):
    generator = schemas.SchemaGenerator(title='Experiment Data Depot')
    return response.Response(generator.get_schema(request=request))

class MetadataTypeViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint that supports viewing and searching .EDD's metadata types
    TODO: implement/confirm access controls for unsafe methods, then make writable
    """

    # Note: queryset must be defined for DjangoModelPermissions in addition to get_queryset(). See
    # related  comment/URL above
    permission_classes = [DjangoModelPermissions]
    queryset = MetadataType.objects.all()
    serializer_class = MetadataTypeSerializer

    def get_queryset(self):
        pk = self.kwargs.get('pk', None)

        queryset = MetadataType.objects.all()
        if pk:
            queryset = queryset.filter(pk=pk)

        params = self.request.query_params
        if params:
            group_id = params.get(METADATA_TYPE_GROUP)
            if group_id:
                if is_numeric_pk(group_id):
                    queryset = queryset.filter(group=group_id)
                else:
                    queryset = queryset.filter(group__group_name=group_id)

            for_context = params.get(METADATA_TYPE_CONTEXT)
            if for_context:
                queryset = queryset.filter(for_context=for_context)

            type_i18n = params.get(METADATA_TYPE_I18N)
            if type_i18n:
                queryset = queryset.filter(type_i18n=type_i18n)

            queryset = _do_optional_regex_filter(params, queryset, 'type_name',
                                                 METADATA_TYPE_NAME_REGEX,
                                                 METADATA_TYPE_LOCALE,)
        return queryset


def _do_optional_regex_filter(query_params_dict, queryset, data_member_name, regex_param_name,
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
    permission_classes = [IsAuthenticated, DjangoModelPermissions]   # TODO: allows unrestricted
                                                                     # read access
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


class StrainViewSet(viewsets.ModelViewSet):
    """
    Defines the set of REST API views available for the base /rest/strain/ resource. Nested views
    are defined elsewhere (e.g. StrainStudiesView).
    """

    permission_classes = [ModelImplicitViewOrResultImpliedPermissions]

    # Note: queryset must be defined for DjangoModelPermissions in addition to get_queryset(). See
    # related  comment/URL above
    queryset = Strain.objects.none()

    serializer_class = StrainSerializer
    lookup_url_kwarg = BASE_STRAIN_URL_KWARG
    lookup_value_regex = PK_OR_TYPICAL_UUID_REGEX

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

        logger.debug('in %(class)s.%(method)s' % {
            'class': self.__class__.__name__,
            'method': self.get_queryset.__name__})

        # never show anything to un-authenticated users
        user = self.request.user
        if (not user) or not user.is_authenticated():
            return Strain.objects.none()

        # build a query, filtering by the provided user inputs (starting out unfiltered)
        query = Strain.objects.all()

        # if a strain UUID or local numeric pk was provided, get it
        if self.kwargs:
            strain_id_filter = self.kwargs.get(self.lookup_url_kwarg)
            if is_numeric_pk(strain_id_filter):
                query = query.filter(pk=strain_id_filter)
            else:
                query = query.filter(registry_id=strain_id_filter)
        # otherwise, we're searching strains, so filter them according to the provided params
        else:
            # parse optional query parameters
            query_params = self.request.query_params
            strain_id_filter = query_params.get(self.lookup_url_kwarg)  # TODO: remove?
            local_pk_filter = query_params.get('pk')
            registry_id_filter = query_params.get(STRAIN_REGISTRY_ID)
            registry_url_regex_filter = query_params.get(STRAIN_REGISTRY_URL_REGEX)
            case_sensitive = query_params.get(STRAIN_CASE_SENSITIVE)
            name_filter = query_params.get(STRAIN_NAME)

            # if provided an ambiguously-defined unique ID for the strain, apply it based
            # on the format of the provided value
            if strain_id_filter:
                if is_numeric_pk(strain_id_filter):
                    query = query.filter(pk=strain_id_filter)
                else:
                    query = query.filter(registry_id=strain_id_filter)

            if local_pk_filter:
                query = query.filter(pk=local_pk_filter)

            if registry_id_filter:
                query = query.filter(registry_id=registry_id_filter)

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

            query = _do_optional_regex_filter(query_params, query, 'name', STRAIN_NAME_REGEX, None)

        query = query.select_related('object_ref')  # TODO: remove -- unneccessary

        # filter results to ONLY the strains accessible by this user. Note that this may
        # prevent some users from accessing strains, depending on how EDD's permissions are set up,
        # but the present alternative is to create a potential leak of experimental strain names /
        # descriptions to potentially competing researchers that use the same EDD instance
        print('User: %s' % str(user))  # TODO: remove debug stmt
        requested_permission = get_requested_study_permission(self.request.method)

        # if additions to the DB query are needed to filter results for users with permission to
        # view them
        if not ((requested_permission == StudyPermission.NONE) or
                (requested_permission == StudyPermission.READ and Study.user_role_can_read(user))):
            user_permission_q = Study.user_permission_q(user, requested_permission,
                                                        keyword_prefix='line__study__')
            query = query.filter(user_permission_q).distinct()

        result_count = len(query)  # Note: more efficient for logging than qs.count()
        logger.debug('StrainViewSet query count=%d' % len(query))
        if result_count < 10:
            logger.debug(query)

        return query

    def list(self, request, *args, **kwargs):
        """
            List strains the user has access to.

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

    def destroy(self, request, *args, **kwargs):
        """
            Delete an existing strain.
            ---
                omit_serializer: true
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


class LineViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint that allows Lines to we viewed or edited.
    TODO: add edit/create capability back in, based on study-level permissions.
    TODO: control view on the basis of study permissions
    """
    queryset = Line.objects.all()  # TODO: strange that this appears required. Remove?
    serializer_class = LineSerializer
    contact = StringRelatedField(many=False)
    experimenter = StringRelatedField(many=False)

    def get_queryset(self):
        query = Line.objects.all()

        # filter by line active status, applying the default (only active lines)
        active_status = self.request.query_params.get(LINE_ACTIVE_STATUS_PARAM,
                                                      LINES_ACTIVE_DEFAULT)
        query = filter_by_active_status(query, active_status, '')
        query = query.select_related('object_ref')
        return query


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
    if active_status == QUERY_ALL_OBJECTS:
        return queryset

    # construct an ORM query keyword based on the relationship of the filtered model class to the
    # Django model class being queried. For example 1 above, when querying Line.objects.all(),
    # we prepend '' and come up with Q(active=True). For example 2, when querying
    # Strain, we prepend 'line__' and get Q(line__active=True)
    query_keyword = '%sactive' % query_prefix
    # return requested status, or active objects only if input was bad
    active_value = (active_status != QUERY_INACTIVE_OBJECTS_ONLY)
    # TODO: remove debug stmt
    print('Active query %s' % str({query_keyword: active_value}))
    active_criterion = Q(**{query_keyword: active_value})
    return queryset.filter(active_criterion)


class StudyViewSet(viewsets.ReadOnlyModelViewSet):  # read-only for now...see TODO below
    """
    API endpoint that provides read-only access to studies, subject to user/role read access
    controls. Study write access is a TODO. To view the list of nested resources in the
    browseable API, access this resource, then press the 'Options' button.
    """
    serializer_class = StudySerializer
    contact = StringRelatedField(many=False)

    def get_queryset(self):
        study_pk = self.kwargs.get('pk')

        user = self.request.user

        permission = StudyPermission.READ
        if self.request.method in HTTP_MUTATOR_METHODS:
            permission = StudyPermission.WRITE

        # if the user's admin / staff role gives read access to all Studies, don't bother querying
        # the database for specific permissions defined on this study
        if permission == StudyPermission.READ and Study.user_role_can_read(user):
            if study_pk:
                study_query = Study.objects.filter(pk=study_pk)
            else:
                study_query = Study.objects.all()
        # otherwise, enforce user access permissions
        else:
            user_permission_q = Study.user_permission_q(user, permission)
            # NOTE: distinct is required since this query can return multiple rows for the same
            # study, one per permission that gives this user access to it
            if study_pk:
                study_query = Study.objects.filter(user_permission_q, pk=study_pk).distinct()
            else:
                study_query = Study.objects.filter(user_permission_q).distinct()

        return study_query

    def create(self, request, *args, **kwargs):
        if not Study.user_can_create(request.user):
            return Response(status=status.HTTP_403_FORBIDDEN)

        return super(StudyViewSet, self).create(request, *args, **kwargs)

    # TODO: test whether update / destroy are protected by get_queryset, or whether they need
        # separate permissions checks to protect them. Then change back to a ModelViewSet.


NUMERIC_PK_PATTERN = re.compile('^\d+$')

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
        kwarg = '%s_%s' % (STRAIN_NESTED_RESOURCE_PARENT_PREFIX, BASE_STRAIN_URL_KWARG)
        # get the strain identifier, which could be either a numeric (local) primary key, or a UUID
        strain_id = self.kwargs.get(kwarg)

        print('lookup_url_kwarg = %s, kwargs = %s' %
              (str(self.lookup_url_kwarg), str(self.kwargs)))

        # figure out which it is
        strain_pk = strain_id if is_numeric_pk(strain_id) else None
        strain_uuid = strain_id if not strain_pk else None

        print('strain_pk=%s, strain_uuid=%s' % (strain_pk, strain_uuid))

        line_active_status = self.request.query_params.get(
            LINE_ACTIVE_STATUS_PARAM, LINES_ACTIVE_DEFAULT
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
            'class': StudyLineView.__name__,
            'method': self.get_queryset.__name__,
            'kwargs': self.kwargs
        })

        # extract URL keyword arguments
        study_id = self.kwargs[self.STUDY_URL_KWARG]

        study_id_is_pk = is_numeric_pk(study_id)
        line_active_status = self.request.query_params.get(LINE_ACTIVE_STATUS_PARAM,
                                                           LINES_ACTIVE_DEFAULT)
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


class StudyLineView(viewsets.ModelViewSet):  # LineView(APIView):
    """
        API endpoint that allows lines within a study to be searched, viewed, and edited.
    """
    serializer_class = LineSerializer
    lookup_url_kwarg = 'line_pk'
    STUDY_URL_KWARG = '%s_pk' % STUDIES_RESOURCE_NAME

    def get_queryset(self):
        logger.debug('in %(class)s.%(method)s' % {
            'class': StudyLineView.__name__, 'method': self.get_queryset.__name__
        })
        print('kwargs: ' + str(self.kwargs))  # TODO: remove debug aid
        print('query_params: ' + str(self.request.query_params))  # TODO: remove debug aid

        # extract study pk URL argument. line pk, if present, will be handled automatically by
        # get_object() inherited from the parent class
        study_pk = self.kwargs[self.STUDY_URL_KWARG]

        user = self.request.user
        requested_permission = (StudyPermission.WRITE if self.request.method in
                                HTTP_MUTATOR_METHODS else StudyPermission.READ)

        # if the user's admin / staff role gives read access to all Studies, don't bother querying
        # the database for specific permissions defined on this study
        if requested_permission == StudyPermission.READ and Study.user_role_can_read(user):
            line_query = Line.objects.filter(study__pk=study_pk)
        else:
            study_user_permission_q = Study.user_permission_q(user, requested_permission,
                                                              keyword_prefix='study__')
            line_query = Line.objects.filter(study_user_permission_q, study__pk=study_pk)

        line_query = _do_optional_regex_filter(self.request.query_params, line_query, 'name',
                                               STUDY_LINE_NAME_REGEX, None,)

        # filter by line active status, applying the default (only active lines)
        line_active_status = self.request.query_params.get(LINE_ACTIVE_STATUS_PARAM,
                                                           LINES_ACTIVE_DEFAULT)
        line_query = filter_by_active_status(line_query, line_active_status)
        # distinct() required by *both* study permissions check and line activity filter above
        line_query = line_query.distinct()

        return line_query

    def create(self, request, *args, **kwargs):
        ##############################################################
        # enforce study write privileges
        ##############################################################
        study_pk = self.kwargs[self.STUDY_URL_KWARG]
        user = self.request.user
        StudyLineView._test_user_write_access(user, study_pk)
        # if user has write privileges for the study, use parent implementation
        return super(StudyLineView, self).create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        ##############################################################
        # enforce study write privileges
        ##############################################################
        study_pk = self.kwargs[self.STUDY_URL_KWARG]
        user = self.request.user
        StudyLineView._test_user_write_access(user, study_pk)
        # if user has write privileges for the study, use parent implementation
        return super(StudyLineView, self).update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        ##############################################################
        # enforce study write privileges
        ##############################################################
        study_pk = self.kwargs[self.STUDY_URL_KWARG]
        user = self.request.user
        StudyLineView._test_user_write_access(user, study_pk)
        # if user has write privileges for the study, use parent implementation
        return super(StudyLineView, self).destroy(request, *args, **kwargs)

    @staticmethod
    def _test_user_write_access(user, study_pk):
        # return a 403 error if user doesn't have write access
        try:
            study = Study.objects.get(pk=study_pk)
            if study.user_can_write(user):
                return None
        except Study.DoesNotExist as e:
            logger.warning('Got request to modify non-existent study %s', study_pk)
        raise PermissionDenied()


class NotImplementedException(APIException):
    status_code = 500
    default_detail = 'Not yet implemented'
