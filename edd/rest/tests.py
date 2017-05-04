"""
Unit tests for EDD's REST API.
"""
from uuid import UUID

from django.contrib.auth.models import AnonymousUser, Permission
import json
from edd.rest.views import StrainViewSet

from main.models import User, Strain, Study, Line, StudyPermission
from rest_framework.test import (APIRequestFactory, force_authenticate, APIClient,
                                 APITransactionTestCase, APITestCase)
from rest_framework.status import (HTTP_200_OK, HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN,
                                   HTTP_404_NOT_FOUND, )

import logging

logger = logging.getLogger(__name__)

SEPARATOR = '*' * 40

# See
# http://www.django-rest-framework.org/api-guide/authentication/#unauthorized-and-forbidden-responses
DRF_UNAUTHENTICATED_PERMISSION_DENIED_CODES = (HTTP_403_FORBIDDEN, HTTP_401_UNAUTHORIZED)

# status code always returned by Django REST Framework when a successfully
# authenticated request is denied permission to a resource.
# See http://www.django-rest-framework.org/api-guide/authentication/#unauthorized-and-forbidden
# -responses
DRF_AUTHENTICATED_BUT_DENIED = HTTP_403_FORBIDDEN

ADD_STRAIN_CODENAME = 'add_strain'
CHANGE_STRAIN_CODENAME = 'change_strain'
DELETE_STRAIN_CODENAME = 'delete_strain'

UNPRIVILEGED_USERNAME = 'unprivileged_user'
STAFF_USERNAME = 'staff.user'
STAFF_STUDY_USERNAME = 'staff.study.user'
ADMIN_USERNAME = 'admin.user'
ADMIN_STAFF_USERNAME = 'admin.staff.user'
STAFF_STRAIN_USER = 'staff.strain.user'
STUDY_OWNER_USERNAME = 'unprivileged.study.owner'
STUDY_READER_USERNAME = 'study.reader.user'
STUDY_READER_GROUP_USER = 'study.reader.group.user'
STUDY_READER_GROUP_NAME = 'study_readers'
STUDY_WRITER_GROUP_USER = 'study.writer.group.user'
STUDY_WRITER_USERNAME = 'study.writer.user'
PLAINTEXT_TEMP_USER_PASSWORD = 'password'

STRAIN_RESOURCE_URL = '/rest/strains'


class StrainResourceTests(APITestCase):
    #available_apps = ['main', 'django.contrib.auth']

    @classmethod
    def setUpTestData(cls):  # TODO: resolve fixture creation / setUp() use w/
        """
        Creates strains, users, and study/line combinations to test the REST resource's application
        of user permissions. Note that this has to run *after* setUp() because it depends on the
        test_user fixture, which isn't applied at the time setUp() is run.
        """
        #super(StrainResourceTests, self).setUp()
        # TODO: do a more granular test of exactly which is required for each resource method
        add_strain_permission = Permission.objects.get(codename=ADD_STRAIN_CODENAME)
        change_strain_permission = Permission.objects.get(codename=CHANGE_STRAIN_CODENAME)
        delete_strain_permission = Permission.objects.get(codename=DELETE_STRAIN_CODENAME)

        # unprivileged
        cls.unprivileged_user = User.objects.create_user(username=UNPRIVILEGED_USERNAME,
                                                          email='unprivileged@localhost',
                                                          password=PLAINTEXT_TEMP_USER_PASSWORD)
        # admin w/ no extra privileges
        cls.superuser = User.objects.create_user(username=ADMIN_USERNAME,
                                                  email='admin@localhost',
                                                  password=PLAINTEXT_TEMP_USER_PASSWORD)
        cls.superuser.is_superuser = True
        cls.superuser.user_permissions.add(change_strain_permission)
        cls.superuser.save()
        # re - fetch from database to force permissions
        # refresh http://stackoverflow.com/questions/10102918/cant-change-user-permissions-during
        # -unittest-in-django
        cls.superuser = User.objects.get(username=ADMIN_USERNAME)

        # as a stopgap, create the "system" user that isn't being applied via migrations...
        # TODO: do this more cleanly later
        cls.system_user = User.objects.create_user(username='system',
                                                    email='jbei-edd-admin@lists.lbl.gov')

        # admin/staff user w/ no extra privileges
        cls.admin_staff_user = User.objects.create_user(username=ADMIN_STAFF_USERNAME,
                                                         email='admin@localhost',
                                                         password=PLAINTEXT_TEMP_USER_PASSWORD)
        cls.admin_staff_user.is_admin = True
        cls.admin_staff_user.is_staff = True
        # self.admin_staff_user.user_permissions.add(add_strain_permission)
        # self.admin_staff_user.user_permissions.add(change_strain_permission)
        # self.admin_staff_user.user_permissions.add(delete_strain_permission)
        cls.admin_staff_user.save()
        cls.admin_staff_user = User.objects.get(username=ADMIN_STAFF_USERNAME)  # refetch from
        # database to
        # force permissions
        # refresh http://stackoverflow.com/questions/10102918/cant-change-user-permissions-during
        # -unittest-in-django

        # staff w/ no extra privileges
        cls.staff_user = User(username=STAFF_USERNAME, email='staff@localhost')
        cls.staff_user.set_password(PLAINTEXT_TEMP_USER_PASSWORD)  # Note: setting password attr
        # directly doesn't
        # work. See "login" subsection of
        # https://docs.djangoproject.com/en/1.9/topics/testing/tools/#making-requests
        cls.staff_user.is_staff = True
        cls.staff_user.save()

        # staff user with access to strain admin
        cls.staff_strain_user = User.objects.create_user(username=STAFF_STRAIN_USER,
                                                          email='staff.study@localhost',
                                                          password=PLAINTEXT_TEMP_USER_PASSWORD)
        cls.staff_strain_user.is_staff = True
        cls.staff_strain_user.user_permissions.add(add_strain_permission)
        cls.staff_strain_user.user_permissions.add(change_strain_permission)
        cls.staff_strain_user.user_permissions.add(delete_strain_permission)
        cls.staff_strain_user.save()
        cls.staff_strain_user = User.objects.get(username=STAFF_STRAIN_USER)  # refetch from
        # database to
        # force permissions
        # refresh http://stackoverflow.com/questions/10102918/cant-change-user-permissions-during
        # -unittest-in-django

        # set up a study with lines/strains/permissions that allow us to test unprivileged user
        # access to ONLY the strains used in studies the user has read access to.
        cls.study_owner = User.objects.create_user(  # TODO: unused
                username=STUDY_OWNER_USERNAME, email='study_owner@localhost',
                password=PLAINTEXT_TEMP_USER_PASSWORD)

        cls.study_read_only_user = User.objects.create_user(
            username=STUDY_READER_USERNAME, email='study_read_only@localhost',
            password=PLAINTEXT_TEMP_USER_PASSWORD)

        cls.study_read_only_group_user = User.objects.create_user(
                username=STUDY_READER_GROUP_USER, email='study.reader@localhost',
                password=PLAINTEXT_TEMP_USER_PASSWORD)

        cls.study_write_only_group_user = User.objects.create_user(
            username=STUDY_WRITER_GROUP_USER, email='study.writer@localhost',
            password=PLAINTEXT_TEMP_USER_PASSWORD
        )

        cls.study_write_only_user = User.objects.create_user(
            username=STUDY_WRITER_USERNAME, email='study.writer@localhost',
            password=PLAINTEXT_TEMP_USER_PASSWORD
        )

        cls.study = Study(name='Test study')
        cls.study.save()
        cls.study.userpermission_set.all().update_or_create(
                user=cls.study_owner, study=cls.study,
                permission_type=StudyPermission.READ)
        cls.study.userpermission_set.update_or_create(user=cls.study_owner,
                                                       study=cls.study,
                                                       permission_type=StudyPermission.WRITE)
        cls.study.save()

        cls.study_strain1 = Strain(name='Study strain 1')
        cls.study_strain1.save()
        cls.study_strain2 = Strain(name='Study strain 2')
        cls.study_strain2.save()
        cls.non_study_strain = Strain(name='Non-study strain')
        cls.non_study_strain.save()

        line1 = Line(name='Study strain1 line', study=cls.study)
        line1.save()
        line1.strains.add(cls.study_strain1)
        line1.save()

        line2 = Line(name='Study strain2 line A', study=cls.study)
        line2.save()
        line2.strains.add(cls.study_strain2)
        line2.save()

        line3 = Line(name='Study strain2 line B', study=cls.study)
        line3.save()
        line3.strains.add(cls.study_strain2)
        # TODO: mark lines 2/3 as replicates?

        line5 = Line(name='Study non-strain line', study=cls.study)
        line5.save()

    # TODO: expand strain actions tested (currently just detail/list)

    def _enforce_strain_read_access(self, url, is_list):
        permissions_err_msg = 'Test permissions setup appears not to have worked'
        self.assertTrue(self.staff_strain_user.has_perm('main.%s' % ADD_STRAIN_CODENAME),
                        permissions_err_msg)
        self.assertTrue(self.staff_strain_user.has_perm('main.%s' % CHANGE_STRAIN_CODENAME),
                        permissions_err_msg)
        self.assertTrue(self.staff_strain_user.has_perm('main.%s' % DELETE_STRAIN_CODENAME),
                        permissions_err_msg)
        self.assertTrue(self.superuser.is_superuser)

        factory = APIRequestFactory()

        # verify that an un-authenticated request gets a 404
        request = factory.get(url, user=AnonymousUser())
        response = StrainViewSet.as_view({'get': 'list'})(request)
        self.assertTrue(response.status_code in DRF_UNAUTHENTICATED_PERMISSION_DENIED_CODES)

        # verify that various authenticated, but unprivileged users
        # are denied access to strains without class level permission or access to a study that
        # uses them. This is important, because viewing strain names/descriptions for
        # un-publicized studies could compromise the confidentiality of the research before
        # it's published self.require_authenticated_access_denied(self.study_owner)
        require_no_result_method = (self._require_authenticated_access_empty_paged_result if
                                    is_list else
                                    self._require_authenticated_access_empty_result)

        #  enforce access denied behavior for the list resource -- same as just showing an empty
        #  list
        if is_list:
            require_no_result_method(url, self.unprivileged_user)
            require_no_result_method(url, self.staff_user)

        # enforce access denied behavior for the strain detail -- permission denied
        else:
            self._require_authenticated_access_denied(url, self.unprivileged_user)
            self._require_authenticated_access_denied(url, self.staff)

        # test that an 'admin' user can access strains even without the write privilege
        self._require_authenticated_access_allowed(url, self.superuser)

        # test that a 'staff' user with strain write privileges can use the resource
        self._require_authenticated_access_allowed(url, self.staff_strain_user)

        # test that an otherwise unprivileged user with read access to a study containing the
        # strain can also use the strain resource to view the strain
        self._require_authenticated_access_allowed(url, self.study_owner)

    def test_strain_nested_study_read_access(self):
        factory = APIRequestFactory()

    def test_client_result_paging(self):
        # TODO: test support for results paging in the client-side REST code
        pass

    def test_strain_uuid_pattern_match(self):
        # TODO: test pattern matching for UUID's. had to make code changes during initial testing
        # to enforce matching for UUID's returned by EDD's REST API, which is pretty wierd after
        # prior successful tests.
        pass

    def _require_authenticated_access_denied(self, url, user):
        logged_in = self.client.login(username=user.username,
                                      password=PLAINTEXT_TEMP_USER_PASSWORD)

        self.assertTrue(logged_in, 'Client login failed. Unable to continue with the test.')

        # request = request_factory.get(self.STRAIN_RESOURCE_URL, user=user)
        # response = StrainViewSet.as_view({'get': 'list'})(request)  # TODO: expand actions tested

        response = self.client.get(url)
        expected_status = DRF_AUTHENTICATED_BUT_DENIED
        print('Location: %s' % response.get('Location'))
        self.assertEquals(expected_status, response.status_code,
                          "Wrong response status code. Expected %(expected)d status but got "
                          "%(observed)d" % {
                              'expected': expected_status,
                              'observed': response.status_code})
        self.client.logout()

    def _require_authenticated_access_allowed(self, url, user):
        logged_in = self.client.login(username=user.username,
                                      password=PLAINTEXT_TEMP_USER_PASSWORD)

        self.assertTrue(logged_in, 'Client login failed. Unable to continue with the test.')

        # request = request_factory.get(self.STRAIN_RESOURCE_URL, user=user)
        # response = StrainViewSet.as_view({'get': 'list'})(request)  # TODO: expand actions tested

        response = self.client.get(url)
        required_result_status = HTTP_200_OK
        self.assertEquals(required_result_status, response.status_code,
                          "Wrong response status code. Expected %(expected)d status but got "
                          "%(observed)d" % {
                              'expected': required_result_status,
                              'observed': response.status_code})
        self.client.logout()

    def _require_authenticated_access_not_found(self, url, user):
        logged_in = self.client.login(username=user.username,
                                      password=PLAINTEXT_TEMP_USER_PASSWORD)

        self.assertTrue(logged_in, 'Client login failed. Unable to continue with the test.')

        # request = request_factory.get(self.STRAIN_RESOURCE_URL, user=user)
        # response = StrainViewSet.as_view({'get': 'list'})(request)  # TODO: expand actions tested

        response = self.client.get(url)
        required_result_status = HTTP_404_NOT_FOUND
        self.assertEquals(required_result_status, response.status_code,
                          "Wrong response status code. Expected %d status but got %d" % (
                              required_result_status, response.status_code))

    def _require_authenticated_access_empty_result(self, url, user):
        logged_in = self.client.login(username=user.username,
                                      password=PLAINTEXT_TEMP_USER_PASSWORD)

        self.assertTrue(logged_in, 'Client login failed. Unable to continue with the test.')

        # request = request_factory.get(self.STRAIN_RESOURCE_URL, user=user)
        # response = StrainViewSet.as_view({'get': 'list'})(request)  # TODO: expand actions tested

        response = self.client.get(url)
        required_result_status = HTTP_200_OK
        self.assertEquals(required_result_status, response.status_code,
                          "Wrong response status code. Expected %d status but got %d" % (
                              required_result_status, response.status_code))

        print('Response content (empty list expected): %s' % str(response.content))  # TODO: remove
        # debug stmt
        self.assertFalse(bool(response.content))

    def _require_authenticated_access_empty_paged_result(self, url, user):
        logged_in = self.client.login(username=user.username,
                                      password=PLAINTEXT_TEMP_USER_PASSWORD)

        self.assertTrue(logged_in, 'Client login failed. Unable to continue with the test.')

        # request = request_factory.get(self.STRAIN_RESOURCE_URL, user=user)
        # response = StrainViewSet.as_view({'get': 'list'})(request)  # TODO: expand actions tested

        response = self.client.get(url)
        required_result_status = HTTP_200_OK
        self.assertEquals(required_result_status, response.status_code,
                          "Wrong response status code. Expected %d status but got %d" % (
                              required_result_status, response.status_code))

        # TODO:
        print('Response content (empty paged result expected): %s' % str(response.content))
        # remove debug stmt
        content_dict = json.loads(response.content)
        self.assertFalse(bool(content_dict['results']))
        self.assertEquals(0, content_dict['count'])
        self.assertEquals(None, content_dict['previous'])
        self.assertEquals(None, content_dict['next'])

    def test_paging(self):
        pass

    def test_strain_list_read_access(self):
        """
        Tests GET /rest/strain
        """
        print(SEPARATOR)
        print('%s(): ' % self.test_strain_list_read_access.__name__)
        print(SEPARATOR)

        list_url = '%s/' % STRAIN_RESOURCE_URL
        print("Testing read access for %s" % list_url)
        self._enforce_strain_read_access(list_url, True)

    def test_strain_detail_read_access(self):
        print(SEPARATOR)
        print('%s(): ' % self.test_strain_detail_read_access.__name__)
        print(SEPARATOR)

        # create a strain so we can test access to its detail view
        strain = Strain.objects.create(name='Test strain', description='Description goes here')

        # construct the URL for the strain detail view
        strain_detail_url = '%(base_strain_url)s/%(pk)d/' % {
            'base_strain_url':  STRAIN_RESOURCE_URL,
            'pk': strain.pk, }

        self._enforce_strain_read_access(strain_detail_url, False)