"""
Unit tests for EDD's REST API.
"""
import json
import logging
from uuid import UUID

from django.contrib.auth.models import AnonymousUser, Permission, Group
from rest_framework.status import (HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST,
                                   HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND)
from rest_framework.test import (APIRequestFactory, APITestCase)

from edd.rest.views import StrainViewSet
from jbei.rest.clients.edd.constants import (STRAINS_RESOURCE_NAME, STRAIN_DESCRIPTION_KEY,
                                             STRAIN_NAME_KEY, STRAIN_REG_ID_KEY,
                                             STRAIN_REG_URL_KEY)
from main.models import Line, Strain, Study, StudyPermission, User

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

UNPRIVILEGED_USERNAME = 'unprivileged_user'
STAFF_USERNAME = 'staff.user'
STAFF_STUDY_USERNAME = 'staff.study.user'
ADMIN_USERNAME = 'admin.user'
ADMIN_STAFF_USERNAME = 'admin.staff.user'

STUDY_OWNER_USERNAME = 'unprivileged.study.owner'
STUDY_READER_USERNAME = 'study.reader.user'
STUDY_READER_GROUP_USER = 'study.reader.group.user'
STUDY_READER_GROUP_NAME = 'study_readers'
STUDY_WRITER_GROUP_USER = 'study.writer.group.user'
STUDY_WRITER_USERNAME = 'study.writer.user'

# Note: ApiTestCase runs in a transction that aborts at the end of the test, so this password will
# never be externally exposed.
PLAINTEXT_TEMP_USER_PASSWORD = 'password'

STRAINS_RESOURCE_URL = '/rest/%(resource)s' % {'resource': STRAINS_RESOURCE_NAME}

DRF_UPDATE_ACTION = 'update'
DRF_CREATE_ACTION = 'create'
DRF_LIST_ACTION = 'list'
DRF_RETRIEVE_ACTION = 'retrieve'


class StrainResourceTests(APITestCase):
    """
    Tests access controls and HTTP return codes for queries to the /rest/strains REST API resource.
    Strains should only be accessible by:
    1) Superusers
    2) Users who have explicit class-level mutator permissions on Strains via a django.contrib.auth
       permission. Any user with a class-level mutator permission has implied read permission on 
       all strains.
    3) Users who have strain read access implied by their read access to an associated study. Since
       EDD only caches the strain name, description, and URL, this should be essentially the same
       visibility granted via access to the study.  There's likely little need for API users to
       access strains in this way, which requires more expensive joins to determine.  However,
       it would be strange to *not* grant read-only access to the strain data already visible
       via the study. Also note that class-level study mutator permissions granted via 
       django.contrib.auth do NOT grant strain access, since that permission only gives access to
       the study name/description, not the data or metadata.
       
    Note that these permissions are enfoced by a combination of EDD's custom 
    ModelImplicitViewOrResultImpliedPermissions class and StrainViewSet's get_queryset() method,
    whose non-empty result implies that the requesting user has access to the returned strains.
    """

    @classmethod
    def setUpTestData(cls):
        """
        Creates strains, users, and study/line combinations to test the REST resource's application
        of user permissions.
        """
        # TODO: do a more granular test of exactly which is required for each resource method
        cls.add_strain_permission = Permission.objects.get(codename='add_strain')
        cls.change_strain_permission = Permission.objects.get(codename='change_strain')
        cls.delete_strain_permission = Permission.objects.get(codename='delete_strain')

        # unprivileged user
        cls.unprivileged_user = User.objects.create_user(username=UNPRIVILEGED_USERNAME,
                                                         email='unprivileged@localhost',
                                                         password=PLAINTEXT_TEMP_USER_PASSWORD)
        # admin user w/ no extra privileges
        cls.superuser = cls._create_user(username=ADMIN_USERNAME,
                                         email='admin@localhost',
                                         is_superuser=True)

        # TODO: remove if unneeded
        # as a stopgap, create the "system" user that isn't being applied via migrations...
        # cls.system_user = User.objects.create_user(username='system',
        #                                            email='jbei-edd-admin@lists.lbl.gov')

        # plain staff w/ no extra privileges
        cls.staff_user = cls._create_user(username=STAFF_USERNAME, email='staff@localhost',
                                          is_staff=True)

        cls.staff_strain_user = cls._create_user(username='staff.strain.user',
                                                 email='staff.study@localhost',
                                                 is_staff=True,
                                                 manage_perms=(cls.add_strain_permission,
                                                               cls.change_strain_permission,
                                                               cls.delete_strain_permission))

        cls.staff_strain_creator = cls._create_user(username='staff.strain.creator',
                                                    email='staff.study@localhost',
                                                    is_staff=True,
                                                    manage_perms=(cls.add_strain_permission,))

        cls.staff_strain_changer = cls._create_user(username='staff.strain.changer',
                                                    email='staff.study@localhost',
                                                    is_staff=True,
                                                    manage_perms=(cls.change_strain_permission,))

        cls.staff_strain_deleter = cls._create_user(username='staff.strain.deleter',
                                                    is_staff=True,
                                                    manage_perms=(cls.delete_strain_permission,))

        # set up a study with lines/strains/permissions that allow us to test unprivileged user
        # access to ONLY the strains used in studies the user has read access to.
        cls.study_owner = User.objects.create_user(
            username=STUDY_OWNER_USERNAME,
            email='study_owner@localhost',
            password=PLAINTEXT_TEMP_USER_PASSWORD)

        cls.study_read_only_user = User.objects.create_user(
            username=STUDY_READER_USERNAME,
            email='study_read_only@localhost',
            password=PLAINTEXT_TEMP_USER_PASSWORD)

        cls.study_write_only_user = User.objects.create_user(
            username=STUDY_WRITER_USERNAME,
            email='study.writer@localhost',
            password=PLAINTEXT_TEMP_USER_PASSWORD)

        cls.study_read_only_group_user = User.objects.create_user(
            username=STUDY_READER_GROUP_USER,
            email='study.reader@localhost',
            password=PLAINTEXT_TEMP_USER_PASSWORD)

        cls.study_write_only_group_user = User.objects.create_user(
            username=STUDY_WRITER_GROUP_USER,
            email='study.writer@localhost',
            password=PLAINTEXT_TEMP_USER_PASSWORD
        )

        # create groups for testing group-level user permissions
        study_read_only_group = Group.objects.create(name='study_read_only_group')
        study_read_only_group.user_set.add(cls.study_read_only_group_user)
        study_read_only_group.save()

        study_write_only_group = Group.objects.create(name='study_write_only_group')
        study_write_only_group.user_set.add(cls.study_write_only_group_user)
        study_write_only_group.save()

        # create the study
        cls.study = Study(name='Test study')
        cls.study.save()
        cls.study.userpermission_set.update_or_create(
                user=cls.study_owner,
                study=cls.study,
                permission_type=StudyPermission.READ)

        # set permissions on the study
        cls.study.userpermission_set.update_or_create(user=cls.study_read_only_user,
                                                      study=cls.study,
                                                      permission_type=StudyPermission.READ)

        cls.study.userpermission_set.update_or_create(user=cls.study_write_only_user,
                                                      study=cls.study,
                                                      permission_type=StudyPermission.WRITE)

        # cls.study.userpermission_set.update_or_create(group=study_read_only_group,
        #                                               study=cls.study,
        #                                               permission_type=StudyPermission.READ)
        #
        # cls.study.userpermission_set.update_or_create(group=study_write_only_group,
        #                                               study=cls.study,
        #                                               permission_type=StudyPermission.WRITE)
        cls.study.save()

        # create some strains / lines in the study
        cls.study_strain1 = Strain(name='Study Strain 1',
                                   registry_id=UUID('f120a00f-8bc3-484d-915e-5afe9d890c5f'))
        cls.study_strain1.registry_url = 'https://registry-test.jbei.org/entry/55349'
        cls.study_strain1.save()
        cls.study_strain2 = Strain(name='Study Strain 2')
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

        line5 = Line(name='Study non-strain line', study=cls.study)
        line5.save()

    @classmethod
    def _create_user(self, username, email='staff.study@localhost', is_admin=False,
                     is_superuser=False,
                     is_staff=True, manage_perms=()):
        """
            A convenience method that creates and returns a test User, with requested 
            permissions set.
        """

        # create and save the user so foreign key based permissions changes will succeed.
        # note: some password is required to allow successful login
        user = User.objects.create_user(username=username,
                                        email=email,
                                        password=PLAINTEXT_TEMP_USER_PASSWORD)

        # return early if no updates to user or its foreign key relationships
        if not (is_admin or is_staff or is_superuser):
            return

        user.is_admin = is_admin
        user.is_staff = is_staff
        user.is_superuser = is_superuser

        if is_staff:
            for permission in manage_perms:
                user.user_permissions.add(permission)

        user.save()

        # re-fetch user from database to force permissions
        # refresh http://stackoverflow.com/questions/10102918/cant-change-user-permissions-during
        # -unittest-in-django
        user = User.objects.get(username=username)

        return user

    def _enforce_strain_read_access(self, url, is_list, drf_action=DRF_LIST_ACTION,
                                    strain_in_study=True):
        """
        A helper method that does the work to test both list and individual strain GET access.
        :param url: 
        :param is_list: 
        :param strain_in_study: True if the provided URL references a strain in a study owned by 
            the user, False otherwise
        :return: 
        """
        factory = APIRequestFactory()

        # verify that an un-authenticated request gets a 404
        request = factory.get(url, user=AnonymousUser())
        response = StrainViewSet.as_view({'get': drf_action})(request)
        self.assertTrue(response.status_code in DRF_UNAUTHENTICATED_PERMISSION_DENIED_CODES)

        # verify that various authenticated, but unprivileged users
        # are denied access to strains without class level permission or access to a study that
        # uses them. This is important, because viewing strain names/descriptions for
        # un-publicized studies could compromise the confidentiality of the research before
        # it's published self.require_authenticated_access_denied(self.study_owner)
        require_no_result_method = (self._require_authenticated_get_access_empty_paged_result if
                                    is_list else
                                    self._require_authenticated_get_access_empty_result)

        #  enforce access denied behavior for the list resource -- same as just showing an empty
        #  list, since otherwise we'd also return a 403 for a legitimately empty list the user
        #  has access to
        if is_list:
            require_no_result_method(url, self.unprivileged_user)
            require_no_result_method(url, self.staff_user)

        # enforce access denied behavior for the strain detail -- permission denied
        else:
            self._require_authenticated_get_access_denied(url, self.unprivileged_user)
            self._require_authenticated_get_access_denied(url, self.staff_user)

        # test that an 'admin' user can access strains even without the write privilege
        self._require_authenticated_get_access_allowed(url, self.superuser)

        # test that 'staff' users with any strain mutator privileges have implied read permission
        self._require_authenticated_get_access_allowed(url, self.staff_strain_creator)
        self._require_authenticated_get_access_allowed(url, self.staff_strain_changer)
        self._require_authenticated_get_access_allowed(url, self.staff_strain_deleter)
        self._require_authenticated_get_access_allowed(url, self.staff_strain_user)

        if strain_in_study:
            # if the strain is in our test study,
            # test that an otherwise unprivileged user with read access to the study can also use
            # the strain resource to view the strain
            self._require_authenticated_get_access_allowed(url, self.study_owner)
        else:
            # if the strain isn't in our test study, test that the study owner, who has no
            # additional privileges, can't access it
            self._require_authenticated_get_access_denied(url, self.study_owner)

    def test_strain_uuid_pattern_match(self):
        # TODO: test pattern matching for UUID's. had to make code changes during initial testing
        # to enforce matching for UUID's returned by EDD's REST API, which is pretty weird after
        # prior successful tests.
        pass

    def test_strain_add(self):
        """
        Tests that the /rest/strains/ resource responds correctly to configured user permissions 
        for adding strains.  Note that django.auth permissions calls this 'add' while DRF
        uses the 'create' action
        """
        print(SEPARATOR)
        print('%s(): ' % self.test_strain_add.__name__)
        print('POST %s' % STRAINS_RESOURCE_URL)
        print(SEPARATOR)

        # Note: missing slash causes 301 response when authenticated
        _URL = STRAINS_RESOURCE_URL + '/'

        # verify that an unprivileged user gets a 403. Note dumps needed for UUID
        post_data = {
            STRAIN_NAME_KEY:        'new strain 1',
            STRAIN_DESCRIPTION_KEY: 'strain 1 description goes here',
            STRAIN_REG_ID_KEY:      '3a3e7b39-258c-4d32-87d6-dd00a66f174f',
            STRAIN_REG_URL_KEY:      'https://registry-test.jbei.org/entry/55350',
        }

        # verify that an un-authenticated request gets a 404
        self._require_unauthenticated_post_access_denied(_URL,
                                                         post_data)

        # verify that unprivileged user can't create a strain
        self._require_authenticated_post_access_denied(_URL,
                                                       self.unprivileged_user,
                                                       post_data)

        # verify that staff permission alone isn't enough to create a strain
        self._require_authenticated_post_access_denied(_URL, self.staff_user, post_data)

        # verify that an administrator can create a strain
        self._require_authenticated_post_access_allowed(_URL,
                                                        self.superuser,
                                                        post_data)

        # verify that attempt to create a strain with a duplicate UUID fails consistency checks
        post_data[STRAIN_REG_URL_KEY] = self.study_strain1.registry_id
        self._require_authenticated_post_conflict(_URL,
                                                  self.superuser,
                                                  post_data)

        # verify that a user with only explicit create permission can create a strain
        post_data = {
            STRAIN_NAME_KEY:        'new strain 2',
            STRAIN_DESCRIPTION_KEY: 'strain 2 description goes here',
            STRAIN_REG_ID_KEY:       None,
            STRAIN_REG_URL_KEY:      None,
        }
        self._require_authenticated_post_access_allowed(_URL,
                                                        self.staff_strain_creator,
                                                        post_data)

    def test_strain_change(self):
        print(SEPARATOR)
        print('%s(): ' % self.test_strain_change.__name__)
        print('POST %s' % STRAINS_RESOURCE_URL)
        print(SEPARATOR)

        # Note: missing slash causes 301 response when authenticated
        url_format = '%(resource_url)s/%(id)s/'

        url = url_format % {'resource_url': STRAINS_RESOURCE_URL,
                            'id':           self.study_strain1.pk}

        # define put data for changing every strain field
        put_data = {
            STRAIN_NAME_KEY:        'Holoferax volcanii',
            STRAIN_DESCRIPTION_KEY: 'strain description goes here',
            STRAIN_REG_ID_KEY:      '124bd9ee-7bb5-4266-91e1-6f16682b2b63',
            STRAIN_REG_URL_KEY:     'https://registry-test.jbei.org/entry/64194',
        }

        # verify that an un-authenticated request gets a 404
        self._require_unauthenticated_put_access_denied(url,
                                                        put_data)

        # verify that unprivileged user can't update a strain
        self._require_authenticated_put_access_denied(url,
                                                      self.unprivileged_user,
                                                      put_data)

        # verify that staff permission alone isn't enough to update a strain
        self._require_authenticated_put_access_denied(url, self.staff_user, put_data)

        # verify that a user can't update an existing strain with the 'create' permission.
        # http://www.django-rest-framework.org/api-guide/generic-views/#put-as-create
        self._do_put(url, self.staff_strain_creator, put_data, HTTP_403_FORBIDDEN)

        # verify that the explicit 'change' permission allows access to update the strain
        self._require_authenticated_put_access_allowed(url, self.staff_strain_changer, put_data)

        # verify that an administrator can update a strain
        self._require_authenticated_put_access_allowed(url,
                                                       self.superuser,
                                                       put_data)

    def _require_unauthenticated_put_access_denied(self, url, put_data):
        factory = APIRequestFactory()
        request = factory.post(url, put_data, format='json', user=AnonymousUser())
        response = StrainViewSet.as_view({'put': DRF_UPDATE_ACTION})(request)
        self.assertTrue(response.status_code in DRF_UNAUTHENTICATED_PERMISSION_DENIED_CODES)

    def _require_unauthenticated_post_access_denied(self, url, post_data):
        factory = APIRequestFactory()
        request = factory.post(url, post_data, format='json', user=AnonymousUser())
        response = StrainViewSet.as_view({'post': DRF_CREATE_ACTION})(request)
        self.assertTrue(response.status_code in DRF_UNAUTHENTICATED_PERMISSION_DENIED_CODES)

    def _require_authenticated_post_access_denied(self, url, user, post_data):
        self._do_post(url, user, post_data, HTTP_403_FORBIDDEN)

    def _require_authenticated_put_access_denied(self, url, user, post_data):
        self._do_put(url, user, post_data, HTTP_403_FORBIDDEN)

    def _require_authenticated_post_access_allowed(self, url, user, post_data):
        self._do_post(url, user, post_data, HTTP_201_CREATED)

    def _require_authenticated_put_access_allowed(self, url, user, post_data):
        self._do_put(url, user, post_data, HTTP_200_OK)

    def _require_authenticated_post_conflict(self, url, user, post_data):
        self._do_post(url, user, post_data, HTTP_400_BAD_REQUEST)

    def _do_post(self, url, user, post_data, required_status):
        logged_in = self.client.login(username=user.username,
                                      password=PLAINTEXT_TEMP_USER_PASSWORD)
        self.assertTrue(logged_in, 'Client login failed. Unable to continue with the test.')

        # TODO: DRF_AUTHENTICATED_BUT_FORBIDDEN would be consistent with DRF results, but 404 will
        # do in a pinch
        response = self.client.post(url, post_data, format='json')
        self.client.logout()

        # TODO: remove debug stmt
        logger.debug('RESPONSE: ' + str(response))
        self.assertEquals(required_status, response.status_code,
                          'Wrong response status code from POST %(url)s for user %(user)s. '
                          'Expected %(expected)d status but got %(observed)d' % {
                              'url':      url, 'user': user.username,
                              'expected': required_status,
                              'observed': response.status_code
                          })

    def _do_put(self, url, user, put_data, required_status):
        logged_in = self.client.login(username=user.username,
                                      password=PLAINTEXT_TEMP_USER_PASSWORD)
        self.assertTrue(logged_in, 'Client login failed. Unable to continue with the test.')

        # TODO: DRF_AUTHENTICATED_BUT_FORBIDDEN would be consistent with DRF results, but 404 will
        # do in a pinch
        response = self.client.put(url, put_data, format='json')
        self.client.logout()

        # TODO: remove debug stmt
        logger.debug('RESPONSE: ' + str(response))
        self.assertEquals(required_status, response.status_code,
                          'Wrong response status code from PUT %(url)s for user %(user)s. '
                          'Expected %(expected)d status but got %(observed)d' % {
                              'url':      url, 'user': user.username,
                              'expected': required_status,
                              'observed': response.status_code
                          })

    def _require_authenticated_get_access_denied(self, url, user):
        logged_in = self.client.login(username=user.username,
                                      password=PLAINTEXT_TEMP_USER_PASSWORD)

        self.assertTrue(logged_in, 'Client login failed. Unable to continue with the test.')

        # request = request_factory.get(self.STRAIN_RESOURCE_URL, user=user)
        # response = StrainViewSet.as_view({'get': 'list'})(request)  # TODO: expand actions tested

        response = self.client.get(url)
        # TODO: DRF_AUTHENTICATED_BUT_FORBIDDEN would be consistent with DRF results, but 404 will
        # do in a pinch
        expected_status = HTTP_404_NOT_FOUND
        logger.debug('Location: %s' % response.get('Location'))

        self.assertEquals(expected_status, response.status_code,
                          'Wrong response status code from %(url)s for user %(user)s. Expected '
                          '%(expected)d status but got %(observed)d' % {
                              'url': url,
                              'user': user.username,
                              'expected': expected_status,
                              'observed': response.status_code})
        self.client.logout()

    def _require_authenticated_get_access_allowed(self, url, user):
        logged_in = self.client.login(username=user.username,
                                      password=PLAINTEXT_TEMP_USER_PASSWORD)
        self.assertTrue(logged_in, 'Client login failed. Unable to continue with the test.')

        response = self.client.get(url)
        required_result_status = HTTP_200_OK
        self.assertEquals(required_result_status, response.status_code,
                          'Wrong response status code from %(url)s for user %(user)s. Expected '
                          '%(expected)d status but got %(observed)d' % {
                              'url': url,
                              'user': user.username,
                              'expected': required_result_status,
                              'observed': response.status_code})
        self.client.logout()

    def _require_authenticated_get_access_not_found(self, url, user):
        logged_in = self.client.login(username=user.username,
                                      password=PLAINTEXT_TEMP_USER_PASSWORD)

        self.assertTrue(logged_in, 'Client login failed. Unable to continue with the test.')

        response = self.client.get(url)
        required_result_status = HTTP_404_NOT_FOUND
        self.assertEquals(required_result_status, response.status_code,
                          'Wrong response status code from %(url)s for user %(user)s. Expected '
                          '%(expected)d status but got %(observed)d' % {
                              'url': url,
                              'user': user.username,
                              'expected': required_result_status,
                              'observed': response.status_code})

    def _require_authenticated_get_access_empty_result(self, url, user):
        logged_in = self.client.login(username=user.username,
                                      password=PLAINTEXT_TEMP_USER_PASSWORD)

        self.assertTrue(logged_in, 'Client login failed. Unable to continue with the test.')

        response = self.client.get(url)
        required_result_status = HTTP_200_OK
        self.assertEquals(required_result_status, response.status_code,
                          "Wrong response status code. Expected %d status but got %d" % (
                              required_result_status, response.status_code))

        self.assertFalse(bool(response.content),
                         'GET %(url)s. Expected an empty list, but got "%(response)s"' % {
            'url': url,
            'response': str(response.content)})

    def _require_authenticated_get_access_empty_paged_result(self, url, user):
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
        logger.debug('Response content (empty paged result expected): %s' % str(response.content))
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
            Tests GET /rest/strains
        """
        print(SEPARATOR)
        print('%s(): ' % self.test_strain_list_read_access.__name__)
        print(SEPARATOR)

        list_url = '%s/' % STRAINS_RESOURCE_URL
        print("Testing read access for %s" % list_url)
        self._enforce_strain_read_access(list_url, True)

    def test_strain_detail_read_access(self):
        """
            Tests GET /rest/strains
        """
        print(SEPARATOR)
        print('%s(): ' % self.test_strain_detail_read_access.__name__)
        print(SEPARATOR)

        strain_detail_url = '%(base_strain_url)s/%(pk)d/' % {
            'base_strain_url': STRAINS_RESOURCE_URL, 'pk': self.study_strain1.pk,
        }

        self._enforce_strain_read_access(strain_detail_url, False)

        # create a strain so we can test access to its detail view
        strain = Strain.objects.create(name='Test strain',
                                       description='Description goes here')

        # construct the URL for the strain detail view
        strain_detail_url = '%(base_strain_url)s/%(pk)d/' % {
            'base_strain_url': STRAINS_RESOURCE_URL,
            'pk':              strain.pk, }

        # test the strain list view as applied to a specific strain..should be the same as the
        # detail view
        self._enforce_strain_read_access(strain_detail_url,
                                         False,
                                         strain_in_study=False)

        # test the strain detail view
        self._enforce_strain_read_access(strain_detail_url,
                                         False,
                                         strain_in_study=False,
                                         drf_action=DRF_RETRIEVE_ACTION)