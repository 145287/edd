from __future__ import unicode_literals

from django.contrib.auth.models import User
from django.test import TestCase


class UserProfileTest(TestCase):
    USERNAME = "Jane Smith"
    EMAIL = "jsmith@localhost"
    PASSWORD = 'password'
    FIRST_NAME = "Jane"
    LAST_NAME = "Smith"

    USERNAME2 = "John Doe"
    EMAIL2 = "jdoe@localhost"

    # create test users
    def setUp(self):
        super(UserProfileTest, self).setUp()
        User.objects.create_user(
            username=self.__class__.USERNAME,
            email=self.__class__.EMAIL,
            password=self.__class__.PASSWORD,
            first_name=self.__class__.FIRST_NAME,
            last_name=self.__class__.LAST_NAME
            )
        User.objects.create_user(
            username=self.__class__.USERNAME2,
            email=self.__class__.EMAIL2,
            password=self.__class__.PASSWORD)

    def test_profile(self):
        """ Ensure user profile has appropriate fields"""
        # Load objects
        user1 = User.objects.get(email=self.__class__.EMAIL)
        user2 = User.objects.get(email="jdoe@localhost")
        # Asserts
        self.assertTrue(user1.profile is not None)
        self.assertTrue(user1.profile.initials == "JS")
        self.assertTrue(user2.profile.initials == '')
