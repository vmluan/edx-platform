# -*- coding: utf-8 -*-
"""Tests for util.password_policy_validators module."""

import mock
import unittest

from ddt import data, ddt, unpack
from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.test.utils import override_settings

from util.password_policy_validators import (
    create_validator_config, edX_validate_password, password_validators_instruction_texts,
)


@ddt
class PasswordPolicyValidatorsTestCase(unittest.TestCase):
    """ Tests for password validator utility functions """


    def test_unicode_password(self):
        """ Tests that edX_validate_password enforces unicode """
        byte_str = b'𤭮'
        unicode_str = u'𤭮'

        # Sanity checks and demonstration of why this test is useful
        self.assertEqual(len(byte_str), 4)
        self.assertEqual(len(unicode_str), 1)

        # Test length check
        with self.assertRaises(ValidationError):
            edX_validate_password(byte_str)
        edX_validate_password(byte_str + byte_str)

        # Test badly encoded password
        with self.assertRaises(ValidationError) as cm:
            edX_validate_password(b'\xff\xff')

        self.assertEquals('Invalid password.', ' '.join(cm.exception.messages))


    @data(
        ([create_validator_config('util.password_policy_validators.MinimumLengthValidator', {'min_length': 2})],
            'at least 2 characters.'),
        ([
            create_validator_config('util.password_policy_validators.MinimumLengthValidator', {'min_length': 2}),
            create_validator_config('util.password_policy_validators.AlphabeticValidator', {'min_alphabetic': 2}),
        ], 'characters, including 2 letters.'),
        ([
            create_validator_config('util.password_policy_validators.MinimumLengthValidator', {'min_length': 2}),
            create_validator_config('util.password_policy_validators.AlphabeticValidator', {'min_alphabetic': 2}),
            create_validator_config('util.password_policy_validators.NumericValidator', {'min_numeric': 1}),
        ], 'characters, including 2 letters & 1 number.'),
        ([
            create_validator_config('util.password_policy_validators.MinimumLengthValidator', {'min_length': 2}),
            create_validator_config('util.password_policy_validators.UppercaseValidator', {'min_upper': 3}),
            create_validator_config('util.password_policy_validators.NumericValidator', {'min_numeric': 1}),
            create_validator_config('util.password_policy_validators.SymbolValidator', {'min_symbol': 2}),
        ], 'including 3 uppercase letters & 1 number & 2 symbols.'),
    )
    @unpack
    def test_password_instructions(self, config, msg):
        """ Tests password instructions """
        with override_settings(AUTH_PASSWORD_VALIDATORS=config):
            self.assertIn(msg, password_validators_instruction_texts())


    @data(
        (u'userna', u'username', 'test@example.com', 'The password is too similar to the username'),
        (u'password', u'username', 'password@example.com', 'The password is too similar to the email'),
        (u'password', u'username', 'test@password.com', 'The password is too similar to the email'),
        (u'password', u'username', 'test@example.com', None),
    )
    @unpack
    @override_settings(
        AUTH_PASSWORD_VALIDATORS=[create_validator_config(
            'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'
        )]
    )
    def test_user_attribute_similarity_validation_errors(self, password, username, email, msg):
        """ Tests edX_validate_password error messages for the UserAttributeSimilarityValidator """
        user = User(username=username, email=email)
        if msg is None:
            edX_validate_password(password, user)
        else:
            with self.assertRaises(ValidationError) as cm:
                edX_validate_password(password, user)
            self.assertIn(msg, ' '.join(cm.exception.messages))
