"""
This file exposes a number of password validators which can be optionally added to
account creation
"""
from __future__ import unicode_literals

import logging
import random
import string
import unicodedata

from django.conf import settings
from django.contrib.auth.password_validation import (
    get_default_password_validators,
    CommonPasswordValidator,
    MinimumLengthValidator,
    UserAttributeSimilarityValidator,
)
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _, ungettext

from student.models import PasswordHistory

log = logging.getLogger(__name__)

DUMMY_USERNAME = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(30))


def password_validators_instruction_texts(password_validators=None):
    """
    Return a string of instruction texts of all configured validators.
    Expects at least the MinimumLengthValidator to be defined.
    """
    complexity_instructions = []
    # For clarity in the printed instructions, the minimum length instruction
    # is separated from the complexity instructions. The substring is used as
    # an indicator to find the proper instruction.
    length_instruction = ''
    length_instruction_substring = 'at least'
    if password_validators is None:
        password_validators = get_default_password_validators()
    for validator in password_validators:
        text = validator.get_instruction_text()
        if text:
            if length_instruction_substring in text:
                length_instruction = text
            else:
                complexity_instructions.append(text)
    if complexity_instructions:
        return _('Your password must contain {length_instruction}, including {complexity_instructions}.').format(
                    length_instruction=length_instruction,
                    complexity_instructions=' & '.join(complexity_instructions)
                )
    else:
        return _('Your password must contain {length_instruction}.'.format(length_instruction=length_instruction))


class CommonPasswordValidator(CommonPasswordValidator):
    def get_instruction_text(self):
        return ''


class MinimumLengthValidator(MinimumLengthValidator):
    def get_instruction_text(self):
        return ungettext(
            'at least %(min_length)d character',
            'at least %(min_length)d characters',
            self.min_length
        ) % {'min_length': self.min_length}


class UserAttributeSimilarityValidator(UserAttributeSimilarityValidator):
    def get_instruction_text(self):
        return ''


class MaximumLengthValidator(object):
    """
    Validate whether the password is shorter than a maximum length.

    Parameters:
        max_length (int): the maximum number of characters to require in the password.
    """
    def __init__(self, max_length=100):
        self.max_length = max_length

    def validate(self, password, user=None):
        if len(password) > self.max_length:
            raise ValidationError(
                ungettext(
                    'This password is too long. It must contain no more than %(max_length)d character.',
                    'This password is too long. It must contain no more than %(max_length)d characters.',
                    self.max_length
                ),
                code='password_too_long',
                params={'max_length': self.max_length},
            )

    def get_help_text(self):
        return ungettext(
            'Your password must contain no more than %(max_length)d character.',
            'Your password must contain no more than %(max_length)d characters.',
            self.max_length
        ) % {'max_length': self.max_length}

    def get_instruction_text(self):
        return ''


class AlphabeticValidator(object):
    """
    Validate whether the password contains at least min_alphabetic letters.

    Parameters:
        min_alphabetic (int): the minimum number of alphabetic characters to require
            in the password. Must be >= 0.
    """
    def __init__(self, min_alphabetic=0):
        self.min_alphabetic = min_alphabetic

    def validate(self, password, user=None):
        count = 0
        for character in password:
            if count == self.min_alphabetic:
                return
            if character.isalpha():
                count += 1
        raise ValidationError(
            ungettext(
                'Your password must contain at least %(min_alphabetic)d letter.',
                'Your password must contain at least %(min_alphabetic)d letters.',
                self.min_alphabetic
            ),
            code='too_few_alphabetic_char',
            params={'min_alphabetic': self.min_alphabetic},
        )

    def get_help_text(self):
        return ungettext(
            'Your password must contain at least %(min_alphabetic)d letter.',
            'Your password must contain at least %(min_alphabetic)d letters.',
            self.min_alphabetic
        ) % {'min_alphabetic': self.min_alphabetic}

    def get_instruction_text(self):
        if self.min_alphabetic > 0:
            return ungettext(
                '%(num)d letter',
                '%(num)d letters',
                self.min_alphabetic
            ) % {'num': self.min_alphabetic}
        else:
            return ''


class NumericValidator(object):
    """
    Validate whether the password contains at least min_numeric numbers.

    Parameters:
        min_numeric (int): the minimum number of numeric characters to require
            in the password. Must be >= 0.
    """
    def __init__(self, min_numeric=0):
        self.min_numeric = min_numeric

    def validate(self, password, user=None):
        count = 0
        for character in password:
            if count == self.min_numeric:
                return
            if character.isnumeric():
                count += 1
        raise ValidationError(
            ungettext(
                'Your password must contain at least %(min_numeric)d number.',
                'Your password must contain at least %(min_numeric)d numbers.',
                self.min_numeric
            ),
            code='too_few_numeric_char',
            params={'min_numeric': self.min_numeric},
        )

    def get_help_text(self):
        return ungettext(
            "Your password must contain at least %(min_numeric)d number.",
            "Your password must contain at least %(min_numeric)d numbers.",
            self.min_numeric
        ) % {'min_numeric': self.min_numeric}

    def get_instruction_text(self):
        if self.min_numeric > 0:
            return ungettext(
                '%(num)d number',
                '%(num)d numbers',
                self.min_numeric
            ) % {'num': self.min_numeric}
        else:
            return ''


class UppercaseValidator(object):
    """
    Validate whether the password contains at least min_upper uppercase letters.

    Parameters:
        min_upper (int): the minimum number of uppercase characters to require
            in the password. Must be >= 0.
    """
    def __init__(self, min_upper=0):
        self.min_upper = min_upper

    def validate(self, password, user=None):
        count = 0
        for character in password:
            if count == self.min_upper:
                return
            if character.isupper():
                count += 1
        raise ValidationError(
            ungettext(
                'Your password must contain at least %(min_upper)d uppercase letter.',
                'Your password must contain at least %(min_upper)d uppercase letters.',
                self.min_upper
            ),
            code='too_few_uppercase_char',
            params={'min_upper': self.min_upper},
        )

    def get_help_text(self):
        return ungettext(
            "Your password must contain at least %(min_upper)d uppercase letter.",
            "Your password must contain at least %(min_upper)d uppercase letters.",
            self.min_upper
        ) % {'min_upper': self.min_upper}

    def get_instruction_text(self):
        if self.min_upper > 0:
            return ungettext(
                '%(num)d uppercase letter',
                '%(num)d uppercase letters',
                self.min_upper
            ) % {'num': self.min_upper}
        else:
            return ''


class LowercaseValidator(object):
    """
    Validate whether the password contains at least min_lower lowercase letters.

    Parameters:
        min_lower (int): the minimum number of lowercase characters to require
            in the password. Must be >= 0.
    """
    def __init__(self, min_lower=0):
        self.min_lower = min_lower

    def validate(self, password, user=None):
        count = 0
        for character in password:
            if count == self.min_lower:
                return
            if character.islower():
                count += 1
        raise ValidationError(
            ungettext(
                'Your password must contain at least %(min_lower)d lowercase letter.',
                'Your password must contain at least %(min_lower)d lowercase letters.',
                self.min_lower
            ),
            code='too_few_lowercase_char',
            params={'min_lower': self.min_lower},
        )

    def get_help_text(self):
        return ungettext(
            "Your password must contain at least %(min_lower)d lowercase letter.",
            "Your password must contain at least %(min_lower)d lowercase letters.",
            self.min_lower
        ) % {'min_lower': self.min_lower}

    def get_instruction_text(self):
        if self.min_lower > 0:
            return ungettext(
                '%(num)d lowercase letter',
                '%(num)d lowercase letters',
                self.min_lower
            ) % {'num': self.min_lower}
        else:
            return ''


class PunctuationValidator(object):
    """
    Validate whether the password contains at least min_punctuation punctuation characters
    as defined by unicode categories.

    Parameters:
        min_punctuation (int): the minimum number of punctuation characters to require
            in the password. Must be >= 0.
    """
    def __init__(self, min_punctuation=0):
        self.min_punctuation = min_punctuation

    def validate(self, password, user=None):
        count = 0
        for character in password:
            if count == self.min_punctuation:
                return
            if 'P' in unicodedata.category(character):
                count += 1
        raise ValidationError(
            ungettext(
                'Your password must contain at least %(min_punctuation)d punctuation character.',
                'Your password must contain at least %(min_punctuation)d punctuation characters.',
                self.min_punctuation
            ),
            code='too_few_punctuation_characters',
            params={'min_punctuation': self.min_punctuation},
        )

    def get_help_text(self):
        return ungettext(
            "Your password must contain at least %(min_punctuation)d punctuation character.",
            "Your password must contain at least %(min_punctuation)d punctuation characters.",
            self.min_punctuation
        ) % {'min_punctuation': self.min_punctuation}

    def get_instruction_text(self):
        if self.min_punctuation > 0:
            return ungettext(
                '%(num)d punctuation character',
                '%(num)d punctuation characters',
                self.min_punctuation
            ) % {'num': self.min_punctuation}
        else:
            return ''


class SymbolValidator(object):
    """
    Validate whether the password contains at least min_symbol symbols as defined by unicode categories.

    Parameters:
        min_symbol (int): the minimum number of symbols to require
            in the password. Must be >= 0.
    """
    def __init__(self, min_symbol=0):
        self.min_symbol = min_symbol

    def validate(self, password, user=None):
        count = 0
        for character in password:
            if count == self.min_symbol:
                return
            if 'S' in unicodedata.category(character):
                count += 1
        raise ValidationError(
            ungettext(
                'Your password must contain at least %(min_symbol)d symbol.',
                'Your password must contain at least %(min_symbol)d symbols.',
                self.min_symbol
            ),
            code='too_few_symbols',
            params={'min_symbol': self.min_symbol},
        )

    def get_help_text(self):
        return ungettext(
            "Your password must contain at least %(min_symbol)d symbol.",
            "Your password must contain at least %(min_symbol)d symbols.",
            self.min_symbol
        ) % {'min_symbol': self.min_symbol}

    def get_instruction_text(self):
        if self.min_symbol > 0:
            return ungettext(
                '%(num)d symbol',
                '%(num)d symbols',
                self.min_symbol
            ) % {'num': self.min_symbol}
        else:
            return ''
