# flake8: noqa

from spkcspider.settings import *  # noqa: F403, F401
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

INSTALLED_APPS += [
    'spkcspider.apps.spider_filets',
    'spkcspider.apps.spider_keys',
    'spkcspider.apps.spider_tags',
    'spkcspider.apps.spider_webcfg',
    'spkcspider_messaging.django.spider_messages'

]
# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '^_08u&*be(*my6$pv^m3fki!2s5)5e)9@l5lnllnh)w3p+$l'

# Database
# https://docs.djangoproject.com/en/1.11/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

# specify fixtures directory for tests
# FIXTURE_DIRS = [
#     "tests/fixtures/"
# ]
