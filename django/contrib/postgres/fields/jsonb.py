from django.contrib.postgres import lookups
from django.db.models import Field, Transform
from django.utils.translation import ugettext_lazy as _

from psycopg2.extras import Json


__all__ = ['JSONField']


class JSONField(Field):
    empty_strings_allowed = False
    description = _('A JSON object')

    def db_type(self, connection):
        return 'jsonb'

    def get_transform(self, name):
        transform = super(JSONField, self).get_transform(name)
        if transform:
            return transform
        return KeyTransformFactory(name)

    def get_prep_value(self, value):
        if value is not None:
            return Json(value)
        return value

    def get_prep_lookup(self, lookup_type, value):
        if lookup_type == 'has_key':
            return value
        if lookup_type == 'has_keys':
            return value
        if isinstance(value, (dict, list)):
            return Json(value)
        return super(JSONField, self).get_prep_lookup(lookup_type, value)


JSONField.register_lookup(lookups.DataContains)
JSONField.register_lookup(lookups.ContainedBy)
JSONField.register_lookup(lookups.HasKey)
JSONField.register_lookup(lookups.HasKeys)


class KeyTransform(Transform):

    def __init__(self, key_name, *args, **kwargs):
        super(KeyTransform, self).__init__(*args, **kwargs)
        self.key_name = key_name

    def as_sql(self, compiler, connection):
        lhs, params = compiler.compile(self.lhs)
        try:
            int(self.key_name)
        except ValueError:
            lookup = "'%s'" % self.key_name
        else:
            lookup = "%s" % self.key_name
        return "%s -> %s" % (lhs, lookup), params


class KeyTransformFactory(object):

    def __init__(self, key_name):
        self.key_name = key_name

    def __call__(self, *args, **kwargs):
        return KeyTransform(self.key_name, *args, **kwargs)
