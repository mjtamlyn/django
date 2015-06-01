from django.db.models import F, Field
from django.db.models.expressions import Func, Value
from django.db.models.functions import Coalesce
from django.db.models.lookups import Lookup


class SearchVectorExact(Lookup):
    lookup_name = 'exact'

    def process_rhs(self, qn, connection):
        if not hasattr(self.rhs, 'output_field') or isinstance(self.rhs.output_field, SearchVectorField):
            self.rhs = SearchQuery(self.rhs, config=self.lhs.config)
        rhs, rhs_params = super(SearchVectorExact, self).process_rhs(qn, connection)
        return rhs, rhs_params

    def as_sql(self, qn, connection):
        lhs, lhs_params = self.process_lhs(qn, connection)
        rhs, rhs_params = self.process_rhs(qn, connection)
        params = lhs_params + rhs_params
        return '%s @@ %s = true' % (lhs, rhs), params


class SearchVectorField(Field):

    def db_type(self, connection):
        return 'tsvector'


class SearchQueryField(Field):

    def db_type(self, connection):
        return 'tsquery'


class SearchVector(Func):
    function = 'to_tsvector'
    arg_joiner = " || ' ' || "
    output_field = SearchVectorField()
    config = None

    def __init__(self, *expressions, **extra):
        super(SearchVector, self).__init__(*expressions, **extra)
        self.source_expressions = [
            Coalesce(expression, Value('')) if isinstance(expression, F) else expression for expression in self.source_expressions
        ]
        self.config = self.extra['config'] = self.extra.get('config')
        if self.extra['config']:
            self.template = "%(function)s('%(config)s', %(expressions)s)"


class SearchQuery(Value):
    output_field = SearchQueryField
    config = None

    def __init__(self, value, **extra):
        config = extra.pop('config', self.config)
        if config:
            self.template = "plainto_tsquery('{}', %s)".format(config)
        else:
            self.template = "plainto_tsquery(%s)"
        super(SearchQuery, self).__init__(value, **extra)

    def as_sql(self, compiler, connection):
        return self.template, [self.value]


SearchVectorField.register_lookup(SearchVectorExact)
