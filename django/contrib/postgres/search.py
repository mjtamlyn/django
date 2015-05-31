from django.db.models import Field, F
from django.db.models.expressions import Func, Value
from django.db.models.functions import Coalesce
from django.db.models.lookups import Lookup


class SearchVectorExact(Lookup):
    lookup_name = 'exact'

    def process_rhs(self, qn, connection):
        if not hasattr(self.rhs, 'output_field') or isinstance(self.rhs.output_field, SearchVectorField):
            self.rhs = SearchQuery(self.rhs, dictionary=self.lhs.dictionary)
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
    dictionary = None

    def __init__(self, *expressions, **extra):
        super(SearchVector, self).__init__(*expressions, **extra)
        self.source_expressions = [
            Coalesce(expression, Value('')) if isinstance(expression, F) else expression for expression in self.source_expressions
        ]
        self.dictionary = self.extra['dictionary'] = self.extra.get('dictionary')
        if self.extra['dictionary']:
            self.template = "%(function)s('%(dictionary)s', %(expressions)s)"


class SearchQuery(Value):
    output_field = SearchQueryField
    dictionary = None

    def __init__(self, value, **extra):
        dictionary = extra.pop('dictionary', self.dictionary)
        if dictionary:
            self.template = "plainto_tsquery('{}', %s)".format(dictionary)
        else:
            self.template = "plainto_tsquery(%s)"
        super(SearchQuery, self).__init__(value, **extra)

    def as_sql(self, compiler, connection):
        return self.template, [self.value]


SearchVectorField.register_lookup(SearchVectorExact)
