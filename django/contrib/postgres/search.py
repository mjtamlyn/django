from django.db.models import F, Field
from django.db.models.expressions import Func, Value
from django.db.models.functions import Coalesce
from django.db.models.lookups import Lookup


class SearchVectorExact(Lookup):
    lookup_name = 'exact'

    def process_rhs(self, qn, connection):
        if not hasattr(self.rhs, 'output_field'):
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
    ADD = '||'

    config = None

    def __init__(self, *expressions, **extra):
        super(SearchVector, self).__init__(*expressions, **extra)

        self.source_expressions = [
            Coalesce(expression, Value('')) if isinstance(expression, F) else expression for expression in self.source_expressions
        ]
        self._output_field = SearchVectorField()

        self.config = self.extra['config'] = self.extra.get('config')
        self.invert = self.extra.get('invert', False)

    def as_sql(self, compiler, connection, function=None, template=None):
        if template is None:
            if self.config:
                template = "%(function)s('%(config)s', %(expressions)s)"
            if self.invert:
                template = "!!(%s)" % self.invert
        return super(SearchVector, self).as_sql(compiler, connection, function=function, template=template)

    def _combine(self, other, connector, reversed, node=None):
        if not type(other) == type(self) or not self.config == other.config:
            raise TypeError('SearchVector can only be combined with other SearchVectors')
        combined = super(SearchVector, self)._combine(other, connector, reversed, node)
        combined.config = self.config
        return combined


class SearchQuery(Value):
    config = None
    invert = False
    output_field = SearchQueryField()

    BITAND = '&&'
    BITOR = '||'
    INVERT = '!!'

    def __init__(self, value, output_field=None, **extra):
        self.config = extra.pop('config', self.config)
        self.invert = extra.pop('invert', self.invert)
        super(SearchQuery, self).__init__(value, output_field=output_field)
        self._output_field = SearchQueryField()

    def as_sql(self, compiler, connection):
        params = [self.value]
        if self.config:
            template = "plainto_tsquery(%s, %s)"
            params = [self.config, self.value]
        else:
            template = "plainto_tsquery(%s)"
        if self.invert:
            template = "!!({})".format(template)
        return template, params

    def _combine(self, other, connector, reversed, node=None):
        combined = super(SearchQuery, self)._combine(other, connector, reversed, node)
        combined.output_field = SearchQueryField()
        return combined

    def __invert__(self):
        extra = {
            'invert': not self.invert,
            'config': self.config,
        }
        obj = type(self)(self.value, **extra)
        return obj


SearchVectorField.register_lookup(SearchVectorExact)
