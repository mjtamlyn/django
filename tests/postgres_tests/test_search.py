from django.test import modify_settings

from . import PostgreSQLTestCase
from .models import NamedTextFieldModel, TextFieldModel

try:
    from django.contrib.postgres.search import SearchVector, SearchQuery
except ImportError:
    pass


@modify_settings(INSTALLED_APPS={'append': 'django.contrib.postgres'})
class SimpleSearchTest(PostgreSQLTestCase):

    @classmethod
    def setUpTestData(cls):
        verses = [
            (
                'Bravely bold Sir Robin, rode forth from Camelot. '
                'He was not afraid to die, o Brave Sir Robin. '
                'He was not at all afraid to be killed in nasty ways. '
                'Brave, brave, brave, brave Sir Robin!'
            ),
            (
                'He was not in the least bit scared to be mashed into a pulp, '
                'Or to have his eyes gouged out, and his elbows broken. '
                'To have his kneecaps split, and his body burned away, '
                'And his limbs all hacked and mangled, brave Sir Robin!'
            ),
            (
                'His head smashed in and his heart cut out, '
                'And his liver removed and his bowels unplugged, '
                'And his nostrils ripped and his bottom burned off,'
                'And his --'
            ),
        ]
        cls.verses = [TextFieldModel.objects.create(field=verse) for verse in verses]
        cls.verse0, cls.verse1, cls.verse2 = cls.verses

    def test_simple(self):
        searched = TextFieldModel.objects.filter(field__search='elbows')
        self.assertSequenceEqual(searched, [self.verse1])

    def test_non_exact_match(self):
        searched = TextFieldModel.objects.filter(field__search='hearts')
        self.assertSequenceEqual(searched, [self.verse2])

    def test_search_two_terms(self):
        searched = TextFieldModel.objects.filter(field__search='heart bowel')
        self.assertSequenceEqual(searched, [self.verse2])

    def test_search_two_terms_with_partial_match(self):
        searched = TextFieldModel.objects.filter(field__search='Robin killed')
        self.assertSequenceEqual(searched, [self.verse0])


class MultipleFieldsTest(PostgreSQLTestCase):

    @classmethod
    def setUpTestData(cls):
        verses = [
            (
                'Bravely bold Sir Robin, rode forth from Camelot. '
                'He was not afraid to die, o Brave Sir Robin. '
                'He was not at all afraid to be killed in nasty ways. '
                'Brave, brave, brave, brave Sir Robin!'
            ),
            (
                'He was not in the least bit scared to be mashed into a pulp, '
                'Or to have his eyes gouged out, and his elbows broken. '
                'To have his kneecaps split, and his body burned away, '
                'And his limbs all hacked and mangled, brave Sir Robin!'
            ),
            (
                'His head smashed in and his heart cut out, '
                'And his liver removed and his bowels unplugged, '
                'And his nostrils ripped and his bottom burned off,'
                'And his --'
            ),
        ]
        cls.verses = [NamedTextFieldModel.objects.create(name='Verse %s' % i, body=verse) for i, verse in enumerate(verses)]
        cls.verse0, cls.verse1, cls.verse2 = cls.verses

    def test_simple_on_body(self):
        searched = NamedTextFieldModel.objects.annotate(
            search=SearchVector('name', 'body'),
        ).filter(search='elbows')
        self.assertSequenceEqual(searched, [self.verse1])

    def test_simple_on_name(self):
        searched = NamedTextFieldModel.objects.annotate(
            search=SearchVector('name', 'body'),
        ).filter(search='verse')
        self.assertSequenceEqual(searched, self.verses)

    def test_non_exact_match(self):
        searched = NamedTextFieldModel.objects.annotate(
            search=SearchVector('name', 'body'),
        ).filter(search='heart')
        self.assertSequenceEqual(searched, [self.verse2])

    def test_search_two_terms(self):
        searched = NamedTextFieldModel.objects.annotate(
            search=SearchVector('name', 'body'),
        ).filter(search='heart verse')
        self.assertSequenceEqual(searched, [self.verse2])

    def test_terms_adjacent(self):
        adjacent = NamedTextFieldModel.objects.create(name='foo', body='bar')
        searched = NamedTextFieldModel.objects.annotate(
            search=SearchVector('name', 'body'),
        ).filter(search='foo')
        self.assertSequenceEqual(searched, [adjacent])
        searched = NamedTextFieldModel.objects.annotate(
            search=SearchVector('name', 'body'),
        ).filter(search='foobar')
        self.assertSequenceEqual(searched, [])

    def test_search_with_null(self):
        nulled = NamedTextFieldModel.objects.create(name='Verse after the minstrel has been killed', body=None)
        searched = NamedTextFieldModel.objects.annotate(
            search=SearchVector('name', 'body'),
        ).filter(search='kill')
        self.assertSequenceEqual(searched, [self.verse0, nulled])

    def test_dictionary_query_explicit(self):
        french = NamedTextFieldModel.objects.create(
            name='French knights',
            body='Oh. Un cadeau. Oui oui.',
        )
        searched = NamedTextFieldModel.objects.annotate(
            search=SearchVector('name', 'body', dictionary='french'),
        ).filter(search=SearchQuery('cadeaux', dictionary='french'))
        self.assertSequenceEqual(searched, [french])

    def test_dictionary_query_implicit(self):
        french = NamedTextFieldModel.objects.create(
            name='French knights',
            body='Oh. Un cadeau. Oui oui.',
        )
        searched = NamedTextFieldModel.objects.annotate(
            search=SearchVector('name', 'body', dictionary='french'),
        ).filter(search='cadeaux')
        self.assertSequenceEqual(searched, [french])
