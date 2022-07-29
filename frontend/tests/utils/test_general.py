from unittest import TestCase

from zapper.utils.general import order_dictionary_by_keys


class TestHelpers(TestCase):

    def test_order_dictionary_by_keys(self):
        d = {'b': 0, 'a': -1}
        ordered = order_dictionary_by_keys(d)
        keys = list(ordered.keys())
        self.assertEqual(keys, ['a', 'b'])
