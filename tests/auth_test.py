import unittest

from alchemy_mock.mocking import UnifiedAlchemyMagicMock, AlchemyMagicMock

from auth.auth_model import Token


class TestAuth(unittest.TestCase):
    def test_get_none(self):
        session = UnifiedAlchemyMagicMock()
        result = session.query(Token).all()
        return self.assertEqual(len(result), 0)

    def test_get_attribute_error(self):
        session = AlchemyMagicMock()
        with self.assertRaises(AttributeError):
            session.query(Token).filter(Token.foo == 1).all()

    def test_get_all(self):
        session = UnifiedAlchemyMagicMock()
        session.add(Token(id=1, source_app='a', request_app='b', access_token='123'))
        result = session.query(Token).all()
        return self.assertEqual(len(result), 1)
