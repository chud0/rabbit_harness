import os
import sys

from requests import HTTPError

sys.path.append(os.getcwd())
from harness import Api
from harness.resources import UserModel, PermissionModel
import unittest


class UsersTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.host = '127.0.0.1'
        cls.admin_user_name = 'guest'
        cls.admin_password = 'guest'
        cls.rmq_api = Api(host=cls.host, user=cls.admin_user_name, password=cls.admin_password, scheme='http')

    def tearDown(self) -> None:
        for user in self.rmq_api.users.get_list():
            if user.pk == self.admin_user_name:
                continue

            user.delete()

    def test_get_current(self):
        user = self.rmq_api.users.get_current()
        self.assertEqual(self.admin_user_name, user.pk)
        self.assertEqual('administrator', user.get('tags'))

    def test_get_list(self):
        users = self.rmq_api.users.get_list()
        self.assertEqual(1, len(users))
        self.assertTrue(isinstance(users[0], UserModel))

    def test_get_detail(self):
        user = self.rmq_api.users.get_detail(self.admin_user_name)
        self.assertTrue(isinstance(user, UserModel))
        self.assertEqual(self.admin_user_name, user.pk)

    def test_get_detail_not_found(self):
        with self.assertRaises(HTTPError):
            self.rmq_api.users.get_detail(self.admin_user_name + 'test')

    def test_create(self):
        user_name = 'test_user'

        result = self.rmq_api.users.create(name=user_name, password=user_name)
        self.assertTrue(result)

        users = self.rmq_api.users.get_list()
        self.assertEqual(2, len(users))
        self.assertEqual(user_name, users[-1].pk)

    def test_delete(self):
        first = 'test_user1'
        second = 'test_user2'
        self.rmq_api.users.create(name=first, password=first)
        self.rmq_api.users.create(name=second, password=second)
        self.assertEqual(3, len(self.rmq_api.users.get_list()))

        self.rmq_api.users.delete(first)
        self.assertEqual(2, len(self.rmq_api.users.get_list()))

        user = self.rmq_api.users.get_detail(second)
        user.delete()
        self.assertEqual(1, len(self.rmq_api.users.get_list()))

    def test_change(self):
        password_hash = '1' * 48
        user_name = 'test_user'
        self.rmq_api.users.create(name=user_name, password=user_name)

        user = self.rmq_api.users.get_detail(user_name)
        self.assertEqual('', user.get('tags'))

        result = user.change(password='test', tags='test_administrator')
        self.assertTrue(result)

        user = self.rmq_api.users.get_detail(user_name)
        self.assertEqual('test_administrator', user.get('tags'))
        self.assertNotEqual(password_hash, user.get('password_hash'))

        result = user.change(password=password_hash, password_hash=True)
        self.assertTrue(result)

        user = self.rmq_api.users.get_detail(user_name)
        self.assertEqual(password_hash, user.get('password_hash'))
        self.assertEqual('test_administrator', user.get('tags'))

    def test_permissions(self):
        permissions = self.rmq_api.users.get_detail(self.admin_user_name).permissions()
        self.assertListEqual(
            [{'user': self.admin_user_name, 'vhost': '/', 'configure': '.*', 'write': '.*', 'read': '.*'}],
            permissions,
        )

    def test_permission(self):
        permission = self.rmq_api.users.get_detail(self.admin_user_name).permission()
        self.assertTrue(isinstance(permission, PermissionModel))

    def test_set_permission(self):
        user_name = 'test_user'
        self.rmq_api.users.create(name=user_name, password=user_name)

        user = self.rmq_api.users.get_detail(user_name)
        self.assertListEqual([], user.permissions())

        with self.assertRaises(HTTPError):
            user.permission()

        with self.assertRaises(HTTPError):
            user.set_permission()

        permission = dict(read='test', write='', configure='.*')
        result = user.set_permission(**permission)
        self.assertTrue(result)

        self.assertDictEqual(dict(user=user_name, vhost='/', **permission), user.permission())

        permission['read'] = '...'
        user.set_permission(read=permission['read'])

        self.assertDictEqual(dict(user=user_name, vhost='/', **permission), user.permission())  # updated read only


if __name__ == '__main__':
    unittest.main()
