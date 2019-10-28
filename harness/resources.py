import json
import logging
from functools import partial
from typing import Iterable, Optional, List, Any, Union
from urllib.parse import quote

import requests
from yarl import URL

logger = logging.getLogger('harness')

GET = 'GET'
POST = 'POST'
PUT = 'PUT'
DELETE = 'DELETE'

StringOrDict = Union[dict, str]


modify_vhost_name = partial(quote, safe='')


class _Missing:
    def __bool__(self):
        return False

    def __copy__(self):
        return self


missing = _Missing()


class BaseApiModel(dict):
    def __init__(self, parent, *args, **kwargs):
        self._parent = parent
        super().__init__(*args, **kwargs)

    @property
    def resource(self):
        return getattr(self._parent.api_instance, self.model_name)

    @property
    def pk(self):
        return self.get('name', None)

    @property
    def model_name(self):
        return self._parent.Meta.api_name

    def __str__(self):
        return f'{self.model_name}: {self.pk}'


class BindingModel(BaseApiModel):
    model_name = 'bindings'

    def __str__(self):
        return f'{self.model_name}: {self.get("destination")} [{self.get("routing_key")}] -> {self.get("source")}'

    @property
    def pk(self):
        return self.get('routing_key')

    def delete(self):
        """
        todo: автоматом брать destination_type и удалять соответственно
        """
        return self.resource.delete(
            exchange=self.get('source'),
            queue=self.get('destination'),
            routing_key=self.get('routing_key'),
            vhost=self.get('vhost'),
        )


class PermissionModel(BaseApiModel):
    model_name = 'permissions'

    @property
    def pk(self):
        return self.get('user')

    @property
    def vhost(self):
        return self.get('vhost')

    def change(self, read: Optional[str] = None, write: Optional[str] = None,configure: Optional[str] = None):
        """
        Change set params only.
        """
        return self.resource.create(
            name=self.pk,
            vhost=self.vhost,
            read=read,
            write=write,
            configure=configure,
        )

    def delete(self):
        return self.resource.delete(name=self.pk, vhost=self.vhost)


class ExchangeModel(BaseApiModel):
    model_name = 'exchanges'

    @property
    def vhost(self):
        return self.get('vhost')

    def bindings_source(self, **kwargs):
        return self.resource.bindings_source(name=self.pk, vhost=self.vhost, **kwargs)

    def bindings_destination(self, **kwargs):
        return self.resource.bindings_destination(name=self.pk, vhost=self.vhost, **kwargs)


class UserModel(BaseApiModel):
    model_name = 'users'

    @property
    def permissions_resource(self):
        return getattr(self._parent.api_instance, 'permissions')

    def change(self, password: str, tags: Optional[str] = None, password_hash: Optional[bool] = False):
        return self.resource.create(
            name=self.pk,
            password=password,
            tags=tags if tags is not None else self.get('tags'),
            password_hash=password_hash,
        )

    def delete(self):
        return self.resource.delete(self.pk)

    def permission(self, vhost: str = '/') -> PermissionModel:
        return self.permissions_resource.get_detail(name=self.pk, vhost=vhost)

    def permissions(self) -> List[PermissionModel]:
        return self.resource.get_list(self.pk, 'permissions', data_class=PermissionModel)

    def set_permission(self, vhost: str = '/', read: Optional[str] = None, write: Optional[str] = None,
                       configure: Optional[str] = None):
        """
        Set if all parameters are set, otherwise update. Permission must be set before updating!
        """
        permissions_resource = getattr(self._parent.api_instance, 'permissions')
        return permissions_resource.create(name=self.pk, vhost=vhost, read=read, write=write, configure=configure)


class ApiResource:
    model_class = BaseApiModel

    class Meta:
        api_name: str = ''

    def __init__(self, api_instance):
        self.api_instance = api_instance

    def _request(self, *args, **kwargs):
        return self.api_instance.request(*args, **kwargs)

    def _get_path(self, *args: Iterable[str]) -> str:
        api_name = getattr(self.Meta, 'api_name', '')
        path = '/'.join((api_name, *filter(bool, args)))  # fixme: жесть)
        logger.debug('Generate path: %s', path)
        return path

    def _format_result(self, data, data_class=None):
        data_class = data_class or self.model_class
        logger.debug('Filter class: %s', data_class)
        if isinstance(data, list):
            return [data_class(self, value) for value in data]
        return data_class(self, data)

    @staticmethod
    def _filter(data_value: dict, pattern: dict):
        for key, value in pattern.items():
            if data_value.get(key, missing) != value:
                return False
        return True

    def _filter_result(self, data: Iterable, filter_pattern: dict):
        """
        Example: api.exchanges.get_list(type='topic')
        """
        return list(filter(partial(self._filter, pattern=filter_pattern), data))

    def get_detail(self, *args):
        url = self._get_path(*args)
        response = self._request(GET, url)
        return self._format_result(response)

    def get_list(self, *args, data_class=None, **kwargs):
        url = self._get_path(*args)
        response = self._request(GET, url)
        return self._format_result(self._filter_result(response, kwargs), data_class=data_class)

    def create(self, *args, raw=False, **kwargs):
        url = self._get_path(*args)
        response = self._request(POST, url, raw=True, **kwargs)
        if raw:
            return response
        return response.ok

    def delete(self, *args, **kwargs):
        url = self._get_path(*args)
        response = self._request(DELETE, url, raw=True, **kwargs)
        return response.ok

    def change(self, *args, **kwargs):
        url = self._get_path(*args)
        response = self._request(PUT, url, raw=True, **kwargs)
        return response.ok


class Connections(ApiResource):
    class Meta(ApiResource.Meta):
        api_name = 'connections'


class Permissions(ApiResource):
    model_class = PermissionModel

    class Meta(ApiResource.Meta):
        api_name = 'permissions'

    def get_detail(self, name: str, vhost: str = '/'):
        """
        :param name: user name
        :param vhost:
        :return:
        """
        return super().get_detail(modify_vhost_name(vhost), name)

    def create(self, name: str, read: Optional[str] = None, write: Optional[str] = None,
               configure: Optional[str] = None, vhost: str = '/'):
        """
        Set if all parameters are set, otherwise update. Permission must be set before updating!
        :param name: user name
        :param read: read: permission regex, if None will not be changed
        :param write: read: permission regex, if None will not be changed
        :param configure: read: permission regex, if None will not be changed
        :param vhost:
        :return:
        """
        permission_words = ('read', 'write', 'configure')

        permissions = dict(zip(permission_words, (read, write, configure)))
        permissions = dict(filter(lambda perm_tuple: perm_tuple[-1] is not None, permissions.items()))

        if len(permissions) == 3:  # set all permissions
            pass
        else:  # update passed
            current_permission = self.get_detail(name=name, vhost=vhost)

            for p_name, perm in current_permission.items():
                if p_name not in permission_words or p_name in permissions:
                    continue
                permissions[p_name] = perm
        return super().change(modify_vhost_name(vhost), name, **permissions)

    def delete(self, name: str, vhost: str = '/'):
        return super().delete(modify_vhost_name(vhost), name)


class Users(ApiResource):
    model_class = UserModel

    class Meta(ApiResource.Meta):
        api_name = 'users'

    def get_current(self):
        url = '/whoami'
        response = self._request(GET, url)
        return self._format_result(response)

    def get_detail(self, name: str, *args):  # fixme: для UserModel.permissions(), обойти
        return super().get_detail(name, *args)

    def create(self, name: str, password: str, tags: str = '', password_hash: bool = False):
        data = {
            'password_hash' if password_hash else 'password': password,
            'tags': tags,
        }
        return self.change(name, **data)


class Bindings(ApiResource):
    model_class = BindingModel

    class Meta(ApiResource.Meta):
        api_name = 'bindings'

    def get_detail(self, vhost: str, exchange: str, queue: str, routing_key: str) -> dict:
        """
        Queue to exchange.
        """
        url = self._get_path(modify_vhost_name(vhost), 'e', exchange, 'q', queue, quote(routing_key))
        response = self._request(GET, url)
        return self._format_result(response)

    def get_detail_exchange_to_exchange(self, vhost: str, source_exchange: str, destination_exchange: str, routing_key: str) -> dict:
        url = self._get_path(modify_vhost_name(vhost), 'e', source_exchange, 'e', destination_exchange, quote(routing_key))
        response = self._request(GET, url)
        return self._format_result(response)

    def bind_queue(self, source_exchange: str, queue: str, routing_key: str, arguments: dict = dict(), vhost: str = '/'):
        return self.create(modify_vhost_name(vhost), 'e', source_exchange, 'q', queue, routing_key=routing_key, arguments=arguments)

    def bind_exchange(self):
        raise NotImplementedError

    def delete(self, exchange: str, queue: str, routing_key: str, vhost: str = '/') -> bool:
        """
        Queue to exchange.
        """
        return super().delete(modify_vhost_name(vhost), 'e', exchange, 'q', queue, quote(routing_key))


class Exchanges(ApiResource):
    model_class = ExchangeModel

    class Meta(ApiResource.Meta):
        api_name = 'exchanges'

    def get_detail(self, name: str, vhost: str = '/'):
        return super().get_detail(modify_vhost_name(vhost), name)

    def bindings_source(self, name: str, vhost: str = '/', **kwargs):
        """
        A list of all bindings in which a given exchange is the source
        """
        return self.get_list(modify_vhost_name(vhost), name, 'bindings', 'source', data_class=BindingModel, **kwargs)

    def bindings_destination(self, name: str, vhost: str = '/', **kwargs):
        """
        A list of all bindings in which a given exchange is the destination.
        """
        return self.get_list(modify_vhost_name(vhost), name, 'bindings', 'destination', data_class=BindingModel, **kwargs)

    def publish_message(self, exchange_name: str, payload: StringOrDict, routing_key: str, properties: dict = None,
                        payload_encoding: str = 'string', vhost: str = '/'):
        """
        Publish a message to a given exchange.
        Please note that the HTTP API is not ideal for high performance publishing; the need to create a new TCP
        connection for each message published can limit message throughput compared to AMQP or other protocols using
        long-lived connections.

        :param exchange_name:
        :param payload:
        :param routing_key:
        :param properties:
        :param payload_encoding: should be either "string" (in which case the payload will be taken to be the UTF-8
            encoding of the payload field) or "base64" (in which case the payload field is taken to be base64 encoded)
        :param vhost:
        :return:
        """
        properties = properties or dict()
        return self.create(
            modify_vhost_name(vhost), exchange_name, 'publish',
            payload=payload,
            routing_key=routing_key,
            properties=properties,
            payload_encoding=payload_encoding,
        )


class Queues(ApiResource):

    class Meta(ApiResource.Meta):
        api_name = 'queues'

    def create(self, name: str, auto_delete: bool = False, durable: bool = True, arguments: Optional[dict] = None,
               vhost: str = '/'):
        arguments = arguments or dict()
        return super().change(
            modify_vhost_name(vhost), name,
            auto_delete=auto_delete,
            durable=durable,
            arguments=arguments,
        )

    def get_list(self, vhost: Optional[str] = None, **kwargs):
        vhost = modify_vhost_name(vhost) if vhost is not None else None
        return super().get_list(vhost, **kwargs)

    def get_detail(self, name: str, vhost: str = '/'):
        return super().get_detail(modify_vhost_name(vhost), name)

    def bindings(self, name: str, vhost: str = '/') -> List:
        """
        A list of all bindings on a given queue.
        :param name:
        :param vhost:
        :return:
        """
        return super().get_list(modify_vhost_name(vhost), name, 'bindings', data_class=BindingModel)

    def get_messages(self, name: str, vhost: str = '/', count: int = 1, requeue: bool = True, encoding: str = 'auto',
                     truncate: int = 50000) -> List[dict]:
        """
        Get messages from a queue.
        Please note that method is intended for diagnostics etc - it does not implement reliable delivery and so should
        be treated as a sysadmin's tool rather than a general API for messaging.

        :param name: queue name
        :param vhost:
        :param count: controls the maximum number of messages to get. You may get fewer messages than this if the queue
            cannot immediately provide them.
        :param requeue: determines whether the messages will be removed from the queue. If requeue is true they will be
            requeued - but their redelivered flag will be set.
        :param encoding: must be either "auto" (in which case the payload will be returned as a string if it is valid
            UTF-8, and base64 encoded otherwise), or "base64" (in which case the payload will always be base64 encoded).
        :param truncate: is present it will truncate the message payload if it is larger than the size given (in bytes).
        :return:
        """
        return super().create(
            modify_vhost_name(vhost), name, 'get',
            raw=True,
            count=count,
            requeue=requeue,
            encoding=encoding,
            truncate=truncate,
        ).json()

    def purge(self, name: str, vhost: str = '/'):
        """
        Purge queue. Warning! It delete all message!!!
        :param name:
        :param vhost:
        :return:
        """
        return super().delete(modify_vhost_name(vhost), name, 'contents')

    def delete(self, name: str, if_empty: Optional[bool] = None, if_unused: Optional[bool] = None, vhost: str = '/'):
        """
        Delete queue. if_empty and if_unused params prevent the delete from succeeding if the queue contains messages,
            or has consumers, respectively.
        :param name: queue name
        :param if_empty: if True and queue have message, queue queue will not be deleted
        :param if_unused: if True and queue have consumers, queue queue will not be deleted
        :param vhost:
        :return:
        """
        url = self._get_path(modify_vhost_name(vhost), name) + '?'
        if if_empty is not None:  # fixme
            url += f'if-empty={json.dumps(if_empty)}'
        if if_unused is not None:
            url += f'if-unused={json.dumps(if_unused)}'
        logger.warning('queue delete url: %s', url)
        response = self._request(DELETE, url, raw=True, silent=True)
        return response.ok


class Api:
    def __init__(self, *, host: str, user: str, password: str, scheme: str = 'https', port: int = 15672, path: str = 'api'):
        self._api_url = URL.build(
            scheme=scheme,
            user=user,
            password=password,
            host=host,
            port=port,
        ) / path

        self.exchanges = Exchanges(self)
        self.queues = Queues(self)
        self.connections = Connections(self)
        self.bindings = Bindings(self)
        self.users = Users(self)
        self.permissions = Permissions(self)

    def __get_full_url(self, path: str):
        return self._api_url.human_repr() + '/' + path  # todo: yarl не экранирует звездочку(

    def request(self, method: str, path: str, params=None, silent: bool = False, raw=False, **kwargs):
        url = self.__get_full_url(path)
        logger.debug('URL: %s', url)
        result = requests.request(method, url, params=params, json=kwargs)

        if not silent:
            result.raise_for_status()

        if raw:
            return result
        return result.json()
