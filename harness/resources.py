import logging
from functools import partial
from typing import Iterable

import requests
from yarl import URL

logger = logging.getLogger('harness')

GET = 'GET'


modify_vhost_name = lambda vhost_name: '%2f' if vhost_name == '/' else vhost_name


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
    def pk(self):
        return self.get('name', None)

    @property
    def model_name(self):
        return self._parent.Meta.api_name

    def __str__(self):
        return f'{self.model_name}: {self.pk}'


class BindingModel(BaseApiModel):
    model_name = 'bindings'

    @property
    def pk(self):
        return f'{self.get("destination")} [{self.get("routing_key")}] -> {self.get("source")}'


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
        path = '/'.join((api_name, *filter(bool, args)))
        return path

    def _format_result(self, data, data_class=None):
        data_class = data_class or self.model_class
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

    def get(self, *args):
        url = self._get_path(*args)
        response = self._request(GET, url)
        return self._format_result(response)

    def get_list(self, *args, data_class=None, **kwargs):
        url = self._get_path(*args)
        response = self._request(GET, url)
        return self._format_result(self._filter_result(response, kwargs), data_class=data_class)


class Connections(ApiResource):
    class Meta(ApiResource.Meta):
        api_name = 'connections'


class Exchanges(ApiResource):
    class Meta(ApiResource.Meta):
        api_name = 'exchanges'

    def get(self, name: str, vhost: str):
        return super().get(modify_vhost_name(vhost), name)

    def bindings_source(self, name: str, vhost: str, **kwargs):
        """
        A list of all bindings in which a given exchange is the source
        """
        return self.get_list(modify_vhost_name(vhost), name, 'bindings', 'source', data_class=BindingModel, **kwargs)

    def bindings_destination(self, name: str, vhost: str, **kwargs):
        return self.get_list(modify_vhost_name(vhost), name, 'bindings', 'destination', data_class=BindingModel, **kwargs)


class Api:
    def __init__(self, *, host: str, user: str, password: str, scheme: str = 'https', port: int = 15672, path: str = 'api'):
        self._api_url = URL.build(
            scheme=scheme,
            user=user,
            password=password,
            host=host,
            port=port,
        ) / path

    def __get_full_url(self, path: str):
        return self._api_url / path

    def request(self, method: str, path: str, params=None, silent: bool = False, **kwargs):
        url = self.__get_full_url(path)
        result = requests.request(method, url, params=params, data=kwargs)

        if not silent:
            result.raise_for_status()

        return result.json()
