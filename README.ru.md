# rabbit_harness
Это небольшая библиотека для администрирования RabbitMQ. Основывается на [HTTP API](https://pulse.mozilla.org/api/) Managment плагина.

*Этот документ на другом языке: [English](README.md), [Русский](README.ru.md).*

## Api
```
from harness import Api
rmq_api = Api(host='127.0.0.1', user='guest', password='guest', scheme='http')
```

> Для тестирования можете запустить RabbitMQ используя Docker: `docker run -p 15672:15672 rabbitmq:3-management`

Библиотека предоставляет доступ к:
- [users](#users) - пользователям
- permissions - правам пользователей
- connections - подключениям
- exchanges - точки обмена
- queues - очередям
- bindings - ...

В каждом из разделов есть общие методы:
- `get_list` для получения списка объектов
- `get_detail` для получения конкретного объекта, часто по имени. Ошибка `HTTPError` если не найден
- `create` для создания нового объекта
- `delete` для удаления объекта. Ошибка `HTTPError` если не найден
- `change` для изменения объекта. Ошибка `HTTPError` если не найден

## Users
Получить всех пользователей:
```
users = rmq_api.users.get_list()
```
или по имени:
```
user = rmq_api.users.get_detail('guest')
```
если пользователь с таким именем не найден то будет выброшена ошибка `HTTPError`.

Для создания нового пользователя:
```
rmq_api.users.create(name='user_name', password='user_password')
```
Удаление:
```
rmq_api.users.delete('user_name')
# or
user.delete()
```
Есть возможность изменить пароль и/или тэг пользователя:
```
user.change(password='test', tags='administrator')
```
вместо пароля можно передать его [хэш](https://www.rabbitmq.com/passwords.html#computing-password-hash):
```
user.change(password='itgX9uMVOgittIgB7yxFegDYcUNwuKBZyyg2QCW/uBAghTCf', password_hash=True)
```
Получить все (список) права пользователя, или для определленного vhost -а (`/` по умолчанию):
```
permissions = user.permissions()
permission = user.permission(vhost='/')
```
и изменить их:
```
user.set_permission(read='test', write='', configure='.*')
```
Установленные права можно изменять по частям (например только на запись):
```
user.set_permission(write='ALL')
```
если права пользователя в данном vhost -е (`/` по умолчанию) ранее не были уставлены будет выброшена ошибка `HTTPError`.
