# rabbit_harness
Small RabbitMQ administration library based on [HTTP API](https://pulse.mozilla.org/api/) Managment plugins.

*Read this in other languages: [English](README.md), [Русский](README.ru.md).*


## How it use
Create api instance:
```
from harness import Api
rmq_api = Api(host='127.0.0.1', user='guest', password='guest', scheme='http')
```

> For testing you can up RabbitMQ using Docker: `docker run -p 15672:15672 rabbitmq:3-management`

### Users
Get all users:
```
users = rmq_api.users.get_list()
```
or get a specific user:
```
user = rmq_api.users.get_detail('guest')
```
if user with this name not found, will be raised `HTTPError`.

For create user:
```
rmq_api.users.create(name='user_name', password='user_password')
```
Delete:
```
rmq_api.users.delete('user_name')
# or
user.delete()
```
It is possible to change password and/or tag:
```
user.change(password='test', tags='administrator')
```
also, you can set password hash:
```
user.change(password='itgX9uMVOgittIgB7yxFegDYcUNwuKBZyyg2QCW/uBAghTCf', password_hash=True)
```
Get all permissions or for specific vhost
```
permissions = user.permissions()
permission = user.permission(vhost='/')
```
and set/change it:
```
user.set_permission(read='test', write='', configure='.*')
```
if the permissions were set once, they can be updated in parts:
```
user.set_permission(write='ALL')
```
otherwise will be raised `HTTPError`.
