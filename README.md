 # BooksApi
Данная работа представляет из себя REST API каталога книг. В данной API можно посмотреть книги, автора ее и издательскую компанию.

## Технологии, используемые в проекте

- Python
- Flask
- sqlite3
- API REST

## Схема базы данных

![Снимок экрана 2022-05-20 в 20 17 12](https://user-images.githubusercontent.com/44827871/169579620-62cc62a5-ba57-4e25-9006-aef4fc5c23c1.png)

## Документация API

Регистрация. 

Запрос POST    /registration  регистрация пользователя.  

Авторизация. 

Запрос POST    /login  авторизация пользователя. 

Выход из профиля\. 

Запрос POST    /logout/access  выход пользователя. 

Представление книг. 

Запрос GET     /books    получение списка всех книг.\
Запрос POST    /books    добавление книги.\

Представление книги. 

Запрос GET     /book/<int:id>  получение отдельной книги.\
Запрос PUT     /book/<int:id>  изменение данных книги.\
Запрос DELETE  /book/<int:id>  удаление книги.\

Представление авторов. 

Запрос GET     /authors  получение списка авторов. 
Запрос POST    /authors  добавление нового автора. 

Представление автора.  

Запрос GET     /author/<int:id>  получение автора. 
Запрос PUT     /author/<int:id>  изменние данных автора. 
Запрос DELETE  /author/<int:id>  удаление автора. 
  
Представление издательских компаний. 

Запрос GET     /publishers  получение списка издателей. 
Запрос POST    /publishers  добавление нового издателя. 

Представление издательской компании. 

Запрос GET     /publisher/<int:id>  получение издательской компании. 
Запрос PUT     /publisher/<int:id>  изменние данных издательской компании. 
Запрос DELETE  /publisher/<int:id>  удаление издательской компании. 

## Пример выполнения запроса

Для начала работы обязательно нужно провести регистрацию

![Снимок экрана 2022-05-20 в 20 34 09](https://user-images.githubusercontent.com/44827871/169582018-b5466830-961d-483c-961e-33c2906f6d1b.png)


Далее нужно провести авторизацию

![Снимок экрана 2022-05-20 в 20 34 49](https://user-images.githubusercontent.com/44827871/169582118-70b852b0-53a0-47dc-8644-879f832cb953.png)

Далее перед каждым запросом нужно добавлять Barier Token, который берется из возращаемоего JSON файла при входе

![Снимок экрана 2022-05-20 в 20 35 56](https://user-images.githubusercontent.com/44827871/169582247-047f5e18-c535-4e39-9ea1-f49e8240b950.png)

Сделаем GET запрос что бы получить список всех книг

![Снимок экрана 2022-05-20 в 20 38 26](https://user-images.githubusercontent.com/44827871/169582607-046790fb-e5b9-4362-a8fc-8f67505ee72d.png)

Далее получим отдельную книгу путем GET запроса

![Снимок экрана 2022-05-20 в 20 39 26](https://user-images.githubusercontent.com/44827871/169582719-f0a9937f-84dd-4e49-b46a-edd4ca387160.png)

Так же сделаем GET запрос и получим список авторов

![Снимок экрана 2022-05-20 в 20 40 16](https://user-images.githubusercontent.com/44827871/169582834-764f89a6-d977-43f5-9993-c58db3ed4eb4.png)

Добавим новую книгу

![Снимок экрана 2022-05-20 в 20 42 14](https://user-images.githubusercontent.com/44827871/169583146-a77f2b88-701a-466b-b9c3-554d8d84da72.png)

![Снимок экрана 2022-05-20 в 20 42 37](https://user-images.githubusercontent.com/44827871/169583205-055964ca-edcf-4f84-938f-53a991ac8698.png)

