from flask import Flask, request, jsonify, make_response
from flask_restful import Api, Resource, reqparse
from flask_jwt_extended import JWTManager
from models import db, BooksModel, AuthorModel, PublishModel, RevokedTokenModel, UserModel
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt)
import models

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///BookTest3.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'some-secret-string'

api = Api(app)
db.init_app(app)

@app.before_first_request
def create_table():
    db.create_all()

app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
jwt = JWTManager(app)

@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
     jti = jwt_payload['jti']
     return models.RevokedTokenModel.is_jti_blocklisted(jti)

parser = reqparse.RequestParser()
parser.add_argument('username', help = 'This field cannot be blank', required = True)
parser.add_argument('password', help = 'This field cannot be blank', required = True)

@api.resource('/registration')
class UserRegistration(Resource):
    def post(self):
        data = parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {'message': 'User {} already exists'.format(data['username'])}

        new_user = UserModel(
            username=data['username'],
            password=UserModel.generate_hash(data['password'])
        )

        try:
            new_user.save_to_db()
            access_token = create_access_token(identity=data['username'])
            refresh_token = create_refresh_token(identity=data['username'])
            return {
                'message': 'User {} was created'.format(data['username']),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        except:
            return {'message': 'Something went wrong'}, 500


@api.resource('/login')
class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])

        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['username'])}

        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity=data['username'])
            refresh_token = create_refresh_token(identity=data['username'])
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        else:
            return {'message': 'Wrong credentials'}


@api.resource('/logout/access')
class UserLogoutAccess(Resource):
    @jwt_required()
    def post(self):
        jti = get_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


@api.resource('/logout/refresh')
class UserLogoutRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        jti = get_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


@api.resource('/token/refresh')
class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {'access_token': access_token}


@api.resource('/users')
class AllUsers(Resource):
    @jwt_required()
    def get(self):
        return UserModel.return_all()

    def delete(self):
        return UserModel.delete_all()


@api.resource('/secret')
class SecretResource(Resource):
    @jwt_required()
    def get(self):
        return {
            'answer': 42
        }


@api.resource('/bookJSON')
class JsonBookView(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        if 'firstName' not in data['author'] or 'lastName' not in data['author'] or 'namePublish' not in data['publish'] or 'address' not in data['publish'] or 'site' not in data['publish'] or "title" not in data or "code" not in data or "year_publish" not in data or "count_page" not in data or "price" not in data or "hardcover" not in data or "abstract" not in data or "status" not in data:
            return {'message': 'error'}
        else:
            checkAuthor = AuthorModel.query.filter_by(firstName=data['author']['firstName']).first()
            if not checkAuthor:
                new_author = AuthorModel(data['author']['firstName'], data['author']['lastName'])
                new_author.save(new_author)

            checkPublisher = PublishModel.query.filter_by(namePublish=data['publish']['namePublish']).first()
            if not checkPublisher:
                new_publisher = PublishModel(data['publish']['namePublish'], data['publish']['address'],
                                             data['publish']['site'])
                new_publisher.save(new_publisher)


            publish_Id = PublishModel.query.filter_by(namePublish=data['publish']['namePublish']).first()
            author_id = AuthorModel.query.filter_by(firstName=data['author']['firstName']).first()

            new_book = BooksModel(author_id.id, publish_Id.id, data['title'], data['code'],
                                  data['year_publish'],
                                  data['count_page'], data['price'], data['hardcover'], data['abstract'],
                                  data['status'])
            new_book.save(new_book)
            return new_book.json(), 201


@api.resource('/books')
class BooksView(Resource):
    @jwt_required()
    def get(self):
        books = BooksModel.query.all()
        return {'Books': list(x.json() for x in books)}

    @jwt_required()
    def post(self):
        data = request.get_json()
        if "authorId" not in data or "publishId" not in data or "title" not in data or "code" not in data or "year_publish" not in data or "count_page" not in data or "price" not in data or "hardcover" not in data or "abstract" not in data or "status" not in data:
            return {'message': 'error'}
        else:
            new_book = BooksModel(data['authorId'], data['publishId'], data['title'], data['code'],
                                  data['year_publish'],
                                  data['count_page'], data['price'], data['hardcover'], data['abstract'],
                                  data['status'])
            new_book.save(new_book)
            return new_book.json(), 201


@api.resource('/book/<int:id>')
class BookView(Resource):
    @jwt_required()
    def get(self, id):
        book = BooksModel.query.filter_by(id=id).first()
        if book:
            return book.json()
        else:
            return {'message': 'book not found'}, 404

    @jwt_required()
    def put(self, id):
        data = request.get_json()
        if "authorId" not in data or "publishId" not in data or "title" not in data or "code" not in data or "year_publish" not in data or "count_page" not in data or "price" not in data or "hardcover" not in data or "abstract" not in data or "status" not in data:
            return {'message': 'error'}
        else:
            book = BooksModel.query.filter_by(id=id).first()
            if book:
                book.authorId = data['authorId']
                book.publishId = data['publishId']
                book.title = data['title']
                book.code = data['code']
                book.year_publish = data['year_publish']
                book.count_page = data['count_page']
                book.price = data['price']
                book.hardcover = data['hardcover']
                book.abstract = data['abstract']
                book.status = data['status']

            else:
                book = PublishModel(id=id, **data)
            book.save(book)

            return book.json()

    @jwt_required()
    def delete(self, id):
        book = BooksModel.query.filter_by(id=id).first()
        if book:
            db.session.delete(book)
            db.session.commit()
            return {'message': 'Deleted'}
        else:
            return {'message': 'book not found'}, 404


@api.resource('/authors')
class AuthorsView(Resource):
    @jwt_required()
    def get(self):
        authors = AuthorModel.query.all()
        return {'Authors': list(x.json() for x in authors)}

    @jwt_required()
    def post(self):
        data = request.get_json()

        if 'firstName' not in data or 'lastName' not in data:
            return {'message': 'error'}
        else:
            checkAuthor = AuthorModel.query.filter_by(firstName=data['firstName']).first()
            if not checkAuthor:
                new_author = AuthorModel(data['firstName'], data['lastName'])
                new_author.save(new_author)
                return jsonify({'Authors': data})
            else:
                return {'message': 'author already in base'}


@api.resource('/publishers')
class PublishersView(Resource):
    @jwt_required()
    def get(self):
        publisher = PublishModel.query.all()
        return {'Publisher': list(x.json() for x in publisher)}

    @jwt_required()
    def post(self):
        data = request.get_json()


        if 'namePublish' not in data or 'address' not in data or 'site' not in data:
            return {'message': 'error'}
        else:
            checkPublisher = PublishModel.query.filter_by(namePublish=data['namePublish']).first()
            if not checkPublisher:
                new_publisher = PublishModel(data['namePublish'], data['address'], data['site'])
                new_publisher.save(new_publisher)
                return jsonify({'Publisher': data})
            else:
                return {'message': 'publisher already in base'}


@api.resource('/publisher/<int:id>')
class PublisherView(Resource):
    @jwt_required()
    def get(self, id):
        publisher = PublishModel.query.filter_by(id=id).first()
        if publisher:
            return publisher.json()
        else:
            return {'message': 'publisher not found'}, 404

    @jwt_required()
    def put(self, id):
        data = request.get_json()
        if 'namePublish' not in data or 'address' not in data or 'site' not in data:
            return {'message': 'error'}
        else:
            publisher = PublishModel.query.filter_by(id=id).first()
            if publisher:
                publisher.namePublish = data['namePublish']
                publisher.address = data['address']
                publisher.site = data['site']
            else:
                publisher = PublishModel(id=id, **data)
            publisher.save(publisher)

            return publisher.json()

    @jwt_required()
    def delete(self, id):
        publisher = PublishModel.query.filter_by(id=id).first()
        if publisher:
            db.session.delete(publisher)
            db.session.commit()
            return {'message': 'Deleted'}
        else:
            return {'message': 'publisher not found'}, 404


@api.resource('/author/<int:id>')
class AuthorView(Resource):
    @jwt_required()
    def get(self, id):
        author = AuthorModel.query.filter_by(id=id).first()
        if author:
            return author.json()
        else:
            return {'message': 'author not found'}, 404

    @jwt_required()
    def put(self, id):
        data = request.get_json()
        if 'firstName' not in data or 'lastName' not in data:
            return {'message': 'error'}
        else:
            author = AuthorModel.query.filter_by(id=id).first()
            if author:
                author.firstName = data['firstName']
                author.lastName = data['lastName']

            else:
                author = PublishModel(id=id, **data)
            author.save(author)

            return author.json()

    @jwt_required()
    def delete(self, id):
        author = AuthorModel.query.filter_by(id=id).first()
        if author:
            db.session.delete(author)
            db.session.commit()
            return {'message': 'Deleted'}
        else:
            return {'message': 'author not found'}, 404


@app.route('/')
def hello_world():  # put application's code here
    return 'Hello World!'


# if __name__ == '__main__':
#     app.run()
