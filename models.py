from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship, backref
from passlib.hash import pbkdf2_sha256 as sha256

db = SQLAlchemy()


class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'username': x.username,
                'password': x.password
            }

        return {'users': list(map(lambda x: to_json(x), UserModel.query.all()))}

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)


class RevokedTokenModel(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120))

    def add(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def is_jti_blocklisted(cls, jti):
        query = cls.query.filter_by(jti=jti).first()
        return bool(query)

class BooksModel(db.Model):
    __tablename__ = 'books'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    authorId = db.Column(db.Integer, db.ForeignKey('author.id'))
    author = db.relationship("AuthorModel", backref=backref("books", uselist=False))
    publishId = db.Column(db.Integer, db.ForeignKey('publish.id'))
    publish = db.relationship("PublishModel", backref=backref("books", uselist=False))
    title = db.Column(db.String(80))
    code = db.Column(db.String(80))
    year_publish = db.Column(db.String(80))
    count_page = db.Column(db.Integer())
    price = db.Column(db.Float())
    hardcover = db.Column(db.String(80))
    abstract = db.Column(db.String(300))
    status = db.Column(db.Boolean())

    def __init__(self, authorId, publishId, title, code, year_publish, count_page, price, hardcover, abstract, status):
        self.authorId = authorId
        self.publishId = publishId
        self.title = title
        self.code = code
        self.year_publish = year_publish
        self.count_page = count_page
        self.price = price
        self.hardcover = hardcover
        self.abstract = abstract
        self.status = status

    def json(self):
        return {"id": self.id, "author": {"authorId": self.authorId, "firstName": self.author.firstName, "lastName": self.author.lastName}, "publisher": {"publishId": self.publishId, "namePublish": self.publish.namePublish, "address": self.publish.address, "site": self.publish.site}, "title": self.title, "code": self.code,
                "year_publish": self.year_publish, "count_page": self.count_page, "price": self.price,
                "hardcover": self.hardcover, "abstract": self.abstract, "status": self.status}

    def save(self, new_book):
        db.session.add(new_book)
        db.session.commit()

    def __repr__(self):
        return f"<books {self.id}>"


class AuthorModel(db.Model):
    __tablename__ = 'author'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    firstName = db.Column(db.String(80))
    lastName = db.Column(db.String(80))
    author = relationship(BooksModel)


    def __init__(self, firstName, lastName):
        self.firstName = firstName
        self.lastName = lastName

    def save(self, new_author):
        db.session.add(new_author)
        db.session.commit()

    def json(self):
        return {"id": self.id, "firstName": self.firstName, "lastName": self.lastName}


class PublishModel(db.Model):
    __tablename__ = 'publish'

    id =  db.Column(db.Integer, primary_key=True, autoincrement=True)
    namePublish = db.Column(db.String(100))
    address = db.Column(db.String(100))
    site = db.Column(db.String(200))

    def __init__(self, namePublish, address, site):
        self.namePublish = namePublish
        self.address = address
        self.site = site

    def save(self, new_publish):
        db.session.add(new_publish)
        db.session.commit()

    def json(self):
        return {"id": self.id, "namePublish": self.namePublish, "address": self.address, "site": self.site}
