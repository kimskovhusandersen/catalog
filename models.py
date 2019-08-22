#!/usr/bin/python3

from flask import Flask, jsonify, request
from marshmallow_sqlalchemy import ModelSchema, field_for
from marshmallow import fields
from sqlalchemy import event, create_engine, Table, MetaData, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import scoped_session, sessionmaker, relationship, backref
from sqlalchemy.ext.declarative import declarative_base
from slugify import slugify
from sqlalchemy.event import listen
from passlib.apps import custom_app_context as pwd_context
import random
import string
from itsdangerous import(
    TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

engine = create_engine('sqlite:///catalog.db')
session = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()
secret_key = ''.join(random.choice(
    string.ascii_uppercase + string.digits) for x in xrange(32))

association = Table('association',
                    Base.metadata,
                    Column('category_id', Integer, ForeignKey(
                        'category.id'), primary_key=True),
                    Column('item_id', Integer, ForeignKey(
                        'item.id'), primary_key=True)
                    )


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.hash(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # Valid Token, but expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        user_id = data['id']
        return user_id


class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    items = relationship('Item', secondary=association, lazy='subquery',
                         backref=backref('categories', lazy=True))
    slug = Column(String(100))

    @staticmethod
    def slugify(target, value, oldvalue, initiator):
        if value and (not target.slug or value != oldvalue):
            target.slug = slugify(value)


class Item(Base):
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(250), nullable=False)
    slug = Column(String(100))

    @staticmethod
    def slugify(target, value, oldvalue, initiator):
        if value and (not target.slug or value != oldvalue):
            target.slug = slugify(value)


Base.metadata.create_all(engine)
event.listen(Category.name, 'set', Category.slugify, retval=False)
event.listen(Item.name, 'set', Item.slugify, retval=False)


# MA-SQLA SCHEMAS
class ItemCategorySchema(ModelSchema):
    class Meta:
        fields = ("id", "name")
        model = Category
        sqla_session = session


class ItemSchema(ModelSchema):
    categories = fields.Nested(ItemCategorySchema, many=True)

    class Meta:
        fields = ("id", "name", "slug", "categories")
        model = Item
        sqla_session = session


class CategorySchema(ModelSchema):
    items = fields.Nested(ItemSchema, many=True, exclude=("categories",))

    class Meta:
        fields = ("id", "name", "slug", "items")
        model = Category
        sqla_session = session


CategorySerializer = CategorySchema()
ItemSerializer = ItemSchema()
