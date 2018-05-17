# import the sqlalchemy classes
from sqlalchemy import (Column,
                        String,
                        Integer,
                        ForeignKey,
                        create_engine)

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

# import class psslib for hashed password
from passlib.apps import custom_app_context as pwd_context


Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True)
    email = Column(String, nullable=False)
    password = Column(String)


    # method for change the password to hash password
    def hash_password(self, password):
        self.password = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(self.password, password)


class Category(Base):
    __tablename__ = 'categories'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    description = Column(String)
    user_id = Column(Integer, ForeignKey('user.id'))
    users = relationship(User)


    @property
    def serilize(self):
        return {

            'name': self.name,
            'description': self.description,
            'id': self.id,

        }


class Items(Base):
    __tablename__ = 'items'
    item_id = Column(Integer, primary_key=True, autoincrement=True)
    itemName = Column(String, nullable=False)
    itemDesc = Column(String)
    itemPrice = Column(String, nullable=False)
    userID = Column(Integer, ForeignKey('user.id'))
    catID = Column(Integer, ForeignKey('categories.id'))
    member = relationship(User)
    cat = relationship(Category)

    @property
    def serilize(self):
        return {
            'id': self.item_id,
            'name': self.itemName,
            'Description': self.itemDesc,
            'Price': self.itemPrice,
        }

engine = create_engine('sqlite:///catalogdata.db')
Base.metadata.create_all(engine)
