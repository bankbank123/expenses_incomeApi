from rest_framework import serializers
from .models import *
from datetime import datetime

#User Serializer
class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_confirmed = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = ['User_id','username', 'password', 'password_confirmed','password_hash', 'email', 'firstname', 'lastname', 'token']
        extra_kwargs = {
            'User_id': {'required': False},
            'username': {'required': True},
            'password_hash': {'required': False},
            'email': {'required': True},
            'firstname': {'required': True},
            'lastname': {'required': True},
            'token': {'required': False},
        }
        
        
class UserLoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    class Meta:
        model = User
        fields = ['User_id','username', 'password' ,'password_hash', 'email', 'firstname', 'lastname', 'token']
        extra_kwargs = {
            'User_id': {'required': False},
            'username': {'required': True},
            'password_hash': {'required': False},
            'email': {'required': False},
            'firstname': {'required': False},
            'lastname': {'required': False},
            'token': {'required': False},
        }
        
class UserTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['User_id','username', 'password_hash', 'email', 'firstname', 'lastname', 'token']
        extra_kwargs = {
            'User_id': {'required': False},
            'username': {'required': False},
            'password_hash': {'required': False},
            'email': {'required': False},
            'firstname': {'required': False},
            'lastname': {'required': False},
            'token': {'required': True},
        }
        
class UserRecoverySerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email','password_recoveryToken', 'password_recoveryToken_expairedAt']
        extra_kwargs = {
            'email': {'required': True},
            'password_recoveryToken': {'required': False},
            'password_recoveryToken_expairedAt': {'required': False},
        }

class UserResetPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_confirmed = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['password', 'password_confirmed', 'password_recoveryToken', 'password_hash']
        extra_kwargs = {
            'password_hash': {'required': False},
            'password_recoveryToken': {'required': True},
        }
        
#Table Serializer
class TableCreateSerializer(serializers.ModelSerializer):
    user_token = serializers.CharField(write_only=True)
    class Meta:
        model = SummaryTable
        fields = ['Table_id', 'Table_name', 'Table_description', 'Table_createBy_id', 'user_token']
        extra_kwargs = {
            'Table_id': {'required': False},
            'Table_name': {'required': True},
            'Table_description': {'required': False},
            'Table_path': {'required': False},
            'Table_edit': {'required': False},
            'Table_createBy_id': {'required': False},
        }
        
class IncomeCreateSerializer(serializers.ModelSerializer):
    user_token = serializers.CharField(write_only=True)
    class Meta:
        model = Income
        fields = ['Income_id', 'Income_title', 'Income_cost', 'Income_datetime','Income_createBy_id', 'user_token']
        extra_kwargs = {
            'Income_id' : {'required' : False},
            'Income_title' : {'required' : True},
            'Income_cost' : {'required' : True},
            'Income_datetime' : {'required' : False},
            'Income_createBy_id' : {'required' : False},
        }
    
    def create(self, validated_data):
        token = validated_data.pop('user_token')
        user = User.objects.get(token=token)
        validated_data['Income_createBy_id'] = user.User_id
        validated_data['Income_datetime'] = datetime.now()
        income = Income.objects.create(**validated_data)
        return income


class ExpensesCreateSerializer(serializers.ModelSerializer):
    user_token = serializers.CharField(write_only=True)
    class Meta:
        model = Expenses
        fields = ['Expenses_id', 'Expenses_title', 'Expenses_cost', 'Expenses_datetime','Expenses_createBy_id', 'user_token']
        extra_kwargs = {
            'Expensese_id' : {'required' : False},
            'Expenses_title' : {'required' : True},
            'Expenses_cost' : {'required' : True},
            'Expenses_datetime' : {'required' : False},
            'Expenses_createBy_id' : {'required' : False},
        }
        
    def create(self, validated_data):
        token = validated_data.pop('user_token')
        user = User.objects.get(token=token)
        validated_data['Expenses_createBy_id'] = user.User_id
        validated_data['Expenses_datetime'] = datetime.now()
        expenses = Expenses.objects.create(**validated_data)
        return expenses    
