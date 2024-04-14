from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import *
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
from django.conf import settings
from django.core.mail import send_mail, EmailMessage, get_connection
from datetime import datetime, timedelta
from django.utils import timezone
import secrets

#User APIs
class UserRegister(APIView):
    def post(self, request, format=None):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            
            # Check if the username or email already exists
            username = serializer.validated_data.get('username')
            email = serializer.validated_data.get('email')
            if User.objects.filter(username=username).exists() or User.objects.filter(email=email).exists():
                return Response({'error': 'Username or email already exists'}, status=status.HTTP_400_BAD_REQUEST)

            # Check if the password matches the confirmed password
            password = serializer.validated_data.pop('password')
            password_confirmed = serializer.validated_data.pop('password_confirmed')
            if password != password_confirmed:
                return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Hash the password
            hashed_password = make_password(password)
            serializer.validated_data['password_hash'] = hashed_password
            
            # Generate and save a new token
            token = secrets.token_hex(255)
            serializer.validated_data['token'] = token
            
            serializer.save()
            return Response(serializer.data['token'], status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserLogin(APIView):
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
                    
            # Get Username and Password for User
            username = serializer.validated_data.get('username')
            password = serializer.validated_data.pop('password')

            # Check if a user with the provided username exists
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return Response({'error': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)

            # Check if the provided password matches the user's password
            if not check_password(password, user.password_hash):
                return Response({'error': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)

            # Generate and save a new token for the user
            token = secrets.token_hex(255)
            user.token = token
            user.save()

            # Return the user data along with the token
            response_data = {
                'token': token
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class getUserToken(APIView):
    def post(self, request, format=None):
        serializer = UserTokenSerializer(data=request.data)
        if serializer.is_valid():
            # Get the token from the request data
            token = serializer.validated_data.get('token')

            # Check if a user with the provided token exists
            try:
                user = User.objects.get(token=token)
            except User.DoesNotExist:
                return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

            # Return the user data if the token is valid
            response_data = {
                'username' : user.username,
                'firstname' : user.firstname,
                'lastname' : user.lastname,
                'email' : user.email,
                'token': token
            }
            return Response(response_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserLogout(APIView):
    def post(self, request, format=None):
        serializer = UserTokenSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data.get('token')
            
            try:
                user = User.objects.get(token=token)
            except User.DoesNotExist:
                return Response({'error': 'plases login to account'}, status=status.HTTP_400_BAD_REQUEST)
            
            user.token = None
            user.save()
            return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserRecovery(APIView):
    def post(self, request, format=None):
        serializer = UserRecoverySerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            
            # Generate a unique token
            password_recovery_token = secrets.token_hex(255)  # Adjust the token length as needed
            
            # Set token expiration time 
            expiration_time = datetime.now() + timedelta(minutes=5)
            
            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)
                user.password_recoveryToken = password_recovery_token
                user.password_recoveryToken_expairedAt = expiration_time
                user.save()
                
                reset_link = f"http://127.0.0.1:8000/api/user/reset-password/?resetToken={password_recovery_token}"  
            
                # Construct email subject and message
                subject = 'Password Reset Instructions'
                message = f'Hi {user.username},\n\nPlease click on the following link to reset your password:\n{reset_link}'

                # Send email
                send_mail(
                    subject,
                    message,
                    settings.EMAIL_HOST_USER,
                    [email],
                    fail_silently=False,
                )
                
                return Response({'message': 'Password reset instructions sent to your email'}, status=status.HTTP_200_OK)
            return Response({'error': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
class UserResetPassword(APIView):
    def post(self, request, format=None):
        serializer = UserResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            password_reset_token = serializer.validated_data.get('password_recoveryToken')
            password = serializer.validated_data.get('password')
            password_confirmed = serializer.validated_data.get('password_confirmed')
            
            if password != password_confirmed:
                return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                user = User.objects.get(password_recoveryToken=password_reset_token)
            except User.DoesNotExist:
                return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)
            
            if user.password_recoveryToken_expairedAt < timezone.now():
                return Response({'error': 'Token expired'}, status=status.HTTP_400_BAD_REQUEST)
            
            hashed_password = make_password(password)
            user.password_hash = hashed_password  # Assign hashed password directly
            user.password_recovery_token = None
            user.password_recovery_token_expires_at = None
            user.save()
            return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#Table
class TableCreate(APIView):
    def post(self, request, format=None):
        serializer = TableCreateSerializer(data=request.data)
            
        if serializer.is_valid():
            table_name = serializer.validated_data.get('Table_name')
            token = serializer.validated_data.pop('user_token')
            
            #check table already exists?
            if SummaryTable.objects.filter(Table_name=table_name).exists():
                return Response({'error' : 'table already exists'} , status=status.HTTP_400_BAD_REQUEST)
            
            #check token
            try: 
                user = User.objects.get(token=token)
            except User.DoesNotExist():
                return Response({'error' : 'Please Login to Create'} , status=status.HTTP_400_BAD_REQUEST)
            
            table_path = secrets.token_hex(100)
            
            serializer.validated_data['Table_name'] = table_name
            serializer.validated_data['Table_path'] = table_path
            serializer.validated_data['Table_createBy_id'] = user.User_id
            serializer.save()
            return Response({'message': 'Create successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#Income
class IncomeCreate(APIView):
    def post(self, request, format=None):
        serializer = IncomeCreateSerializer(data=request.data)
        if serializer.is_valid():
            
            income = serializer.save()
            table_path_req = request.data.get('table_path')
            try:
                table = SummaryTable.objects.get(Table_path=table_path_req)
            except SummaryTable.DoesNotExist:
                return Response({'error': 'please create table'}, status=status.HTTP_400_BAD_REQUEST)
            
            group_income = groupIncome.objects.create(Table=table, Income=income)
            group_income.save()
            
            return Response({'message': 'Create successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#Expensese
class ExpensesCreate(APIView):
    def post(self, request, format=None):
        serializer = ExpensesCreateSerializer(data=request.data)
        if serializer.is_valid():
            expenses = serializer.save()
            # Assuming 'table_path' and 'expenses_id' are provided in the request data
            table_path_req = request.data.get('table_path')
            try:
                table = SummaryTable.objects.get(Table_path=table_path_req)
            except SummaryTable.DoesNotExist:
                return Response({'error': 'please create table'}, status=status.HTTP_400_BAD_REQUEST)
            group_expense = groupExpenses.objects.create(Table=table, Expenses=expenses)
            group_expense.save()
            return Response({'message': 'Create successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)