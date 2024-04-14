from django.urls import path
from .views import *

urlpatterns = [
    path('user/register/', UserRegister.as_view(), name='user-register'),
    path('user/login/', UserLogin.as_view(), name='user-login'),
    path('user/logout/', UserLogout.as_view(), name='user-logout'),
    path('user/loginToken/', UserToken.as_view(), name='user-login-token'),
    path('user/recovery/', UserRecovery.as_view(), name='user_recovery'),
    path('user/reset-password/', UserResetPassword.as_view(), name='user_reset_password'),
    path('table/create/', TableCreate.as_view(), name='table-create'),
    path('income/create/', IncomeCreate.as_view(), name='income-create'),
    path('expenses/create/', ExpensesCreate.as_view(), name='expenses-create'),
]
