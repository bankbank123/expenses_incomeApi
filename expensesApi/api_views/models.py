from django.db import models

# Create your models here.

class User(models.Model):
    User_id = models.BigAutoField(primary_key=True)
    username = models.CharField(null=False, max_length=1000)
    password_hash = models.CharField(null=False, max_length=1000)
    password_recoveryToken = models.CharField(null=True, max_length=1000)
    password_recoveryToken_expairedAt = models.DateTimeField(null=True)
    email = models.EmailField(null=False, max_length=1000)
    firstname = models.CharField(null=False, max_length=1000)
    lastname = models.CharField(null=False, max_length=1000)
    token = models.CharField(null=True, max_length=1000)

class Expenses(models.Model):
    Expenses_id = models.BigAutoField(primary_key=True)
    Expenses_title = models.CharField(null=False, max_length=1000)
    Expenses_cost = models.FloatField(null=True)
    Expenses_datetime = models.DateTimeField()
    Expenses_createBy = models.ForeignKey(User, on_delete=models.CASCADE)
    
class Income(models.Model):
    Income_id = models.BigAutoField(primary_key=True)
    Income_title = models.CharField(null=False, max_length=1000)
    Income_cost = models.FloatField(null=True)
    Income_datetime = models.DateTimeField()
    Income_createBy = models.ForeignKey(User, on_delete=models.CASCADE)
    
class SummaryTable(models.Model):
    Table_id = models.BigAutoField(primary_key=True)
    Table_name = models.CharField(null=False, max_length=1000)
    Table_description = models.CharField(null=True, max_length=1000)
    Table_path = models.CharField(null=False, max_length=1000)
    Table_edit = models.BooleanField(default=False)
    Table_createBy = models.ForeignKey(User, on_delete=models.CASCADE)

class groupIncome(models.Model):
    id = models.BigAutoField(primary_key=True)
    Table = models.ForeignKey(SummaryTable, on_delete=models.CASCADE)
    Income = models.ForeignKey(Income, on_delete=models.CASCADE)
    
class groupExpenses(models.Model):
    id = models.BigAutoField(primary_key=True)
    Table = models.ForeignKey(SummaryTable, on_delete=models.CASCADE)
    Expenses = models.ForeignKey(Expenses, on_delete=models.CASCADE)
    
