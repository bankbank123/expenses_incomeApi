# Generated by Django 5.0.4 on 2024-04-12 19:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api_views', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='password_recoveryToken',
            field=models.CharField(max_length=1000, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='password_recoveryToken_expairedAt',
            field=models.DateTimeField(null=True),
        ),
    ]
