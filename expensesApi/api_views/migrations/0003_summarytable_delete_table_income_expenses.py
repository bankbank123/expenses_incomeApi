# Generated by Django 5.0.4 on 2024-04-12 22:02

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api_views', '0002_user_password_recoverytoken_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='SummaryTable',
            fields=[
                ('Table_id', models.BigAutoField(primary_key=True, serialize=False)),
                ('Table_name', models.CharField(max_length=1000)),
                ('Table_description', models.CharField(max_length=1000)),
                ('Table_shareKey', models.CharField(max_length=1000)),
                ('Table_edit', models.BooleanField(default=False)),
                ('Table_Expenses', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api_views.expenses')),
                ('Table_Income', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api_views.income')),
                ('Table_createBy', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api_views.user')),
            ],
        ),
        migrations.DeleteModel(
            name='Table_Income_Expenses',
        ),
    ]
