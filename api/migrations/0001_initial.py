# Generated by Django 2.0 on 2017-12-21 14:33

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('auth', '0009_alter_user_last_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('C_name', models.CharField(help_text='Enter category name', max_length=255)),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('date_modified', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='HistoricalOrder',
            fields=[
                ('id', models.IntegerField(auto_created=True, blank=True, db_index=True, verbose_name='ID')),
                ('customer_name', models.CharField(help_text='Enter Customer name', max_length=255)),
                ('customer_address', models.TextField()),
                ('Phone_number', models.CharField(help_text='enter phone number', max_length=255)),
                ('Order_date', models.DateTimeField(blank=True, editable=False)),
                ('delivery_date', models.DateTimeField()),
                ('history_id', models.AutoField(primary_key=True, serialize=False)),
                ('history_date', models.DateTimeField()),
                ('history_change_reason', models.CharField(max_length=100, null=True)),
                ('history_type', models.CharField(choices=[('+', 'Created'), ('~', 'Changed'), ('-', 'Deleted')], max_length=1)),
            ],
            options={
                'ordering': ('-history_date', '-history_id'),
                'get_latest_by': 'history_date',
                'verbose_name': 'historical order',
            },
        ),
        migrations.CreateModel(
            name='Mall',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('MName', models.CharField(help_text='Enter Mall Name', max_length=255)),
                ('MAddress', models.CharField(help_text='Enter Address of the Mall', max_length=255)),
                ('M_image', models.ImageField(upload_to='media/document/%Y/%m/%d/')),
                ('M_Status', models.CharField(max_length=255)),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('date_modified', models.DateTimeField(auto_now=True)),
                ('MCategory', models.ManyToManyField(blank=True, to='api.Category', verbose_name='Mall Categories')),
            ],
        ),
        migrations.CreateModel(
            name='Order',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('customer_name', models.CharField(help_text='Enter Customer name', max_length=255)),
                ('customer_address', models.TextField()),
                ('Phone_number', models.CharField(help_text='enter phone number', max_length=255)),
                ('Order_date', models.DateTimeField(auto_now_add=True)),
                ('delivery_date', models.DateTimeField()),
            ],
        ),
        migrations.CreateModel(
            name='Product',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('P_name', models.CharField(help_text='Enter Product Name', max_length=255)),
                ('P_image', models.ImageField(upload_to='media/document/product/%Y/%m/%d/')),
                ('p_Cost', models.CharField(help_text='Enter Product Cost', max_length=255)),
                ('P_status', models.CharField(choices=[('A', 'Avilable'), ('NA', 'Not Avilable'), ('N', 'New stoke'), ('Ol', 'Old stoke'), ('O', 'Others')], max_length=1)),
                ('P_features', models.TextField()),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('date_modified', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='ProductType',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('PT_name', models.CharField(help_text='enter Type name', max_length=255)),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('date_modified', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='Shop',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('SName', models.CharField(help_text='Enter shop Name', max_length=255)),
                ('SCategory', models.CharField(help_text='Enter shop Category', max_length=255)),
                ('Shop_number', models.CharField(help_text='Enter shop number', max_length=255)),
                ('S_status', models.CharField(choices=[('O', 'Open'), ('C', 'Close'), ('S', 'Shifted'), ('o', 'Other')], max_length=1)),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('date_modified', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='ShopType',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('T_name', models.CharField(help_text='enter Type name', max_length=255)),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('date_modified', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL)),
                ('full_name', models.CharField(max_length=255)),
                ('address', models.TextField()),
                ('phone_number', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('user', models.OneToOneField(blank=True, on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='UserProfile', serialize=False, to=settings.AUTH_USER_MODEL)),
                ('full_name', models.CharField(max_length=255)),
                ('address', models.TextField()),
                ('phone_number', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Brand',
            fields=[
                ('brand_name', models.CharField(max_length=255)),
                ('product_id', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to='api.Product')),
            ],
        ),
        migrations.CreateModel(
            name='Cart',
            fields=[
                ('product_id', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to='api.Product')),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('date_modified', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='Color',
            fields=[
                ('product_id', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to='api.Product')),
                ('color_name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='ProductSize',
            fields=[
                ('product_id', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to='api.Product')),
                ('size_name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='WishList',
            fields=[
                ('product_id', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to='api.Product')),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('date_modified', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.AddField(
            model_name='shop',
            name='Product_type',
            field=models.ManyToManyField(blank=True, to='api.Product', verbose_name='Shop type'),
        ),
        migrations.AddField(
            model_name='shop',
            name='Shop_location',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.Mall'),
        ),
        migrations.AddField(
            model_name='shop',
            name='Shop_type',
            field=models.ManyToManyField(blank=True, to='api.ShopType', verbose_name='Product type'),
        ),
        migrations.AddField(
            model_name='product',
            name='P_type',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.ProductType'),
        ),
        migrations.AddField(
            model_name='historicalorder',
            name='history_user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL),
        ),
    ]
