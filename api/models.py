from django.db import models
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
from django.db.models.fields.related import ManyToManyField
from django.contrib.auth.models import User
from simple_history.models import HistoricalRecords



ROLE_CHOICES = (
    ('c1', 'choice1'),
    ('c2', 'choice2'),
    ('c3', 'choice3'),
    ('o', 'other'),
    )
GENDER_CHOICES = (
    ('M', 'Male'),
    ('F', 'Female'),
    ('o', 'other'),
    )
PTYPE_CHOICES = (
    ('A', 'Avilable'),
    ('NA', 'Not Avilable'),
    ('N', 'New stoke'),
    ('Ol', 'Old stoke'),
    ('O', 'Others'),
    )
SSTATUS_CHOICES = (
    ('O', 'Open'),
    ('C', 'Close'),
    ('S', 'Shifted'),
    ('o', 'Other'),
    )
ESTATUS_CHOICES = (
    ('D', 'on-duty'),
    ('L', 'leave'),
    ('W', 'Weekly off'),
    ('O', 'Other'),
    )

# Create your models here.
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
       
    
class Category(models.Model):
    C_name = models.CharField(max_length=255, blank=False, help_text="Enter category name")
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.C_name
    
class ProductType(models.Model):
    PT_name = models.CharField(max_length=255, blank=False, help_text="enter Type name")
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.PT_name
    
class ShopType(models.Model):
    T_name = models.CharField(max_length=255, blank=False, help_text="enter Type name")
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.T_name
    
class Mall(models.Model):
    MName = models.CharField(max_length=255, blank=False, help_text="Enter Mall Name")
    MCategory = models.ManyToManyField(Category, blank=True, verbose_name=("Mall Categories") )
    MAddress = models.CharField(max_length=255, blank=False, help_text="Enter Address of the Mall")
    M_image = models.ImageField(upload_to= 'media/document/%Y/%m/%d/')
    M_Status = models.CharField(max_length=255)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.MName
    
class Product(models.Model):
    P_name = models.CharField(max_length=255, blank=False, help_text="Enter Product Name")
    P_image = models.ImageField(upload_to= 'media/document/product/%Y/%m/%d/')
    p_Cost = models.CharField(max_length=255, blank=False, help_text="Enter Product Cost")
    P_type = models.ForeignKey(ProductType, on_delete=models.CASCADE)
    P_status = models.CharField(max_length=1, choices=PTYPE_CHOICES)
    P_features = models.TextField()
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.P_name
    
class Shop(models.Model):
    SName = models.CharField(max_length=255, blank=False, help_text="Enter shop Name")
    SCategory = models.CharField(max_length=255, blank=False, help_text="Enter shop Category")
    Shop_number = models.CharField(max_length=255, blank=False, help_text="Enter shop number")
    Shop_type = ManyToManyField(ShopType, blank=True, verbose_name=("Product type"))
    S_status = models.CharField(max_length=1, choices=SSTATUS_CHOICES)
    Product_type = ManyToManyField(Product, blank=True, verbose_name=("Shop type"))
    Shop_location = models.ForeignKey(Mall, on_delete=models.CASCADE)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.SName
    
"""class Employee(models.Model):
    Emp_name = models.CharField(max_length=255, blank=False, help_text="Enter Employee Name")
    Emp_email = models.EmailField(max_length=255, null=True, blank=True, unique=True, help_text="Enter Email")
    Emp_age = models.CharField(max_length=255, help_text="Enter age")
    Emp_salary = models.CharField(max_length=255, blank=False, help_text="Enter Salary")
    Emp_image = models.ImageField(upload_to= 'media/document/%y/%m/%d/')
    Emp_role = models.CharField(max_length=1, choices=ROLE_CHOICES)
    Emp_gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    W_mall = models.ForeignKey(Mall, on_delete=models.CASCADE)
    W_shop = models.ForeignKey(Shop, on_delete=models.CASCADE)
    Emp_status = models.CharField(max_length=1, choices=ESTATUS_CHOICES)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.Emp_Name  """
    
class Order(models.Model):
    customer_name = models.CharField(max_length=255, blank=False, help_text="Enter Customer name")
    customer_address = models.TextField()
    Phone_number = models.CharField(max_length=255, blank=False, help_text="enter phone number")
    Order_date = models.DateTimeField(auto_now_add=True)
    delivery_date = models.DateTimeField()
    history = HistoricalRecords()
    
    def __str__(self):
        return self.customer_name
    

"""class User(AbstractUser, PermissionsMixin):
    User = get_user_model()
    name = models.CharField(max_length=100, blank=True, null=True)
    address = models.CharField(max_length=100, blank=True, null=True)
    phone_number = models.CharField(max_length=100, blank=True, null=True)"""


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True, blank=True, related_name="UserProfile")
    full_name = models.CharField(max_length=255)
    address = models.TextField()
    phone_number =models.CharField(max_length=255)
    #email = models.EmailField(max_length=255, null=True, blank=True, unique=True, help_text="Enter Email")
    #Password = models.CharField(max_length=255, blank=False)
    def __str__(self):
        return self.full_name
    

"""class User(AbstractUser):
    full_name = models.CharField(max_length=255)
    address = models.TextField()
    phone_number =models.CharField(max_length=255)
    class Meta:
        db_table = 'auth_user'"""
        
"""class CustomUserManager(BaseUserManager):
    def _create_user(self, email, password,
                     is_staff, is_superuser, **extra_fields):
        
        #Creates and saves a User with the given email and password.
        
        now = timezone.now()
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email,
                          is_staff=is_staff, is_active=True,
                          is_superuser=is_superuser, last_login=now,
                          date_joined=now, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        return self._create_user(email, password, False, False,
                                 **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        return self._create_user(email, password, True, True,
                                 **extra_fields)
        
        
class CustomUser(AbstractBaseUser, PermissionsMixin):
    User = get_user_model()
    email = models.EmailField(('email address'), max_length=254, unique=True)
    first_name = models.CharField(('first name'), max_length=30, blank=True)
    last_name = models.CharField(('last name'), max_length=30, blank=True)
    address = models.CharField(('address'), max_length=255, blank=True)
    phone = models.CharField(('phone'), max_length=255, blank=True)
    is_staff = models.BooleanField(('staff status'), default=False,
        help_text=('Designates whether the user can log into this admin '
                    'site.'))
    is_active = models.BooleanField(('active'), default=True,
        help_text=('Designates whether this user should be treated as '
                    'active. Unselect this instead of deleting accounts.'))
    date_joined = models.DateTimeField(('date joined'), default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = ('user')
        db_table = 'auth_user'
        verbose_name_plural = ('users')

    def get_absolute_url(self):
        return "/users/%s/" % urlquote(self.email)

    def get_full_name(self):
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        return self.first_name

    def email_user(self, subject, message, from_email=None):
        send_mail(subject, message, from_email, [self.email])"""
     
class User(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    full_name = models.CharField(max_length=255)
    address = models.TextField()
    phone_number =models.CharField(max_length=255)
    
class WishList(models.Model):
    product_id = models.OneToOneField(Product, on_delete=models.CASCADE, primary_key=True)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.product_id
    
class Cart(models.Model):
    product_id = models.OneToOneField(Product, on_delete=models.CASCADE, primary_key=True)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)

class Brand(models.Model):
    brand_name = models.CharField(max_length=255)
    product_id = models.OneToOneField(Product, on_delete=models.CASCADE, primary_key=True)
    
class ProductSize(models.Model):
    product_id = models.OneToOneField(Product, on_delete=models.CASCADE, primary_key=True)
    size_name = models.CharField(max_length=255)
    
class Color(models.Model):
    product_id = models.OneToOneField(Product, on_delete=models.CASCADE, primary_key=True)
    color_name = models.CharField(max_length=255)
	
class Listing(models.Model):
    business_name = models.CharField(max_length=80)
    business_email = models.EmailField()
    business_website = models.CharField(max_length=80)
    business_phone = models.CharField(max_length=80)
	
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(max_length=500, blank=True)
    location = models.CharField(max_length=30, blank=True)
    birth_date = models.DateField(null=True, blank=True)
	
@receiver(post_save, sender=User)
def update_user_profile(sender, instance, created, **kwargs):
	if ctrated:
		profile.objects.create(user=instance)
	instance.profile.save()