from django.shortcuts import render, redirect
from rest_framework import generics, permissions, status
from .models import Mall
from .serializers import MallSerializer
from .models import Shop
from .serializers import ShopSerializer
from django.contrib.auth.models import User
from .serializers import UserSerializer
from .models import Product
from .serializers import ProductSerializer
from django.http.response import HttpResponse
import datetime
#from .form import LoginForm, PasswordResetRequestForm
from rest_framework.permissions import IsAdminUser, IsAuthenticated, AllowAny
from .models import Order
from .serializers import OrderSerializer
from .models import UserProfile
from .serializers import UserProfileSerializer
from django.template.context_processors import request
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication,\
    BasicAuthentication, TokenAuthentication
from rest_framework.response import Response
from .serializers import ChangePasswordSerializer, WishListSerializer
from django.views.generic.edit import FormView
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.db.models.query_utils import Q
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.template import loader
from django.core.mail import send_mail
from django.conf.global_settings import DEFAULT_FROM_EMAIL
from django.contrib import messages
#from api.form import SetPasswordForm
from django.contrib.auth import get_user_model, login, hashers
from rest_framework.renderers import TemplateHTMLRenderer
from api.models import WishList, Cart
from api.serializers import CartSerializer
from rest_framework.decorators import api_view, permission_classes
from django.utils import translation
from django.utils.translation import gettext as _
from rest_framework.compat import authenticate
from rest_framework.authtoken.models import Token
from rest_framework.status import HTTP_401_UNAUTHORIZED
import email
from django.views.generic.base import TemplateView
from api.forms import NewBusinessForm, UserCreationForm
from django.views.decorators.csrf import csrf_exempt
#import base64
#from django.contrib.auth.forms import UsernameField
#from MySQLdb.constants.ER import USERNAME
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.decorators import login_required
from .forms import SignUpForm, SignUpForm15, myLoginForm, jenkinUrlForm
from django.contrib import auth
from django.http import HttpResponseRedirect
# Create your views here.

class LocaleMiddleware(object):
    def process_request(self, request):
        language = translation.get_language_from_request(request)
        translation.activate(language)
        request.ar = translation.get_language()
        
    def process_response(self, request, response):
        translation.deactivate()
        return response

"""class LocaleMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        language_code = 'ar' 
        translation.activate(language_code)
        response = self.get_response(request)
        translation.deactivate()
        return response"""

        
class createMallView(generics.ListCreateAPIView):
    queryset = Mall.objects.all()
    serializer_class = MallSerializer
    
    def perform_create(self, serializer):
        serializer.save()
    def get(self, request, *args, **kwargs):
        setattr(request, 'ar', 'en')
        return super().get(self, request, *args, **kwargs)
    
def model_form_upload(request):
        if request.method == 'POST':
            form = Mall(request.POST, request.FILES)
            if form.is_valid():
                form.save()
                return redirect('home')
        else:
            form = Mall()
        return render(request, '/model_form_upload.html', {
            'form': form
        })
      
class detailsMallView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Mall.objects.all();
    serializer_class = MallSerializer
    
class createShopView(generics.ListCreateAPIView):
    queryset = Shop.objects.all()
    serializer_class = ShopSerializer
    
    def perform_create(self, serializer):
        serializer.save()

class detailsShopView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Shop.objects.all();
    serializer_class = ShopSerializer
    
class fetchDataview(generics.RetrieveAPIView):
    queryset = Shop.objects.raw(' select shop.name, shoptype.id from shop LEFT JOIN shoptype on shop.id=shoptype.id order by shop.shop.name')
    serializer_class = ShopSerializer
    
class viewUserTable(generics.ListCreateAPIView):
    queryset = User.objects.raw('select * from auth_user')
    serializer_class = UserSerializer
    
class createProductView(generics.ListCreateAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    
    def perform_create(self, serializer):
        serializer.save()
# class for product details based on product list
"""class detailsProductView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer"""
  
class detailsProductView(generics.RetrieveAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = (IsAdminUser,)
    
    def details(self, request):
        queryset = self.get_queryset()
        serializer = ProductSerializer(queryset, many=False)
        pdata = {'status':200,'response':serializer.data,'msg':"product successfully displayed"}
        return Response(pdata)
  
@api_view(['POST'])
@permission_classes((AllowAny,))     
def ProductDetails(request):
    serializer = ProductSerializer(data=request.data)
    if serializer.is_valid():
        pdata = {'status':200, 'response':serializer.data, 'msg':"product successfully displayed"}
        return Response(pdata)
    
"""def hello(request):
    today = datetime.datetime.now().date()
    daysOfWeek = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    return redirect("https://www.djangoproject.com")
    #return render(request, "test.html", {"today" : today, "days_of_week" : daysOfWeek})

def viewArticle(request, articleId):
   text = "Displaying article Number : %s"%articleId
   return HttpResponse(text)
"""
#the given view is used for mall list api view    
class MallsList(generics.ListAPIView):
    queryset = Mall.objects.all()
    serializer_class = MallSerializer
    permission_classes = (IsAdminUser,)
    model = Mall
    paginate_by = 10
    
    def list(self, request):
        queryset = self.get_queryset()
        serializer = MallSerializer(queryset, many=True)
        mdata = {'status':200,'response':serializer.data,'msg':"Mall List"}
        return Response(mdata)  
    
     
#the given view is used for shop list api view      
class Shoplist(generics.ListAPIView):
    queryset = Shop.objects.all()
    serializer_class = ShopSerializer
    permission_classes = (IsAdminUser,)
    
    def list(self, request):
        queryset = self.get_queryset()
        serializer = ShopSerializer(queryset, many=True)
        sdata = {'status':200,'response':serializer.data,'msg':"Shop List"}
        return Response(sdata)  

#the given view is used for Product list api view 
class Productlist(generics.ListAPIView):
    queryset = Product.objects.all()
    serializer_class  = ProductSerializer
    permission_class = (IsAdminUser,)
    
    def list(self, request):
        queryset = self.get_queryset()
        serializer = ProductSerializer(queryset, many=True)
        mdata = {'status':200,'response':serializer.data,'msg':"Product List"}
        return Response(mdata)  


class SearchProductlist(generics.ListAPIView):
    serializer_class  = ProductSerializer
    
    def get_queryset(self):
        user = self.request.user
        return Product.objects.filter(P_name=user)
    
class OrderCreateView(generics.CreateAPIView):
    queryset = Order.objects.all()
    serializer_class  = OrderSerializer
    
    def perform_create(self, serializer):
        serializer.save()
        
##the given view is used for creating order       
@api_view(['POST'])
@permission_classes((AllowAny,))       
def CreateOrder(request):
    serialized = OrderSerializer(data=request.data)
    if serialized.is_valid():
        serialized.save()
        codata = {'status':200, 'msg':("Product is Successfully Ordered")}
        return Response(codata)
    else:
        co1data = {'status':501, 'msg':"Something happning wrong"}
        return Response(co1data)
    
    
#filter_backends = (filters.DjangoFilterBackend,filters.OrderingFilter,)
#filter_fields = ('completed',)

class OrderDeatilsView(generics.RetrieveAPIView):
    queryset = Order.objects.all()
    serializer_class  = OrderSerializer
    
class OrderHistory(generics.ListAPIView):
    queryset = Order.objects.raw('select * from api_historicalorder')
    serializer_class  = OrderSerializer
    



class UserRegistration(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class  = UserSerializer

    def perform_create(self, serializer):
        serializer.save()
        return Response(status=200)
    
##the given view is used for create user 
@api_view(['POST'])
@permission_classes((AllowAny,))
def create_user(request,):
    serialized = UserSerializer(data=request.data)
    if serialized.is_valid():  
        instance = serialized.save()
        instance.set_password(instance.password)
        instance.save()
        #rs = {serialized.data}
        sData = {'status':200,'response':serialized.data, 'msg':("User Successfully Registered")}
        return Response(sData)
    else:         
        s1data = {'status':501, 'msg':("Email or Username already exist")}
        return Response(s1data)
    
    
"""class MallsFilterList(generics.ListAPIView):
    queryset = Mall.objects.all()
    serializer_class  = MallSerializer
    filter_backends = (filters.backends)
    
class MallFilterList(filters.FilterSet):
    class Meta:
        model = Mall
        fields = {'MName':['exact', 'in', 'startswith']}"""
from django.utils.decorators import method_decorator
##the given view is used for user login        
@api_view(["POST"])
@permission_classes((AllowAny,))
@method_decorator(csrf_exempt)
def login_user(request):
    authentication_classes = (SessionAuthentication)#(TokenAuthentication, SessionAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)
    language = 'ar'
    translation.activate(language)
    username = request.data.get("username")
    password = request.data.get("password")
    encoded = make_password(password)
    check_password(password, encoded)
    user = authenticate(request, username=username, password=password)
    print(user)
    if user is not None:
        login(request, user) 
        user= User.objects.get(pk=user.id)
        query = 'select full_name, address, phone_number from api_userprofile where user_id=user.id'
        user1 = UserProfile.objects.get(pk = user.id)
        print(user1)
        print(user1.phone_number)           
        rs = {'id': user.id,'username':user.username,'email': user.email,'full_name':user1.full_name, 'address':user1.address, 'phone_number':user1.phone_number}
        ldata = {'status':200, 'response':rs,'msg':"User Successfully Logged"}
        return Response(ldata)
    else:
        if user is not None:
            if user.is_active:
                login(request, user)
                rs = {'id': user.id,'username':user.username,'email': user.email, 'full_name': user.userprofile.full_name}
                ldata = {'status':200,'response':rs,'msg':"User Successfully Login"}
                return Response(ldata) 
            else:
                u1data= {'status':501, 'msg':"User account is not valid"}
                return Response(u1data)
        else:
            u1data= {'status':501, 'msg':"Invalid Username or Password"}
            return Response(u1data)    
    l1data = {'status':501,' msg':"Invalid Username or Password"}
    return Response(l1data)
        

"""class UserLogin(APIView):
    authentication_classes = (TokenAuthentication, SessionAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)
    
    def get(self, request, format=None):
         content = {
        'user': str(request.user),
        'auth': str(request.auth),  
        }
         ldata = {'status':201,'response':content,'msg':_("sucess")}
         return Response(ldata)"""

##the given view is used for update user password
class UpdatePassword(APIView):
    permission_classes = (permissions.IsAuthenticated, )

    def get_object(self, queryset=None):
        return self.request.user

    def put(self, request, *args, **kwargs):
        self.object = self.get_object()
        print(self.object)
        serializer = ChangePasswordSerializer(data=request.data)
        print(serializer)

        if serializer.is_valid():
            id = serializer.data.get("id")
            print(id)
            old_password = serializer.data.get("old_password")
            print(old_password)
            encoded = make_password(old_password)
            print(encoded)
            check_password(old_password, encoded)
            if not self.object.check_password(old_password):
                pdata = {'status':500, 'msg':"Old password is: wrong password"}
                return Response(pdata)
                #return Response({"old_password": ["Wrong password."]}, 
                                #status=status.HTTP_400_BAD_REQUEST)
            new_password = serializer.data.get("new_password")
            print(new_password)
            self.object.set_password(new_password)
            #self.object.set_password(serializer.data.get("new_password"))
            print(self.object.set_password(serializer.data.get("new_password")))
            self.object.save()
            cdata = {'status':200,'msg':"New Password saved sucessfully"}
            return Response(cdata)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
"""class Login(APIView):
    permission_classes = (permissions.IsAuthenticated, )
    username = request.POST['username']
    password = request.POST['password']
    user = authenticate(request, username=username, password=password)

    def get_object(self, queryset=None):
        return self.request.user

    def put(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = UserLoginSerializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            username = serializer.data.get("username")
            password = serializer.data.get("username")
            if not self.object.check_username(username):
                return Response({"username": ["Wrong username."]}, 
                                status=status.HTTP_400_BAD_REQUEST)
            if not self.object.check_username(password):
                return Response({"password": ["Wrong password."]}, 
                                status=status.HTTP_400_BAD_REQUEST)
                return user"""
                           
"""def Usersignup(request):
    username = request.POST['username']
    password = request.POST['password']
    user = authenticate(request, username=username, password=password)
    if user is not None:
        login(request, user)
        udata = {'status':200,'response':user,'msg':_("login success")}
        return Response(udata)
        # Redirect to a success page.
    else:
        if user is not None:
            if user.is_active:
                udata = {'status':201,'response':user,'msg':_("login success")}
                login(request, user)
                return Response(udata)
            else:
                u1data= {'status':401,'response':user,'msg':_("login success")}
                return Response(u1data)
        else:
            u1data= {'status':402,'response':user,'msg':_("login success")}
            return Response(u1data)
    #if user is not None:
        #if user.is_active:
            #login(request, user)
            
            # Redirect to a success page.
        #else:
            # Return a 'disabled account' error message
    #else:
        # Return an 'invalid login' error message."""
        
        
class WishListCreate(generics.ListCreateAPIView):
    queryset = WishList.objects.all()
    serializer_class  = WishListSerializer
    
    def perform_create(self, serializer):
        serializer.save()

class RemoveFromWishList(generics.DestroyAPIView):
    queryset = WishList.objects.all()
    serializer_class  = WishListSerializer
    
class CartCreate(generics.ListCreateAPIView):
    queryset = Cart.objects.all()
    serializer_class  = CartSerializer
    
    def perform_create(self, serializer):
        serializer.save()
    
    
"""class ResetPasswordRequestView(FormView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "registration/password_reset_email.html"
    success_url = '/api/login'
    form_class = PasswordResetRequestForm
    
    @staticmethod
    def validate_email_address(email):
        try:
            validate_email(email)
            return True
        except ValidationError:
            return False
    
    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if form.is_valid():
            data= form.cleaned_data["email_or_username"]
        if self.validate_email_address(data) is True: 
            associated_users= User.objects.filter(Q(email=data)|Q(username=data))
            if associated_users.exists():
                for user in associated_users:
                    c = {
                         'email': user.email,
                         'domain': request.META['HTTP_HOST'],
                         'site_name': 'your site',
                         'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                         'user': user,
                         'token': default_token_generator.make_token(user),
                         'protocol': 'http',
                         }
                    subject_template_name='registration/password_reset_subject.txt' 
                            # copied from django/contrib/admin/templates/registration/password_reset_subject.txt to templates directory
                    email_template_name='registration/password_reset_email.html'    
                            # copied from django/contrib/admin/templates/registration/password_reset_email.html to templates directory
                    subject = loader.render_to_string(subject_template_name, c)
                            # Email subject *must not* contain newlines
                    subject = ''.join(subject.splitlines())
                    email = loader.render_to_string(email_template_name, c)
                    send_mail(subject, email, DEFAULT_FROM_EMAIL , [user.email], fail_silently=False)
                result = self.form_valid(form)
                messages.success(request, 'An email has been sent to ' + data +". Please check its inbox to continue reseting password.")
                return result
            else:
                associated_users= User.objects.filter(username=data)
                if associated_users.exists():
                    for user in associated_users:
                        c = {
                            'email': user.email,
                            'domain': 'example.com', #or your domain
                            'site_name': 'example',
                            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                            'user': user,
                            'token': default_token_generator.make_token(user),
                            'protocol': 'http',
                            }
                        subject_template_name='registration/password_reset_subject.txt'
                        email_template_name='registration/password_reset_email.html'
                        subject = loader.render_to_string(subject_template_name, c)
                        # Email subject *must not* contain newlines
                        subject = ''.join(subject.splitlines())
                        email = loader.render_to_string(email_template_name, c)
                        send_mail(subject, email, DEFAULT_FROM_EMAIL , [user.email], fail_silently=False)
                    result = self.form_valid(form)
                    messages.success(request, 'Email has been sent to ' + data +"'s email address. Please check its inbox to continue reseting password.")
                    return result
                result = self.form_invalid(form)
                messages.error(request, 'This username does not exist in the system.')
                return result
            messages.error(request, 'Invalid Input')
            return self.form_invalid(form)
        
class PasswordResetConfirmView(FormView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "registration/password_reset_email.html"
    success_url = '/admin/'
    form_class = SetPasswordForm

    def post(self, request, uidb64=None, token=None, *arg, **kwargs):
        UserModel = get_user_model()
        form = self.form_class(request.POST)
        assert uidb64 is not None and token is not None  # checked by URLconf
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            if form.is_valid():
                new_password= form.cleaned_data['new_password2']
                user.set_password(new_password)
                user.save()
                messages.success(request, 'Password has been reset.')
                return self.form_valid(form)
            else:
                messages.error(request, 'Password reset has not been unsuccessful.')
                return self.form_invalid(form)
        else:
            messages.error(request,'The reset password link is no longer valid.')
            return self.form_invalid(form)"""
                    
                    
class UserList(generics.ListCreateAPIView):
    #model = User
    #paginate_by = 10

    queryset = User.objects.all()[:5]#raw("select * from api_mall ")
    serializer_class = UserSerializer
    permission_classes = (IsAdminUser,)
        
    def list(self, request):
        queryset = self.get_queryset()
        serializer = UserSerializer(queryset, many=True)
        return Response(serializer.data)
             
"""def Usersignup(request):
    username = request.POST['username']
    password = request.POST['password']
    user = authenticate(request, username=username, password=password)
    if user is not None:
        login(request, user)
        udata = {'status':200,'response':user,'msg':_("login success")}
        return Response(udata)
        # Redirect to a success page.
    else:
        if user is not None:
            if user.is_active:
                udata = {'status':201,'response':user,'msg':_("login success")}
                login(request, user)
                return Response(udata)
            else:
                u1data= {'status':401,'response':user,'msg':_("login success")}
                return Response(u1data)
        else:
            u1data= {'status':402,'response':user,'msg':_("login success")}
            return Response(u1data)
    #if user is not None:
        #if user.is_active:
            #login(request, user)
            
            # Redirect to a success page.
        #else:
            # Return a 'disabled account' error message
    #else:
        # Return an 'invalid login' error message."""
#auth token authentication       
"""@api_view(["POST"])
def login1(request):
    #authentication_classes = (TokenAuthentication, SessionAuthentication, BasicAuthentication)
    #permission_classes = (IsAuthenticated,)
    username = request.data.get("username")
    password = request.data.get("password")

    user = authenticate(username=username, password=password)
    if not user:
        return Response({"error": "Login failed"}, status=HTTP_401_UNAUTHORIZED)

    token= Token.objects.get_or_create(user=user)
    return Response({"token": token.key})"""

"""def user_login(request):
    context = RequestContext(request)
    if request.method == 'POST':
          username = request.POST['username']
          password = request.POST['password']
          user = authenticate(username=username, password=password)
          if user is not None:
              if user.is_active:
                  login(request, user)
                  # Redirect to index page.
                  return HttpResponseRedirect("rango/")
              else:
                  # Return a 'disabled account' error message
                  return HttpResponse("You're account is disabled.")
          else:
              # Return an 'invalid login' error message.
              print  "invalid login details " + username + " " + password
              return render_to_response('login.html', {}, context)
    else:
        # the login is a  GET request, so just show the user the login form.
        return render_to_response('login.html', {}, context)"""
        
"""class userprofileCreate(generics.ListCreateAPIView):
    queryset = UserProfile.objects.get(user_id=31)
    serializer_class  = UserProfileSerializer"""


"""@login_required
def register(request):
	user = User.objects.get(username=request.user.username)
	customer = Customer(user=user)
	form=CustomerForm(request.POST or None, instance=customer)
	context = {"customerform": form,
	"form_url": reverse_lazy('customer:register'),
	"type":"register"
	}
	if request.method=="POST":
	#print("success")
		if form.is_valid():
			f=form.save()
			f.account_no=f.acc_no()
			f.save()
			group=get_object_or_404(Group, name='Customer')
			user.groups.add(group)
		return HttpResponseRedirect(reverse('customer:index'))
	return render(request, "register.html", context)"""	
class HomePageView(TemplateView):
    def get(self, request, **kwargs):
        return render(request, 'index.html', context=None)
		
class HomePageView1(TemplateView):
    template_name = "index.html"

class AboutPageView1(TemplateView):
    template_name = "about.html"
	
class AboutPageView15(TemplateView):
    template_name = "temp.html"
	
class newBusiness(FormView):
    form_class = NewBusinessForm
    success_url ="/"
    template_name = "temp.html"
    def form_valid(self, form):
        form.save()
        return redirect(self.success_url )
		
"""def index15(request):
	return render(request, 'showdata.html', context=None)"""
	
	
def addNewUser(request):
	template_name="adduser.html"
	return render(request, 'adduser.html', context=None)
	
@csrf_exempt
def index15(request):
    if request.method == 'POST':
        business_name = request.POST.get('business_name')
        business_email = request.POST.get('business_email')
        business_website = request.POST.get('business_website')
		#business_phone = request.POST.get('business_phone')
        context = {
            'business_name': business_name,
            'business_email': business_email,
            'business_website': business_website,
			'business_phone' :business_phone,
        }
        print("hi");
        template = loader.get_template('showdata.html')
        return HttpResponse(template.render(context, request))
    else:
        template = loader.get_template('index.html')
        return HttpResponse(template.render())	
		
def testlogin(request):
	return render(request, 'login.html', context=None)
		
"""@api_view(['POST'])
@permission_classes((AllowAny,))
def create_NewUser(request,):
    form=UserForm(request.POST)
    if form.is_valid():
		username=form.cleaned_data['username']
		password=form.cleaned_data['password']
		email=form.cleaned_data['email'
		user=user.object.create_user(username=username, password=password, email=email)
        instance = user.save()
        instance.set_password(instance.password)
        instance.save()
        return Response(sData)
    else:         
        s1data = {'status':501, 'msg':("Email or Username already exist")}
        return Response(s1data)"""
		
def login_user15(request):
    logout(request)
    username = password = ''
    if request.POST:
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                return HttpResponseRedirect('/main/')
    return render_to_response('login.html', context_instance=RequestContext(request))
	
@login_required(login_url='/api/login/')
def main(request):
	return render(request, 'home.html')
	
	
def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=raw_password)
            login(request, user)
            return redirect('home')
    else:
        form = SignUpForm()
    return render(request, 'signup.html', {'form': form})

@login_required
def home15(request):
    return render(request, 'home.html')
	
@login_required
def about(request):
    return render(request, 'about.html')
	
@login_required
def contact(request):
    return render(request, 'contact.html')
	
def signup115(request):
    if request.method == 'POST':
        form = SignUpForm15(request.POST)
        if form.is_valid():
            user = form.save()
            user.refresh_from_db()  # load the profile instance created by the signal
            user.profile.birth_date = form.cleaned_data.get('birth_date')
            user.save()
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=user.username, password=raw_password)
            login(request, user)
            return redirect('home')
    else:
        form = SignUpForm15()
    return render(request, 'signup.html', {'form': form})
#redirect login page
def myLoggedinPage(request):
	return render(request, 'login_1.html');
	
def login_view_My(request):
    username = request.POST.get('username')#('username', '')
    password = request.POST.get('password')#('password', '')
    user = auth.authenticate(username=username, password=password)
    if user is not None and user.is_active:
        # Correct password, and the user is marked "active"
        auth.login(request, user)
        # Redirect to a success page.
        return HttpResponseRedirect("login/home/")
    else:
        # Show an error page
        return HttpResponseRedirect("/mylogin/")
		
def logout_view_My(request):
    auth.logout(request)
    # Redirect to a success page.
    return HttpResponseRedirect("logout/")
#https://media.readthedocs.org/pdf/jira/latest/jira.pdf jira python documentation
#http://192.168.0.45:8080/rest/api/2/issue/createmeta?projectKeys=JIR&issuetypeNames=Task&expand=projects.issuetypes.fields
#http://192.168.0.45:8080/rest/api/2/issue/createmeta?projectkeys=JIR&issuetypeNames=Bug&expand=JiraApiTest.Bug.101
import requests	
def createJiraBug(request):
	headers = {'Content-type': 'application/json'}
	data = {"fields": {"project":{"key": "JIR"},
                              "summary": "REST ye merry gentlemen.",
                              "description": "Creating of an issue using project keys and issue type names using the REST API",
                              "issuetype": {"name": "Bug"}
                              }}
	#response = requests.get("http://192.168.0.45:8080/rest/api/2/issue/createmeta?projectKeys=JIR&issuetypeNames=Issue&expand=projects.issuetypes.fields")
	#response = requests.get("http://192.168.0.45:8080/rest/api/2/issue/createmeta?projectKeys=JIR&issuetypeNames=Bug&expand=jiraApiTest.Bug.fields")
	response = requests.post("http://192.168.0.45:8080/rest/api/2/issue/createmeta",
	headers=headers, data=json.dumps(data), auth=('divya_chakraborty', 'Windows123$'))
	#response = requests.get(url="http://192.168.0.45:8080/rest/api/2/issue/createmeta?", data=data, headers=headers)#auth=('divya_chakraborty', 'Windows123$'))
	print(response)
	geodata = response.json()
	print(geodata)
	return HttpResponse(response)
	
	
# new code for jenkins
import json
#import simplejson as json data=json.dumps(data)
#@api_view(['POST'])
def getjiradata(request):
	headers = {"Content-Type":"application/json"}
	data = {"fields": {"project":{"key": "JIR"},
                              "summary": "Error created using python",
                              "description": "Creating of an issue using python project keys and issue type names using the REST API",
                              "issuetype": {"name": "Bug"}
                              }}
	response = requests.post("http://192.168.0.45:8080/rest/api/2/issue", data=json.dumps(data), headers=headers, auth=('divya_chakraborty', 'Windows123$'))
	print(response)
	#geodata = response.json()
	return HttpResponse(response)
#http://192.168.0.45:8081/job/IONApp/ws/www/.scannerwork/report.json
import urllib.request
import base64
from urllib.request import urlopen
def getResponsejenkins(request):
	#username = "manmeet_kaur"
	#password= "manmeet"
	#response = requests.get('http://192.168.0.45:8081/job/IONApp/ws/www/.scannerwork/report.json')
	#geodata = response.json()
	#req = urllib.request.Request("http://192.168.0.45:8081/job/IONApp/ws/www/.scannerwork/report.json?username=manmeet_kaur&password=manmeet")
	#opener = urllib.build_urlopen()
	#f = opener.open(req)
	#json = json.loads(f.read())
	#base64string = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
	#request.add_header("Authorization", "Basic %s" % base64string)   
	#print("response")
	#response = urllib.request.urlopen(req)
	#print (response)
	#print(response)
	#print("hi")
	#wp =request.urlopen("http://google.com")
	#pw = wp.read()
	#print(pw)
	#url = 'http://192.168.0.45:8081/job/IONApp/ws/www/.scannerwork/report.json?username=manmeet_kaur&password=manmeet'
	#r = requests.get(url)
	#print(r)
	#data = json.loads(r.content.decode())
	#print(data)
	"""try:
		with urllib.request.urlopen('http://192.168.0.45:8081/job/IONApp/ws/www/.scannerwork/report.json') as response:
			info =  response.read()#.decode('ASCII')
			print(info)
			thing = json.loads(str(info))
	except urllib.error.URLError as e:
		#print("reading local", e)
		##thing=json.load(open("report.json"))
		info="occuring error"
	except StandardError as e:
		print("failed funnily")
		sys.exit()"""
	url = 'http://192.168.0.45:8081/job/IONApp/ws/www/.scannerwork/report.json'
	username = 'manmeet_kaur'
	password = 'manmeet'
	res=requests.get(url, auth=(username, password)).content
	#print(requests.get(url, auth=(username, password)).content)
	#geodata = res.json()
	#v = geodata['version']
	#print(v)
	data = json.loads(res.decode('utf-8'))
	print(data['issues'][0]['key'])
	c = len(data['issues'])
	print(c)
	for i in range(0,1):
		"""if int(data['issues'][i]['line']) != '':
			print(data['issues'][i]['key'])
			print(data['issues'][i]['component'])
			print(int(data['issues'][i]['line']))
			print(int(data['issues'][i]['startLine']))
			print(int(data['issues'][i]['startOffset']))
			print(int(data['issues'][i]['endLine']))
			print(int(data['issues'][i]['endOffset']))
			print(data['issues'][i]['message'])
			print(data['issues'][i]['severity'])
			print(data['issues'][i]['rule'])
			print(data['issues'][i]['status'])
			print(data['issues'][i]['isNew'])
			print(data['issues'][i]['creationDate'])
			print("hello python " + "add other message")
		else:
			print(data['issues'][i]['key'])
			print(data['issues'][i]['component'])
			print(data['issues'][i]['message'])
			print(data['issues'][i]['severity'])
			print(data['issues'][i]['rule'])
			print(data['issues'][i]['status'])
			print(data['issues'][i]['isNew'])
			print(data['issues'][i]['creationDate'])"""
		try:
			#if int(data['issues'][i]['line']) is not None:
			#if "line" in data['issues'][i] and "startLine" in data['issues'][i] and "startOffset" in data['issues'][i] and "endLine" in data['issues'][i] and "endOffset" in data['issues'][i]:
			if data['issues'][i].get('line') != None and data['issues'][i].get('startLine') != None and data['issues'][i].get('startOffset') != None and data['issues'][i].get('endLine') != None and data['issues'][i].get('endOffset') != None:
				#Description = "The Jenkins key of the issue is "+data['issues'][i]['key']+"-in "+data['issues'][i]['component']+" line number-"+str(data['issues'][i]['line'])+" startLine is-"+str(data['issues'][i]['startLine'])+" startoffset-"+str(data['issues'][i]['startOffset'])+" endline "+str(data['issues'][i]['endLine'])+" endOffset "+str(data['issues'][i]['endOffset'])+" message-"+data['issues'][i]['message']+" severity-"+data['issues'][i]['severity']+" rule-"+data['issues'][i]['rule']+" status "+data['issues'][i]['status']+" isNew "+str(data['issues'][i]['isNew'])+" creationDate "+data['issues'][i]['creationDate']
				#print(Description)
				Description = "The Jenkins key of the issue is "+data['issues'][i]['key']
				Description+= " in file "+data['issues'][i]['component']
				Description+= " Line Number is-"+str(data['issues'][i]['line'])
				Description+= " startLine-"+str(data['issues'][i]['startLine'])
				Description+= " startOffset-"+str(data['issues'][i]['startOffset'])
				Description+= " endLine-"+str(data['issues'][i]['endLine'])
				Description+= " endOffset-"+str(data['issues'][i]['endOffset'])
				Description+= " message: "+str(data['issues'][i]['message'])
				Description+= " severity-"+str(data['issues'][i]['severity'])
				Description+= " rule-: "+str(data['issues'][i]['rule'])
				Description+= " Status is "+str(data['issues'][i]['status'])
				Description+= " is New "+str(data['issues'][i]['isNew'])
				Description+= " and creationDate is "+str(data['issues'][i]['creationDate'])
				sum = data['issues'][i]['message']
				print(Description)
				#create_Jira_Data(request, Description, sum)
			else:
				#Description = "The Jenkins key of the issue is "+data['issues'][i]['key']+"-in "+data['issues'][i]['component']+" message-"+data['issues'][i]['message']+" severity-"+data['issues'][i]['severity']+" rule-"+data['issues'][i]['rule']+" status "+data['issues'][i]['status']+" isNew "+str(data['issues'][i]['isNew'])+" creationDate "+data['issues'][i]['creationDate']
				Description = "The Jenkins key of the issue is "+data['issues'][i]['key']
				Description+= " in file "+data['issues'][i]['component']
				Description+= " message: "+str(data['issues'][i]['message'])
				Description+= " severity-"+str(data['issues'][i]['severity'])
				Description+= " rule-: "+str(data['issues'][i]['rule'])
				Description+= " Status is "+str(data['issues'][i]['status'])
				Description+= " is New "+str(data['issues'][i]['isNew'])
				Description+= " and creationDate is "+str(data['issues'][i]['creationDate'])
				sum = data['issues'][i]['message']
				print(Description)
				#create_Jira_Data(request, Description, sum)
		except:
			print("something Goes wrong")
		#self.create_Jira_Data(request, Description, sum)
	return HttpResponse(Description)
#http://192.168.0.45:8000/newBug/
#http://192.168.0.45:8081/job/IONApp/ws/www/.scannerwork/report.json
#https://docs.atlassian.com/DAC/rest/jira/6.1.html
#http://192.168.0.45:8000/newjsonjenkins/
#def create_Jira_Data(request, discription, sum):
#http://192.168.0.45:8000/newjsonjenkins/ jira bug creation data get from jenkins
#new jenkins form with jira -http://192.168.0.45:8000/jenkinsform/
def create_Jira_Data(request, discription, sum):
	#des =discription.split(', ', 0)
	#sum = sum.split(', ', 0)
	#print(discription)
	#print(sum)
	headers = {"Content-Type":"application/json"}
	data = {"fields": {"project":{"key": "JIR"},
                              "summary": sum,
                              "description": discription,
                              "issuetype": {"name": "Bug"}
                              }}
	response = requests.post("http://192.168.0.45:8080/rest/api/2/issue", data=json.dumps(data), headers=headers, auth=('divya_chakraborty', 'Windows123$'))
	#print(response)
	#geodata = response.json()
	#return HttpResponse(response)
	
def post_list(request):
    return render(request, 'jenkins.html', {})
	
def MyCustomLogin(request):
	username="not logged in"
	if request.method == "POST":
		MyLoginForm = myLoginForm(request.POST)
		print("hi")
		if MyLoginForm.is_valid():
			username = MyLoginForm.cleaned_data['username']
			print(username)
	else:
		MyLoginForm = myLoginForm()
	return render(request, 'login.html', {"username" : username})

import urllib	
def jenkinsFormDisplay(request):
	#res=''
	if request.method=="POST":
		myJenkinForm = jenkinUrlForm(request.POST)
		#data1 = request.POST.get('url')
		#print(data1)
		if myJenkinForm.is_valid():
			url = myJenkinForm.cleaned_data['url']
			#data = myJenkinForm.cleaned_data
			#url1 = data['url']
			#data1 = request.POST.get('url')
			#print(data1)
			#print(url)
			key = myJenkinForm.cleaned_data['key']
			type = myJenkinForm.cleaned_data['type']
			username = 'manmeet_kaur'
			password = 'manmeet'
			res=requests.get(url, auth=(username, password)).content
			data = json.loads(res.decode('utf-8'))
			#data = res.decode('utf-8')
			#distros_dict = json.load(res)
			#print(d)
			c = len(data['issues'])
			#print(data['issues'][0].get('line'))
			#md = json.dumps(data)
			#data1 = res.json()
			#d = data['issues'][0]
			#st = str(d)
			#print(st)
			#t=json.loads(res.content)
			#m1=data['issues'][0]
			#print(ma)
			#print(c)
			for i in range(0,1):
				try:
					#if data['issues'][i].get('line') != None and data['issues'][i].get('startLine') != None and data['issues'][i].get('startOffset') != None and data['issues'][i].get('endLine') != None and data['issues'][i].get('endOffset') != None:
					if data['issues'][i].get('line') != None:
						#discription = "The Jenkins key of the issue is "+data['issues'][i]['key']+"-in "+data['issues'][i]['component']+" line number-"+str(data['issues'][i]['line'])+" startLine is-"+str(data['issues'][i]['startLine'])+" startoffset-"+str(data['issues'][i]['startOffset'])+" endline "+str(data['issues'][i]['endLine'])+" endOffset "+str(data['issues'][i]['endOffset'])+" message-"+data['issues'][i]['message']+" severity-"+data['issues'][i]['severity']+" rule-"+data['issues'][i]['rule']+" status "+data['issues'][i]['status']+" isNew "+str(data['issues'][i]['isNew'])+" creationDate "+data['issues'][i]['creationDate']
						Description = "The Jenkins key of the issue is "+res['issues'][i]['key']
						Description+= " in file "+res['issues'][i]['component']
						Description+= " Line Number is-"+str(res['issues'][i]['line'])
						Description+= " startLine-"+str(res['issues'][i]['startLine'])
						Description+= " startOffset-"+str(res['issues'][i]['startOffset'])
						Description+= " endLine-"+str(res['issues'][i]['endLine'])
						Description+= " endOffset-"+str(res['issues'][i]['endOffset'])
						Description+= " message: "+str(res['issues'][i]['message'])
						Description+= " severity-"+str(res['issues'][i]['severity'])
						Description+= " rule is "+str(res['issues'][i]['rule'])
						Description+= " Status is "+str(res['issues'][i]['status'])
						Description+= " is New "+str(res['issues'][i]['isNew'])
						Description+= " and creationDate is "+str(res['issues'][i]['creationDate'])
						sum = res['issues'][i]['message']
						create_Jira_Data(request, Description, sum)
					else:
						#discription = "The Jenkins key of the issue is "+data['issues'][i]['key']+"-in "+data['issues'][i]['component']+" message-"+data['issues'][i]['message']+" severity-"+data['issues'][i]['severity']+" rule-"+data['issues'][i]['rule']+" status "+data['issues'][i]['status']+" isNew "+str(data['issues'][i]['isNew'])+" creationDate "+data['issues'][i]['creationDate']
						Description = "The Jenkins key of the issue is "+res['issues'][i]['key']
						Description+= " in file "+res['issues'][i]['component']
						Description+= " message: "+str(res['issues'][i]['message'])
						Description+= " severity-"+str(res['issues'][i]['severity'])
						Description+= " rule-: "+str(res['issues'][i]['rule'])
						Description+= " Status is "+str(res['issues'][i]['status'])
						Description+= " is New "+str(res['issues'][i]['isNew'])
						Description+= " and creationDate is "+str(res['issues'][i]['creationDate'])
						sum = res['issues'][i]['message']
						create_Jira_Data(request, Description, sum)
				except:
					print("Something Goes Wrong")
				Description = data['issues'][i]
				res = " ".join(("{}={}".format(*i) for i in Description.items()))
				sum = data['issues'][i]['message']
				create_Jira_Data(request, res, sum)
				#print(Description)
				#print(sum)
	else:
		myJenkinForm = jenkinUrlForm()
	#return render(request, 'jenkinsresult.html', {"message":"Bug Are Successfully Created"})
	return HttpResponse(res)
	
def multipleUser(request):
	test = Mall.objects.raw('SELECT * FROM api_mall')
	#print(test[0].MName)
	for x in test:
		return HttpResponse(x)
	