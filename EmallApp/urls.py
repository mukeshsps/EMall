"""EmallApp URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from api.views import HomePageView, index15,addNewUser, signup, home15, signup115, about, contact, myLoggedinPage, multipleUser, login_view_My, createJiraBug, getjiradata, getResponsejenkins, post_list, MyCustomLogin, jenkinsFormDisplay
from api import views
from django.views.generic import TemplateView

urlpatterns = [
    #path('admin/', admin.site.urls),
	path('admin/', admin.site.urls),
	path('api/', include('api.urls')),
	path('api-auth/', include('rest_framework.urls')),
	#path('home/', HomePageView.as_view()),
	#url('login55/', django.contrib.auth.views.login, {'template_name': 'login.html'}, name='mysite_login'),
	#path('getdata/', views.index15),
	#path('adduser/', views.addNewUser),
	#path('api/login15/home/', HomePageView1.as_view()),
	path('signup/', signup, name='signup'),
	#path('signup115/', signup115, name='signup'),
	#path('login/$', auth_views.login, name="login"),
    #url(r'^login/$', auth_views.login, {'template_name': 'login.html'}, name='login'),
	path('login/', auth_views.login, {'template_name': 'login.html'}, name='login'),
    path('logout/', auth_views.logout, {'next_page': 'login'}, name='logout'),
    #path('logout/', auth_views.logout, name='logout'),
	path('login/home/', home15, name='home'),
	path('login/home/about/', about, name='about'),
	#path('about/', about, {'template_name': 'about.html'}, name='about'),
	path('login/home/contact/', contact, name='contact'),
	#path('contact/', contact, {'template_name': 'contact.html'},name='contact'),
	path('mylogin/', myLoggedinPage, name='myLoggedinPage'),
	path('frontuserlogin/', login_view_My, name='login_view_My'),
	path('createBug/', createJiraBug, name='createJiraBug'),
	path('newBug/', getjiradata, name='getjiradata'),
	path('newjsonjenkins/', getResponsejenkins, name='getResponsejenkins'),
	path('jenkinsview/', post_list, name='post_list'),
	path('mycustomagain/', MyCustomLogin, name='MyCustomLogin'),
	path('connection/',TemplateView.as_view(template_name = 'loggedin.html')),
	path('jenkinsform/',TemplateView.as_view(template_name = 'jenkins.html')),
	path('mycustomagain1/', jenkinsFormDisplay, name='jenkinsFormDisplay'),
	path('mymalllist/', multipleUser, name='multipleUser'),
	
]
admin.site.site_header = "E_Mall Site Administration"
admin.site.site_title = "E-Mall Site Admin"
admin.site.site_url = 'home/'
admin.site.index_title = 'Mukesh site'
admin.empty_value_display = '**Empty**'