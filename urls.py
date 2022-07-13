from django.conf.urls import url
from rest_framework.urlpatterns import format_suffix_patterns
from .views import createMallView, detailsMallView
from .views import createShopView, detailsShopView
from .views import fetchDataview, viewUserTable, createProductView,\
    detailsProductView, MallsList, Shoplist,\
    Productlist, SearchProductlist, OrderCreateView, OrderDeatilsView,\
    OrderHistory, UpdatePassword
#from .views import ResetPasswordRequestView
from api.views import WishListCreate, CartCreate, RemoveFromWishList,\
    create_user, UserRegistration, UserList, CreateOrder, login_user
#from django.views.generic.base import TemplateView

app_name = 'api'
urlpatterns = {
    url(r'^mall_create/$', createMallView.as_view(), name="create"),
    url(r'^mall_details/(?P<pk>[0-9]+)/$', detailsMallView.as_view(), name="details"),
    url(r'^shop_create/$', createShopView.as_view(), name="create"),
    url(r'^shop_details/(?P<pk>[0-9]+)/$', detailsShopView.as_view(), name="details"),
    url(r'^fetch_join/(?P<pk>[0-9]+)/$', fetchDataview.as_view(), name="details"),
    url(r'^view_user/$', viewUserTable.as_view(), name="details"),
    url(r'^product_create/$', createProductView.as_view(), name="details"),
    url(r'^product_details/(?P<pk>[0-9]+)/$', detailsProductView.as_view(), name="details"),
    url('mall_list/$', MallsList.as_view(), name="list"),#mall list api
    url('shop_list/$', Shoplist.as_view(), name="list"),#shop list api
    url('product_list/$', Productlist.as_view(), name="list"),#product list api
    url(r'^product_search_list/$', SearchProductlist.as_view(), name="searchlist"),
    url(r'^order_create/$', OrderCreateView.as_view(), name="create"),#create order api
    url(r'^order_details/(?P<pk>[0-9]+)/$', OrderDeatilsView.as_view(), name="details"),
    url(r'^order_history/$', OrderHistory.as_view(), name="create"),
    url(r'^user_registration/$', UserRegistration.as_view(), name="create"),
    #url(r'^user_login/$', UserLogin.as_view(), name="create"),
    url(r'^change_password/$', UpdatePassword.as_view(), name="create"),#changr password api
    #url(r'^reset_password/$', ResetPasswordRequestView.as_view(), name="create"),
    url(r'^create_wishlist/$', WishListCreate.as_view(), name="create"),
    url(r'^create_cart/$', CartCreate.as_view(), name="create"),
    url(r'^delete_from_wishlist/(?P<pk>[0-9]+)/$', RemoveFromWishList.as_view(), name="delete"),
    url('create_user/$', create_user, name="create"),#this link for usercreation
    url('login/$', login_user),#user login
    url('cerate_user_list/$', UserList.as_view(), name="create"),
    url('create_order/$', CreateOrder),
    
    

    #for test create_user
    #url(r'^viewarticle/(\d+)/$', viewArticle, name="viewArticle"),
    #url(r'^hellotest/$', hello, name="hello"),
    #url(r'^connection/',TemplateView.as_view(template_name = 'login.html')),
}
urlpatterns = format_suffix_patterns(urlpatterns)
