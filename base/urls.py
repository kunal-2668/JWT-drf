from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)
from .views import MyTokenObtainView ,UserRegistration,GetAllUsers ,UserLogin, UserProfile,UserLogout,RefreshTokenView


urlpatterns = [
    path('token/', MyTokenObtainView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('userrergistration',UserRegistration.as_view(),name='userregistration'),
    path('GetAllUsers',GetAllUsers.as_view(),name='GetAllUsers'),
    path('userlogin',UserLogin.as_view(),name='userlogin'),
    path('logout',UserLogout.as_view(),name='UserLogout'),
    path('userprofile',UserProfile.as_view(),name='UserProfile'),
    path('RefreshTokenView',RefreshTokenView.as_view(),name='RefreshTokenView'),

]
