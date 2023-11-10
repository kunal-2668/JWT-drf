from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from .serializers import UserRegistrationSerializer , UserSerilizer , UserLoginSerializer, userProfileSerializer
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from django.http import HttpResponse
import jwt, datetime, requests
from rest_framework import exceptions

# **************************************************************
# Custom renderer

from rest_framework import renderers
import json

class userRenderer(renderers.JSONRenderer):
    charset = 'utf-8'

    def render(self, data, accepted_media_type=None, renderer_context=None):
        response = ''
        if 'ErrorDetail' in str(data):
            response = json.dumps({'errors':data})
        else:
            response = json.dumps(data)
        
        return response



# **************************************************************
# Decode JWT

def create_access_token(id):
    return jwt.encode({
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
        'iat': datetime.datetime.utcnow()
    }, 'access_secret', algorithm='HS256')

def decode_access_token(token):
    try:
        payload = jwt.decode(token, 'access_secret', algorithms='HS256')

        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('unauthenticated')

def create_refresh_token(id):
    return jwt.encode({
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow()
    }, 'refresh_secret', algorithm='HS256')

def decode_refresh_token(token):
    try:
        payload = jwt.decode(token, 'refresh_secret', algorithms='HS256')

        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('unauthenticated')



# **************************************************************
# Create your views here.

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['username'] = user.username
        # ...

        return token


class MyTokenObtainView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistration(APIView):
    renderer_classes = [userRenderer]

    def post(self,request):
        serializer = UserRegistrationSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_tokens_for_user(user)
        return Response({'message':'success',"data":serializer.data,'token':token})


class UserLogin(APIView):
    renderer_classes = [userRenderer]

    def post(self,request):
        serializer = UserLoginSerializer(data = request.data)

        serializer.is_valid(raise_exception=True)
        username = serializer.data.get('username')
        password = serializer.data.get('password')
        user = authenticate(username=username,password=password)

        if user is not None:
            token = get_tokens_for_user(user)
            
            response = Response()
            
            response.set_cookie(key='refreshToken',value=token['refresh'],httponly=True)
            response.data = {'message':'Login Success','token':token}

            return response

        else:
            return Response({'non_fields_errors':{'message':'Invalid Email/Password'}})


class UserLogout(APIView):
    def post(self,request):
        response = Response()

        response.delete_cookie(key='refreshToken')

        response.data = {
            'message':'Logout Success'
        }

        return response

class GetAllUsers(APIView):
    renderer_classes = [userRenderer]
    def get(self,request):
        data = User.objects.all()
        serializer = UserSerilizer(data,many=True)
        return Response({'message':'success','data':serializer.data})


class UserProfile(APIView):
    renderer_classes = [userRenderer]
    permission_classes = [IsAuthenticated]

    def get(self,request):
        serializer = userProfileSerializer(request.user)
        # user = request.COOKIES.get("refreshToken")
        return Response({'data':serializer.data})

class RefreshTokenView(APIView):
    def post(self,request):
        requesttoken = request.data['refresh']
        url = "http://localhost:8000/api/token/refresh/"
        body = {
                "refresh": requesttoken
            }
        response = Response()
        data = requests.post(url,body).json()

        if "token_not_valid" in str(data):
            response.data = {'message':'Token Blacklisted'}
        else:
            # response.delete_cookie(key='refreshToken')

            response.set_cookie(key='refreshToken',value=data['refresh'],httponly=True)

            response.data = {'message':'Success','token':data}

        return response