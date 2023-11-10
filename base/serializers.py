from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate


class UserSerilizer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

        extra_kwargs={
                'password':{'write_only':True}
            }

class UserRegistrationSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(style={'input_type':"password"}, write_only = True)
    class Meta:
        model = User
        fields = ['username','password','confirm_password']

        extra_kwargs={
            'password':{'write_only':True}
        }

    def validate(self, data):
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        if password != confirm_password:
            raise serializers.ValidationError('password comfirmation failed')
        return data

    def create(self, validated_data):
        return User.objects.create_user(username=validated_data['username'],password=validated_data['password'])


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(style={'input_type':"password"})
    
    
class userProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username','id']

        
