from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Transaction

class TransferSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    recipient_account = serializers.EmailField()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
    
class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = ('id', 'user', 'amount', 'recipient_account', 'status', 'created_at', 'payment_id', 'payer_id')
        read_only_fields = ('user', 'status', 'created_at', 'payment_id', 'payer_id')