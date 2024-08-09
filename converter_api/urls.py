from django.urls import path
from .views import TransferView
from rest_framework.response import Response
from rest_framework import status
from .views import TransferView, ExecutePaymentView, custom_logout
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import TransactionCreateView, TransactionListView
from .views import register, login, transfer_view, transaction_list
from .views import transfer
from django.contrib.auth.views import LogoutView

urlpatterns = [
    # Traditional Django views
    path('register/', register, name='register'),
    path('login/', login, name='login'),
    path('transfer/', transfer_view, name='transfer'),
    path('transactions/', transaction_list, name='transaction_list'),
    path('payout/', transfer, name='payout'),
    path('logout/', custom_logout, name='logout'),

    # DRF views
    path('api/transfer/', TransferView.as_view(), name='api_transfer'),
    path('api/transactions/', TransactionListView.as_view(), name='api_transactions'),
    path('api/transactions/create/', TransactionCreateView.as_view(), name='api_transaction_create'),
    path('api/transfer/execute/', ExecutePaymentView.as_view(), name='api_transfer_execute'),
]
