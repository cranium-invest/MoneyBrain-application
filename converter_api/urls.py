from django.urls import path
from .views import TransferView
from rest_framework.response import Response
from rest_framework import status
from .views import TransferView, ExecutePaymentView, custom_logout, submit_kyc, kyc_form
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import TransactionCreateView, TransactionListView
from .views import register, login, transfer_view, transaction_list
from .views import transfer, create_payout, test_view, redirect_to_paypal, paypal_callback
from django.contrib.auth.views import LogoutView
from . import views

urlpatterns = [
    # Traditional Django views
    path('test-create-payout/', create_payout, name='test_create_payout'),
    path('register/', register, name='register'),
    path('login/', login, name='login'),
    path('transfer/', transfer_view, name='transfer'),
    path('transactions/', transaction_list, name='transaction_list'),
    path('payout/', transfer, name='payout'),
    path('logout/', custom_logout, name='logout'),
    path('kyc/', kyc_form, name='kyc_form'), 
    path('submit-kyc/', submit_kyc, name='submit_kyc'),
    path('paypalpayout/', views.payout_form, name='payout_form'),
    path('paypal/authorize/', redirect_to_paypal, name='paypal_authorize'),
    path('paypal/callback/', paypal_callback, name='paypal_callback'),
    path('privacy-policy/', views.privacy_policy, name='privacy_policy'),
    path('user-agreement/', views.user_agreement, name='user_agreement'),
    path('paypal/user-info/', views.get_paypal_user_info, name='paypal_user_info'),

    # DRF views
    path('api/transfer/', TransferView.as_view(), name='api_transfer'),
    path('api/transactions/', TransactionListView.as_view(), name='api_transactions'),
    path('api/transactions/create/', TransactionCreateView.as_view(), name='api_transaction_create'),
    path('api/transfer/execute/', ExecutePaymentView.as_view(), name='api_transfer_execute'),
]
