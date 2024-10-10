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
from .views import  list_transactions, save_sender, create_payout,transfer, create_bank_transaction, submit_kyc, kyc_form, webhook_handler, verify_otp_view, initiate_collection_view, create_sender, initiate_ghs_collection,handle_webhook, supported_affiliations_view, create_momo_api_user, get_ecobank_institutions, create_token_transaction,payment_view, eco_info_render, test_view,transaction_complete, get_bearer_token,token_view, redirect_to_paypal,initiate_transfer, paypal_callback, account_information, MoneyGramView, check_deposit, billpay_view, upload_check_images
from django.contrib.auth.views import LogoutView
from . import views

urlpatterns = [
    path('test-create-payout/', create_payout, name='test_create_payout'),
    path('register/', register, name='register'),
    path('login/', login, name='login'),
    path('transfer/', transfer_view, name='transfer'),
    path('payout/', transfer, name='payout'),
    path('kyc/', kyc_form, name='kyc_form'), 
    path('submit-kyc/', submit_kyc, name='submit_kyc'),
    path('transactions/', transaction_list, name='transaction_list'),
    path('logout/', custom_logout, name='logout'),
    path('paypalpayout/', views.payout_form, name='payout_form'),
    path('paypal/authorize/', redirect_to_paypal, name='paypal_authorize'),
    path('paypal/callback/', paypal_callback, name='paypal_callback'),
    path('privacy-policy/', views.privacy_policy, name='privacy_policy'),
    path('user-agreement/', views.user_agreement, name='user_agreement'),
    path('paypal/user-info/', views.get_paypal_user_info, name='paypal_user_info'),
    path('mtransfer/', MoneyGramView.as_view(), name='moneygram_transfer'),
    path('check-deposit/', check_deposit, name='check_deposit'),
    path('billpay/', billpay_view, name='billpay'),
    path('upload-check-images/', upload_check_images, name='upload_check_images'),
    path('account-information/', account_information, name='account_information'),
    path('ecobank-payment/', initiate_transfer, name='ecobank_payment'),
    path('access-bearer-eco/',token_view, name='bearer-eco'),
    path('transaction-complete/', views.transaction_complete, name='transaction_complete'),
    path('eco-info-page/', views.eco_info_render, name='eco_info'),
    path('token-transaction/', create_token_transaction, name='token_transaction'),
    path('eco-inter-transfer/', payment_view, name='eco_inter'),
    path('eco-institution/', get_ecobank_institutions, name='eco_institution'),
    path('momo/integration/', create_momo_api_user, name='momo_integration'),
    path('initiate-ghs-collection/', initiate_ghs_collection, name='initiate_ghs_collection'),
    path('webhooks/', handle_webhook, name='webhook'),
    path('create-sender/', create_sender, name='create_sender'),
    path('initiate-collection/', initiate_collection_view, name='initiate_collection'),
    path('verify-otp/<str:payin_method_id>/<str:phone_number>/<str:mobile_provider>/', verify_otp_view, name='verify_otp'),
    path('webhook/', webhook_handler, name='webhook_handler'),
    path('account_validations/', views.validate_account, name='account_validations'),
    path('create-bank-transaction/', create_bank_transaction, name='create_transaction'),
    path('webhooks/transferzero/', views.transferzero_webhook, name='transferzero_webhook'),
    path('setup-webhook/', views.SetupWebhookView.as_view(), name='setup_webhook'),
    path('get-senders/', views.list_senders, name='get-senders'),
    path('delete-senders/', views.delete_sender, name='delete_sender'),
    path('sender/create/', save_sender, name='save_sender'),
    path('list_transactions/', list_transactions, name='list_transactions'),

    # DRF views
    path('api/transfer/', TransferView.as_view(), name='api_transfer'),
    path('api/transactions/', TransactionListView.as_view(), name='api_transactions'),
    path('api/transactions/create/', TransactionCreateView.as_view(), name='api_transaction_create'),
    path('api/transfer/execute/', ExecutePaymentView.as_view(), name='api_transfer_execute'),
]
