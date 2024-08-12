from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import TransferSerializer
from paypalrestsdk import Payment
from django.conf import settings
import paypalrestsdk
from rest_framework import generics
from .serializers import UserSerializer
from rest_framework.permissions import IsAuthenticated
from .serializers import TransactionSerializer
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from .models import Transaction
from .forms import CustomUserCreationForm, CustomAuthenticationForm
import requests
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import logout
from django.views.generic import TemplateView
from django.http import HttpResponse



paypalrestsdk.configure({
    "mode": settings.PAYPAL_MODE,
    "client_id": settings.PAYPAL_CLIENT_ID,
    "client_secret": settings.PAYPAL_CLIENT_SECRET,
})

class TransferView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = TransferSerializer(data=request.data)
        if serializer.is_valid():
            amount = serializer.validated_data['amount']
            recipient_account = serializer.validated_data['recipient_account']
            payment = Payment({
                "intent": "sale",
                "payer": {
                    "payment_method": "paypal"
                },
                "transactions": [{
                    "amount": {
                        "total": f"{amount:.2f}",
                        "currency": "USD"
                    },
                    "payee": {
                        "email": recipient_account
                    },
                    "description": "Transfer from ZAR to USD"
                }],
                "redirect_urls": {
                    "return_url": "http://localhost:8000/api/transfer/execute/",
                    "cancel_url": "http://localhost:8000/api/transfer/cancel/"
                }
            })
            if payment.create():
                transaction = Transaction.objects.create(
                    user=request.user,
                    amount=amount,
                    recipient_account=recipient_account,
                    payment_id=payment.id
                )
                for link in payment.links:
                    if link.rel == "approval_url":
                        approval_url = link.href
                        return Response({'approval_url': approval_url}, status=status.HTTP_201_CREATED)
            return Response({'error': 'Payment creation failed'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class TransactionCreateView(generics.CreateAPIView):
    queryset = Transaction.objects.all()
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class TransactionListView(generics.ListAPIView):
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Transaction.objects.filter(user=self.request.user)
    
class ExecutePaymentView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        payment_id = request.GET.get('paymentId')
        payer_id = request.GET.get('PayerID')
        try:
            transaction = Transaction.objects.get(payment_id=payment_id, user=request.user)
        except Transaction.DoesNotExist:
            return Response({'error': 'Transaction not found'}, status=status.HTTP_400_BAD_REQUEST)

        payment = paypalrestsdk.Payment.find(payment_id)
        if payment.execute({"payer_id": payer_id}):
            transaction.status = 'Completed'
            transaction.payer_id = payer_id
            transaction.save()
            return Response({'status': 'Payment successful'}, status=status.HTTP_200_OK)
        else:
            transaction.status = 'Failed'
            transaction.save()
            return Response({'status': 'Payment execution failed'}, status=status.HTTP_400_BAD_REQUEST)
        

def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')
    else:
        form = CustomUserCreationForm()
    return render(request, 'registration/register.html', {'form': form})

def login(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            auth_login(request, user)
            return redirect('transfer')
    else:
        form = AuthenticationForm()
    return render(request, 'registration/login.html', {'form': form})


def transfer_view(request):
    amount = 0.01 
    return render(request, 'transfer_form.html', {'amount': amount})


@login_required
def transaction_list(request):
    transactions = Transaction.objects.filter(user=request.user)
    return render(request, 'transfer/transaction_list.html', {'transactions': transactions})

# Views For AZA Finances Services
import os
import logging
from django.conf import settings

logger = logging.getLogger(__name__)
import hmac
import hashlib
import json
import requests
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.conf import settings

logger = logging.getLogger(__name__)

def transfer(request):
    if request.method == 'POST':
        sender_data = {
            'first_name': request.POST.get('first_name'),
            'last_name': request.POST.get('last_name'),
            'phone_country': request.POST.get('phone_country'),
            'phone_number': request.POST.get('phone_number'),
            'country': request.POST.get('country'),
            'city': request.POST.get('city'),
            'street': request.POST.get('street'),
            'postal_code': request.POST.get('postal_code'),
            'address_description': request.POST.get('address_description', ''),
            'birth_date': request.POST.get('birth_date'),
            'email': request.POST.get('email'),
            'external_id': request.POST.get('external_id'),
            'ip': request.POST.get('ip'),
            'documents': []
        }

        recipient_data = {
            'requested_amount': request.POST.get('requested_amount'),
            'requested_currency': request.POST.get('requested_currency'),
            'payout_method': {
                'type': 'USD::Balance',
                'details': {
                    'reference': request.POST.get('payout_method')
                }
            }
        }

        payin_method_data = {
            'type': request.POST.get('payin_type'),
            'ux_flow': 'ussd_popup',
            'in_details': {
                'phone_number': request.POST.get('phone_number_payin'),
                'mobile_provider': request.POST.get('mobile_provider')
            }
        }

        transaction_data = {
            'input_currency': request.POST.get('input_currency'),
            'external_id': request.POST.get('transaction_external_id'),
            'metadata': request.POST.get('transaction_metadata', '{}')
        }

        api_url = 'https://api-sandbox.transferzero.com/v1/transactions'
        headers = {
            'Authorization': f"Bearer {settings.TRANSFERZERO_API_KEY}",
            'Content-Type': 'application/json',
        }
        payload = {
            'transaction': {
                'sender': sender_data,
                'recipients': [recipient_data],
                'payin_methods': [payin_method_data],
                'input_currency': transaction_data['input_currency'],
                'external_id': transaction_data['external_id'],
                'metadata': transaction_data['metadata'],
            }
        }

        try:
            response = requests.post(api_url, json=payload, headers=headers, timeout=10)
            response.raise_for_status()
            logger.info("Response status code: %s", response.status_code)
            logger.info("Response content: %s", response.content)
        except requests.exceptions.RequestException as e:
            logger.error("Request Exception: %s", str(e))
            return JsonResponse({'error': str(e)}, status=500)

        if response.status_code == 201:
            return JsonResponse({'message': 'Transaction created successfully!'})
        else:
            return JsonResponse({'error': 'Failed to create transaction', 'details': response.json()}, status=response.status_code)

    return render(request, 'payout.html')

@csrf_exempt
def transferzero_webhook(request):
    if request.method == 'POST':
        webhook_content = request.body.decode('utf-8')
        webhook_url = request.build_absolute_uri()
        webhook_headers = {
            'Authorization-Nonce': request.headers.get('Authorization-Nonce'),
            'Authorization-Key': request.headers.get('Authorization-Key'),
            'Authorization-Signature': request.headers.get('Authorization-Signature'),
        }

        if validate_webhook(webhook_url, webhook_content, webhook_headers):
            webhook_data = json.loads(webhook_content)

            event_type = webhook_data.get('event')

            if event_type.startswith('payin_method'):
                handle_payin_method(webhook_data)
            elif event_type.startswith('transaction'):
                handle_transaction(webhook_data)
            elif event_type.startswith('sender'):
                handle_sender(webhook_data)

            return JsonResponse({'status': 'success'}, status=200)
        else:
            return JsonResponse({'error': 'Invalid webhook signature'}, status=400)

    return JsonResponse({'error': 'Invalid method'}, status=405)

def validate_webhook(webhook_url, webhook_content, webhook_headers):
    signature = webhook_headers['Authorization-Signature']
    nonce = webhook_headers['Authorization-Nonce']
    api_key = webhook_headers['Authorization-Key']

    # Create the expected signature
    data = f"{webhook_url}{nonce}{webhook_content}"
    expected_signature = hmac.new(
        settings.TRANSFERZERO_API_SECRET.encode('utf-8'),
        data.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected_signature)

def handle_payin_method(webhook_data):
    external_id = webhook_data['object']['external_id']
    if webhook_data['event'] == 'payin_method.error':
        # Handle collection attempt failed
        pass

def handle_transaction(webhook_data):
    transaction_id = webhook_data['object']['id']
    external_id = webhook_data['object']['external_id']
    
    if webhook_data['event'] == 'transaction.paid_in':
        # Handle customer has paid in the funds event
        pass
    elif webhook_data['event'] == 'transaction.paid_out':
        # Handle funds have been put into internal balance event
        pass
    elif webhook_data['event'] == 'transaction.canceled':
        # Handle transaction canceled due to non-receipt of funds event
        pass

def handle_sender(webhook_data):
    if webhook_data['event'] == 'sender.approved':
        # Handle sender approved event
        pass
    elif webhook_data['event'] == 'sender.rejected':
        # Handle sender rejected event
        pass

#Manual handling of external id.

def get_transaction_status(request):
    if request.method == 'GET':
        external_id = request.GET.get('external_id')
        if not external_id:
            return JsonResponse({'error': 'External ID is required'}, status=400)

        api_url = f'https://api-sandbox.transferzero.com/v1/transactions?external_id={external_id}'
        headers = {
            'Authorization': f"Bearer {settings.TRANSFERZERO_API_KEY}",
            'Content-Type': 'application/json',
        }

        try:
            response = requests.get(api_url, headers=headers, timeout=10)
            response.raise_for_status()

            data = response.json()
            if data['object']:
                transaction = data['object'][0]
                return JsonResponse(transaction, status=200)
            else:
                return JsonResponse({'error': 'Transaction not found'}, status=404)

        except requests.exceptions.RequestException as e:
            logger.error("Request Exception: %s", str(e))
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid method'}, status=405)

def submit_kyc(request):
    if request.method == 'POST':
        kyc_data = {
            'first_name': request.POST.get('first_name'),
            'last_name': request.POST.get('last_name'),
            'phone_number': request.POST.get('phone_number'),
            'email': request.POST.get('email'),
            'document_type': request.POST.get('document_type'),
        }
        
        files = {
            'document_image': request.FILES.get('document_image'),  # Ensure you handle file uploads
            'address_proof': request.FILES.get('address_proof'),      # Ensure you handle file uploads
        }

        api_url = 'https://api-sandbox.transferzero.com/v1/kyc'
        headers = {
        'Authorization': f"Bearer {settings.TRANSFERZERO_API_KEY}",
        'Content-Type': 'application/json',
        } 

        try:
            response = requests.post(api_url, data=kyc_data, files=files, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return JsonResponse({'message': 'KYC submitted successfully!', 'details': data}, status=200)
        except requests.exceptions.RequestException as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid method'}, status=405)

def kyc_form(request):
    if request.method == 'POST':
        # Handle form submission
        return submit_kyc(request)
    return render(request, 'kyc_form.html')

#PayPal Payout

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import paypalrestsdk
import json

@csrf_exempt
def create_payout(request):
    print("create_payout view was called")  # Add this line to debug
    if request.method == 'POST':
        data = json.loads(request.body)
        
        # Initialize PayPal SDK
        paypalrestsdk.configure({
            "mode": "sandbox",  # "live" for production
            "client_id": "ATBbRT9lILunOOtDf2NPwq46I7cioSmEjtGDZ35ueel0xQI3hz-GWbcubtEdC8f7wDKYkSJvOBzFP5sG",
            "client_secret": "EKfdOsrE9fvoIfpa4TPBvnKiZDpEyukr2fH6vfF6dvrKgxiAuUQVi2CRQIm-kn-FaotM0nhE_rvLpjw3"
        })
        
        payout = paypalrestsdk.Payout({
            "sender_batch_header": {
                "sender_batch_id": data['sender_batch_header']['sender_batch_id'],
                "email_subject": data['sender_batch_header']['email_subject'],
                "email_message": data['sender_batch_header']['email_message']
            },
            "items": data['items']
        })

        if payout.create():
            return JsonResponse({'status': 'success', 'payout_id': payout.batch_header.payout_batch_id})
        else:
            return JsonResponse({'status': 'error', 'message': payout.error})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


def payout_form(request):
    return render(request, 'paypalPayout.html')

#REDIRECTION PAYPAL

import base64
import urllib.parse

def redirect_to_paypal(request):
    client_id = 'ATh5idjKiAZa-dmnpO5pTgkOBOkjgufseTxsd4a2hpy34xC0-DmfFyx23NucPnBPs_bcTsyPXW3rmE9k'
    redirect_uri = 'nativexo://paypalpay'
    scope = 'openid profile email'
    
    # Properly URL encode the redirect_uri and scope
    encoded_redirect_uri = urllib.parse.quote_plus(redirect_uri)
    encoded_scope = urllib.parse.quote_plus(scope)
    
    auth_url = (
        f'https://www.sandbox.paypal.com/signin/authorize'
        f'?response_type=code'
        f'&client_id={client_id}'
        f'&redirect_uri={encoded_redirect_uri}'
        f'&scope={encoded_scope}'
    )
    
    return redirect(auth_url)

import base64
import requests
from django.http import JsonResponse

def paypal_callback(request):
    code = request.GET.get('code')
    if not code:
        return JsonResponse({'error': 'No code provided'}, status=400)

    # Exchange authorization code for access token
    token_url = 'https://api.sandbox.paypal.com/v1/oauth2/token'
    client_id = 'ATh5idjKiAZa-dmnpO5pTgkOBOkjgufseTxsd4a2hpy34xC0-DmfFyx23NucPnBPs_bcTsyPXW3rmE9k'
    client_secret = 'ENMiubCDkzIehpUEOFDGHA_wWcBhpzj-xtb7pmebvkATEJT3akrJqe8XAVcLpSnFcI9pDzng6IBG42AU'
    redirect_uri = 'nativexo://paypalpay'  # Standard web URL
    
    auth_string = f'{client_id}:{client_secret}'
    auth_header = base64.b64encode(auth_string.encode()).decode()
    
    response = requests.post(
        token_url,
        headers={
            'Authorization': f'Basic {auth_header}',
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri
        }
    )
    
    if response.status_code == 200:
        tokens = response.json()
        # Store tokens in session or database
        request.session['paypal_access_token'] = tokens.get('access_token')
        return JsonResponse({'success': 'Authorization successful', 'tokens': tokens})
    else:
        return JsonResponse({'error': 'Failed to get access token'}, status=response.status_code)

def privacy_policy(request):
    return render(request, 'privacy_policy.html')

def user_agreement(request):
    return render(request, 'user_agreement.html')

def get_paypal_user_info(request):
    access_token = request.session.get('paypal_access_token')
    if not access_token:
        return JsonResponse({'error': 'Access token is missing'}, status=400)
    
    userinfo_url = 'https://api.sandbox.paypal.com/v1/identity/openidconnect/userinfo'
    
    response = requests.get(
        userinfo_url,
        headers={
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
    )
    
    if response.status_code == 200:
        user_info = response.json()
        return JsonResponse({'user_info': user_info})
    else:
        return JsonResponse({'error': 'Failed to get user info'}, status=response.status_code)


def custom_logout(request):
    logout(request)
    return redirect('login')

def test_view(request):
    return HttpResponse("Test view is working")
