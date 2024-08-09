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
from rest_framework import generics
from .models import Transaction
from .serializers import TransactionSerializer
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from .models import Transaction
from .forms import CustomUserCreationForm, CustomAuthenticationForm

import requests
from django.conf import settings
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import logout
from django.views.generic import TemplateView


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
from django.shortcuts import render
from django.http import JsonResponse
import requests

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
            'Authorization': 'Bearer gDhUJ08ACADaESduvV9euaXqRE55r0hsUaUsxKkxwyPN1ES/yY6pdI1txn6lysEuZZIa5u0RQF8uflbBSoIpyA==',
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
            response = requests.post(api_url, json=payload, headers=headers)
            response.raise_for_status()
            # Log the full response for debugging
            print("Response status code:", response.status_code)
            print("Response content:", response.content)
        except requests.exceptions.RequestException as e:
            print("Request Exception:", str(e))
            return JsonResponse({'error': str(e)}, status=500)

        if response.status_code == 201:
            return JsonResponse({'message': 'Transaction created successfully!'})
        else:
            return JsonResponse({'error': 'Failed to create transaction', 'details': response.json()}, status=response.status_code)

    return render(request, 'payout.html')

def custom_logout(request):
    logout(request)
    return redirect('login')