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
from .models import Profile
from django.contrib.auth.models import User
from django.shortcuts import render, get_object_or_404

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
        

def generate_client_id():
    return "CLIENT_" + str(uuid.uuid4())[:12]

def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()  # Save the user instance
            
            # Create and save the Profile instance
            Profile.objects.create(
                user=user,
                client_id=generate_client_id()  # Assign the client ID
            )
            
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
            return redirect('eco_info')
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

#PayPal Payout

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import paypalrestsdk
import json

@csrf_exempt
def create_payout(request):
    print("create_payout view was called") 
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

        
#Money gram API

from django.views import View
from django.conf import settings
import requests
from django.http import JsonResponse
import uuid
from .forms import TransferForm

class MoneyGramView(View):
    base_url = "https://sandboxapi.moneygram.com/transfer/v1/transactions"
    api_key = settings.MONEYGRAM_API_KEY  

    def get_quote(self, amount, destination_country):
        url = f"{self.base_url}/quote"
        headers = {
            'Authorization': f"Bearer {self.api_key}",
            'Content-Type': 'application/json',
            'X-MG-ClientRequestId': str(uuid.uuid4()),
            'X-MG-ConsumerIPAddress': self.get_client_ip(), 
        }
        data = {
            "targetAudience": "AGENT_FACING",
            "agentPartnerId": 30150519,
            "destinationCountryCode": destination_country,
            "serviceOptionCode": "WILL_CALL",
            "sendAmount": {
                "value": float(amount),
                "currencyCode": "USD" 
            }
        }
        response = requests.post(url, headers=headers, json=data)
        return response.json()

    def update_transaction(self, transaction_id, sender_info, receiver_info):
        url = f"{self.base_url}/{transaction_id}"
        headers = {
            'Authorization': f"Bearer {self.api_key}",
            'Content-Type': 'application/json',
        }
        data = {
            "sender": sender_info,
            "receiver": receiver_info,
        }
        response = requests.put(url, headers=headers, json=data)
        return response.json()

    def commit_transaction(self, transaction_id):
        url = f"{self.base_url}/{transaction_id}/commit"
        headers = {
            'Authorization': f"Bearer {self.api_key}",
            'Content-Type': 'application/json',
        }
        response = requests.put(url, headers=headers)
        return response.json()

    def get_client_ip(self):
        """Utility function to get client IP address."""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = self.request.META.get('REMOTE_ADDR')
        return ip

    def get(self, request):
        form = TransferForm()
        return render(request, 'moneygram_transfer.html', {'form': form})

    def post(self, request):
        form = TransferForm(request.POST)
        if form.is_valid():
            amount = form.cleaned_data['amount']
            destination_country = form.cleaned_data['destination_country']
            sender_info = {
                "name": form.cleaned_data['sender_name'],
                "address": form.cleaned_data['sender_address'],
                "phone": form.cleaned_data['sender_phone'],
                "email": form.cleaned_data['sender_email'],
            }
            receiver_info = {
                "name": form.cleaned_data['receiver_name'],
                "address": form.cleaned_data.get('receiver_address', ''),  # optional
                "phone": form.cleaned_data['receiver_phone'],
                "email": form.cleaned_data['receiver_email'],
            }

            quote_response = self.get_quote(amount, destination_country)
            transaction_id = quote_response.get('transactionId')

            if transaction_id:
                update_response = self.update_transaction(transaction_id, sender_info, receiver_info)
                commit_response = self.commit_transaction(transaction_id)
                return JsonResponse(commit_response)
            else:
                return JsonResponse(quote_response, status=400)
        return render(request, 'moneygram_transfer.html', {'form': form})

#GRASS HOPPER API
import requests
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import CheckDepositForm
from .models import UploadedImage

def check_deposit(request):
    if request.method == 'POST':
        form = CheckDepositForm(request.POST, request.FILES)
        if form.is_valid():
            # Save the uploaded images
            uploaded_images = form.save()  # Save images to the database
            back_image_file_id = uploaded_images.back_image.name
            front_image_file_id = uploaded_images.front_image.name

            # Prepare the payload with image file IDs
            payload = {
                "account_id": form.cleaned_data['account_id'],
                "amount": str(form.cleaned_data['amount']),
                "back_image_file_id": back_image_file_id,
                "front_image_file_id": front_image_file_id,
                "device": {
                    "os_name": form.cleaned_data['os_name'],
                    "os_version": form.cleaned_data['os_version']
                },
                "person_id": form.cleaned_data['person_id']
            }

            response = requests.post(
                settings.GRASSHOPPER_API_URL,
                auth=(settings.GRASSHOPPER_API_KEY_ID, settings.GRASSHOPPER_API_KEY_VALUE),
                headers={'Content-Type': 'application/json'},
                json=payload
            )

            if response.status_code == 200:
                messages.success(request, 'Deposit check successful!')
                return redirect('check_deposit')
            else:
                messages.error(request, f'Error: {response.json().get("message", "Unknown error")}')
                return redirect('check_deposit')
    else:
        form = CheckDepositForm()

    return render(request, 'check_deposit.html', {'form': form})

from .forms import BillPayForm

def billpay_view(request):
    if request.method == 'POST':
        form = BillPayForm(request.POST)
        if form.is_valid():
            account_id = form.cleaned_data['account_id']
            amount = form.cleaned_data['amount']
            billpay_counterparty_id = form.cleaned_data['billpay_counterparty_id']
            person_id = form.cleaned_data['person_id']

            url = 'https://api.grasshopper.bank/billpay/payment'
            headers = {
                'Content-Type': 'application/json',
            }
            data = {
                'account_id': account_id,
                'amount': str(amount),
                'billpay_counterparty_id': billpay_counterparty_id,
                'person_id': person_id
            }
            response = requests.post(
                url,
                headers=headers,
                json=data,
                auth=(settings.GRASSHOPPER_API_KEY_ID, settings.GRASSHOPPER_API_KEY_VALUE)
            )
            
            if response.status_code == 200:
                return JsonResponse({'status': 'success', 'message': 'Payment processed successfully!'})
            else:
                return JsonResponse({'status': 'error', 'message': 'Payment failed!', 'details': response.json()})
    else:
        form = BillPayForm()

    return render(request, 'billpay.html', {'form': form})

from django.core.files.storage import default_storage
from django.http import JsonResponse

def upload_check_images(request):
    if request.method == 'POST':
        front_image = request.FILES.get('front_image')
        back_image = request.FILES.get('back_image')
        
        front_image_id = default_storage.save(front_image.name, front_image)
        back_image_id = default_storage.save(back_image.name, back_image)
        
        return JsonResponse({
            'front_image_file_id': front_image_id,
            'back_image_file_id': back_image_id
        })
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

from datetime import datetime

def account_information(request):
    return render(request, 'account_information.html', {'current_year': datetime.now().year})


#Eco cash API

import uuid
import hashlib
import json
from datetime import datetime
import requests
from django.shortcuts import render
from django.http import JsonResponse
from django.conf import settings
from .forms import EcoTransferForm, DeleteSenderForm
from json.decoder import JSONDecodeError

def generate_unique_id():
    return str(uuid.uuid4().hex)

def get_current_datetime():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def generate_sha512_hash(clientid, batchsequence, batchamount, transactionamount,
                         batchid, transactioncount, batchcount, transactionid,
                         debittype, affiliateCode, totalbatches, execution_date, labkey):
    concat_string = (
        f"{clientid}{batchsequence}{batchamount}{transactionamount}"
        f"{batchid}{transactioncount}{batchcount}{transactionid}"
        f"{debittype}{affiliateCode}{totalbatches}{execution_date}{labkey}"
    )
    sha512_hash = hashlib.sha512(concat_string.encode('utf-8')).hexdigest()
    
    return sha512_hash

def get_bearer_token():
    url = 'https://developer.ecobank.com/corporateapi/user/token'
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Origin': 'developer.ecobank.com',
    }

    userid ='iamaunifieddev103'
    password = '$2a$10$Wmame.Lh1FJDCB4JJIxtx.3SZT0dP2XlQWgj9Q5UAGcDLpB0yRYCC' 
    data = {
        'userId': userid,
        'password':password
    }
    
    response = requests.post(url, headers=headers, json=data)
    print(response.json())
    if response.status_code == 200:
        response_data = response.json()
        return response_data.get('token')
    else:
        raise Exception(f"Failed to get token: {response.text}")

def token_view(request):
    try:
        token = get_bearer_token()
        print(token)
        return JsonResponse({'token': token})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def initiate_transfer(request):
    if request.method == 'POST':
        form = EcoTransferForm(request.POST)
        if form.is_valid():
            data = {
                "amount": float(form.cleaned_data['amount']),
                "exchange_rate": float(form.cleaned_data['exchange_rate']),
                "recipient_first_name": form.cleaned_data['recipient_first_name'],
                "recipient_last_name": form.cleaned_data['recipient_last_name'],
                "recipient_residential_address": form.cleaned_data['recipient_residential_address'],
                "recipient_id_type": form.cleaned_data['recipient_id_type'],
                "recipient_id_expiry_date": form.cleaned_data['recipient_id_expiry_date'].strftime('%m/%d/%Y'),
                "recipient_dob": form.cleaned_data['recipient_dob'].strftime('%m/%d/%Y'),
                "receiver_phone_number": form.cleaned_data['receiver_phone_number'],
                "sender_first_name": form.cleaned_data['sender_first_name'],
                "sender_last_name": form.cleaned_data['sender_last_name'],
                "sender_phone_number": form.cleaned_data['sender_phone_number'],
                "sender_residential_address": form.cleaned_data['sender_residential_address'],
                "sender_id_type": form.cleaned_data['sender_id_type'],
                "sender_id_number": form.cleaned_data['sender_id_number'],
                "sender_id_expiry_date": form.cleaned_data['sender_id_expiry_date'].strftime('%m/%d/%Y'),
                "sender_dob": form.cleaned_data['sender_dob'].strftime('%m/%d/%Y'),
                "sender_nationality": form.cleaned_data['sender_nationality'],
                "receiver_nationality": form.cleaned_data['receiver_nationality'],
                "destination_account_number": form.cleaned_data['destination_account_number'],
                "destination_country": form.cleaned_data['destination_country'],
                "destination_bank": form.cleaned_data['destination_bank'],
                "source_country": form.cleaned_data['source_country'],
                "source_bank": form.cleaned_data['source_bank'],
                "narration": form.cleaned_data['narration'],
                "currency": form.cleaned_data['currency'],
                "sender_currency": form.cleaned_data['sender_currency'],
                "receiver_currency": form.cleaned_data['receiver_currency']
            }

            
            payment_header = {
                "clientid": "EGHTelc000043",
                "batchsequence": "1",
                "batchamount": data['amount'],
                "transactionamount": data['amount'],
                "batchid": "EG1593490",
                "transactioncount": 1,
                "batchcount": 1, 
                "transactionid": "E12T443308",
                "debittype": "Multiple", 
                "affiliateCode": "EGH",
                "totalbatches": "1",
                "execution_date": get_current_datetime()
            }

            request_id = '20000000QW4'

            extension = [
                {
                    "request_id": request_id,
                    "request_type": "ECOBANKAFRICA",
                    "param_list": json.dumps([
                        {"key": "receiverLastName", "value": data['recipient_last_name']},
                        {"key": "receiverFirstName", "value": data['recipient_first_name']},
                        {"key": "amount", "value": data['amount']},
                        {"key": "currency", "value": data['currency']},
                        {"key": "senderPhoneNumber", "value": data['sender_phone_number']},
                        {"key": "receiverPhoneNumber", "value": data['receiver_phone_number']},
                        {"key": "destinationAccountNumber", "value": data['destination_account_number']},
                        {"key": "narration", "value": data['narration']},
                        {"key": "exchangeRate", "value": data['exchange_rate']}
                    ]),
                    "amount": data['amount'],
                    "currency": data['currency'],
                    "status": "",
                    "rate_type": "spot"
                }
            ]

            try:
                token = get_bearer_token()
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': str(e)})

            secret_key = '$2a$10$Wmame.Lh1FJDCB4JJIxtx.3SZT0dP2XlQWgj9Q5UAGcDLpB0yRYCC'
            lab_key = '0C/5F7QHdMv40uVGaTbt5nXdJOxi105k2LN9goPRqTUrwZrdYOYbvC0sJz7G0iT9'

            secure_hash = '398d4f285cc33e12f035da19fa9d954be35afaf66816531c4f1a1aedd3c6f132a85c62b23ca12d7b9a99bf5a84fc69b66738289a70e8f8115e90ffaa060f4026'
            payment_data = {
                "paymentHeader": payment_header,
                "extension": extension,
                "execution_date": get_current_datetime(),
                "secureHash": secure_hash
            }

            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json',
                'lab_key': lab_key,
                'Accept': 'application/json',
                'Origin': 'developer.ecobank.com',
            }

            response = requests.post('https://developer.ecobank.com/corporateapi/merchant/payment', headers=headers, json=payment_data)

            print("Response Content:", response.text)

            try:
                response_data = response.json()
            except json.JSONDecodeError:
                return JsonResponse({'status': 'error', 'message': 'Invalid response from the Ecobank API', 'response_text': response.text})

            if response.status_code == 200:
                return redirect('transaction_complete')
            else:
                error_message = response.json().get('message', 'Failed to initiate transfer')
                return JsonResponse({'status': 'error', 'message': error_message})
    else:
        form = EcoTransferForm()

    return render(request, 'eco_form.html', {'form': form})

def transaction_complete(request):
    return render(request, 'transaction_complete.html')

def eco_info_render(request):
    return render(request, 'eco_cash_info.html')


#Token X-press

import secrets
import hashlib
import requests
from django.shortcuts import render, redirect
from django.conf import settings
from .forms import TokenTransactionForm, CrossBorderPaymentForm, affiliationReForm

def generate_secure_hash(payload, lab_key):
    """Generate SHA-512 secure hash."""
    data = payload + lab_key
    hash_object = hashlib.sha512(data.encode('utf-8'))
    return hash_object.hexdigest()

def create_token_transaction(request):
    if request.method == "POST":
        form = TokenTransactionForm(request.POST)
        if form.is_valid():
            sender_name = form.cleaned_data['sender_name']
            sender_mobile_no = form.cleaned_data['sender_mobile_no']
            sender_id = form.cleaned_data['sender_id']
            beneficiary_name = form.cleaned_data['beneficiary_name']
            beneficiary_mobile_no = form.cleaned_data['beneficiary_mobile_no']
            amount = float(form.cleaned_data['amount'])
            transaction_description = form.cleaned_data['transaction_description']
            withdrawal_channel = form.cleaned_data['withdrawal_channel']
            transaction_currency = form.cleaned_data['transaction_currency']
            currency = form.cleaned_data['currency']
            source_account = form.cleaned_data['source_account']
            source_account_currency = form.cleaned_data['source_account_currency']
            

            source_account_type = "Corporate"
            rate_type = "Spot"
            secret_code = secrets.token_hex(8)


            url = 'https://developer.ecobank.com/corporateapi/merchant/payment'
            
            payment_header = {
                "clientid": "EGHTelc000043",
                "batchsequence": "1",
                "batchamount": 520,
                "transactionamount": 520,
                "batchid": "EG1593490",
                "transactioncount": 6,
                "batchcount": 6,
                "transactionid": "E12T443308",
                "debittype": "Multiple",
                "affiliateCode": "EGH",
                "totalbatches": "1",
                "execution_date": "2024-08-15 00:00:00"
            }

            payload_header = "".join(str(payment_header[key]) for key in payment_header)
            
            lab_key = 'XT7zuounWNKXmbwdAR+qYhyQymRdsEUylXFZ/frwBBjDKZsPCDlUjAMH4OQT+uvU'

            # secure_hash = generate_secure_hash(payload_header, lab_key) For Live

            secure_hash = '398d4f285cc33e12f035da19fa9d954be35afaf66816531c4f1a1aedd3c6f132a85c62b23ca12d7b9a99bf5a84fc69b66738289a70e8f8115e90ffaa060f4026'

            extension = [
                    {
                        "request_id": "432",
                        "request_type": "token",
                        "param_list": json.dumps([
                            {"key": "transactionDescription", "value": transaction_description},
                            {"key": "secretCode", "value": secret_code},
                            {"key": "sourceAccount", "value": source_account},
                            {"key": "sourceAccountCurrency", "value": source_account_currency},
                            {"key": "sourceAccountType", "value": source_account_type},
                            {"key": "senderName", "value": sender_name},
                            {"key": "ccy", "value": transaction_currency},
                            {"key": "senderMobileNo", "value": sender_mobile_no},
                            {"key": "amount", "value": amount},
                            {"key": "senderId", "value": sender_id},
                            {"key": "beneficiaryName", "value": beneficiary_name},
                            {"key": "beneficiaryMobileNo", "value": beneficiary_mobile_no},
                            {"key": "withdrawalChannel", "value": withdrawal_channel}
                        ]),
                        "amount": amount,
                        "currency": currency,
                        "status": "",
                        "rate_type": rate_type
                    }
                ]
            payment_data = {
                "paymentHeader": payment_header,
                "extension" : extension,
                "execution_date": get_current_datetime(),
                "secureHash": secure_hash
            }
            
            try:
                token = get_bearer_token()
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': str(e)})
            
            headers = {
                'Authorization': f'Bearer {token}',
                'Origin': 'developer.ecobank.com',
                'lab_key': lab_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(url, headers =headers, json=payment_data)
            
            print("Response Content:", response.text)

            try:
                response_data = response.json()
            except json.JSONDecodeError:
                return JsonResponse({'status': 'error', 'message': 'Invalid response from the Ecobank API', 'response_text': response.text})

            if response.status_code == 200:
                return redirect('transaction_complete')
            else:
                error_message = response.json().get('message', 'Failed to initiate transfer')
                return JsonResponse({'status': 'error', 'message': error_message, 'secure_hash':secure_hash})
    else:
        form = TokenTransactionForm()

    return render(request, 'token_transaction_form.html', {'form': form})

#internation X-transfer

import json
import hashlib
import hmac
import requests
from django.conf import settings
from django.shortcuts import render
from django.http import JsonResponse
from .models import Sender

def payment_view(request):
    if request.method == 'POST':
        form = CrossBorderPaymentForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            receiver_id_expiry_date = form.cleaned_data['receiver_id_expiry_date'].strftime('%m/%d/%Y')
            receiver_dob = form.cleaned_data['receiver_dob'].strftime('%m/%d/%Y')
            sender_dob = form.cleaned_data['sender_dob'].strftime('%m/%d/%Y')
            sender_id_expiry_date= form.cleaned_data['sender_id_expiry_date'].strftime('%m/%d/%Y')

            payment_header = {
                "clientid": "EGHTelc000043",
                "batchsequence": "1",
                "batchamount": float(data['amount']),
                "transactionamount": float(data['amount']),
                "batchid": "EG1593490",
                "transactioncount": 1,
                "batchcount": 1,
                "transactionid": data['batchid'],
                "debittype": "Multiple",
                "affiliateCode": data['affiliate_code'],
                "totalbatches": "1",
                "execution_date": get_current_datetime()
            }

            param_list = [
                {"key": "receiverLastName", "value": data['receiver_last_name']},
                {"key": "sourceCountry", "value": data['source_country']},
                {"key": "senderNationality", "value": data['sender_nationality']},
                {"key": "senderPhoneNumber", "value": data['sender_phone_number']},
                {"key": "destinationBank", "value": data['destination_bank']},
                {"key": "purpose", "value": data['purpose']},
                {"key": "receiverCcy", "value": data['receiver_ccy']},
                {"key": "receiverIdNumber", "value": data['receiver_id_number']},
                {"key": "senderIdNumber", "value": data['sender_id_number']},
                {"key": "senderCcy", "value": data['sender_ccy']},
                {"key": "senderGender", "value": data['sender_gender']},
                {"key": "sourceBank", "value": data['source_bank']},
                {"key": "receiverFirstName", "value": data['receiver_first_name']},
                {"key": "senderLastName", "value": data['sender_last_name']},
                {"key": "receiverResidentialAddress", "value": data['receiver_residential_address']},
                {"key": "receiverIdType", "value": data['receiver_id_type']},
                {"key": "receiverIdExpiryDate", "value": receiver_id_expiry_date},
                {"key": "product", "value": data['product']},
                {"key": "senderIdType", "value": data['sender_id_type']},
                {"key": "receiverDOB", "value": receiver_dob},
                {"key": "receiverPhoneNumber", "value": data['receiver_phone_number']},
                {"key": "senderDOB", "value": sender_dob},
                {"key": "senderFirstName", "value": data['sender_first_name']},
                {"key": "receiverNationality", "value": data['receiver_nationality']},
                {"key": "destinationAccountNumber", "value": data['destination_account_number']},
                {"key": "destinationCountry", "value": data['destination_country']},
                {"key": "narration", "value": data['narration']},
                {"key": "senderResidentialAddress", "value": data['sender_residential_address']},
                {"key": "senderIdExpiryDate", "value": sender_id_expiry_date}
            ]

            extension = {
                "request_id": "20000000QW4",
                "request_type": "ECOBANKAFRICA",
                "param_list": json.dumps(param_list),
                "amount": float(data['amount']),
                "currency": data['sender_ccy'],
                "status": "",
                "rate_type": "spot"
            }

            secure_hash = '398d4f285cc33e12f035da19fa9d954be35afaf66816531c4f1a1aedd3c6f132a85c62b23ca12d7b9a99bf5a84fc69b66738289a70e8f8115e90ffaa060f4026'

            payment_data = {
                "paymentHeader": payment_header,
                "extension": [extension],
                "secureHash": secure_hash,
                "execution_date": get_current_datetime(),
            }
            
            lab_key = '0C/5F7QHdMv40uVGaTbt5nXdJOxi105k2LN9goPRqTUrwZrdYOYbvC0sJz7G0iT9'
            
            try:
                token = get_bearer_token()
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': str(e)})

            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json',
                'lab_key': lab_key,
                'Accept': 'application/json',
                'Origin': 'developer.ecobank.com',
            }

            response = requests.post('https://developer.ecobank.com/corporateapi/merchant/payment', headers=headers, json=payment_data)

            print("Response Content:", response.text)


            try:
                response_data = response.json()
            except json.JSONDecodeError:
                return JsonResponse({'status': 'error', 'message': 'Invalid response from the Ecobank API', 'response_text': response.text})

            if response.status_code == 200:
                return redirect('transaction_complete')
            else:
                error_message = response.json().get('message', 'Failed to initiate transfer')
                return JsonResponse({'status': 'error', 'message': error_message, 'secure_hash':secure_hash})
    else:
        form = CrossBorderPaymentForm()

    return render(request, 'eco_interpayment_form.html', {'form': form})

#Get Affiliations

import requests
import hashlib
import uuid


def generate_secure_hash(request_id, secret_key):
    data = request_id + secret_key
    hash_object = hashlib.sha512(data.encode())
    return hash_object.hexdigest()

def generate_unique_id():
    return str(uuid.uuid4().hex)

def get_ecobank_institutions(request):
    if request.method == 'POST':
        form = affiliationReForm(request.POST)
        if form.is_valid():
            affiliate_code = form.cleaned_data['affiliate_code']
            destination_country = form.cleaned_data['destination_country']
    
            request_id = generate_unique_id()
            profile = Profile.objects.get(user=request.user)
            client_id = profile.client_id
            lab_key = 'XT7zuounWNKXmbwdAR+qYhyQymRdsEUylXFZ/frwBBjDKZsPCDlUjAMH4OQT+uvU'
            #secure_hash = generate_secure_hash(request_id, lab_key) fro live
            secure_hash = '398d4f285cc33e12f035da19fa9d954be35afaf66816531c4f1a1aedd3c6f132a85c62b23ca12d7b9a99bf5a84fc69b66738289a70e8f8115e90ffaa060f4026'
    
            try:
                token = get_bearer_token()
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': str(e)})
    
            url = 'https://developer.ecobank.com/corporateapi/merchant/payment'
            
            headers = {
                'Authorization': f'Bearer {token}',
                'Origin': 'developer.ecobank.com',
                'lab_key': lab_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            payload = {
                "requestId": request_id,
                "clientId": client_id,
                "affiliateCode": affiliate_code,
                "destinationCountry": destination_country,
                "secureHash": secure_hash
            }
            
            try:
                response = requests.post(url, headers=headers, json=payload)
                response.raise_for_status()
                if response.status_code == 204:
                    return JsonResponse({'status': 'success', 'message': 'No content returned'})
                else:
                    return JsonResponse({'status': 'success', 'message': 'Request successful, but no content returned'})
            except requests.exceptions.RequestException as e:
                return JsonResponse({'status': 'error', 'message': str(e)}, status=response.status_code if response else 500)
        else:
            return JsonResponse({'status': 'error', 'message': 'Form is invalid'})
    else:
        form = affiliationReForm()
    return render(request, 'institutions.html', {'form': form})

def supported_affiliations_view(request):
    try:
        institutions = get_ecobank_institutions(request)
        affiliations = [(inst['affiliateCode'], inst['affiliateName']) for inst in institutions]
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

    return render(request, 'supported_affiliations.html', {'affiliations': affiliations})


#MTN momo wallet
import uuid
import requests
from django.http import JsonResponse

def create_momo_api_user(request):

    base_url = "https://sandbox.momodeveloper.mtn.com/v1_0/apiuser"

    reference_id = str(uuid.uuid4())

    headers = {
        "X-Reference-Id": reference_id,
        "Ocp-Apim-Subscription-Key": "50adab826edb49949af14e81b112df1c",
        "Content-Type": "application/json"
    }

    payload = {}

    response = requests.get(base_url, headers=headers)
    print(response.text)
    try:
        data = response.json()
        return JsonResponse(data, status=200)
    except ValueError:
        return JsonResponse({"error": "Invalid JSON Response", "details": response.text}, status=500)
    else:
        return JsonResponse({"error": "Unexpected API Response", "details": response.text}, status=response.status_code)

#AZA Finances API

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
        pass

def handle_transaction(webhook_data):
    transaction_id = webhook_data['object']['id']
    external_id = webhook_data['object']['external_id']
    
    if webhook_data['event'] == 'transaction.paid_in':
        pass
    elif webhook_data['event'] == 'transaction.paid_out':
        pass
    elif webhook_data['event'] == 'transaction.canceled':
        pass

def handle_sender(webhook_data):
    if webhook_data['event'] == 'sender.approved':
        pass
    elif webhook_data['event'] == 'sender.rejected':
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
            'document_image': request.FILES.get('document_image'),
            'address_proof': request.FILES.get('address_proof'),
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
        return submit_kyc(request)
    return render(request, 'kyc_form.html')


import requests
import uuid
from django.shortcuts import render
from django.http import JsonResponse
from .models import GHSTransaction
from django.conf import settings

def initiate_ghs_collection(request):
    if request.method == "POST":
        phone_number = request.POST.get('phone_number')
        mobile_provider = request.POST.get('mobile_provider')

        if not phone_number or not mobile_provider:
            return JsonResponse({'error': 'Phone number and mobile provider are required'}, status=400)

        # Generate a unique transaction ID
        transaction_id = uuid.uuid4().hex

        # Create a new transaction record in the database
        transaction = GHSTransaction.objects.create(
            phone_number=phone_number,
            mobile_provider=mobile_provider,
            ux_flow='ussd_menu_approval',
            transaction_id=transaction_id,
            status='initiated'
        )
        url = "https://api-sandbox.transferzero.com/v1"
        payload = {
            "input_currency": "GHS",
            "payin_methods": [
                {
                    "id": "7334d150-41f8-4710-858b-e16a96df0c71",
                    "type": "GHS::Mobile",
                    "ux_flow": transaction.ux_flow,
                    "in_details": {
                        "phone_number": transaction.phone_number,
                        "mobile_provider": transaction.mobile_provider
                    },
                    "out_details": {
                        "style": "ussd_menu_approval",
                        "menu_option": "6",
                        "requires_pin": True,
                        "dialing_number": "*170#"
                    }
                }
            ]
        }

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {settings.TRANSFERZERO_API_KEY}'
        }

        response = requests.post(url, json=payload, headers=headers)

        if response.status_code == 200:
            response_data = response.json()
            transaction.transaction_id = response_data.get('transaction_id', transaction.transaction_id)
            transaction.status = 'pending'
            transaction.save()

            return JsonResponse({'message': 'Transaction initiated successfully', 'transaction_id': transaction.transaction_id})
        else:
            error_message = response.json().get('error', 'Unknown error')
            return JsonResponse({'error': f'Failed to initiate transaction: {error_message}'}, status=response.status_code)

    return render(request, 'initiate_ghs_collection.html')



def handle_webhook(request):
    if request.method == "POST":
        webhook_data = json.loads(request.body)

        event = webhook_data.get('event')
        transaction_id = webhook_data.get('object', {}).get('transaction_id')

        try:
            transaction = GHSTransaction.objects.get(transaction_id=transaction_id)
        except GHSTransaction.DoesNotExist:
            return HttpResponse(status=404)

        if event == "payin_method.paid_in":
            transaction.status = 'paid'
        elif event == "payin_method.error":
            transaction.status = 'error'
        else:
            transaction.status = 'pending'

        transaction.save()

        return HttpResponse(status=200)

    return HttpResponse(status=405)


#REAL AZA FINANCES API SOLUTIONS
import hmac
import json
from django.conf import settings
from .forms import SenderForm, BankTransactionForm
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import hashlib
import uuid
import requests
from .forms import GHSCollectionForm, OTPVerificationForm

API_KEY = settings.API_KEY
API_SECRET = settings.API_SECRET
URL = settings.URL
COLLECTION_URL = settings.COLLECTION_URL
TANSACTION_URL = settings.TANSACTION_URL

METHOD = "POST"

def create_sender(request):
    if request.method == 'POST':
        form = SenderForm(request.POST, request.FILES)
        
        if form.is_valid():

            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            email = form.cleaned_data['email']
            phone_country = form.cleaned_data['phone_country']
            phone_number = form.cleaned_data['phone_number']
            country = form.cleaned_data['country']
            city = form.cleaned_data['city']
            street = form.cleaned_data['street']
            postal_code = form.cleaned_data['postal_code']
            birth_date = form.cleaned_data['birth_date']
            document_file = request.FILES['document_file']


            document_base64 = base64.b64encode(document_file.read()).decode('utf-8')

            profile = request.user.profile 
            client_id = profile.client_id  
            
            request_body = {
                "sender": {
                    "country": country,
                    "phone_country": phone_country,
                    "phone_number": phone_number,
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "city": city,
                    "street": street,
                    "postal_code": postal_code,
                    "birth_date": birth_date.isoformat(),
                    "documents": [
                        {
                            "upload": f"data:image/png;base64,{document_base64}",
                            "upload_file_name": document_file.name,
                            "metadata": {"meta": "data"}
                        }
                    ],
                    "ip": request.META['REMOTE_ADDR'],
                    "external_id": client_id,
                    "metadata": {"meta": "data"}
                }
            }

            nonce = str(uuid.uuid4())

            json_body = json.dumps(request_body)
            body_hash = hashlib.sha512(json_body.encode()).hexdigest()


            string_to_sign = f"{nonce}&{METHOD}&{URL}&{body_hash}"


            signature = hmac.new(
                API_SECRET.encode(),
                string_to_sign.encode(),
                hashlib.sha512
            ).hexdigest()


            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization-Key": API_KEY,
                "Authorization-Nonce": nonce,
                "Authorization-Signature": signature
            }


            response = requests.post(URL, headers=headers, json=request_body)

            if response.status_code == 201:
                return render(request, 'success.html', {"data": response.json()})
            else:
                return render(request, 'error.html', {"error": response.json()})
    
    else:
        form = SenderForm()

    return render(request, 'create_sender.html', {'form': form})


#AZA Collection

# Your API details

import logging
logger = logging.getLogger(__name__)

def validate_account(mobile_number=None, country='GH', currency='GHS'):
    url = 'https://api-sandbox.transferzero.com/v1/account_validations/'

    payload = {
        'phone_number': mobile_number,
        'country': country,
        'currency': currency,
        'method': 'mobile'
    }

    nonce = str(uuid.uuid4())

    json_body = json.dumps(payload)
    body_hash = hashlib.sha512(json_body.encode()).hexdigest()


    string_to_sign = f"{nonce}&{METHOD}&{URL}&{body_hash}"


    signature = hmac.new(
                API_SECRET.encode(),
                string_to_sign.encode(),
                hashlib.sha512
            ).hexdigest()

    headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization-Key": API_KEY,
                "Authorization-Nonce": nonce,
                "Authorization-Signature": signature
            }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        result = response.json()

        logger.info(f"Validation response: {result}")

        if response.status_code == 200 and result.get('object'):
            return JsonResponse({'valid': True})
        else:
            return JsonResponse({'valid': False, 'message': 'Invalid mobile number'}, status=422)

    except requests.exceptions.RequestException as e:
        logger.error(f"Account validation error: {e}")
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
def initiate_collection_view(request):
    logger.info(f"Request method: {request.method}")
    if request.method == 'POST':
        logger.info(f"Request POST data: {request.POST}")
        form = GHSCollectionForm(request.POST, request.FILES)

        if form.is_valid():
            phone_number = form.cleaned_data['phone_number']
            mobile_provider = form.cleaned_data['mobile_provider']
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            email = form.cleaned_data['email']
            phone_country = form.cleaned_data['phone_country']
            country = form.cleaned_data['country']
            city = form.cleaned_data['city']
            street = form.cleaned_data['street']
            postal_code = form.cleaned_data['postal_code']
            birth_date = form.cleaned_data['birth_date']
            document_file = request.FILES['document_file']

            document_base64 = base64.b64encode(document_file.read()).decode('utf-8')

            sender_details = {
                "country": country,
                "phone_country": phone_country,
                "phone_number": phone_number,
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "city": city,
                "street": street,
                "postal_code": postal_code,
                "birth_date": birth_date.isoformat(),
                "documents": [
                    {
                        "upload": f"data:image/png;base64,{document_base64}",
                        "upload_file_name": document_file.name,
                        "metadata": {"meta": "data"}
                    }
                ],
                "ip": request.META['REMOTE_ADDR'],
                "external_id": str(uuid.uuid4()),
                "metadata": {"meta": "data"}
            }

            recipient_details = {
                "requested_amount": "50",
                "requested_currency": "GHS",
                "payout_method": {
                    "type": "USD::Balance",
                    "details": {
                        "reference": str(uuid.uuid4()),
                    }
                }
            }

            collection_body = {
                "sender": sender_details,
                "recipients": [recipient_details],
                "payin_methods": [{
                    "type": "GHS::Mobile",
                    "ux_flow": "otp_verified_ussd_popup",
                    "in_details": {
                        "phone_number": phone_number,
                        "mobile_provider": mobile_provider,
                    }
                }],
                "input_currency": "GHS",
                "external_id": str(uuid.uuid4()),
                "metadata": {}
            }

            collection_body_json = json.dumps(collection_body)
            body_hash = hashlib.sha512(collection_body_json.encode()).hexdigest()
            nonce = str(uuid.uuid4())
            string_to_sign = f"{nonce}&{METHOD}&{COLLECTION_URL}&{body_hash}"

            signature = hmac.new(
                API_SECRET.encode(),
                string_to_sign.encode(),
                hashlib.sha512
            ).hexdigest()

            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization-Key": API_KEY,
                "Authorization-Nonce": nonce,
                "Authorization-Signature": signature
            }

            logger.info(f"String to Sign: {string_to_sign}")
            logger.info(f"Body Hash: {body_hash}")
            logger.info(f"Signature: {signature}")

            logger.info(f"Serialized JSON Body for Hash: {collection_body_json}")
            collection_response = requests.post(COLLECTION_URL, headers=headers, json=collection_body)
            logger.info(f"Body Sent to API: {collection_body_json}")
            logger.info(f"Collection Status code: {collection_response.status_code}")
            logger.info(f"Collection Response text: {collection_response.text}")

            if collection_response.status_code == 200:
                collection_response_data = collection_response.json()
                payin_method_id = collection_response_data['payin_methods'][0]['id']
                return redirect('verify_otp', payin_method_id=payin_method_id, phone_number=phone_number, mobile_provider=mobile_provider)
            else:
                return JsonResponse({"error": collection_response.text or "Unknown error occurred"}, status=collection_response.status_code)
        else:
            logger.error(f"Form errors: {form.errors}")
            return JsonResponse({"error": form.errors}, status=400)
    else:
        form = GHSCollectionForm()
    return render(request, 'collection_form.html', {'form': form})


def verify_otp_view(request, payin_method_id, phone_number, mobile_provider):
    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data['otp']


            otp_url = f"https://api-sandbox.transferzero.com/v1/payin_methods/{payin_method_id}"
            otp_payload = {
                "in_details": {
                    "phone_number": phone_number,
                    "mobile_provider": mobile_provider,
                    "otp": otp
                }
            }


            nonce = str(uuid.uuid4())
            body_hash = hashlib.sha512(json.dumps(otp_payload).encode('utf-8')).hexdigest()
            string_to_sign = f"{nonce}&{METHOD}&{otp_url}&{body_hash}"
            signature = hmac.new(
                API_SECRET.encode(),
                string_to_sign.encode(),
                hashlib.sha512
            ).hexdigest()

            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization-Key": API_KEY,
                "Authorization-Nonce": nonce,
                "Authorization-Signature": signature
            }


            response = requests.patch(otp_url, headers=headers, data=json.dumps(otp_payload))

            if response.status_code == 200:
                return JsonResponse({"success": "OTP verified and collection process started"})
            else:
                return JsonResponse({"error": response.text}, status=response.status_code)
    else:
        form = OTPVerificationForm(initial={
            'payin_method_id': payin_method_id,
            'phone_number': phone_number,
            'mobile_provider': mobile_provider
        })

    return render(request, 'otp_verification_form.html', {'form': form})

@csrf_exempt
def webhook_handler(request):
    if request.method == 'POST':
        try:
            body = request.body
            headers = request.headers

            received_signature = headers.get('Authorization-Signature')
            nonce = headers.get('Authorization-Nonce')

            body_hash = hashlib.sha512(body).hexdigest()
            string_to_sign = f"{nonce}&POST&{request.get_full_path()}&{body_hash}"
            expected_signature = hmac.new(API_SECRET.encode(), string_to_sign.encode(), hashlib.sha512).hexdigest()

            if hmac.compare_digest(received_signature, expected_signature):
                data = json.loads(body)
                logger.info(f"Webhook received: {data}")

                if data['event'] == 'transaction.paid_in':
                    pass
                elif data['event'] == 'transaction.paid_out':
                    pass
                elif data['event'] == 'transaction.canceled':
                    pass
                elif data['event'] == 'sender.approved':
                    pass
                elif data['event'] == 'sender.rejected':
                    pass

                return JsonResponse({'status': 'success'})
            else:
                return JsonResponse({'error': 'Invalid signature'}, status=400)
        except Exception as e:
            logger.error(f"Webhook error: {str(e)}")
            return JsonResponse({'error': 'Internal Server Error'}, status=500)
    else:
        return JsonResponse({'error': 'Method Not Allowed'}, status=405)


import requests
import uuid
from django.shortcuts import render
from django.http import JsonResponse
from .models import GHSTransaction
from django.conf import settings

def initiate_ghs_collection(request):
    if request.method == "POST":
        phone_number = request.POST.get('phone_number')
        mobile_provider = request.POST.get('mobile_provider')

        if not phone_number or not mobile_provider:
            return JsonResponse({'error': 'Phone number and mobile provider are required'}, status=400)


        transaction_id = uuid.uuid4().hex

        transaction = GHSTransaction.objects.create(
            phone_number=phone_number,
            mobile_provider=mobile_provider,
            ux_flow='ussd_menu_approval',
            transaction_id=transaction_id,
            status='initiated'
        )
        url = "https://api-sandbox.transferzero.com/v1"
        payload = {
            "input_currency": "GHS",
            "payin_methods": [
                {
                    "id": "7334d150-41f8-4710-858b-e16a96df0c71",
                    "type": "GHS::Mobile",
                    "ux_flow": transaction.ux_flow,
                    "in_details": {
                        "phone_number": transaction.phone_number,
                        "mobile_provider": transaction.mobile_provider
                    },
                    "out_details": {
                        "style": "ussd_menu_approval",
                        "menu_option": "6",
                        "requires_pin": True,
                        "dialing_number": "*170#"
                    }
                }
            ]
        }

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {API_KEY}'
        }

        response = requests.post(url, json=payload, headers=headers)

        if response.status_code == 200:
            response_data = response.json()
            transaction.transaction_id = response_data.get('transaction_id', transaction.transaction_id)
            transaction.status = 'pending'
            transaction.save()

            return JsonResponse({'message': 'Transaction initiated successfully', 'transaction_id': transaction.transaction_id})
        else:
            error_message = response.json().get('error', 'Unknown error')
            return JsonResponse({'error': f'Failed to initiate transaction: {error_message}'}, status=response.status_code)

    return render(request, 'initiate_ghs_collection.html')


#LATEST API REVIEW GOING LIVE

def create_bank_transaction(request):
    if request.method == 'POST':
        form = BankTransactionForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            
            
            user = request.user
            profile = get_object_or_404(Profile, user=user)
            client_id = profile.client_id
            
            payload = {
                "transaction": {
                    "input_currency": data['input_currency'],
                    "sender": {
                        "country": data['sender_country'],
                        "phone_number": data['sender_phone_number'],
                        "email": data['sender_email'],
                        "first_name": data['sender_first_name'],
                        "last_name": data['sender_last_name'],
                        "city": data['sender_city'],
                        "street": data['sender_street'],
                        "postal_code": data['sender_postal_code'],
                        "birth_date": data['sender_birth_date'].strftime("%Y-%m-%d"),
                        "ip": request.META.get('REMOTE_ADDR'),
                        "metadata": {"sendRef": client_id}
                    },
                    "recipients": [
                        {
                            "requested_amount": str(data['recipient_requested_amount']),
                            "requested_currency": data['recipient_requested_currency'],
                            "retriable": True,
                            "payout_method": {
                                "type": "NGN::Bank",
                                "details": {
                                    "first_name": data['recipient_first_name'],
                                    "last_name": data['recipient_last_name'],
                                    "bank_code": data['recipient_bank_code'],
                                    "bank_account": data['recipient_bank_account'],
                                    "bank_account_type": data['recipient_bank_account_type']
                                }
                            }
                        }
                    ],
                    "metadata": {"sendRef": client_id},
                    "external_id": str(uuid.uuid4())
                }
            }

            transaction_body_json = json.dumps(payload)
            body_hash = hashlib.sha512(transaction_body_json.encode()).hexdigest()
            nonce = str(uuid.uuid4())
            string_to_sign = f"{nonce}&{METHOD}&{COLLECTION_URL}&{body_hash}"

            signature = hmac.new(
                API_SECRET.encode(),
                string_to_sign.encode(),
                hashlib.sha512
            ).hexdigest()

            response = requests.post(
                'https://api-sandbox.transferzero.com/v1/transactions',
                headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization-Key": API_KEY,
                "Authorization-Nonce": nonce,
                "Authorization-Signature": signature
            },
                json=payload
            )

            if response.status_code == 201:
                return JsonResponse(response.json())
            else:
                return JsonResponse({'error': response.json()}, status=response.status_code)

    else:
        form = BankTransactionForm()

    return render(request, 'create_bank_transaction.html', {'form': form})

@csrf_exempt
def transferzero_webhook(request):
    if request.method == 'POST':
        try:
            payload = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload'}, status=400)

        event_type = payload.get('event_type')
        data = payload.get('data', {})

        external_id = data.get('external_id')

        transaction = get_object_or_404(Transaction, external_id=external_id)

        if event_type == 'transaction.paid_in':
            transaction.status = 'paid_in'
            transaction.save()
            print(f"Transaction {transaction.external_id} has been paid in.")

        elif event_type == 'recipient.paid_out':
            transaction.status = 'paid_out'
            transaction.save()
            print(f"Transaction {transaction.external_id} has been paid out.")

        elif event_type == 'recipient.pending':
            transaction.status = 'pending'
            transaction.save()
            print(f"Transaction {transaction.external_id} payout is pending.")

        elif event_type == 'recipient.error':
            transaction.status = 'error'
            transaction.save()
            print(f"Transaction {transaction.external_id} encountered an error.")

        elif event_type == 'transaction.processing':
            transaction.status = 'processing'
            transaction.save()
            print(f"Transaction {transaction.external_id} is processing.")

        elif event_type == 'transaction.canceled':
            transaction.status = 'canceled'
            transaction.save()
            print(f"Transaction {transaction.external_id} has been canceled.")

        else:
            print(f"Unhandled event type: {event_type} for transaction {external_id}")
        return HttpResponse(status=200)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


#SETUP AZA FINANCES WEBHOOK (ADMINS)

class SetupWebhookView(View):
    def get(self, request, *args, **kwargs):
        WEBHOOK_URL = 'https://api-sandbox.transferzero.com/v1/webhooks'

        body = {
          "webhook": {
            "url": "https://abcd1234.ngrok.io/webhooks/aza/",
            "events": [
              "transaction.paid_in",
              "transaction.paid_out",
              "transaction.refunded"
            ],
            "metadata": {
              "description": "Webhook for AZA transaction events"
            }
          }
        }

        webhook_body_json = json.dumps(body)
        body_hash = hashlib.sha512(webhook_body_json.encode()).hexdigest()
        nonce = str(uuid.uuid4())
        string_to_sign = f"{nonce}&{METHOD}&{WEBHOOK_URL}&{body_hash}"

        signature = hmac.new(
                API_SECRET.encode(),
                string_to_sign.encode(),
                hashlib.sha512
            ).hexdigest()

        response = requests.post(
        'https://api-sandbox.transferzero.com/v1/webhooks',
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization-Key": API_KEY,
            "Authorization-Nonce": nonce,
            "Authorization-Signature": signature
        },
        json=body
        )

        print("Response status code:", response.status_code)
        print("Response content:", response.text)

        try:
            response_json = response.json()
        except json.JSONDecodeError:
            response_json = {'error': 'Failed to decode JSON'}

        if response.status_code == 201:
            return JsonResponse(response_json)
        else:
            return JsonResponse({'error': response_json}, status=response.status_code)



import hashlib
import hmac
import uuid
import json
import requests
from django.http import JsonResponse

@login_required
def list_senders(request):
    SENDERS_URL = "https://api-sandbox.transferzero.com/v1/senders"
    GET_METHOD = 'GET'
    
    try:
        profile = request.user.profile
        client_id = profile.client_id
        if not client_id:
            return render(request, 'senders_list.html', {'error': 'Client ID is not set for your profile.'})
    except Profile.DoesNotExist:
        return render(request, 'senders_list.html', {'error': 'User profile not found.'})

    params = {
        "page": request.GET.get("page", 1),
        "per": request.GET.get("per", 10),
        "created_at_from": request.GET.get("created_at_from", ''),
        "created_at_to": request.GET.get("created_at_to", ''),
        "external_id": client_id,
    }
    
    query_string = '&'.join([f"{key}={value}" for key, value in params.items() if value])
    
    full_url = f"{SENDERS_URL}?{query_string}"

    body_hash = hashlib.sha512(''.encode()).hexdigest()

    nonce = str(uuid.uuid4())

    string_to_sign = f"{nonce}&{GET_METHOD}&{full_url}&{body_hash}"

    signature = hmac.new(
        API_SECRET.encode(),
        string_to_sign.encode(),
        hashlib.sha512
    ).hexdigest()

    response = requests.get(
        full_url,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization-Key": API_KEY,
            "Authorization-Nonce": nonce,
            "Authorization-Signature": signature
        }
    )

    print("Response status code:", response.status_code)
    print("Response content:", response.text)

    try:
        response_json = response.json()
    except json.JSONDecodeError:
        response_json = {'error': 'Failed to decode JSON'}

    if response.status_code == 200:
        return render(request, 'senders_list.html', {'senders': response_json['object'], 'pagination': response_json['meta']['pagination']})
    else:
        return JsonResponse({'error': response_json}, status=response.status_code)

@login_required
def delete_sender(request):
    DELETE_METHOD = 'DELETE'
    SENDERS_URL = "https://api-sandbox.transferzero.com/v1/senders"
    sender_id = None

    if request.method == 'POST':
        form = DeleteSenderForm(request.POST)
        if form.is_valid():
            sender_id = form.cleaned_data['sender_id']

    params = {
        "external_id": sender_id,
    }

    query_string = '&'.join([f"{key}={value}" for key, value in params.items() if value])

    full_url = f"{SENDERS_URL}/{sender_id}?{query_string}"

    body_hash = hashlib.sha512(''.encode()).hexdigest()
    nonce = str(uuid.uuid4()) 

    string_to_sign = f"{nonce}&{DELETE_METHOD}&{full_url}&{body_hash}"
    signature = hmac.new(
        API_SECRET.encode(),
        string_to_sign.encode(),
        hashlib.sha512
    ).hexdigest()

    response = requests.delete(
        full_url,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization-Key": API_KEY,
            "Authorization-Nonce": nonce,
            "Authorization-Signature": signature
        }
    )

    print("Response status code:", response.status_code)
    print("Response content:", response.text)
    print("Response headers:", response.headers)

    try:
        response_json = response.json()
    except json.JSONDecodeError:
        response_json = {'error': 'Failed to decode JSON'}

    if response.status_code == 200:
        return JsonResponse({'message': 'Sender deleted successfully.'})
    else:
        form = DeleteSenderForm()
    
    return render(request, 'delete_sender.html', {'form': form})

@login_required
def save_sender(request):
    if request.method == 'POST':

        user = request.user
        sender_id = request.POST.get('sender_id')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        phone_country = request.POST.get('phone_country')
        phone_number = request.POST.get('phone_number')
        country = request.POST.get('country')
        city = request.POST.get('city')
        street = request.POST.get('street')
        postal_code = request.POST.get('postal_code')
        birth_date = request.POST.get('birth_date')


        sender = Sender.objects.create(
            user=user,
            sender_id=sender_id,
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone_country=phone_country,
            phone_number=phone_number,
            country=country,
            city=city,
            street=street,
            postal_code=postal_code,
            birth_date=birth_date,
        )

        messages.success(request, 'Sender created successfully!')
        return redirect('eco_info') 

    return redirect('display_sender')


@login_required
def list_transactions(request):
    TRANSACTION_URL = "https://api-sandbox.transferzero.com/v1/transactions"
    GET_METHOD = 'GET'

    try:
        profile = request.user.profile
        client_id = profile.client_id
    except Profile.DoesNotExist:
        return render(request, 'error.html', {'error': 'User profile not found.'})
    
    user = request.user

    sender = get_object_or_404(Sender, user=user)
    sender_id = sender.sender_id

    params = {
        "page": 1,
        "per": 10,
        "sender_id": '911a41eb-d23d-4a35-ace7-8ac6a18a4f52',
        "transaction_type": 'automated'
    }

    query_string = '&'.join([f"{key}={value}" for key, value in params.items() if value ])

    full_url = f"{TRANSACTION_URL}?{query_string}"
    
    body_hash = hashlib.sha512(''.encode()).hexdigest()

    nonce = str(uuid.uuid4())

    string_to_sign = f"{nonce}&{GET_METHOD}&{full_url}&{body_hash}"

    signature = hmac.new(
        API_SECRET.encode(),
        string_to_sign.encode(),
        hashlib.sha512
    ).hexdigest()

    response = requests.get(
        full_url,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization-Key": API_KEY,
            "Authorization-Nonce": nonce,
            "Authorization-Signature": signature
        }
    )

    print("Response status code:", response.status_code)
    print("Response content:", response.text)

    try:
        response_json = response.json()
    except json.JSONDecodeError:
        response_json = {'error': 'Failed to decode JSON'}

    if response.status_code == 200:
             return render(request, 'transactions.html', {'transactions': response_json['object'], 'pagination': response_json['meta']['pagination']})
    else:
            transactions = []
            print(f"Error fetching transactions: {response_json.get('error', 'Unknown error')}") 
    
    return render(request, 'transactions.html', {'transactions': transactions})