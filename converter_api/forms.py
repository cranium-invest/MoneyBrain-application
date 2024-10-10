from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from .models import UploadedImage, Sender

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')

class CustomAuthenticationForm(AuthenticationForm):
    username = forms.CharField(label='Username', max_length=254)
    password = forms.CharField(label='Password', widget=forms.PasswordInput)

class TransferForm(forms.Form):
    amount = forms.DecimalField(max_digits=10, decimal_places=2)
    destination_country = forms.CharField(max_length=2)  # e.g., 'IND' for India
    sender_name = forms.CharField(max_length=100)
    sender_address = forms.CharField(max_length=255)
    sender_phone = forms.CharField(max_length=15)
    sender_email = forms.EmailField()
    receiver_name = forms.CharField(max_length=100)
    receiver_address = forms.CharField(max_length=255, required=False)
    receiver_phone = forms.CharField(max_length=15)
    receiver_email = forms.EmailField()

class CheckDepositForm(forms.ModelForm):
    account_id = forms.CharField(max_length=100, label='Account ID')
    amount = forms.DecimalField(max_digits=10, decimal_places=2, label='Amount')
    os_name = forms.CharField(max_length=50, label='OS Name')
    os_version = forms.CharField(max_length=50, label='OS Version')
    person_id = forms.CharField(max_length=100, label='Person ID')
    back_image = forms.ImageField(label='Back Image')
    front_image = forms.ImageField(label='Front Image')

    class Meta:
        model = UploadedImage
        fields = ['back_image', 'front_image']



class BillPayForm(forms.Form):
    account_id = forms.CharField(max_length=100, required=True)
    amount = forms.DecimalField(max_digits=10, decimal_places=2, required=True)
    billpay_counterparty_id = forms.CharField(max_length=100, required=True)
    person_id = forms.CharField(max_length=100, required=True)

from django import forms

class EcoTransferForm(forms.Form):
    recipient_first_name = forms.CharField(max_length=100, label='Recipient First Name')
    recipient_last_name = forms.CharField(max_length=100, label='Recipient Last Name')
    recipient_residential_address = forms.CharField(max_length=50, label='Recipient Residential Address')
    recipient_id_type = forms.CharField(max_length=20, label='Recipient ID Type')
    recipient_id_expiry_date = forms.DateField(input_formats=['%m/%d/%Y'], label='Recipient ID Expiry Date')
    recipient_dob = forms.DateField(input_formats=['%m/%d/%Y'], label='Recipient Date of Birth')
    receiver_phone_number = forms.CharField(max_length=20, label='Receiver Phone_number')  # Added this line
    sender_first_name = forms.CharField(max_length=100, label='Sender First Name')
    sender_last_name = forms.CharField(max_length=100, label='Sender Last Name')
    sender_phone_number = forms.CharField(max_length=20, label='Sender Phone Number')
    sender_residential_address = forms.CharField(max_length=50, label='Sender Residential Address')
    sender_id_type = forms.CharField(max_length=20, label='Sender ID Type')
    sender_id_number = forms.CharField(max_length=20, label='Sender ID Number')
    sender_id_expiry_date = forms.DateField(input_formats=['%m/%d/%Y'], label='Sender ID Expiry Date')
    sender_dob = forms.DateField(input_formats=['%m/%d/%Y'], label='Sender Date of Birth')
    sender_nationality = forms.CharField(max_length=2, label='Sender Nationality')
    receiver_nationality = forms.CharField(max_length=2, label='Receiver Nationality')
    amount = forms.DecimalField(max_digits=10, decimal_places=2, label='Amount')
    currency = forms.ChoiceField(choices=[('GHS', 'GHS'), ('USD', 'USD'),('ZAR', 'ZAR')], label='Currency')
    sender_currency = forms.ChoiceField(choices=[('GHS', 'GHS'), ('USD', 'USD'), ('ZAR', 'ZAR')], label='Sender Currency')
    receiver_currency = forms.ChoiceField(choices=[('GHS', 'GHS'), ('USD', 'USD'), ('ZAR', 'ZAR')], label='Receiver Currency')
    destination_account_number = forms.CharField(max_length=20, label='Destination Account Number')
    destination_country = forms.CharField(max_length=2, label='Destination Country')
    destination_bank = forms.CharField(max_length=20, label='Destination Bank')
    source_country = forms.CharField(max_length=20, label='Source Country')
    source_bank = forms.CharField(max_length=20, label='Source Bank')
    narration = forms.CharField(max_length=50, label='Narration')
    exchange_rate = forms.DecimalField(max_digits=10, decimal_places=2, label='Exchange Rate')

class TokenTransactionForm(forms.Form):
    sender_name = forms.CharField(max_length=100, required=True, widget=forms.TextInput(attrs={'placeholder': 'Sender Name'}))
    sender_mobile_no = forms.CharField(max_length=15, required=True, widget=forms.TextInput(attrs={'placeholder': 'Sender Mobile Number'}))
    sender_id = forms.CharField(max_length=50, required=True, widget=forms.TextInput(attrs={'placeholder': 'Sender ID'}))
    beneficiary_name = forms.CharField(max_length=100, required=True, widget=forms.TextInput(attrs={'placeholder': 'Beneficiary Name'}))
    beneficiary_mobile_no = forms.CharField(max_length=15, required=True, widget=forms.TextInput(attrs={'placeholder': 'Beneficiary Mobile Number'}))
    amount = forms.DecimalField(max_digits=22, decimal_places=2, required=True, widget=forms.NumberInput(attrs={'placeholder': 'Amount'}))
    transaction_description = forms.CharField(max_length=255, required=True, widget=forms.TextInput(attrs={'placeholder': 'Transaction Description'}))
    withdrawal_channel = forms.ChoiceField(choices=[('ATM', 'ATM'), ('Xpress', 'Xpress')], required=True)
    currency = forms.ChoiceField(choices=[('GHS', 'GHS'), ('USD', 'USD')], required=True, widget=forms.Select(attrs={'placeholder': 'Debit Account Currency'}))
    transaction_currency = forms.ChoiceField(choices=[('GHS', 'GHS')], required=True, widget=forms.Select(attrs={'placeholder': 'Transaction Currency'}))
    source_account = forms.CharField(max_length=16, required=True, widget=forms.TextInput(attrs={'placeholder': 'Source Account Number'}))
    source_account_currency = forms.ChoiceField(choices=[('GHS', 'GHS'), ('USD', 'USD')], required=True, widget=forms.Select(attrs={'placeholder': 'Source Account Currency'}))


class CrossBorderPaymentForm(forms.Form):
    receiver_last_name = forms.CharField(max_length=50, label='Receiver Last Name')
    source_country = forms.CharField(max_length=2, label='Source Country')
    sender_nationality = forms.CharField(max_length=2, label='Sender Nationality')
    sender_phone_number = forms.CharField(max_length=20, label='Sender Phone Number')
    destination_bank = forms.CharField(max_length=20, label='Destination Bank')
    purpose = forms.CharField(max_length=50, label='Purpose')
    receiver_ccy = forms.CharField(max_length=3, label='Receiver Currency')
    receiver_id_number = forms.CharField(max_length=20, label='Receiver ID Number')
    sender_id_number = forms.CharField(max_length=20, label='Sender ID Number')
    sender_ccy = forms.CharField(max_length=3, label='Sender Currency')
    sender_gender = forms.CharField(max_length=1, label='Sender Gender')
    source_bank = forms.CharField(max_length=20, label='Source Bank')
    receiver_first_name = forms.CharField(max_length=20, label='Receiver First Name')
    sender_last_name = forms.CharField(max_length=20, label='Sender Last Name')
    receiver_residential_address = forms.CharField(max_length=50, label='Receiver Residential Address')
    receiver_id_type = forms.CharField(max_length=20, label='Receiver ID Type')
    receiver_id_expiry_date = forms.DateField(input_formats=['%m/%d/%Y'],widget=forms.TextInput(attrs={'class': 'datepicker'}), label='Receiver ID Expiry Date')
    product = forms.CharField(max_length=10, initial='ACCOUNT', label='Product')
    sender_id_type = forms.CharField(max_length=20, label='Sender ID Type')
    receiver_dob = forms.DateField(input_formats=['%m/%d/%Y'], widget=forms.TextInput(attrs={'class': 'datepicker'}), label='Receiver Date of Birth')
    receiver_phone_number = forms.CharField(max_length=20, label='Receiver Phone Number')
    sender_dob = forms.DateField(input_formats=['%m/%d/%Y'], widget=forms.TextInput(attrs={'class': 'datepicker'}), label='Sender Date of Birth')
    sender_first_name = forms.CharField(max_length=20, label='Sender First Name')
    receiver_nationality = forms.CharField(max_length=2, label='Receiver Nationality')
    destination_account_number = forms.CharField(max_length=20, label='Destination Account Number')
    destination_country = forms.CharField(max_length=2, label='Destination Country')
    narration = forms.CharField(max_length=50, label='Narration')
    sender_residential_address = forms.CharField(max_length=50, label='Sender Residential Address')
    sender_id_expiry_date = forms.DateField(input_formats=['%m/%d/%Y'], widget=forms.TextInput(attrs={'class': 'datepicker'}), label='Sender ID Expiry Date')
    amount = forms.DecimalField(max_digits=22, decimal_places=2, label='Amount')
    currency = forms.ChoiceField(choices=[('GHS', 'GHS'), ('USD', 'USD'),('ZAR','ZAR'), ('ZWL','ZWL')], required=True, widget=forms.Select(attrs={'placeholder': 'Debit Account Currency'}))
    batchid = forms.CharField(max_length=15, label='Batch ID')
    affiliate_code = forms.ChoiceField(choices=[('EGH', 'EGH'), ('ENG', 'ENG'), ('ETG', 'ETG'), ('ESN', 'ESN'), ('ESA', 'ESA'), ('EMZ','EMZ'),('EBO','EBO')], required=True)

class affiliationReForm(forms.Form):
    affiliate_code = forms.ChoiceField(choices=[('EGH', 'EGH'), ('ENG', 'ENG'), ('ETG', 'ETG'), ('ESN', 'ESN'), ('ESA', 'ESA'), ('EMZ','EMZ'),('EBO','EBO')], required=True)
    destination_country = forms.CharField(max_length=2, label='Destination Country')

class SenderForm(forms.Form):
    first_name = forms.CharField(max_length=100)
    last_name = forms.CharField(max_length=100)
    email = forms.EmailField()
    phone_country = forms.CharField(max_length=2, initial='UG')
    phone_number = forms.CharField(max_length=15)
    country = forms.CharField(max_length=2, initial='UG')
    city = forms.CharField(max_length=100)
    street = forms.CharField(max_length=200)
    postal_code = forms.CharField(max_length=10)
    birth_date = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}))
    document_file = forms.FileField() 

class GHSCollectionForm(forms.Form):
    first_name = forms.CharField(max_length=30, label="First Name", required=True )
    last_name = forms.CharField(max_length=30, label="Last Name", required=True )
    phone_number = forms.CharField(max_length=15, label="Phone Number", required=True)
    email = forms.EmailField()
    phone_country = forms.CharField(max_length=2, initial='UG')
    country = forms.CharField(max_length=2, initial='UG')
    city = forms.CharField(max_length=100)
    street = forms.CharField(max_length=200)
    postal_code = forms.CharField(max_length=10)
    birth_date = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}))
    mobile_provider = forms.ChoiceField(choices=[
        ('airtel', 'Airtel'),
        ('tigo', 'Tigo'),
        ('mtn', 'MTN'),
        ('vodafone', 'Vodafone')
    ], label="Mobile Provider", required=True)
    document_file = forms.FileField() 


    
class OTPVerificationForm(forms.Form):
    payin_method_id = forms.CharField(max_length=100, widget=forms.HiddenInput())
    phone_number = forms.CharField(max_length=15, label="Phone Number")
    mobile_provider = forms.CharField(max_length=50, label="Mobile Provider")
    otp = forms.CharField(max_length=6, label="OTP")


# forms.py

from django import forms

class BankTransactionForm(forms.Form):
    input_currency = forms.CharField(max_length=3)
    sender_country = forms.CharField(max_length=2)
    sender_phone_number = forms.CharField(max_length=15)
    sender_email = forms.EmailField()
    sender_first_name = forms.CharField(max_length=50)
    sender_last_name = forms.CharField(max_length=50)
    sender_city = forms.CharField(max_length=100)
    sender_street = forms.CharField(max_length=100)
    sender_postal_code = forms.CharField(max_length=10)
    sender_birth_date = forms.DateField()
    recipient_first_name = forms.CharField(max_length=50)
    recipient_last_name = forms.CharField(max_length=50)
    recipient_requested_amount = forms.DecimalField(max_digits=10, decimal_places=2)
    recipient_requested_currency = forms.CharField(max_length=3)
    recipient_bank_code = forms.CharField(max_length=10)
    recipient_bank_account = forms.CharField(max_length=20)
    recipient_bank_account_type = forms.CharField(max_length=10)


class DeleteSenderForm(forms.Form):
    sender_id = forms.UUIDField(label='Sender ID', help_text='Enter the Sender ID to delete')
