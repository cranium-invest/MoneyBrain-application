document.getElementById('payoutForm').addEventListener('submit', function(event) {
    event.preventDefault();
    
    const formData = new FormData(this);
    
    // Collect payout items from the form
    const items = [{
        recipient_type: formData.get('recipient_type'),
        amount: {
            value: formData.get('amount_value'),
            currency: formData.get('amount_currency')
        },
        note: formData.get('note'),
        sender_item_id: formData.get('sender_item_id'),
        receiver: formData.get('receiver'),
        alternate_notification_phone: formData.get('alternate_notification_phone'),
        notification_language: formData.get('notification_language')
    }];
    
    const data = {
        sender_batch_header: {
            sender_batch_id: formData.get('batch_id'),
            email_subject: formData.get('email_subject'),
            email_message: formData.get('email_message')
        },
        items: items
    };

    fetch('/api/payouts', { // Update this URL to your actual backend endpoint
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken') // Include CSRF token if needed
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        console.log('Success:', data);
        // Handle success response, e.g., show a success message to the user
    })
    .catch((error) => {
        console.error('Error:', error);
        // Handle error response, e.g., show an error message to the user
    });
});

// Utility function to get CSRF token
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}
