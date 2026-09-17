fetch('/api/me')
    .then(response => {
        document.getElementById('loadingArea').classList.add('d-none');
        
        if (response.ok) {
            return response.json().then(data => {
                document.getElementById('profileArea').classList.remove('d-none');
                document.getElementById('providerName').innerText = data.provedor;
                
                const emailEl = document.getElementById('userEmail');
                emailEl.innerText = data.email;
                emailEl.title = data.email; 
            });
        } else {
            document.getElementById('loginArea').classList.remove('d-none');
        }
    })
    .catch(error => {
        console.error(error);
        document.getElementById('loadingArea').classList.add('d-none');
        document.getElementById('loginArea').classList.remove('d-none');
    });
