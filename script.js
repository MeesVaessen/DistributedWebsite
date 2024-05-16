document.addEventListener('DOMContentLoaded', function() {
    const loginButton = document.getElementById('loginButton');
    loginButton.addEventListener('click', login);
});

async function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    const salt = await fetchSalt(username);
    if (!salt) {
        console.error('User not found');
        return;
    }

    const hashedPassword = await hashPassword(password, salt); 
    console.log('Generated salt:', salt);

    const payload = {
        username: username,
        password: hashedPassword,
        salt: salt
    };

    fetch('http://192.168.0.9:8080/user/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    })
    .then(async response => {
        if (response.ok) {
            const responseData = await response.json();
        
            if (responseData.success) {
                console.log('Login successful');
                window.location.href = '/dashboard';
            } else {
                console.error('Login failed');
            }
        } else {
            console.error('Login failed');
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

async function fetchSalt(username) {
    const formData = new FormData();
    formData.append('username', username);

    const response = await fetch('http://192.168.0.9:8080/user/getsalt', {
        method: 'POST',
        body: formData
    });

    const data = await response.json();

    return data.salt;
}

async function hashPassword(password, salt) {
    const saltedPassword = salt + password; // Concatenate the fetched salt with the entered password

    const encoder = new TextEncoder();
    const data = encoder.encode(saltedPassword);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashedPassword = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
    return hashedPassword;
}


document.getElementById('dropbox').addEventListener('click', function(event) {
    event.preventDefault();
    document.getElementById('fileInput').click();
});

document.getElementById('fileInput').addEventListener('change', function() {
    const fileInput = this;
    const files = fileInput.files;
    const allowedExtensions = ['py']; 

    if (files.length > 0) {
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const fileNameParts = file.name.split('.');
            const fileExtension = fileNameParts[fileNameParts.length - 1].toLowerCase();
            
            if (!allowedExtensions.includes(fileExtension)) {
                alert('Only Python files are allowed');
                fileInput.value = ''; 
                return;
            }
        }
        
        document.getElementById('dropbox').classList.add('selected');
        
   
        const hashInput = document.getElementById('hashInput').value.trim();
        if (hashInput === '') {
            alert('Hash is required');
            return;
        }
        
        const progressBar = document.getElementById('progressBar');
        progressBar.style.width = '0%';
        progressBar.style.display = 'block';
        const interval = setInterval(function() {
            progressBar.style.width = parseFloat(progressBar.style.width) + 10 + '%';
            if (progressBar.style.width === '100%') {
                clearInterval(interval);
                progressBar.style.display = 'none';
           
                document.getElementById('dropbox').classList.add('success');
                document.getElementById('dropbox').innerText = files[0].name;
            }
        }, 200);

    } else {
        document.getElementById('dropbox').classList.remove('selected');
        
        const hashInput = document.getElementById('hashInput').value.trim();
        if (hashInput === '') {
            alert('Hash is required');
            return;
        }
        
    }
});

function uploadFiles() {
    const files = document.getElementById('fileInput').files;
    const hashInput = document.getElementById('hashInput').value.trim();
    
    if (files.length > 0) {
        const formData = new FormData();
        for (let i = 0; i < files.length; i++) {
            formData.append('files[]', files[i]);
        }
        

        if (hashInput === '') {
            alert('Hash is required');
            return;
        }
        
        formData.append('hash', hashInput);
        
        fetch('http://192.168.0.9:8080/file/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Error uploading files');
            }
            return response.json();
        })
        .then(data => {
            console.log('Files uploaded successfully:', data);
            alert('Files uploaded successfully!');
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error uploading files');
        });
    } else {
        if (hashInput === '') {
            alert('Please select files to upload and enter hash');
        } else {
            alert('Files are not selected, proceeding with hash only');

        }
    }
}

const socket = new WebSocket('ws://145.220.74.141:8181/File/upload');

socket.addEventListener('message', function(event) {
    try {
        const message = JSON.parse(event.data);
        console.log('Type:', message.Type);
        console.log('Content:', message.Content);
    } catch (error) {
        console.error('Error parsing WebSocket message:', error);
    }
});

socket.addEventListener('error', function(event) {
    console.error('WebSocket error:', event);
});

socket.addEventListener('close', function(event) {
    console.log('WebSocket connection closed');
});
