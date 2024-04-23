document.addEventListener('DOMContentLoaded', function() {
    const loginButton = document.getElementById('loginButton');
    loginButton.addEventListener('click', login);
});

async function login2() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    const hashedPassword = await hashPassword(password);

    const payload = {
        name: username,
        password: hashedPassword
    };

   return fetch('http://145.220.74.141:8080/User/login', {
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

async function login(){
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    const hashedPassword = await hashPassword(password);

    const userData = {
        name: username,
        password: hashedPassword
    };

    return fetch('http://145.220.74.141:8080/User/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(userData)
    })
    .then(response => {
        if(response.ok){
            console.log('success');
            return response.json();
        }else {
            console.error('failed');
            throw new Error('failed');
        }
    })
    .then(data => {
        console.log(data);
        return data;
    })
    .catch(error =>{
        console.error('failed: ', error);
        throw error;
    })

}

async function hashPassword(password) {

    const salt = generateSalt();


    const saltedPassword = salt + password;


    const encoder = new TextEncoder();
    const data = encoder.encode(saltedPassword);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashedPassword = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
    return hashedPassword;
}

function generateSalt() {

    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let salt = '';
    for (let i = 0; i < 16; i++) {
        salt += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    return salt;
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
    }
});

function uploadFiles() {
    const files = document.getElementById('fileInput').files;
    if (files.length > 0) {
        const formData = new FormData();
        formData.append('file', files[0], files[0].name); // Specify the filename explicitly
        formData.append('type', 'text/x-python'); // Specify the file type

        fetch('http://145.220.74.141:8080/File/upload', {
            method: 'POST',
            headers: {
                'Accept': '*/*',
                // Ensure Content-Type is multipart/form-data, but do not include the boundary here
            },
            body: formData
        })
        .then(response => {
            console.log(response);
            if (!response.ok) {
                throw new Error('Success');
            }
            return response.json();
        })
        .then(data => {
            console.log('Files uploaded successfully:', data);
        })
        .catch(error => {
            console.error('Error:', error);
        });
    } else {
        alert('Please select files to upload');
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