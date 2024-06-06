document.addEventListener('DOMContentLoaded', function() {
    const loginButton = document.getElementById('loginButton');
    loginButton.addEventListener('click', login);
    const usernameInput = document.getElementById('username');
    usernameInput.addEventListener('blur', async function() {
        const username = this.value;
        if (username) {
            const staticSalt = await fetchSaltFromDatabase(username);
            if (staticSalt) {
                loginButton.dataset.salt = staticSalt;
            }
        }
    });
    const passwordInput = document.getElementById('password');
    passwordInput.addEventListener('input', async function() {
        const staticSalt = loginButton.dataset.salt;
        if (staticSalt) {
            await hashPassword(this.value, staticSalt);
        }
    });
});
function setCookie(name, value, days) {
    let expires = "";
    if (days) {
        const date = new Date();
        date.setTime(date.getTime() + (days*24*60*60*1000));
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + (value || "")  + expires + "; path=/";
}
async function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const staticSalt = this.dataset.salt;
    if (!staticSalt) {
        return;
    }
    const hashedPassword = await hashPassword(password, staticSalt);
    const payload = {
        name: username,
        password: hashedPassword
    };
    fetch('https://api.decoderfontys.nl/User/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    }).then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    }).then(data => {
        console.log(data); // Log the response body
        setCookie("JWT",data.token,0.5)
   
        window.location.href = "/Dashboard";
    })
    .catch(error => {
        console.error('There was a problem with the fetch operation:', error);
        alert("Incorrect login details");
    });
}
function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for(let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) == ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

// Function to check for JWT cookie and redirect if not found
function checkJwtCookieAndRedirect() {
const jwt = getCookie('JWT');
if(window.location.href!=='https://decoderfontys.nl/'){
    if (!jwt) {
        window.location.href = 'https://decoderfontys.nl/';
}
}

}
window.onload = checkJwtCookieAndRedirect;
async function hashPassword(password, salt) {
const saltedPassword = salt + password;
const encoder = new TextEncoder();
const data = encoder.encode(saltedPassword);
const hashBuffer = await crypto.subtle.digest('SHA-256', data);
const hashArray = Array.from(new Uint8Array(hashBuffer));
const hashedPassword = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
return hashedPassword;
}
async function fetchSaltFromDatabase(username) {
try {
    const payload = {
        name: username,
    };
    const response = await fetch('https://api.decoderfontys.nl/User/getSalt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    });
    if (response.ok) {
        const data = await response.json();
        return data.salt;
    } else {
        return null;
    }
} catch {
    return null;
}
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

        document.getElementById('dropbox').classList.add('active');
        document.getElementById('dropbox').innerHTML = `<p>${files[0].name}</p>`;
    } else {
        document.getElementById('dropbox').classList.remove('selected');
        document.getElementById('dropbox').innerHTML = `<p>Click or drop Python files here to upload</p>`;
    }
});
function uploadHash() {
    const hashInput = document.getElementById('hashInput').value.trim();
    if (hashInput === '') {
        return;
    } else {
        const requestData = { message: hashInput };
 
        fetch('https://api.decoderfontys.nl/File/sendMessage?message=' + hashInput, {
            method: 'POST',
            headers: {
                'Accept': '*/*',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Error uploading hash');
            }
            return response.json();
        })
        .then(data => {
            console.log('Hash uploaded successfully:', data);
            openWebSocket(); // Open WebSocket after hash upload to receive progress updates
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }
}
 
function uploadFile() {
    const files = document.getElementById('fileInput').files;
 
    if (files.length > 0) {
        const formData = new FormData();
        formData.append('file', files[0], files[0].name);
        formData.append('type', 'text/x-python');
 
        fetch('https://api.decoderfontys.nl/file/upload', {
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
        });
    } else {
        alert('Please select files to upload');
    }
}
 
function openWebSocket() {
    const socket = new WebSocket('ws://api.decoderfontys.nl/File/upload');
 
    socket.addEventListener('open', function(event) {
        const progressContainer = document.getElementById('progressContainer');
        progressContainer.style.display = 'block';
    });
 
    socket.addEventListener('message', function(event) {
        try {
            const message = JSON.parse(event.data);
            const triedPasswords = message.Tried_Passwords || 0;
            const elapsedTime = message.Elapsed_Time || 0;
 
            const maxAttempts = 916132832;
            const progressPercent = (triedPasswords / maxAttempts) * 100;
 
            const progressBar = document.getElementById('progressBar');
            const triedPasswordsText = document.getElementById('triedPasswords');
            const elapsedTimeText = document.getElementById('elapsedTime');
           
            progressBar.style.width = progressPercent + '%';
            triedPasswordsText.innerText = `Tried Passwords: ${triedPasswords}`;
            elapsedTimeText.innerText = `Elapsed Time: ${elapsedTime}s`;
 
            if (message.Type === 'Password_Found') {
                const foundPassword = document.getElementById('foundPassword');
                foundPassword.value = message.Content;
                foundPassword.style.display = 'block';
            }
 
            if (progressPercent >= 100) {
                const progressContainer = document.getElementById('progressContainer');
                progressContainer.style.display = 'none';
            }
        } catch (error) {
            console.error('Error parsing WebSocket message:', error);
        }
    });
 
    socket.addEventListener('error', function(event) {
        console.error('WebSocket error:', event);
        const progressContainer = document.getElementById('progressContainer');
        progressContainer.style.display = 'none';
    });
 
    socket.addEventListener('close', function(event) {
        console.log('WebSocket connection closed');
        const progressContainer = document.getElementById('progressContainer');
        progressContainer.style.display = 'none';
    });
}
