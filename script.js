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
        setCookie("JWT", data.token, 0.5);
        window.location.href = "/Dashboard";
    })
    .catch(error => {
        console.error('There was a problem with the fetch operation:', error);
        alert("Incorrect login details");
    });
}

function setCookie(name, value, hours) {
    let expires = "";
    if (hours) {
        const date = new Date();
        date.setTime(date.getTime() + (hours * 60 * 60 * 1000));
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + (value || "") + expires + "; path=/";
}

function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) == ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

function checkJwtCookieAndRedirect() {
    const jwt = getCookie('JWT');
    if (window.location.href !== 'https://decoderfontys.nl/') {
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
window.onload = openWebSocket();

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
        console.log(`Authorization: Bearer ${token}`);
    } else {
        const token = getCookie("JWT");
        const requestData = { 
            message: hashInput,
            wsToken: _webSocketToken
        };
        
const overlay = document.getElementById('overlay');
        overlay.style.display = 'block';
        
        fetch('Https://api.decoderfontys.nl/File/sendMessage?message='+hashInput+'&wsToken='+_webSocketToken , {
            method: 'POST',
            headers: {
                'Accept': '*/*',
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
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
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }
}

var _webSocketToken = "";

function uploadFile() {
    const files = document.getElementById('fileInput').files;
    const token = getCookie("JWT");
    const webSocketToken = _webSocketToken;

    if (files.length > 0) {
        const formData = new FormData();
        formData.append('file', files[0], files[0].name);
        formData.append('type', 'text/x-python');
        console.log(`Authorization: Bearer ${token}`);
        
        fetch('https://api.decoderfontys.nl/file/upload?wsToken='+ webSocketToken, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            },
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

            document.getElementById('dropbox').classList.add('selected');
            document.getElementById('dropbox').innerHTML = `<p>${files[0].name}</p>`;
        })
        .catch(error => {
            console.error('Error:', error);
        });
    } else {
        alert('Please select files to upload');
    }
}

function openWebSocket() {
    console.log("open websocket method");
    const socket = new WebSocket('wss://websocket.decoderfontys.nl/');
    console.log("Creating connection");
                
    socket.addEventListener('open', function(event) {
        console.log("open connection");
        const progressContainer = document.getElementById('progressContainer');
        progressContainer.style.display = 'block';
    });

    socket.addEventListener('message', function(event) {
        try {
            const message = JSON.parse(event.data);
            console.log(message);
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

            if (message.Type === 'Connection_Token') {
                _webSocketToken = message.Content;
                console.log("Connection Token recieved: ", _webSocketToken);
            }

            if (progressPercent >= 100) {
                const progressContainer = document.getElementById('progressContainer');
                overlay.style.display = 'none';
            }
        } catch (error) {
            console.error('Error parsing WebSocket message:', error);
        }
    });

    // socket.onmessage = function (event) {
    //     console.log(event.data);
    //     try {
    //         const message = JSON.parse(event.data);
    //         console.log(message);
    //         const triedPasswords = message.Tried_Passwords || 0;
    //         const elapsedTime = message.Elapsed_Time || 0;

    //         const maxAttempts = 916132832;
    //         const progressPercent = (triedPasswords / maxAttempts) * 100;

    //         const progressBar = document.getElementById('progressBar');
    //         const triedPasswordsText = document.getElementById('triedPasswords');
    //         const elapsedTimeText = document.getElementById('elapsedTime');
           
    //         progressBar.style.width = progressPercent + '%';
    //         triedPasswordsText.innerText = `Tried Passwords: ${triedPasswords}`;
    //         elapsedTimeText.innerText = `Elapsed Time: ${elapsedTime}s`;

    //         if (message.Type === 'Password_Found') {
    //             const foundPassword = document.getElementById('foundPassword');
    //             foundPassword.value = message.Content;
    //             foundPassword.style.display = 'block';
    //         }

    //         if (message.Type === 'Connection_Token') {
    //             _webSocketToken = message.Content;
    //             console.log("Connection Token recieved: ", _webSocketToken);
    //         }

    //         if (progressPercent >= 100) {
    //             const progressContainer = document.getElementById('progressContainer');
    //             progressContainer.style.display = 'none';
    //         }
    //     } catch (error) {
    //         console.error('Error parsing WebSocket message:', error);
    //     }
    // };

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
