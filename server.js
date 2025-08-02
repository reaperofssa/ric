const express = require('express');
const fs = require('fs');
const bcrypt = require('bcrypt');
const qs = require('querystring');
const nodemailer = require('nodemailer');
const axios = require('axios'); // Install with: npm install axios
const path = require('path');
const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static('public')); // Serve static files from public directory

const USERS_FILE = './users.json';
const VERIFIED_EMAILS_FILE = './verified_emails.json';
const DEPLOYMENTS_FILE = './deployments.json';

// Load or initialize users file
const loadUsers = () => {
    if (!fs.existsSync(USERS_FILE)) return {};
    return JSON.parse(fs.readFileSync(USERS_FILE));
};

const saveUsers = (users) => {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
};

// Load verified emails
const loadVerifiedEmails = () => {
    if (!fs.existsSync(VERIFIED_EMAILS_FILE)) return [];
    return JSON.parse(fs.readFileSync(VERIFIED_EMAILS_FILE));
};

const saveVerifiedEmails = (emails) => {
    fs.writeFileSync(VERIFIED_EMAILS_FILE, JSON.stringify(emails, null, 2));
};

// Load and save deployments
const loadDeployments = () => {
    if (!fs.existsSync(DEPLOYMENTS_FILE)) return {};
    return JSON.parse(fs.readFileSync(DEPLOYMENTS_FILE));
};

const saveDeployments = (deployments) => {
    fs.writeFileSync(DEPLOYMENTS_FILE, JSON.stringify(deployments, null, 2));
};

// Generate 89-digit token (digits only)
const generateToken = () => {
    let token = '';
    while (token.length < 89) {
        token += Math.floor(Math.random() * 10);
    }
    return token;
};

const generateVerificationCode = () => {
    return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit
};

// Configure nodemailer transport
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'maskeelone0@gmail.com',
        pass: 'ktxr wjdf rkyt qvhj'
    }
});

// Send verification email
const sendVerificationEmail = async (email, code) => {
    await transporter.sendMail({
        from: '"Akane Pairing" <no-reply@akanepairing.com>',
        to: email,
        subject: '🔐 Your Akane Pairing Verification Code',
        text: `Hello,

Thank you for signing up with Akane Pairing!

Your verification code is: ${code}

Enter this code to verify your email address.

– Akane Pairing Team`,
        html: `
            <div style="background: #f2f2f7; padding: 40px 0; font-family: 'Segoe UI', sans-serif;">
                <div style="max-width: 600px; background: #ffffff; margin: auto; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                    <div style="background: linear-gradient(135deg, #ff4d88, #e60073); padding: 24px; text-align: center; color: #fff;">
                        <h1 style="margin: 0; font-size: 24px;">Akane Pairing</h1>
                        <p style="margin: 8px 0 0;">Verify Your Email Address</p>
                    </div>
                    <div style="padding: 30px;">
                        <p style="font-size: 16px; color: #333;">Hi there,</p>
                        <p style="font-size: 16px; color: #333;">
                            Thank you for joining <strong>Akane Pairing</strong>! To complete your registration, please verify your email address using the code below:
                        </p>

                        <div style="margin: 30px 0; text-align: center;">
                            <div style="
                                display: inline-block;
                                background: #ffeaf2;
                                color: #e60073;
                                padding: 16px 32px;
                                font-size: 26px;
                                font-weight: bold;
                                border-radius: 8px;
                                letter-spacing: 4px;
                                border: 2px dashed #e60073;
                            ">
                                ${code}
                            </div>
                        </div>

                        <p style="font-size: 14px; color: #666;">
                            If you didn’t request this code, please ignore this message.
                        </p>
                        <p style="font-size: 14px; color: #666;">
                            This code will expire in 10 minutes.
                        </p>
                        <p style="font-size: 16px; margin-top: 40px; color: #333;">
                            With ❤️,<br>
                            The Akane Pairing Team
                        </p>
                    </div>
                    <div style="background: #fafafa; text-align: center; padding: 16px; font-size: 12px; color: #aaa;">
                        © ${new Date().getFullYear()} Akane Pairing. All rights reserved.
                    </div>
                </div>
            </div>
        `
    });
};

// Register route
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
        return res.status(400).json({ error: 'Missing fields' });
    }

    const users = loadUsers();
    const verifiedEmails = loadVerifiedEmails();

    if (users[username]) {
        return res.status(409).json({ error: 'Username already exists' });
    }

    if (verifiedEmails.includes(email)) {
        return res.status(409).json({ error: 'Email is already verified and in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const authToken = generateToken();
    const verificationCode = generateVerificationCode();

    try {
        await sendVerificationEmail(email, verificationCode);
    } catch (error) {
        return res.status(500).json({ error: 'Failed to send verification email' });
    }

    users[username] = {
        email,
        password: hashedPassword,
        authToken,
        verified: false,
        verificationCode
    };

    saveUsers(users);

    res.json({
        message: 'User registered. Verification code sent to email.',
        authToken
    });
});

// Verify email route
app.post('/verify', (req, res) => {
    const { username, code } = req.body;

    const users = loadUsers();
    const verifiedEmails = loadVerifiedEmails();

    const user = users[username];
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    if (user.verified) {
        return res.status(400).json({ error: 'User already verified' });
    }

    if (user.verificationCode !== code) {
        return res.status(400).json({ error: 'Invalid verification code' });
    }

    user.verified = true;
    delete user.verificationCode;

    if (!verifiedEmails.includes(user.email)) {
        verifiedEmails.push(user.email);
    }

    saveUsers(users);
    saveVerifiedEmails(verifiedEmails);

    res.json({ message: 'Email verified successfully' });
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    const users = loadUsers();
    const user = users[username];

    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.verified) {
        return res.status(401).json({ error: 'Account not verified' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    res.json({
        message: 'Login successful',
        authToken: user.authToken,
        username: username
    });
});

// Check auth token route
app.get('/check', (req, res) => {
    const { auth } = req.query;

    if (!auth) {
        return res.status(400).json({ valid: false, error: 'Missing auth token' });
    }

    const users = loadUsers();

    // Find user by token
    const user = Object.values(users).find(u => u.authToken === auth);

    if (!user || !user.verified) {
        return res.json({ valid: false });
    }

    res.json({ valid: true });
});

// Start deployment route
app.post('/start', async (req, res) => {
    const { authToken, session_id } = req.body;

    // Validate required fields
    if (!authToken || !session_id) {
        return res.status(400).json({ 
            error: 'Missing required fields: authToken and session_id' 
        });
    }

    // Verify auth token
    const users = loadUsers();
    const user = Object.values(users).find(u => u.authToken === authToken);

    if (!user || !user.verified) {
        return res.status(401).json({ error: 'Invalid or unverified auth token' });
    }

    // Get username for tracking deployments
    const username = Object.keys(users).find(key => users[key].authToken === authToken);

    // Check if user has already deployed
    const deployments = loadDeployments();
    if (deployments[username]) {
        return res.status(409).json({ 
            error: 'Only one deployment allowed per account. You have already deployed.' 
        });
    }

    try {
    // Clean the session_id before using it
    const cleanSessionId = String(session_id)
        .trim()                     // Remove leading/trailing whitespace
        .replace(/\u200B/g, '')    // Remove zero-width spaces
        .replace(/\s/g, '');       // Remove any accidental spaces

    console.log('Cleaned session_id:', JSON.stringify(cleanSessionId));

    // Make deploy request to external API
    const deployResponse = await axios.post('https://tested-0939583b45ae.herokuapp.com/deploy',
        qs.stringify({ session_id: cleanSessionId }),
        {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            timeout: 1900000 // 30 second timeout
        }
    );
    

        // Check if deploy was successful
        if (deployResponse.status === 200 || deployResponse.status === 201) {
            // Mark user as deployed
            deployments[username] = {
                session_id: session_id,
                deployed_at: new Date().toISOString(),
                deploy_response: deployResponse.data
            };
            saveDeployments(deployments);

            return res.json({
                success: true,
                message: 'Your script has started running',
                deploy_data: deployResponse.data
            });
        } else {
            return res.status(500).json({
                error: 'Deploy request failed',
                details: deployResponse.data
            });
        }

    } catch (error) {
        console.error('Deploy API Error:', error.message);
        
        // Handle different types of errors
        if (error.code === 'ECONNABORTED') {
            return res.status(408).json({ 
                error: 'Deploy request timed out. Please try again.' 
            });
        }
        
        if (error.response) {
            // The external API responded with an error
            return res.status(error.response.status).json({
                error: 'Deploy failed',
                details: error.response.data
            });
        }
        
        // Network or other errors
        return res.status(500).json({
            error: 'Failed to connect to deploy service',
            details: error.message
        });
    }
});

// Get deployment status route
app.get('/deployment-status', (req, res) => {
    const { authToken } = req.query;

    if (!authToken) {
        return res.status(400).json({ error: 'Auth token required' });
    }

    const users = loadUsers();
    const user = Object.values(users).find(u => u.authToken === authToken);

    if (!user || !user.verified) {
        return res.status(401).json({ error: 'Invalid auth token' });
    }

    const username = Object.keys(users).find(key => users[key].authToken === authToken);
    const deployments = loadDeployments();

    if (deployments[username]) {
        return res.json({
            deployed: true,
            deployment_info: deployments[username]
        });
    } else {
        return res.json({
            deployed: false,
            message: 'No deployment found for this account'
        });
    }
});

// Get user info route
app.get('/user-info', (req, res) => {
    const { authToken } = req.query;

    if (!authToken) {
        return res.status(400).json({ error: 'Auth token required' });
    }

    const users = loadUsers();
    
    // Find user by token
    const userEntry = Object.entries(users).find(([username, userData]) => 
        userData.authToken === authToken
    );

    if (!userEntry) {
        return res.status(401).json({ error: 'Invalid auth token' });
    }

    const [username, userData] = userEntry;

    if (!userData.verified) {
        return res.status(401).json({ error: 'Account not verified' });
    }

    // Get deployment info if exists
    const deployments = loadDeployments();
    const deploymentInfo = deployments[username] || null;

    res.json({
        username: username,
        email: userData.email,
        verified: userData.verified,
        hasDeployment: !!deploymentInfo,
        deploymentInfo: deploymentInfo
    });
});

// HTML Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
