const express = require('express');
const bcrypt = require('bcrypt');
const qs = require('querystring');
const nodemailer = require('nodemailer');
const axios = require('axios');
const path = require('path');
const { MongoClient } = require('mongodb'); // Install with: npm install mongodb

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static('public')); // Serve static files from public directory

// MongoDB connection
const MONGODB_URI = 'mongodb+srv://reikeraxx:yGE7i0Oov6KoMzKl@cluster0.g0delua.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const DB_NAME = 'akane_pairing';

let db;
let usersCollection;
let verifiedEmailsCollection;
let deploymentsCollection;

// Initialize MongoDB connection
async function initializeDatabase() {
    try {
        const client = new MongoClient(MONGODB_URI);
        await client.connect();
        console.log('Connected to MongoDB');
        
        db = client.db(DB_NAME);
        usersCollection = db.collection('users');
        verifiedEmailsCollection = db.collection('verified_emails');
        deploymentsCollection = db.collection('deployments');
        
        // Create indexes for better performance
        await usersCollection.createIndex({ username: 1 }, { unique: true });
        await usersCollection.createIndex({ authToken: 1 });
        await usersCollection.createIndex({ email: 1 }); // Remove unique constraint to allow cleanup
        await verifiedEmailsCollection.createIndex({ email: 1 }, { unique: true });
        await deploymentsCollection.createIndex({ username: 1 }, { unique: true });
        
    } catch (error) {
        console.error('MongoDB connection error:', error);
        process.exit(1);
    }
}

// Helper functions for database operations
const findUserByUsername = async (username) => {
    return await usersCollection.findOne({ username });
};

const findUserByToken = async (authToken) => {
    return await usersCollection.findOne({ authToken });
};

const createUser = async (userData) => {
    return await usersCollection.insertOne(userData);
};

const updateUser = async (username, updateData) => {
    return await usersCollection.updateOne({ username }, { $set: updateData });
};

const isEmailVerified = async (email) => {
    const result = await verifiedEmailsCollection.findOne({ email });
    return !!result;
};

const addVerifiedEmail = async (email) => {
    return await verifiedEmailsCollection.insertOne({ 
        email, 
        verified_at: new Date() 
    });
};

const findDeployment = async (username) => {
    return await deploymentsCollection.findOne({ username });
};

const createDeployment = async (deploymentData) => {
    return await deploymentsCollection.insertOne(deploymentData);
};

const getTotalUserCount = async () => {
    return await usersCollection.countDocuments();
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
                            If you didn't request this code, please ignore this message.
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

    try {
        const existingUser = await findUserByUsername(username);
        if (existingUser) {
            return res.status(409).json({ error: 'Username already exists' });
        }

        // Check if email is already in use by a VERIFIED account
        const existingEmailUser = await usersCollection.findOne({ email });
        if (existingEmailUser && existingEmailUser.verified) {
            return res.status(409).json({ error: 'Email is already in use by a verified account' });
        }
        
        // If email exists but account is not verified, delete the old unverified account
        if (existingEmailUser && !existingEmailUser.verified) {
            await usersCollection.deleteOne({ email });
            console.log(`Deleted unverified account for email: ${email}`);
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const authToken = generateToken();
        const verificationCode = generateVerificationCode();

        try {
            await sendVerificationEmail(email, verificationCode);
        } catch (error) {
            console.error('Email sending error:', error);
            return res.status(500).json({ error: 'Failed to send verification email' });
        }

        const userData = {
            username,
            email,
            password: hashedPassword,
            authToken,
            verified: false,
            verificationCode,
            created_at: new Date()
        };

        await createUser(userData);

        res.json({
            message: 'User registered. Verification code sent to email.',
            authToken
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Verify email route
app.post('/verify', async (req, res) => {
    const { username, code } = req.body;

    try {
        const user = await findUserByUsername(username);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.verified) {
            return res.status(400).json({ error: 'User already verified' });
        }

        if (user.verificationCode !== code) {
            return res.status(400).json({ error: 'Invalid verification code' });
        }

        await updateUser(username, { 
            verified: true, 
            verified_at: new Date(),
            $unset: { verificationCode: "" }
        });

        const emailVerified = await isEmailVerified(user.email);
        if (!emailVerified) {
            await addVerifiedEmail(user.email);
        }

        res.json({ message: 'Email verified successfully' });
    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    try {
        const user = await findUserByUsername(username);

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

        // Update last login
        await updateUser(username, { last_login: new Date() });

        res.json({
            message: 'Login successful',
            authToken: user.authToken,
            username: username
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Check auth token route
app.get('/check', async (req, res) => {
    const { auth } = req.query;

    if (!auth) {
        return res.status(400).json({ valid: false, error: 'Missing auth token' });
    }

    try {
        const user = await findUserByToken(auth);

        if (!user || !user.verified) {
            return res.json({ valid: false });
        }

        res.json({ valid: true });
    } catch (error) {
        console.error('Auth check error:', error);
        res.status(500).json({ valid: false, error: 'Internal server error' });
    }
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

    try {
        // Verify auth token
        const user = await findUserByToken(authToken);

        if (!user || !user.verified) {
            return res.status(401).json({ error: 'Invalid or unverified auth token' });
        }

        // Check if user has already deployed
        const existingDeployment = await findDeployment(user.username);
        if (existingDeployment) {
            return res.status(409).json({ 
                error: 'Only one deployment allowed per account. You have already deployed.' 
            });
        }

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
            const deploymentData = {
                username: user.username,
                session_id: session_id,
                deployed_at: new Date(),
                deploy_response: deployResponse.data
            };
            
            await createDeployment(deploymentData);

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
app.get('/deployment-status', async (req, res) => {
    const { authToken } = req.query;

    if (!authToken) {
        return res.status(400).json({ error: 'Auth token required' });
    }

    try {
        const user = await findUserByToken(authToken);

        if (!user || !user.verified) {
            return res.status(401).json({ error: 'Invalid auth token' });
        }

        const deployment = await findDeployment(user.username);

        if (deployment) {
            return res.json({
                deployed: true,
                deployment_info: deployment
            });
        } else {
            return res.json({
                deployed: false,
                message: 'No deployment found for this account'
            });
        }
    } catch (error) {
        console.error('Deployment status error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get user info route
app.get('/user-info', async (req, res) => {
    const { authToken } = req.query;

    if (!authToken) {
        return res.status(400).json({ error: 'Auth token required' });
    }

    try {
        const user = await findUserByToken(authToken);

        if (!user) {
            return res.status(401).json({ error: 'Invalid auth token' });
        }

        if (!user.verified) {
            return res.status(401).json({ error: 'Account not verified' });
        }

        // Get deployment info if exists
        const deployment = await findDeployment(user.username);

        res.json({
            username: user.username,
            email: user.email,
            verified: user.verified,
            hasDeployment: !!deployment,
            deploymentInfo: deployment
        });
    } catch (error) {
        console.error('User info error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get total user count route
app.get('/user-count', async (req, res) => {
    try {
        const totalUsers = await getTotalUserCount();
        res.json({
            total_users: totalUsers,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('User count error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// HTML Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Initialize database and start server
async function startServer() {
    await initializeDatabase();
    
    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}

startServer().catch(console.error);
