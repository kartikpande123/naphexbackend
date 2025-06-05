const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const bcrypt = require('bcrypt'); // Import bcrypt for password hashing
const { addUserToDatabase, firebaseAdmin } = require('./db/firebaseService');
const cron = require('node-cron');
const moment = require('moment-timezone');
const schedule = require('node-schedule');
const multer = require('multer');
const sharp = require("sharp")
const app = express();


//Midllewares
const cors = require('cors');

// Use this before all routes
app.use(cors({
  origin: '*', // ✅ Allow all origins
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization'],
  credentials: true, // optional, only if you support cookies/auth headers
}));



app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ limit: '20mb', extended: true }));



//Multer for file uploads 
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB file size limit
    },
    fileFilter: (req, file, cb) => {
        // Accept image files only
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'), false);
        }
    }
});

const port = 3200;

//firestore
const firestore = admin.firestore();
const db = admin.database();

// Edumarc SMS API Configuration
const EDUMARC_API_URL = 'https://smsapi.edumarcsms.com/api/v1/sendsms';
const API_KEY = '0d9b7e18eb384af2975f47a75b62a433';
const SENDER_ID = 'EDUMRC';
const TEMPLATE_ID = '1707168926925165526';

// // * API for user login with phone and password
// const bcrypt = require('bcrypt'); // Assuming bcrypt is used for hashing passwords


app.get("/", (req,res)=>{
    res.send("Naphex Game Bakcend Is Running!")
})


app.post('/login', async (req, res) => {
    const { phoneNo, password } = req.body;

    if (!phoneNo || !password) {
        return res.status(400).json({
            success: false,
            message: 'Phone number and password are required.'
        });
    }

    try {
        // Format phone number for Auth
        const formattedPhoneNo = phoneNo.startsWith('+91') ? phoneNo : `+91${phoneNo}`;

        // Get reference to Users node
        const dbRef = firebaseAdmin.database();
        const usersRef = dbRef.ref('/Users');

        // Fetch users data
        const snapshot = await usersRef.once('value');
        const usersData = snapshot.val();

        if (!usersData) {
            return res.status(401).json({
                success: false,
                message: 'No users found in database.'
            });
        }

        // Find user by phone number
        let userData = null;
        let userKey = null;

        Object.keys(usersData).forEach(key => {
            const currentUser = usersData[key];
            if (currentUser && currentUser.phoneNo === phoneNo) {
                userData = currentUser;
                userKey = key;
            }
        });

        if (!userData) {
            return res.status(401).json({
                success: false,
                message: 'User not found in database.'
            });
        }

        // Compare passwords
        const isValidPassword = await bcrypt.compare(password, userData.password);

        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Invalid password.'
            });
        }

        // Get user record from Firebase Auth
        const userRecord = await firebaseAdmin.auth().getUserByPhoneNumber(formattedPhoneNo);

        // Generate custom token
        const customToken = await firebaseAdmin.auth().createCustomToken(userRecord.uid);

        // FIXED: Properly get userIds from the database
        const userids = {
            myuserid: userData.userIds?.myuserid || userData.userId || '', // Check both possible paths
            myrefrelid: userData.userIds?.myrefrelid || userData.referId || '' // Check both possible paths
        };

        // If userIds are empty and should have values, update them in the database
        if (!userids.myuserid || !userids.myrefrelid) {
            // Generate new IDs if they don't exist
            userids.myuserid = userids.myuserid || `USER${Math.random().toString(36).substr(2, 8).toUpperCase()}`;
            userids.myrefrelid = userids.myrefrelid || `REF${Math.random().toString(36).substr(2, 8).toUpperCase()}`;

            // Update the database with new IDs
            await usersRef.child(userKey).child('userIds').set(userids);
        }

        // Prepare response data with current timestamp and proper userIds
        const responseData = {
            success: true,
            message: 'Login successful',
            customToken,
            userData: {
                name: userData.name,
                phoneNo: userData.phoneNo,
                email: userData.email,
                tokens: userData.tokens,
                city: userData.city,
                state: userData.state,
                createdAt: userData.createdAt,
                loginTimestamp: new Date().toISOString(),
                userids: userids  // Now properly populated
            }
        };

        return res.status(200).json(responseData);

    } catch (error) {
        console.error('Login error:', error);
        return res.status(401).json({
            success: false,
            message: 'Invalid credentials or user not found.',
            debug: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});
// Utility function to test password verification
app.post('/test-password', async (req, res) => {
    const { phoneNo, password } = req.body;

    try {
        // Get reference to Users node
        const dbRef = firebaseAdmin.database();
        const usersRef = dbRef.ref('/Users');

        // Fetch all user subcollections
        const snapshot = await usersRef.once('value');
        const usersData = snapshot.val();

        if (!usersData) {
            return res.status(404).json({
                success: false,
                message: 'No users found in database'
            });
        }

        // Find user by phone number across all subcollections
        let userData = null;

        Object.keys(usersData).forEach(key => {
            const currentUser = usersData[key];
            if (currentUser && currentUser.phoneNo === phoneNo) {
                userData = currentUser;
            }
        });

        // If no user found
        if (!userData) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        console.log('Stored hash:', userData.password);
        console.log('Attempting to match password:', password);

        const isMatch = await bcrypt.compare(password, userData.password);

        res.json({
            success: true,
            passwordMatches: isMatch,
            storedHash: userData.password
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});


/**
* API to verify if phone number exists before registration
*/
app.post('/check-phone', async (req, res) => {
    const { phoneNo } = req.body;

    // Validate input
    if (!phoneNo) {
        return res.status(400).json({
            success: false,
            message: 'Phone number is required.',
        });
    }

    try {
        // Check if the phone number exists in Firebase Authentication
        const user = await firebaseAdmin.auth().getUserByPhoneNumber(`+91${phoneNo}`);

        // If user is found, respond with "already registered"
        return res.status(200).json({
            success: false,
            message: 'Phone number already registered.',
            userData: {
                uid: user.uid,
                phoneNo: user.phoneNumber,
                displayName: user.displayName || null,
                email: user.email || null,
            },
        });
    } catch (error) {
        if (error.code === 'auth/user-not-found') {
            // If no user is found, phone number is available
            return res.status(200).json({
                success: true,
                message: 'Phone number available for registration.',
            });
        }

        // Handle unexpected errors
        console.error('Error checking phone number:', error.message);
        return res.status(500).json({
            success: false,
            message: 'Failed to check phone number.',
            error: error.message,
        });
    }
});


/**
* API to get user profile by phone number (protected route)
*/
app.get('/user-profile/:phoneNo', (req, res) => {
    try {
        const { phoneNo } = req.params;
        console.log(`\nFetching user data for phone number: ${phoneNo}`);

        // Set headers for Server-Sent Events
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.setHeader('Access-Control-Allow-Origin', '*');

        // Function to log user data
        const logUserData = (userData, userId) => {
            console.log('\nUser Details Found:');
            console.log('User ID:', userId);

            // Log all properties of userData
            for (const [key, value] of Object.entries(userData)) {
                if (key === 'userids') {
                    console.log('User IDs:');
                    console.log('- Referral ID:', value.myrefrelid);
                    console.log('- User ID:', value.myuserid);
                } else if (typeof value !== 'object') {
                    console.log(`${key}:`, value);
                } else if (value !== null) {
                    console.log(`${key}:`, JSON.stringify(value, null, 2));
                }
            }
            console.log('\n');
        };

        // Reference to the Users node
        const usersRef = admin.database().ref('Users');

        // Use once() instead of on() for a one-time data fetch
        usersRef.once('value')
            .then((snapshot) => {
                const users = snapshot.val();
                let userData = null;
                let foundUserId = null;

                // Search for user with matching phone number
                for (const userKey in users) {
                    if (users[userKey].phoneNo === phoneNo) {
                        userData = {
                            ...users[userKey],
                            userId: userKey
                        };
                        foundUserId = userKey;
                        break;
                    }
                }

                if (userData) {
                    logUserData(userData, foundUserId);
                    
                    // Send data to client
                    res.write(`data: ${JSON.stringify({
                        success: true,
                        tokens: userData.tokens || 0,
                        userData: userData
                    })}\n\n`);
                    
                    // End the response after sending data
                    res.end();
                } else {
                    console.log('User not found for phone number:', phoneNo);
                    res.write(`data: ${JSON.stringify({
                        success: false,
                        message: 'User not found'
                    })}\n\n`);
                    
                    // End the response
                    res.end();
                }
            })
            .catch((error) => {
                console.error('Error fetching data:', error);
                res.write(`data: ${JSON.stringify({
                    success: false,
                    message: 'Error fetching user data'
                })}\n\n`);
                
                // End the response on error
                res.end();
            });

        // Handle client disconnect
        req.on('close', () => {
            console.log('Connection closed for phone number:', phoneNo);
        });

    } catch (error) {
        console.error('Error in API:', error);
        res.status(500).json({
            success: false,
            message: 'Error setting up real-time profile'
        });
    }
});


//  API to verify OTP and complete registration/login/
app.post('/verify-otp', async (req, res) => {
    const { phoneNo, otp, storedOtp } = req.body; // storedOtp from your debug response

    if (!phoneNo || !otp || !storedOtp) {
        return res.status(400).json({
            success: false,
            message: 'Phone number and OTP are required.'
        });
    }

    try {
        // Verify OTP match
        if (otp === storedOtp) {
            try {
                // Check if user exists
                const userData = await getUserByPhone(phoneNo);

                // Generate auth token if user exists
                const customToken = await firebaseAdmin.auth().createCustomToken(userData.userData.authUID);

                res.status(200).json({
                    success: true,
                    message: 'OTP verified successfully',
                    isExistingUser: true,
                    customToken,
                    userData: userData.userData
                });
            } catch (error) {
                // User doesn't exist - proceed with registration flow
                res.status(200).json({
                    success: true,
                    message: 'OTP verified successfully',
                    isExistingUser: false
                });
            }
        } else {
            res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            });
        }
    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to verify OTP'
        });
    }
});



/**
 * API to send OTP
 */
app.post('/send-otp', async (req, res) => {
    const { phoneNo } = req.body;

    // Validate the phone number
    if (!phoneNo) {
        return res.status(400).json({
            success: false,
            message: 'Phone number is required.'
        });
    }

    // Validate phone number format (10 digits)
    if (!/^\d{10}$/.test(phoneNo)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid phone number format. Please provide a 10-digit number.'
        });
    }

    try {
        // Generate a 6-digit OTP
        const otp = crypto.randomInt(100000, 999999).toString();

        // Create the message following Edumarc's template format
        const message = `Your verification OTP for verification is: ${otp}. OTP is confidential, refrain from sharing it with anyone. By Edumarc Technologies`;

        const payload = {
            number: [phoneNo],
            message: message,
            senderId: SENDER_ID,
            templateId: TEMPLATE_ID
        };

        // Make the API request to Edumarc
        const response = await axios({
            method: 'POST',
            url: EDUMARC_API_URL,
            headers: {
                'Content-Type': 'application/json',
                'apikey': API_KEY
            },
            data: payload
        });

        // Log the response for debugging
        console.log('SMS API Response:', response.data);

        // Check the response
        if (response.data && response.status === 200) {
            return res.status(200).json({
                success: true,
                message: 'OTP sent successfully',
                transactionId: response.data.transactionId, // If provided by API
                debug: {
                    otp: otp // Remove in production
                }
            });
        } else {
            throw new Error('Failed to send OTP');
        }

    } catch (error) {
        console.error('Error details:', {
            message: error.message,
            response: error.response?.data,
            status: error.response?.status
        });

        return res.status(error.response?.status || 500).json({
            success: false,
            message: error.response?.data?.message || 'Failed to send OTP. Please try again later.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

/**
 * API to add user and their subcollection to Firebase.
 */

app.post('/add-user', async (req, res) => {
    const { name, phoneNo, email, password, referralId, myuserid, myrefrelid, city, state } = req.body;

    // Validate required fields
    if (!name || !phoneNo || !password || !myuserid || !myrefrelid || !city || !state) {
        return res.status(400).json({
            success: false,
            message: 'Required fields missing: name, phoneNo, password, myuserid, myrefrelid, city, state.'
        });
    }

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create the user in Firebase Authentication
        const userRecord = await firebaseAdmin.auth().createUser({
            phoneNumber: `+91${phoneNo}`,
            password: password,
            displayName: name,
            email: email || undefined,
        });

        // Get reference to Users collection
        const dbRef = firebaseAdmin.database();
        const usersRef = dbRef.ref('/Users');

        // Find the highest existing user number
        const snapshot = await usersRef.orderByKey().once('value');
        let highestNumber = 0;
        snapshot.forEach((childSnapshot) => {
            const userKey = childSnapshot.key;
            const match = userKey.match(/user-(\d+)/);
            if (match) {
                const userNumber = parseInt(match[1]);
                highestNumber = Math.max(highestNumber, userNumber);
            }
        });

        // Generate next user ID
        const nextUserNumber = highestNumber + 1;
        const userPath = `user-${nextUserNumber}`;

        // Get current date and time
        const createdAt = new Date().toISOString(); // ISO string format for date and time

        // Prepare user data for the main collection
        const userData = {
            name: name,
            phoneNo: phoneNo,
            email: email || null,
            password: hashedPassword,
            referralId: referralId || null,
            tokens: 200,
            city: city,
            state: state,
            createdAt: createdAt,  // Store creation date and time
        };

        // Save user data to the Users main collection
        await dbRef.ref(`/Users/${userPath}`).set(userData);

        // Prepare user data for the subcollection (UserIds)
        const userIdsData = {
            myuserid: myuserid,
            myrefrelid: myrefrelid,
        };

        // Save userIds data to the subcollection
        await dbRef.ref(`/Users/${userPath}/userIds`).set(userIdsData);

        // Create custom token for immediate login
        const customToken = await firebaseAdmin.auth().createCustomToken(userRecord.uid);

        res.status(200).json({
            success: true,
            message: 'User added successfully',
            authUid: userRecord.uid,
            customToken,
            userData: {
                userId: userPath,
                name,
                phoneNo,
                email: email || null,
                referralId: referralId || null,
                tokens: 200,
                city,
                state,
                createdAt,  // Include created date and time in the response
            },
            userIdsData: userIdsData, // Send the userIds data in the response as well
        });
    } catch (error) {
        console.error('Error adding user:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add user.',
            error: error.message,
        });
    }
});



// Optional: Add a health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'OK' });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        success: false,
        message: 'Internal server error'
    });
});


app.post('/reset-password', async (req, res) => {
    const { phoneNo, newPassword } = req.body;

    // Validate request body
    if (!phoneNo || !newPassword) {
        return res.status(400).json({
            success: false,
            message: 'Phone number and new password are required.'
        });
    }

    try {
        // Get reference to Users node
        const dbRef = firebaseAdmin.database();
        const usersRef = dbRef.ref('/Users');

        // Fetch all user subcollections
        const snapshot = await usersRef.once('value');
        const usersData = snapshot.val();

        if (!usersData) {
            return res.status(404).json({
                success: false,
                message: 'No users found in database.'
            });
        }

        // Find user by phone number
        let userKey = null;
        Object.keys(usersData).forEach(key => {
            const currentUser = usersData[key];
            if (currentUser && currentUser.phoneNo === phoneNo) {
                userKey = key;
            }
        });

        if (!userKey) {
            return res.status(404).json({
                success: false,
                message: 'User not found.'
            });
        }

        // Hash new password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        // Update password in Firebase Database
        await dbRef.ref(`/Users/${userKey}`).update({
            password: hashedNewPassword
        });

        // Update password in Firebase Auth
        const formattedPhoneNo = phoneNo.startsWith('+91') ? phoneNo : `+91${phoneNo}`;
        const userRecord = await firebaseAdmin.auth().getUserByPhoneNumber(formattedPhoneNo);
        await firebaseAdmin.auth().updateUser(userRecord.uid, {
            password: newPassword
        });

        return res.status(200).json({
            success: true,
            message: 'Password reset successfully'
        });

    } catch (error) {
        console.error('Password reset error:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to reset password',
            debug: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});




//Game1 Apis open=close
//API to search and deduct tokens
app.post("/deduct-tokens", async (req, res) => {
    try {
        const { phoneNo, amount } = req.body;

        // Basic input validation
        if (!phoneNo || amount === undefined) {
            return res.status(400).json({
                success: false,
                message: "Missing required parameters"
            });
        }

        // Validate amount is a number and positive
        const numAmount = Number(amount);
        if (isNaN(numAmount) || numAmount <= 0) {
            return res.status(400).json({
                success: false,
                message: "Invalid amount"
            });
        }

        // Get reference to Users node
        const usersRef = admin.database().ref('Users');

        // Get all users
        const snapshot = await usersRef.once('value');
        const users = snapshot.val();

        // Find user with matching phone number
        let userKey = null;
        let userData = null;

        Object.entries(users).forEach(([key, user]) => {
            if (user.phoneNo === phoneNo) {
                userKey = key;
                userData = user;
            }
        });

        if (!userData) {
            return res.status(404).json({
                success: false,
                message: "User not found"
            });
        }

        // Check if user has sufficient tokens
        if (!userData.tokens || userData.tokens < numAmount) {
            return res.status(400).json({
                success: false,
                message: "Insufficient tokens",
                currentTokens: userData.tokens || 0
            });
        }

        // Calculate new balance
        const newBalance = userData.tokens - numAmount;

        // Update user's token balance
        await usersRef.child(userKey).update({
            tokens: newBalance
        });

        // Return success response
        return res.status(200).json({
            success: true,
            message: "Tokens deducted successfully",
            currentBalance: newBalance,
            deductedAmount: numAmount
        });

    } catch (error) {
        console.error("Error in deduct-tokens endpoint:", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error"
        });
    }
});


//Bet details bet section 
app.post('/store-game-action', async (req, res) => {
    try {
        // Get the necessary data from the request body
        const { phoneNo, sessionNumber, gameMode, betAmount, selectedNumbers } = req.body;

        // Validate the input data
        if (!phoneNo || !sessionNumber || !gameMode || !betAmount || !selectedNumbers) {
            return res.status(400).json({ success: false, message: 'Missing required game action details' });
        }

        // Get reference to Firebase Database
        const dbRef = firebaseAdmin.database();
        const usersRef = dbRef.ref('/Users');

        // Get the users data from Firebase
        const snapshot = await usersRef.once('value');
        const usersData = snapshot.val();

        if (!usersData) {
            return res.status(404).json({ success: false, message: 'No users found in database' });
        }

        // Find the user by phone number
        let userKey = null;
        Object.keys(usersData).forEach(key => {
            const currentUser = usersData[key];
            if (currentUser && currentUser.phoneNo === phoneNo) {
                userKey = key;
            }
        });

        if (!userKey) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Get current date
        const currentDate = new Date().toISOString().split('T')[0];

        // References for different subcollections within game1
        const userGamesRef = dbRef.ref(`/Users/${userKey}/game1`);
        const totalBetRef = userGamesRef.child('total-bet-amount');
        const dailyBetRef = userGamesRef.child('daily-bet-amount');

        // Create the game action data to be stored
        const gameAction = {
            timestamp: new Date().toISOString(),
            sessionNumber,
            gameMode,
            betAmount,
            selectedNumbers,
            status: 'pending',
        };

        // Generate a unique ID for this game action
        const newGameRef = userGamesRef.child('game-actions').push();

        // Store the game action
        await newGameRef.set(gameAction);

        // Update Total Bet Amount
        const totalBetSnapshot = await totalBetRef.once('value');
        let totalBetData = totalBetSnapshot.val() || { totalAmount: 0 };

        totalBetData.totalAmount = (totalBetData.totalAmount || 0) + parseFloat(betAmount);
        await totalBetRef.set(totalBetData);

        // Update Daily Bet Amount
        const dailyBetSnapshot = await dailyBetRef.once('value');
        let dailyBetData = dailyBetSnapshot.val() || {};

        // Check if today's entry exists, if not create a new one
        if (!dailyBetData[currentDate]) {
            dailyBetData[currentDate] = {
                totalAmount: 0,
                betIds: [] // Array to store bet IDs for the day
            };
        }

        // Add bet amount to today's total
        dailyBetData[currentDate].totalAmount += parseFloat(betAmount);

        // Add the current bet ID to the day's bet IDs
        dailyBetData[currentDate].betIds.push(newGameRef.key);

        // Clean up old entries (optional: remove entries older than 30 days)
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

        Object.keys(dailyBetData).forEach(date => {
            if (new Date(date) < thirtyDaysAgo) {
                delete dailyBetData[date];
            }
        });

        // Save daily bet data
        await dailyBetRef.set(dailyBetData);

        // Return success response
        return res.status(200).json({
            success: true,
            message: 'Game action stored successfully',
            gameId: newGameRef.key,
            gameData: gameAction,
            totalBetAmount: totalBetData.totalAmount,
            todayBetAmount: dailyBetData[currentDate].totalAmount,
            todayBetIds: dailyBetData[currentDate].betIds
        });

    } catch (error) {
        console.error('Error storing game action:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to store game action',
            error: error.message,
        });
    }
});




//Admin Dashboard user show api
app.get('/api/users', (req, res) => {
    try {
        // Set headers for Server-Sent Events (SSE)
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.setHeader('Access-Control-Allow-Origin', '*');

        // Reference to the Users node in Firebase Realtime Database
        const dbRef = firebaseAdmin.database();
        const usersRef = dbRef.ref('/Users');

        // Send initial data to the client
        const sendData = (usersData) => {
            res.write(`data: ${JSON.stringify({
                success: true,
                data: usersData
            })}\n\n`);
        };

        // Function to format users data
        const formatUsersData = (usersData) => {
            return Object.keys(usersData).map((key) => ({
                userId: key,
                ...usersData[key],
            }));
        };

        // Fetch the initial data and send it to the client
        usersRef.once('value', (snapshot) => {
            if (snapshot.exists()) {
                const usersData = snapshot.val();
                const formattedData = formatUsersData(usersData);
                sendData(formattedData); // Send data initially
            } else {
                res.write(`data: ${JSON.stringify({
                    success: false,
                    message: 'No users found'
                })}\n\n`);
            }
        });

        // Set up real-time listener to watch for changes in the Users node
        const listener = usersRef.on('value', (snapshot) => {
            const usersData = snapshot.val();
            if (usersData) {
                const formattedData = formatUsersData(usersData);
                sendData(formattedData); // Send updated data
            } else {
                res.write(`data: ${JSON.stringify({
                    success: false,
                    message: 'No users found'
                })}\n\n`);
            }
        });

        // Handle client disconnect
        req.on('close', () => {
            console.log('Connection closed');
            usersRef.off('value', listener); // Stop listening to the database changes
        });

    } catch (error) {
        console.error('Error in API:', error);
        res.status(500).json({
            success: false,
            message: 'Error setting up real-time user data updates'
        });
    }
});


//Playes game bets for result generation
// Initialize OpenCloseGameDetails collection if it doesn't exist
async function initializeCollectionIfNeeded() {
    try {
        const dbRef = admin.database().ref('/OpenCloseGameDetails');
        const snapshot = await dbRef.once('value');

        if (!snapshot.exists()) {
            // Initialize the basic structure with betted-numbers subcollection
            await dbRef.set({
                'totalPlayerBetAmount': 0,
                'totalPlayerWinAmount': 0
            });
        }
    } catch (error) {
        console.error('Error initializing collection:', error);
    }
}

// Cron jobs for cleanup
cron.schedule('30 17 * * *', async () => {
    try {
        const bettedNumbersRef = admin.database().ref('/OpenCloseGameDetails/betted-numbers/session-1');
        await bettedNumbersRef.remove();
        console.log('Session 1 bets cleaned up at 5:30 PM');
    } catch (error) {
        console.error('Error cleaning session 1:', error);
    }
});

cron.schedule('55 23 * * *', async () => {
    try {
        const bettedNumbersRef = admin.database().ref('/OpenCloseGameDetails/betted-numbers/session-2');
        await bettedNumbersRef.remove();
        console.log('Session 2 bets cleaned up at 11:55 PM');
    } catch (error) {
        console.error('Error cleaning session 2:', error);
    }
});

app.post('/store-bet-numbers', async (req, res) => {
    try {
        await initializeCollectionIfNeeded();

        const {
            sessionNumber, // This will be 1 or 2 from your frontend
            choiceMode,   // This matches your frontend modes: 'open-pana', 'open-number', etc.
            selectedNumbers, // Array of numbers from your frontend
            betAmount    // Amount from your frontend
        } = req.body;

        // Validate inputs
        if (!sessionNumber || !choiceMode || !selectedNumbers || !betAmount) {
            return res.status(400).json({
                success: false,
                message: 'Missing required bet details'
            });
        }

        // Convert session number to session-1 or session-2 format
        const sessionKey = `session-${sessionNumber}`;

        // Create reference to the specific betted-numbers path
        const betsRef = admin.database().ref('/OpenCloseGameDetails/betted-numbers')
            .child(sessionKey)
            .child(choiceMode);

        // Get current bets for this choice mode
        const snapshot = await betsRef.once('value');
        const currentBets = snapshot.val() || {};

        // Format the numbers into a single string if multiple numbers
        const numberKey = selectedNumbers.join('');

        // Update or add the bet amount for these numbers
        if (currentBets[numberKey]) {
            currentBets[numberKey] += parseInt(betAmount);
        } else {
            currentBets[numberKey] = parseInt(betAmount);
        }

        // Store the updated bets
        await betsRef.set(currentBets);

        // Update total bet amount in OpenCloseGameDetails
        const totalsRef = admin.database().ref('/OpenCloseGameDetails');
        const totalsSnapshot = await totalsRef.once('value');
        const totals = totalsSnapshot.val() || {};

        const currentTotalBet = (totals.totalPlayerBetAmount || 0) + parseInt(betAmount);
        await totalsRef.child('totalPlayerBetAmount').set(currentTotalBet);

        return res.status(200).json({
            success: true,
            message: 'Bet numbers stored successfully',
            data: {
                session: sessionKey,
                choiceMode,
                bettedNumbers: numberKey,
                betAmount,
                totalBetAmount: currentTotalBet
            }
        });

    } catch (error) {
        console.error('Error storing bet numbers:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to store bet numbers',
            error: error.message
        });
    }
});


//game result generation function and apis
class SecurePayoutGenerator {
    constructor(secretKey) {
        this.secretKey = secretKey;
        this.results = {};
    }

    isValidPanna(panna) {
        const pannaStr = panna.toString().padStart(3, '0');
        return [...pannaStr].every((digit, i) =>
            i === 0 ? digit !== '0' : digit >= pannaStr[i - 1]
        );
    }

    calculateNumberFromPanna(panna) {
        return [...panna.toString().padStart(3, '0')]
            .reduce((sum, digit) => sum + parseInt(digit), 0) % 10;
    }

    generateSecureRandom() {
        const array = new Uint32Array(1);
        crypto.getRandomValues(array);
        return array[0];
    }

    _formatBetsData(firebaseBets) {
        return {
            openPanna: firebaseBets?.['open-pana'] || {},
            closePanna: firebaseBets?.['close-pana'] || {},
            openNumber: firebaseBets?.['open-number'] || {},
            closeNumber: firebaseBets?.['close-number'] || {},
            openClose: firebaseBets?.['open-close'] || {}
        };
    }

    calculatePayout(category, result, bets, multipliers) {
        const betAmount = bets[category]?.[result] || 0;
        return betAmount * multipliers[category];
    }

    async processOpenResults(firebaseBets, multipliers) {
        const bets = this._formatBetsData(firebaseBets);
        const validPannas = [...Array(1000).keys()]
            .filter(num => this.isValidPanna(num))
            .map(num => num.toString().padStart(3, '0'));

        if (Object.keys(bets.openPanna).length === 0 && Object.keys(bets.openNumber).length === 0) {
            const randomIndex = this.generateSecureRandom() % validPannas.length;
            const randomPanna = validPannas[randomIndex];
            const randomNumber = this.calculateNumberFromPanna(randomPanna);

            return {
                openPanna: randomPanna,
                openNumber: randomNumber,
                totalOpenPayout: 0,
                details: {
                    openPannaPayout: 0,
                    openNumberPayout: 0
                }
            };
        }

        const openResults = validPannas.map(openPanna => {
            const openNumber = this.calculateNumberFromPanna(openPanna);
            const payoutOpenPanna = this.calculatePayout('openPanna', openPanna, bets, multipliers);
            const payoutOpenNumber = this.calculatePayout('openNumber', openNumber, bets, multipliers);
            const totalOpenPayout = payoutOpenPanna + payoutOpenNumber;

            return {
                openPanna,
                openNumber,
                totalOpenPayout,
                details: {
                    openPannaPayout: payoutOpenPanna,
                    openNumberPayout: payoutOpenNumber
                }
            };
        });

        const minPayout = Math.min(...openResults.map(r => r.totalOpenPayout));
        const minPayoutResults = openResults.filter(r => r.totalOpenPayout === minPayout);
        const randomIndex = this.generateSecureRandom() % minPayoutResults.length;
        return minPayoutResults[randomIndex];
    }

    async processCloseResults(firebaseBets, multipliers, openResults) {
        if (!openResults || !openResults["open-number"] || !openResults["open-pana"]) {
            throw new Error("Open results are required for close processing");
        }

        const bets = this._formatBetsData(firebaseBets);
        const validPannas = [...Array(1000).keys()]
            .filter(num => this.isValidPanna(num))
            .map(num => num.toString().padStart(3, '0'));

        if (Object.keys(bets.closePanna).length === 0 &&
            Object.keys(bets.closeNumber).length === 0 &&
            Object.keys(bets.openClose).length === 0) {
            const randomIndex = this.generateSecureRandom() % validPannas.length;
            const randomPanna = validPannas[randomIndex];
            const randomNumber = this.calculateNumberFromPanna(randomPanna);

            return {
                closePanna: randomPanna,
                closeNumber: randomNumber,
                openClose: `${openResults["open-number"]}${randomNumber}`,
                totalClosePayout: 0,
                details: {
                    closePannaPayout: 0,
                    closeNumberPayout: 0,
                    openClosePayout: 0
                }
            };
        }

        const closeResults = validPannas.map(closePanna => {
            const closeNumber = this.calculateNumberFromPanna(closePanna);
            const openClose = `${openResults["open-number"]}${closeNumber}`;
            const payoutClosePanna = this.calculatePayout('closePanna', closePanna, bets, multipliers);
            const payoutCloseNumber = this.calculatePayout('closeNumber', closeNumber, bets, multipliers);
            const payoutOpenClose = this.calculatePayout('openClose', openClose, bets, multipliers);
            const totalClosePayout = payoutClosePanna + payoutCloseNumber + payoutOpenClose;

            return {
                closePanna,
                closeNumber,
                openClose,
                totalClosePayout,
                details: {
                    closePannaPayout: payoutClosePanna,
                    closeNumberPayout: payoutCloseNumber,
                    openClosePayout: payoutOpenClose
                }
            };
        });

        const minClosePayout = Math.min(...closeResults.map(r => r.totalClosePayout));
        const minClosePayoutResults = closeResults.filter(r => r.totalClosePayout === minClosePayout);
        const randomIndex = this.generateSecureRandom() % minClosePayoutResults.length;
        return minClosePayoutResults[randomIndex];
    }
}

async function generateAndStoreResults(sessionNumber, type) {
    const db = admin.database();
    const betsRef = db.ref(`/OpenCloseGameDetails/betted-numbers/${sessionNumber}`);
    const currentDate = new Date().toISOString().split("T")[0];
    const resultsRef = db.ref(`/Results/${currentDate}`);

    const secureKey = "your-secure-key";
    const multipliers = {
        openPanna: 100,
        closePanna: 100,
        openNumber: 10,
        closeNumber: 10,
        openClose: 100
    };
    const generator = new SecurePayoutGenerator(secureKey);

    try {
        const formattedSessionNumber = sessionNumber.replace(/-/g, "");
        const snapshot = await betsRef.once("value");
        const firebaseBets = snapshot.val();

        let resultsToStore = {
            timestamp: new Date().toISOString()
        };

        if (type === "open") {
            const openResults = await generator.processOpenResults(firebaseBets, multipliers);
            resultsToStore[formattedSessionNumber] = {
                "open-number": openResults.openNumber,
                "open-pana": openResults.openPanna,
                "nums": `${openResults.openPanna} ${openResults.openNumber}`,
                "details": {
                    openNumberPayout: openResults.details.openNumberPayout,
                    openPannaPayout: openResults.details.openPannaPayout,
                    totalOpenPayout: openResults.totalOpenPayout
                }
            };
        } else if (type === "close") {
            const sessionSnapshot = await resultsRef.child(formattedSessionNumber).once("value");
            const existingResults = sessionSnapshot.val();

            if (!existingResults) {
                throw new Error(`Open results missing for ${formattedSessionNumber}`);
            }

            const closeResults = await generator.processCloseResults(firebaseBets, multipliers, existingResults);

            resultsToStore[formattedSessionNumber] = {
                ...existingResults,
                "close-number": closeResults.closeNumber,
                "close-pana": closeResults.closePanna,
                "nums": `${existingResults["open-pana"]} ${existingResults["open-number"]} ${closeResults.closeNumber} ${closeResults.closePanna}`,
                "details": {
                    ...existingResults.details,
                    closeNumberPayout: closeResults.details.closeNumberPayout,
                    closePannaPayout: closeResults.details.closePannaPayout,
                    openClosePayout: closeResults.details.openClosePayout
                }
            };
        }

        await resultsRef.update(resultsToStore);
        console.log(`Successfully stored ${type} results for ${sessionNumber}`);
    } catch (error) {
        console.error(`Error generating ${type} results for ${sessionNumber}:`, error);
        throw error;
    }
}

function scheduleResultGeneration() {
    const scheduleTimes = [
        { time: "14:30", session: "session-1", type: "open" },
        { time: "17:30", session: "session-1", type: "close" },
        { time: "21:30", session: "session-2", type: "open" },
        { time: "23:50", session: "session-2", type: "close" }
    ];

    scheduleTimes.forEach(({ time, session, type }) => {
        const [hours, minutes] = time.split(":").map(Number);

        schedule.scheduleJob(`${minutes} ${hours} * * *`, () => {
            generateAndStoreResults(session, type)
                .then(() => {
                    console.log(`Scheduled ${type} result generation completed for ${session} at ${time}`);
                })
                .catch(error => {
                    console.error(`Error in scheduled ${type} result generation for ${session}:`, error);
                });
        });

        console.log(`Scheduled ${type} generation for ${session} at ${time} daily`);
    });
}

scheduleResultGeneration();



// app.post('/generate-game-results', async (req, res) => {
//     try {
//         const now = moment().tz('Asia/Kolkata');
//         const currentDate = now.format('YYYY-MM-DD');

//         // Define session times
//         const sessions = [
//             {
//                 number: 'session1',
//                 openTime: moment().tz('Asia/Kolkata').set({ hour: 12, minute: 16, second: 0 }),
//                 closeTime: moment().tz('Asia/Kolkata').set({ hour: 17, minute: 25, second: 0 }),
//             },
//             {
//                 number: 'session2',
//                 openTime: moment().tz('Asia/Kolkata').set({ hour: 22, minute: 45, second: 0 }),
//                 closeTime: moment().tz('Asia/Kolkata').set({ hour: 23, minute: 50, second: 0 }),
//             },
//         ];

//         const determineSession = () => {
//             for (const session of sessions) {
//                 const openWindowStart = moment(session.openTime).subtract(5, 'minutes');
//                 const openWindowEnd = moment(session.openTime).add(5, 'minutes');
//                 const closeWindowStart = moment(session.closeTime).subtract(5, 'minutes');
//                 const closeWindowEnd = moment(session.closeTime).add(5, 'minutes');

//                 if (now.isBetween(openWindowStart, openWindowEnd)) {
//                     return { sessionType: 'open', ...session };
//                 }
//                 if (now.isBetween(closeWindowStart, closeWindowEnd)) {
//                     return { sessionType: 'close', ...session };
//                 }
//             }
//             return null;
//         };

//         const sessionInfo = determineSession();

//         if (!sessionInfo) {
//             return res.status(400).json({
//                 success: false,
//                 message: 'Not within a valid session time',
//                 currentTime: now.format('YYYY-MM-DD HH:mm:ss'),
//             });
//         }

//         const { sessionType, number: sessionNumber } = sessionInfo;
//         const generator = new SecurePayoutGenerator(process.env.SECRET_KEY || 'your-secret-key');

//         const multipliers = {
//             openPanna: 100,
//             closePanna: 100,
//             openNumber: 10,
//             closeNumber: 10,
//             openClose: 100,
//         };

//         // Firebase references
//         const db = admin.database();
//         const betsRef = db.ref(`/OpenCloseGameDetails/betted-numbers/${sessionNumber}`);
//         const resultsRef = db.ref('/Results');

//         // Format bets for the SecurePayoutGenerator class
//         const formatBetsForGenerator = async () => {
//             const formattedBets = {};

//             if (sessionType === 'open') {
//                 const [openPanaSnap, openNumberSnap] = await Promise.all([
//                     betsRef.child('open-pana').once('value'),
//                     betsRef.child('open-number').once('value'),
//                 ]);

//                 formattedBets['open-pana'] = openPanaSnap.val() || {};
//                 formattedBets['open-number'] = openNumberSnap.val() || {};
//             } else {
//                 const [closePanaSnap, closeNumberSnap, openCloseSnap] = await Promise.all([
//                     betsRef.child('close-pana').once('value'),
//                     betsRef.child('close-number').once('value'),
//                     betsRef.child('open-close').once('value'),
//                 ]);

//                 formattedBets['close-pana'] = closePanaSnap.val() || {};
//                 formattedBets['close-number'] = closeNumberSnap.val() || {};
//                 formattedBets['open-close'] = openCloseSnap.val() || {};
//             }

//             return formattedBets;
//         };

//         // Get and process bets
//         const bets = await formatBetsForGenerator();

//         let generatedResults;
//         let formattedResults;

//         if (sessionType === 'open') {
//             generatedResults = await generator.processOpenResults(bets, multipliers);

//             formattedResults = {
//                 'open-number': generatedResults.openNumber,
//                 'open-pana': generatedResults.openPanna,
//                 'nums': `${generatedResults.openPanna} ${generatedResults.openNumber}`,
//                 '_payout': {
//                     openPannaPayout: generatedResults.details.openPannaPayout,
//                     openNumberPayout: generatedResults.details.openNumberPayout,
//                     totalPayout: generatedResults.totalOpenPayout
//                 }
//             };
//         } else {
//             // Get existing open results for close session
//             const openResultSnap = await resultsRef.child(currentDate).child(sessionNumber).once('value');
//             const openResult = openResultSnap.val();

//             if (!openResult || !openResult['open-pana'] || !openResult['open-number']) {
//                 throw new Error('Open results required for close session processing');
//             }

//             // Set existing open results in generator
//             generator.results = {
//                 openPanna: openResult['open-pana'],
//                 openNumber: openResult['open-number'],
//                 totalOpenPayout: openResult._payout?.totalPayout || 0
//             };

//             generatedResults = await generator.processCloseResults(bets, multipliers);

//             formattedResults = {
//                 ...openResult,
//                 'close-number': generatedResults.closeNumber,
//                 'close-pana': generatedResults.closePanna,
//                 'nums': `${openResult['open-pana']} ${openResult['open-number']} ${generatedResults.closeNumber} ${generatedResults.closePanna}`,
//                 '_payout': {
//                     ...openResult._payout,
//                     closePannaPayout: generatedResults.details.closePannaPayout,
//                     closeNumberPayout: generatedResults.details.closeNumberPayout,
//                     openClosePayout: generatedResults.details.openClosePayout,
//                     totalPayout: generatedResults.totalClosePayout
//                 }
//             };
//         }

//         // Store results
//         await resultsRef.child(currentDate).child(sessionNumber).update(formattedResults);

//         res.status(200).json({
//             success: true,
//             message: `${sessionNumber} ${sessionType} result generated and stored successfully`,
//             results: formattedResults,
//             currentTime: now.format('YYYY-MM-DD HH:mm:ss'),
//         });

//     } catch (error) {
//         console.error('Error generating game results:', error);
//         res.status(500).json({
//             success: false,
//             message: 'Failed to generate game results',
//             error: error.message,
//         });
//     }
// });
// // Cron jobs for all four sessions
// // Session 1 Open Result at 2:30 PM
// cron.schedule('56 11 * * *', () => {
//     axios.post('http://localhost:3200/generate-game-results')
//         .then(response => {
//             console.log('Game results generated successfully:', response.data);
//         })
//         .catch(error => {
//             console.error('Error generating game results:', error.response ? error.response.data : error.message);
//         });
// }, {
//     timezone: 'Asia/Kolkata' // Set the timezone to Asia/Kolkata
// });



// // Session 1 Close Result at 5:25 PM
// cron.schedule('57 11 * * *', () => {
//     axios.post('http://localhost:3200/generate-game-results')
//         .then(response => {
//             console.log('Session 1 - Close result saved at 5:25 PM:', response.data);
//         })
//         .catch(error => {
//             console.error('Error posting Session 1 close result:',
//                 error.response ? error.response.data : error.message);
//         });
// }, {
//     timezone: 'Asia/Kolkata' // Make sure to set the timezone to Asia/Kolkata
// });

// // Session 2 Open Result at 9:25 PM
// cron.schedule('51 23 * * *', () => {
//     axios.post('http://localhost:3200/generate-game-results')
//         .then(response => {
//             console.log('Session 2 - Open result saved at 9:25 PM:', response.data);
//         })
//         .catch(error => {
//             console.error('Error posting Session 2 open result:',
//                 error.response ? error.response.data : error.message);
//         });
// }, {
//     timezone: 'Asia/Kolkata' // Make sure to set the timezone to Asia/Kolkata
// });


// // Session 2 Close Result at 11:50 PM
// cron.schedule('53 23 * * *', () => {
//     axios.post('http://localhost:3200/generate-game-results')
//         .then(response => {
//             console.log('Session 2 - Close result saved at 11:50 PM:', response.data);
//         })
//         .catch(error => {
//             console.error('Error posting Session 2 close result:',
//                 error.response ? error.response.data : error.message);
//         });
// }, {
//     timezone: 'Asia/Kolkata' // Make sure to set the timezone to Asia/Kolkata
// });




//User who play open-close
app.get('/users-with-openclose', async (req, res) => {
    // Set headers for Server-Sent Events
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Access-Control-Allow-Origin', '*');

    try {
        // Keep track of connected clients
        const clients = new Set();
        req.on('close', () => {
            clients.delete(res);
        });
        clients.add(res);

        // Get reference to Users node in Firebase
        const dbRef = firebaseAdmin.database();
        const usersRef = dbRef.ref('/Users');

        // Function to process and send user data
        const processAndSendUsers = async () => {
            try {
                const snapshot = await usersRef.once('value');
                const usersData = snapshot.val();

                if (!usersData) {
                    sendSSEMessage(res, {
                        type: 'error',
                        message: 'No users found in database'
                    });
                    return;
                }

                const usersWithGames = [];

                // Iterate through all users
                for (const [userKey, userData] of Object.entries(usersData)) {
                    const userGamesRef = dbRef.ref(`/Users/${userKey}/game1`);
                    const gamesSnapshot = await userGamesRef.once('value');
                    const gamesData = gamesSnapshot.val();

                    if (gamesData) {
                        // Fetch all subcollections for this user
                        const userSubcollections = {};
                        const subcollections = ['games', 'userIds'];

                        for (const subcollection of subcollections) {
                            const subcollectionRef = dbRef.ref(`/Users/${userKey}/${subcollection}`);
                            const subcollectionSnapshot = await subcollectionRef.once('value');
                            userSubcollections[subcollection] = subcollectionSnapshot.val();
                        }

                        // Create a comprehensive user object
                        const userWithGamesDetails = {
                            userId: userKey,
                            mainDetails: userData,
                            ...userSubcollections
                        };

                        usersWithGames.push(userWithGamesDetails);

                        // Send individual user updates
                        sendSSEMessage(res, {
                            type: 'user_processed',
                            user: userWithGamesDetails
                        });
                    }
                }

                // Send final users collection
                sendSSEMessage(res, {
                    type: 'initial_load',
                    users: usersWithGames,
                    message: `Found ${usersWithGames.length} users who played games`
                });

            } catch (error) {
                sendSSEMessage(res, {
                    type: 'error',
                    message: 'Failed to retrieve users with games',
                    error: error.message
                });
            }
        };

        // Setup Firebase real-time listeners
        const setupRealTimeListeners = () => {
            // Listener for new users
            usersRef.on('child_added', async (snapshot) => {
                const newUser = snapshot.val();
                const userId = snapshot.key;

                // Check if user has game data
                const userGamesRef = dbRef.ref(`/Users/${userId}/game1`);
                const gamesSnapshot = await userGamesRef.once('value');
                const gamesData = gamesSnapshot.val();

                if (gamesData) {
                    const userSubcollections = {};
                    const subcollections = ['games', 'userIds'];

                    for (const subcollection of subcollections) {
                        const subcollectionRef = dbRef.ref(`/Users/${userId}/${subcollection}`);
                        const subcollectionSnapshot = await subcollectionRef.once('value');
                        userSubcollections[subcollection] = subcollectionSnapshot.val();
                    }

                    const newUserDetails = {
                        userId: userId,
                        mainDetails: newUser,
                        ...userSubcollections
                    };

                    // Broadcast new user to all clients
                    clients.forEach(client => {
                        sendSSEMessage(client, {
                            type: 'new_user',
                            user: newUserDetails
                        });
                    });
                }
            });

            // Listener for user updates
            usersRef.on('child_changed', async (snapshot) => {
                const updatedUser = snapshot.val();
                const userId = snapshot.key;

                // Similar processing as new user, but with 'user_processed' type
                const userGamesRef = dbRef.ref(`/Users/${userId}/game1`);
                const gamesSnapshot = await userGamesRef.once('value');
                const gamesData = gamesSnapshot.val();

                if (gamesData) {
                    const userSubcollections = {};
                    const subcollections = ['games', 'userIds'];

                    for (const subcollection of subcollections) {
                        const subcollectionRef = dbRef.ref(`/Users/${userId}/${subcollection}`);
                        const subcollectionSnapshot = await subcollectionRef.once('value');
                        userSubcollections[subcollection] = subcollectionSnapshot.val();
                    }

                    const updatedUserDetails = {
                        userId: userId,
                        mainDetails: updatedUser,
                        ...userSubcollections
                    };

                    // Broadcast updated user to all clients
                    clients.forEach(client => {
                        sendSSEMessage(client, {
                            type: 'user_processed',
                            user: updatedUserDetails
                        });
                    });
                }
            });
        };

        // Helper function to send SSE messages
        const sendSSEMessage = (client, data) => {
            client.write(`data: ${JSON.stringify(data)}\n\n`);
        };

        // Initial load and setup real-time listeners
        await processAndSendUsers();
        setupRealTimeListeners();

        // Keep connection open
        req.on('close', () => {
            clients.delete(res);
            // Optional: Remove listeners if no clients are connected
            if (clients.size === 0) {
                usersRef.off();
            }
        });

    } catch (error) {
        console.error('SSE Setup Error:', error);
        res.status(500).end();
    }
});


//Api for show result to user and admin
app.get('/fetch-results', async (req, res) => {
    try {
        // Set headers for Server-Sent Events
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.setHeader('Access-Control-Allow-Origin', '*');

        const { date } = req.query;
        const now = moment().tz('Asia/Kolkata');
        const today = date || (now.hour() < 10 ? now.subtract(1, 'day').format('YYYY-MM-DD') : now.format('YYYY-MM-DD'));

        // Limit for previous results (31 days)
        const PREVIOUS_RESULTS_LIMIT = 31;

        // Firebase database reference
        const dbRef = firebaseAdmin.database();
        const resultsRef = dbRef.ref('/Results');

        // Function to fetch results
        const fetchResults = async () => {
            const snapshot = await resultsRef.once('value');
            const allResults = snapshot.val() || {};

            // Fetch today's results
            const todayResults = {
                session1: allResults[today]?.session1 || null,
                session2: allResults[today]?.session2 || null,
            };

            // Fetch previous results (up to 31 days)
            const previousResults = Object.keys(allResults)
                .filter(dateKey =>
                    moment(dateKey).isBefore(today) && // Ensure it's a previous date
                    allResults[dateKey]?.session1 && // Ensure session1 exists
                    allResults[dateKey]?.session2 // Ensure session2 exists
                )
                .sort((a, b) => moment(b).diff(moment(a))) // Sort in descending order
                .slice(0, PREVIOUS_RESULTS_LIMIT) // Limit to the most recent 31 results
                .map(dateKey => ({
                    date: dateKey,
                    session1: allResults[dateKey].session1 || null,
                    session2: allResults[dateKey].session2 || null,
                }));

            return {
                date: today,
                todayResults,
                previousResults,
            };
        };

        // Function to send updates
        const sendUpdate = async () => {
            try {
                const results = await fetchResults();
                res.write(`data: ${JSON.stringify({
                    success: true,
                    message: 'Results fetched successfully',
                    results,
                })}\n\n`);
            } catch (err) {
                console.error('Error fetching results:', err);
                res.write(`data: ${JSON.stringify({
                    success: false,
                    message: 'Error fetching results',
                    error: err.message,
                })}\n\n`);
            }
        };

        // Send the initial update
        await sendUpdate();

        // Send periodic updates every 5 seconds
        const intervalId = setInterval(sendUpdate, 5000);

        // Handle client disconnection
        req.on('close', () => {
            clearInterval(intervalId);
            console.log('Client disconnected');
        });
    } catch (error) {
        console.error('Error in results API:', error);
        res.write(`data: ${JSON.stringify({
            success: false,
            message: 'Error fetching results',
            error: error.message,
        })}\n\n`);
        res.end();
    }
});





//Winners section
// API to match results and create winners in Firebase Realtime Database
app.post('/match-results', async (req, res) => {
    try {
        const dbRef = firebaseAdmin.database();
        const resultsRef = dbRef.ref('/Results');
        const usersRef = dbRef.ref('/Users');
        const winnersRef = dbRef.ref('/Winners');
        const processedDatesRef = dbRef.ref('/ProcessedDates');

        // Get the current date based on server time
        const now = moment().tz('Asia/Kolkata');
        const today = now.format('YYYY-MM-DD');

        // 1️⃣ Check if today's results have already been processed
        const alreadyProcessedSnapshot = await processedDatesRef.child(today).once('value');
        if (alreadyProcessedSnapshot.exists()) {
            return res.status(400).json({
                success: false,
                message: `Results for ${today} have already been processed`,
            });
        }

        // 2️⃣ Fetch today's results
        const resultsSnapshot = await resultsRef.child(today).once('value');
        const todayResults = resultsSnapshot.val();

        if (!todayResults) {
            return res.status(404).json({
                success: false,
                message: 'No results found for today',
            });
        }

        // 3️⃣ Fetch all users
        const usersSnapshot = await usersRef.once('value');
        const usersData = usersSnapshot.val();

        if (!usersData) {
            return res.status(404).json({
                success: false,
                message: 'No users found',
            });
        }

        const allWinners = {};

        // 4️⃣ Process each session of today's results
        for (const [session, sessionResults] of Object.entries(todayResults)) {
            const sessionWinners = [];

            // 5️⃣ Process each user's game actions for today's session
            for (const [userId, userData] of Object.entries(usersData)) {
                const userGamesRef = usersRef.child(`${userId}/game1/game-actions`);
                const gamesSnapshot = await userGamesRef.once('value');
                const gamesData = gamesSnapshot.val();

                if (!gamesData) continue;

                // Check each game action for winning conditions
                for (const [gameId, gameData] of Object.entries(gamesData)) {
                    // Ensure the bet was placed today (server-generated timestamp)
                    const betTimestamp = gameData.timestamp
                        ? moment(gameData.timestamp).tz('Asia/Kolkata').format('YYYY-MM-DD')
                        : null;

                    if (betTimestamp !== today) {
                        // Skip bets that are not from today
                        continue;
                    }

                    // 6️⃣ Check for winning condition
                    const winnerEntry = checkWinCondition(
                        session,
                        sessionResults,
                        gameData,
                        userId,
                        userData,
                        gameId,
                        today
                    );

                    if (winnerEntry) {
                        // Save winner to the /Winners collection
                        const newWinnerRef = winnersRef.push();
                        await newWinnerRef.set(winnerEntry);

                        // Update user's tokens using an atomic transaction
                        const userTokensRef = usersRef.child(`${userId}/tokens`);
                        await userTokensRef.transaction((currentTokens) => {
                            return (currentTokens || 0) + winnerEntry.amountWon;
                        });

                        sessionWinners.push(winnerEntry);
                    }
                }
            }

            allWinners[session] = sessionWinners;
        }

        // 7️⃣ Mark today's date as processed to prevent duplicate processing
        await processedDatesRef.child(today).set(true);

        // 8️⃣ Return success response
        res.status(200).json({
            success: true,
            message: 'Results matched and winners calculated',
            winners: allWinners,
            totalWinnersCount: Object.values(allWinners).reduce(
                (sum, session) => sum + session.length,
                0
            ),
        });

    } catch (error) {
        console.error('Error in result matching:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to match results and calculate winners',
            error: error.message,
        });
    }
});

// Helper Function: Check Winning Conditions
function checkWinCondition(session, sessionResults, gameData, userId, userData, gameId, today) {
    const gameMode = gameData.gameMode; // open-number, close-number, open-pana, open-close, etc.
    const betAmount = gameData.betAmount;
    const selectedNumbers = gameData.selectedNumbers;

    let amountWon = 0;

    if (gameMode === "open-number" && session === "session1") {
        // Match open-number for session1
        if (selectedNumbers.includes(parseInt(sessionResults["open-number"]))) {
            amountWon = betAmount * 10; // Example multiplier
            return createWinnerEntry(userId, userData.phoneNo, gameId, betAmount, amountWon, "openNumber", today, session);
        }
    } else if (gameMode === "close-number" && session === "session2") {
        // Match close-number for session2
        if (selectedNumbers.includes(parseInt(sessionResults["close-number"]))) {
            amountWon = betAmount * 10; // Example multiplier
            return createWinnerEntry(userId, userData.phoneNo, gameId, betAmount, amountWon, "closeNumber", today, session);
        }
    } else if (gameMode === "open-pana" && session === "session1") {
        // Match open-pana for session1
        if (selectedNumbers.join("") === sessionResults["open-pana"]) {
            amountWon = betAmount * 100; // Example multiplier
            return createWinnerEntry(userId, userData.phoneNo, gameId, betAmount, amountWon, "openPana", today, session);
        }
    } else if (gameMode === "close-pana" && session === "session2") {
        // Match close-pana for session2
        if (selectedNumbers.join("") === sessionResults["close-pana"]) {
            amountWon = betAmount * 100; // Example multiplier
            return createWinnerEntry(userId, userData.phoneNo, gameId, betAmount, amountWon, "closePana", today, session);
        }
    } else if (gameMode === "open-close") {
        // Open-close match for the current session
        const openCloseResult = `${sessionResults["open-number"]}${sessionResults["close-number"]}`;
        const userSelection = selectedNumbers.join(""); // Concatenate selected numbers

        if (userSelection === openCloseResult) {
            amountWon = betAmount * 100; // Example multiplier
            return createWinnerEntry(userId, userData.phoneNo, gameId, betAmount, amountWon, "openClose", today, session);
        }
    }

    return null; // No match, no winner
}


// Helper Function: Create Winner Entry
function createWinnerEntry(userId, phoneNo, gameId, betAmount, amountWon, winType, date, session) {
    return {
        userId,
        phoneNo,
        gameId,
        betAmount,
        amountWon,
        winType,
        date,
        session,
    };
}



cron.schedule('55 23 * * *', async () => {
    try {
        const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3200';

        console.log('Starting the match-results API call at 11:55 PM');

        const response = await axios.post(`${API_BASE_URL}/match-results`);

        console.log('Match-results API called successfully:', response.data);
    } catch (error) {
        console.error(
            'Error calling the match-results API:',
            error.response ? error.response.data : error.message
        );
    }
}, {
    timezone: 'Asia/Kolkata'
});



// API to fetch winners
app.get('/fetch-winners', async (req, res) => {
    try {
        const dbRef = firebaseAdmin.database();
        const winnersRef = dbRef.ref('/Winners');

        // Fetch all winners data
        const winnersSnapshot = await winnersRef.once('value');
        const winnersData = winnersSnapshot.val() || {};

        // Convert winners to array
        const winnersList = Object.entries(winnersData).map(([key, winner]) => ({
            id: key,
            ...winner
        }));

        res.status(200).json({
            success: true,
            message: 'All winners fetched successfully',
            winners: winnersList,
            count: winnersList.length
        });
    } catch (error) {
        console.error('Error fetching winners:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch winners',
            error: error.message
        });
    }
});


//update game status
app.post('/update-game-status', async (req, res) => {
    try {
        const dbRef = firebaseAdmin.database();
        const usersRef = dbRef.ref('/Users');
        const winnersRef = dbRef.ref('/Winners');

        const now = moment().tz('Asia/Kolkata');
        const today = now.format('YYYY-MM-DD');

        // Fetch all winners for today
        const winnersSnapshot = await winnersRef.orderByChild('date').equalTo(today).once('value');
        const winnersData = winnersSnapshot.val();

        // Extract the winning game IDs
        const winningGameIds = winnersData ? Object.values(winnersData).map(winner => winner.gameId) : [];

        // Fetch all users
        const usersSnapshot = await usersRef.once('value');
        const usersData = usersSnapshot.val();

        if (!usersData) {
            return res.status(404).json({
                success: false,
                message: 'No users found',
            });
        }

        let totalUpdated = 0;

        // Iterate through all users
        for (const [userId, userData] of Object.entries(usersData)) {
            const userGamesRef = usersRef.child(`${userId}/game1/game-actions`);
            const gamesSnapshot = await userGamesRef.once('value');
            const gamesData = gamesSnapshot.val();

            if (!gamesData) continue;

            // Iterate through all the user's games
            for (const [gameId, gameData] of Object.entries(gamesData)) {
                // Only process games with status 'pending'
                if (gameData.status !== 'pending') continue;

                // Check if the current game ID is in the list of winning game IDs
                if (winningGameIds.includes(gameId)) {
                    // Update game status to "won"
                    await userGamesRef.child(gameId).update({ status: 'won' });

                    totalUpdated++;

                    // Optionally, you can also update the user's tokens here if needed
                    const betAmount = gameData.betAmount;
                    const userTokensRef = usersRef.child(`${userId}/tokens`);
                    await userTokensRef.transaction((currentTokens) => {
                        return (currentTokens || 0) + (betAmount * 10);  // Example multiplier, adjust based on game mode
                    });
                } else {
                    // Update game status to "lost"
                    await userGamesRef.child(gameId).update({ status: 'lost' });
                    totalUpdated++;
                }
            }
        }

        // Return a success response
        res.status(200).json({
            success: true,
            message: `${totalUpdated} games status updated successfully.`,
        });
    } catch (error) {
        console.error('Error in updating game status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update game statuses',
            error: error.message,
        });
    }
});

cron.schedule('57 23 * * *', async () => {
    try {
        const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3200';

        console.log('Running /update-game-status cron job at 11:57 PM');

        const response = await axios.post(`${API_BASE_URL}/update-game-status`);

        console.log('Game status update result:', response.data);
    } catch (error) {
        console.error(
            'Error running /update-game-status cron job:',
            error.response ? error.response.data : error.message
        );
    }
}, {
    timezone: 'Asia/Kolkata'
});
cron.schedule('57 23 * * *', async () => {
    try {
        const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3200';

        console.log('Running /update-game-status cron job at 11:57 PM');

        const response = await axios.post(`${API_BASE_URL}/update-game-status`);

        console.log('Game status update result:', response.data);
    } catch (error) {
        console.error(
            'Error running /update-game-status cron job:',
            error.response ? error.response.data : error.message
        );
    }
}, {
    timezone: 'Asia/Kolkata'
});




//add wins subcollection to user ds

app.post('/add-winner-to-wins', async (req, res) => {
    try {
        const dbRef = firebaseAdmin.database();
        const winnersRef = dbRef.ref('/Winners');

        // Fetch all winners
        const winnersSnapshot = await winnersRef.once('value');
        const winnersData = winnersSnapshot.val();

        if (!winnersData) {
            return res.status(404).json({
                success: false,
                message: 'No winners found'
            });
        }

        // Counter for processed winners
        let processedWinnersCount = 0;

        // Process each winner
        for (const [winnerId, winnerData] of Object.entries(winnersData)) {
            // Destructure winner data
            const {
                userId,
                gameId,
                session,
                winType,
                betAmount,
                amountWon,
                phoneNo,
                date
            } = winnerData;

            // Validate required fields
            if (!userId || !gameId) {
                console.warn(`Skipping winner ${winnerId} due to missing userId or gameId`);
                continue;
            }

            // Reference to the user's game wins
            const userGameWinsRef = dbRef.ref(`Users/${userId}/game1/wins`);

            // Create a new win entry
            const newWinRef = userGameWinsRef.push();

            // Prepare win data
            const winData = {
                winnerId,
                gameId,
                session,
                winType,
                betAmount,
                amountWon,
                phoneNo: phoneNo || null,
                date: date || moment().tz('Asia/Kolkata').format('YYYY-MM-DD'),
            };

            // Save the win entry
            await newWinRef.set(winData);

            processedWinnersCount++;
        }

        res.status(200).json({
            success: true,
            message: 'Winners added to wins subcollection',
            processedWinnersCount
        });

    } catch (error) {
        console.error('Error adding winners to wins subcollection:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add winners to wins subcollection',
            error: error.message
        });
    }
});


cron.schedule('57 23 * * *', async () => {
    try {
        const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3200';

        console.log('Running /add-winner-to-wins cron job at 11:57 PM');

        const response = await axios.post(`${API_BASE_URL}/add-winner-to-wins`);

        console.log('Winners to wins subcollection update result:', response.data);
    } catch (error) {
        console.error(
            'Error running /add-winner-to-wins cron job:',
            error.response ? error.response.data : error.message
        );
    }
}, {
    scheduled: true,
    timezone: "Asia/Kolkata"
});



//Open Close Game Admin Profit
app.get('/updateGameDetails', async (req, res) => {
    // Set headers for SSE
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    // Function to calculate and send game details
    const calculateAndSendGameDetails = async () => {
        try {
            let totalPlayerBetAmount = 0;
            let totalPlayerWinAmount = 0;

            // 1. Get the reference to the Firebase Realtime Database
            const db = firebaseAdmin.database();

            // 2. Fetch all users from 'Users' collection
            const usersSnapshot = await db.ref('Users').once('value');
            const usersData = usersSnapshot.val();

            if (!usersData) {
                res.write(`data: ${JSON.stringify({
                    success: false,
                    message: 'No users found in the Users collection'
                })}\n\n`);
                return;
            }

            // 3. Loop through each user
            Object.keys(usersData).forEach(userId => {
                const userData = usersData[userId];

                // Check if game1 and game-actions exist
                if (userData?.game1?.['game-actions']) {
                    // Calculate bet amounts
                    const gameActions = userData.game1['game-actions'];
                    Object.keys(gameActions).forEach(gameId => {
                        const betAmount = parseFloat(gameActions[gameId]?.betAmount) || 0;
                        totalPlayerBetAmount += betAmount;
                    });
                }

                // Check if game1 and wins exist
                if (userData?.game1?.wins) {
                    // Calculate win amounts
                    const wins = userData.game1.wins;
                    Object.keys(wins).forEach(winId => {
                        const amountWon = parseFloat(wins[winId]?.amountWon) || 0;
                        totalPlayerWinAmount += amountWon;
                    });
                }
            });

            // 4. Calculate totalNetProfit (profit or loss)
            const totalNetProfit = totalPlayerBetAmount - totalPlayerWinAmount;

            // 5. Update the 'OpenCloseGameDetails' node with calculated values
            const gameDetailsRef = db.ref('OpenCloseGameDetails');
            const today = new Date().toISOString().slice(0, 10); // Get today's date in YYYY-MM-DD format
            await gameDetailsRef.child('totalPlayerBetAmount').set(totalPlayerBetAmount);
            await gameDetailsRef.child('totalPlayerWinAmount').set(totalPlayerWinAmount);
            await gameDetailsRef.child('dailyProfitLoss').child(today).set(totalNetProfit);

            // 6. Send the calculated details via SSE
            res.write(`data: ${JSON.stringify({
                success: true,
                message: 'Game details updated successfully!',
                totalPlayerBetAmount,
                totalPlayerWinAmount,
                totalNetProfit
            })}\n\n`);
        } catch (error) {
            console.error('Error updating game details:', error);
            res.write(`data: ${JSON.stringify({
                success: false,
                message: 'Internal Server Error',
                error: error.message
            })}\n\n`);
        }
    };

    // Initial calculation
    await calculateAndSendGameDetails();

    // Set up real-time listener for Users collection
    const db = firebaseAdmin.database();
    const usersRef = db.ref('Users');

    // Listen for any changes in the Users collection
    const changeListener = usersRef.on('value', () => {
        calculateAndSendGameDetails();
    });

    // Handle client disconnection
    req.on('close', () => {
        console.log('Client disconnected from /updateGameDetails');
        // Remove the listener when client disconnects
        usersRef.off('value', changeListener);
    });
});


cron.schedule('58 23 * * *', async () => {
    try {
        const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3200';

        console.log('Running cron job to update game details at 11:58 PM');

        const response = await axios.get(`${API_BASE_URL}/updateGameDetails`);

        console.log('Game details updated successfully via cron job:', response.data);
    } catch (error) {
        console.error(
            'Error running the cron job:',
            error.response ? error.response.data : error.message
        );
    }
}, {
    timezone: 'Asia/Kolkata'
});




//for main component
app.get('/getOpenCloseProfitLoss', (req, res) => {
    // Set headers for SSE
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    // Function to send the initial value of OpenCloseGameDetails
    const sendInitialData = async () => {
        try {
            const db = firebaseAdmin.database();
            const gameDetailsRef = db.ref('OpenCloseGameDetails');
            const snapshot = await gameDetailsRef.once('value');
            const gameDetails = snapshot.val();

            if (!gameDetails) {
                res.write(`data: ${JSON.stringify({
                    success: false,
                    message: 'No data found in OpenCloseGameDetails'
                })}\n\n`);
                return;
            }

            // Send the initial game details to the client
            res.write(`data: ${JSON.stringify({
                success: true,
                message: 'Initial game details fetched successfully!',
                totalPlayerBetAmount: gameDetails.totalPlayerBetAmount,
                totalPlayerWinAmount: gameDetails.totalPlayerWinAmount
            })}\n\n`);
        } catch (error) {
            console.error('Error fetching game details:', error);
            res.write(`data: ${JSON.stringify({
                success: false,
                message: 'Internal Server Error',
                error: error.message
            })}\n\n`);
        }
    };

    // Send initial data once when client connects
    sendInitialData();

    // Set up real-time listener for changes in OpenCloseGameDetails
    const db = firebaseAdmin.database();
    const gameDetailsRef = db.ref('OpenCloseGameDetails');

    // Listen for any changes in OpenCloseGameDetails
    const changeListener = gameDetailsRef.on('value', (snapshot) => {
        const gameDetails = snapshot.val();

        if (!gameDetails) {
            res.write(`data: ${JSON.stringify({
                success: false,
                message: 'No data found in OpenCloseGameDetails'
            })}\n\n`);
            return;
        }

        // Send the updated game details to the client
        res.write(`data: ${JSON.stringify({
            success: true,
            message: 'Game details updated successfully!',
            totalPlayerBetAmount: gameDetails.totalPlayerBetAmount,
            totalPlayerWinAmount: gameDetails.totalPlayerWinAmount
        })}\n\n`);
    });

    // Handle client disconnection
    req.on('close', () => {
        console.log('Client disconnected from /getGameDetails');
        gameDetailsRef.off('value', changeListener); // Remove the real-time listener
    });
});


// for chart
app.get('/gameDetailsStream', (req, res) => {
    // Set headers for SSE
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-open');

    // Function to send game details
    const sendGameDetails = () => {
        try {
            const db = firebaseAdmin.database();

            // Create a listener for changes in OpenCloseGameDetails
            const gameDetailsRef = db.ref('OpenCloseGameDetails');

            gameDetailsRef.on('value', (snapshot) => {
                const gameDetails = snapshot.val();

                if (gameDetails) {
                    // Send the data as an SSE event
                    res.write(`data: ${JSON.stringify({
                        success: true,
                        message: 'Game details updated',
                        data: gameDetails
                    })}\n\n`);
                }
            }, (error) => {
                // Send error event if there's an issue
                res.write(`event: error\ndata: ${JSON.stringify({
                    success: false,
                    message: 'Error fetching game details',
                    error: error.message
                })}\n\n`);
            });

            // Handle client disconnect
            req.on('close', () => {
                gameDetailsRef.off('value');
            });
        } catch (error) {
            res.write(`event: error\ndata: ${JSON.stringify({
                success: false,
                message: 'Internal Server Error',
                error: error.message
            })}\n\n`);
        }
    };

    // Start sending game details
    sendGameDetails();
});


// send winner winner notification


app.get('/get-winners', async (req, res) => {
    try {
        const db = admin.database();
        const winnersRef = db.ref('Winners');

        const snapshot = await winnersRef.once('value');
        const winners = snapshot.val();

        // Convert to array and filter out already shown winners
        const winnersList = Object.keys(winners || {}).map(key => ({
            id: key,
            ...winners[key]
        }));

        res.json(winnersList);
    } catch (error) {
        console.error('Error fetching winners:', error);
        res.status(500).json({ error: true, message: 'Internal server error' });
    }
});

app.post('/mark-winner-claimed/:phoneNo', async (req, res) => {
    try {
        const { phoneNo } = req.params;
        const db = admin.database();
        const winnersRef = db.ref('Winners');

        // Find and update the specific winner
        const snapshot = await winnersRef.once('value');
        const winners = snapshot.val();

        let updateKey = null;
        for (let key in winners) {
            if (winners[key].phoneNo === phoneNo && !winners[key].popupShown) {
                updateKey = key;
                break;
            }
        }

        if (updateKey) {
            // Update the specific winner's popupShown flag
            await winnersRef.child(updateKey).update({
                popupShown: true
            });

            res.json({
                success: true,
                message: "Winner popup marked as shown"
            });
        } else {
            res.status(404).json({
                success: false,
                message: "No matching winner found"
            });
        }
    } catch (error) {
        console.error('Error marking winner as claimed:', error);
        res.status(500).json({
            error: true,
            message: 'Internal server error'
        });
    }
});

//Game 2 action demo
app.post('/store-game2-action', async (req, res) => {
    try {
        // Get the necessary data from the request body
        const { phoneNo, betAmount } = req.body;

        // Validate the input data
        if (!phoneNo || !betAmount) {
            return res.status(400).json({ success: false, message: 'Missing required game action details' });
        }

        // Get reference to Firebase Database
        const dbRef = firebaseAdmin.database();
        const usersRef = dbRef.ref('/Users');

        // Get the users data from Firebase
        const snapshot = await usersRef.once('value');
        const usersData = snapshot.val();

        if (!usersData) {
            return res.status(404).json({ success: false, message: 'No users found in database' });
        }

        // Find the user by phone number
        let userKey = null;
        Object.keys(usersData).forEach(key => {
            const currentUser = usersData[key];
            if (currentUser && currentUser.phoneNo === phoneNo) {
                userKey = key;
            }
        });

        if (!userKey) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Get current date
        const currentDate = new Date().toISOString().split('T')[0];

        // References for game2 subcollection
        const userGamesRef = dbRef.ref(`/Users/${userKey}/game2`);
        const dailyBetRef = userGamesRef.child('daily-bet-amount');

        // Get current daily bet snapshot
        const dailyBetSnapshot = await dailyBetRef.once('value');
        let dailyBetData = dailyBetSnapshot.val() || {};

        // Check if today's entry exists, if not create a new one
        if (!dailyBetData[currentDate]) {
            dailyBetData[currentDate] = {
                totalAmount: 0,
                betIds: [] // Array to store bet IDs for the day
            };
        }

        // Add bet amount to today's total
        dailyBetData[currentDate].totalAmount += parseFloat(betAmount);

        // Generate a unique ID for this bet
        const newBetRef = userGamesRef.child('bet-actions').push();
        dailyBetData[currentDate].betIds.push(newBetRef.key);

        // Clean up old entries (optional: remove entries older than 30 days)
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

        Object.keys(dailyBetData).forEach(date => {
            if (new Date(date) < thirtyDaysAgo) {
                delete dailyBetData[date];
            }
        });

        // Save daily bet data
        await dailyBetRef.set(dailyBetData);

        // Return success response
        return res.status(200).json({
            success: true,
            message: 'Game2 bet action stored successfully',
            betId: newBetRef.key,
            todayBetAmount: dailyBetData[currentDate].totalAmount,
            todayBetIds: dailyBetData[currentDate].betIds
        });

    } catch (error) {
        console.error('Error storing game2 action:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to store game2 bet action',
            error: error.message,
        });
    }
});


//Help Section
// Image compression function
async function compressImage(buffer, maxSizeBytes = 1024 * 1024) {
    let quality = 0.9;
    let compressedBuffer = buffer;
    let mimeType = 'image/jpeg';

    while (compressedBuffer.length > maxSizeBytes && quality > 0.1) {
        try {
            compressedBuffer = await sharp(buffer)
                .resize({
                    width: 1920, // Max width
                    withoutEnlargement: true
                })
                .jpeg({ quality: Math.round(quality * 100) })
                .toBuffer();

            quality -= 0.1;
        } catch (error) {
            console.error('Image compression error:', error);
            break;
        }
    }

    return {
        buffer: compressedBuffer,
        base64: compressedBuffer.toString('base64')
    };
}

// Help request route
app.post('/help-request',
    cors(),
    upload.single('photo'),
    async (req, res) => {
        try {
            const { name, number, userId, description } = req.body;

            // Prepare help request document
            const helpRequest = {
                name,
                number,
                description,
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
                status: 'pending',
            };

            // Add optional user ID if provided
            if (userId) {
                helpRequest.userId = userId;
            }

            // Compress and store image if uploaded
            if (req.file) {
                try {
                    // Compress image
                    const compressedImage = await compressImage(req.file.buffer);

                    // Store compressed base64 image
                    helpRequest.photo = compressedImage.base64;

                    // Optional: Log compression details
                    console.log('Original Size:', req.file.buffer.length, 'bytes');
                    console.log('Compressed Size:', compressedImage.buffer.length, 'bytes');
                } catch (compressionError) {
                    console.error('Image compression failed:', compressionError);
                    // Fallback to original image if compression fails
                    helpRequest.photo = req.file.buffer.toString('base64');
                }
            }

            // Save to Firestore
            const docRef = await firestore.collection('helpRequests').add(helpRequest);

            // Return success response
            res.status(201).json({
                success: true,
                message: 'Help request submitted successfully',
                requestId: docRef.id
            });

        } catch (error) {
            console.error('Error creating help request:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to submit help request',
                error: error.message
            });
        }
    }
);

app.get('/help-requests', async (req, res) => {
    try {
        const { status, sortBy, order, limit } = req.query;

        // Start with base query
        let query = firestore.collection('helpRequests');

        // Add status filter if provided
        if (status) {
            query = query.where('status', '==', status);
        }

        // Add sorting
        const sortField = sortBy || 'createdAt';
        const sortOrder = order || 'desc';
        query = query.orderBy(sortField, sortOrder);

        // Add limit if provided
        if (limit) {
            query = query.limit(parseInt(limit));
        }

        const snapshot = await query.get();

        if (snapshot.empty) {
            return res.status(200).json({
                success: true,
                message: 'No help requests found',
                data: []
            });
        }

        const helpRequests = [];

        snapshot.forEach(doc => {
            helpRequests.push({
                id: doc.id,
                ...doc.data(),
                createdAt: doc.data().createdAt ? doc.data().createdAt.toDate() : null
            });
        });

        res.status(200).json({
            success: true,
            message: 'Help requests retrieved successfully',
            count: helpRequests.length,
            data: helpRequests
        });

    } catch (error) {
        console.error('Error fetching help requests:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch help requests',
            error: error.message
        });
    }
});


app.patch('/help-requests/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;
  
      // Validate input
      if (!id) {
        return res.status(400).json({
          success: false,
          message: 'Help request ID is required'
        });
      }
  
      // Validate status
      const validStatuses = ['pending', 'resolved', 'rejected'];
      if (!status || !validStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid status. Must be one of: pending, resolved, rejected'
        });
      }
  
      // Reference to the specific help request document
      const helpRequestRef = firestore.collection('helpRequests').doc(id);
  
      // Check if the document exists
      const doc = await helpRequestRef.get();
      if (!doc.exists) {
        return res.status(404).json({
          success: false,
          message: 'Help request not found'
        });
      }
  
      // Update the status
      await helpRequestRef.update({
        status: status,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
  
      // Fetch the updated document to return to the client
      const updatedDoc = await helpRequestRef.get();
  
      res.status(200).json({
        success: true,
        message: `Help request status updated to ${status}`,
        data: {
          id: updatedDoc.id,
          ...updatedDoc.data()
        }
      });
  
    } catch (error) {
      console.error('Error updating help request status:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to update help request status',
        error: error.message
      });
    }
  });


//   Binary System Functionality and apis
/////////////////////////////////////////
// Binary System Registration API
app.post("/registerUser", async (req, res) => {
    try {
        const { userId, name, referralId, myrefrelid } = req.body;
        if (!userId || !name || !myrefrelid) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        const binaryUsersRef = db.ref("binaryUsers");
        const usersSnapshot = await binaryUsersRef.once("value");

        let updates = {};
        let referrerUserId = null;

        // Check if referralId exists in myrefrelid
        usersSnapshot.forEach((child) => {
            if (child.val().myrefrelid === referralId) {
                referrerUserId = child.key;
            }
        });

        if (!usersSnapshot.exists()) {
            // No users exist, create root user
            updates[`binaryUsers/${userId}`] = {
                name,
                referralId: null,
                leftChild: null,
                rightChild: null,
                myrefrelid, // Store myrefrelid
                playedAmounts: {},
                carryForward: {},
                bonusReceived: {}
            };
        } else {
            if (!referrerUserId) {
                return res.status(400).json({ error: "Invalid referral ID" });
            }

            const referrerRef = db.ref(`binaryUsers/${referrerUserId}`);
            const referrerSnapshot = await referrerRef.once("value");

            if (!referrerSnapshot.exists()) {
                return res.status(400).json({ error: "Invalid referral ID" });
            }

            let referrerData = referrerSnapshot.val();

            // Check left and right placement
            if (!referrerData.leftChild) {
                updates[`binaryUsers/${referrerUserId}/leftChild`] = userId;
            } else if (!referrerData.rightChild) {
                updates[`binaryUsers/${referrerUserId}/rightChild`] = userId;
            } else {
                return res.status(400).json({ error: "Both referral slots are occupied" });
            }

            // Create new user entry
            updates[`binaryUsers/${userId}`] = {
                name,
                referralId: referrerUserId, // Store userId of referrer
                leftChild: null,
                rightChild: null,
                myrefrelid, // Store myrefrelid
                playedAmounts: {},
                carryForward: {},
                bonusReceived: {}
            };
        }

        await db.ref().update(updates);
        return res.status(201).json({ message: "User registered successfully", userId, referralId: referrerUserId || null });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

//Binary refrelid exist check api (signup)
app.get("/checkReferralSlots/:referralId", async (req, res) => {
    try {
        const { referralId } = req.params;

        if (!referralId) {
            return res.status(400).json({
                error: "Referral ID is required"
            });
        }

        const binaryUsersRef = db.ref("binaryUsers");
        const usersSnapshot = await binaryUsersRef.once("value");

        // First check: Does the myrefrelid exist?
        let referrerData = null;
        let referrerUserId = null;

        usersSnapshot.forEach((child) => {
            if (child.val().myrefrelid === referralId) {
                referrerUserId = child.key;
                referrerData = child.val();
            }
        });

        if (!referrerData) {
            return res.status(404).json({
                success: false,
                error: "Referral ID not found",
                exists: false
            });
        }

        // Second check: Check slot availability
        const leftSlotAvailable = !referrerData.leftChild;
        const rightSlotAvailable = !referrerData.rightChild;

        // Prepare response
        const response = {
            success: true,
            exists: true,
            referrerUserId,
            referrerName: referrerData.name,
            slots: {
                left: {
                    available: leftSlotAvailable,
                    childId: referrerData.leftChild || null
                },
                right: {
                    available: rightSlotAvailable,
                    childId: referrerData.rightChild || null
                }
            },
            slotsAvailable: leftSlotAvailable || rightSlotAvailable
        };

        if (!leftSlotAvailable && !rightSlotAvailable) {
            response.message = "Both slots are occupied";
        } else if (leftSlotAvailable && rightSlotAvailable) {
            response.message = "Both slots are available";
        } else {
            response.message = `${leftSlotAvailable ? 'Left' : 'Right'} slot is available`;
        }

        return res.status(200).json(response);

    } catch (error) {
        console.error("Error checking referral slots:", error);
        return res.status(500).json({
            success: false,
            error: "Internal server error",
            message: error.message
        });
    }
});

// API to update daily played amount
app.post("/updatePlayedAmount", async (req, res) => {
    try {
        const { userId, amount } = req.body;
        if (!userId || !amount || amount <= 0) {
            return res.status(400).json({ error: "Invalid userId or amount" });
        }

        const today = new Date().toISOString().split("T")[0];
        const playedAmountRef = db.ref(`dailyCalculations/${today}/${userId}/totalPlayedAmount`);

        // Update the daily total (incremental updates)
        await playedAmountRef.transaction((currentAmount) => {
            return (currentAmount || 0) + amount;
        });

        return res.status(200).json({ message: "Played amount updated successfully" });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

// Scheduled function to finalize daily played amounts and update business at 11:55 PM
const finalizeDailyAmounts = async () => {
    try {
        const today = new Date().toISOString().split("T")[0];
        const calculationsRef = db.ref(`dailyCalculations/${today}`);
        const snapshot = await calculationsRef.once("value");

        if (!snapshot.exists()) return;

        const updates = {};
        snapshot.forEach((userSnapshot) => {
            const userId = userSnapshot.key;
            const userData = userSnapshot.val();

            // Store finalized total played amount
            updates[`binaryUsers/${userId}/playedAmounts/${today}`] = userData.totalPlayedAmount || 0;
        });

        await db.ref().update(updates);
        console.log("Daily played amounts finalized and stored.");
    } catch (error) {
        console.error("Error finalizing daily played amounts:", error);
    }
};

schedule.scheduleJob("43 12 * * *", finalizeDailyAmounts); //11:55


// Function to calculate total business for a user left and right update daily
///////////////////////////////////
const calculateTotalBusiness = async (userId, date) => {
    const userRef = db.ref(`binaryUsers/${userId}`);
    const userSnapshot = await userRef.once("value");
    if (!userSnapshot.exists()) return { leftBusiness: 0, rightBusiness: 0, playedAmount: 0 };

    const userData = userSnapshot.val();
    const playedAmount = userData.playedAmounts?.[date] || 0;

    let leftBusiness = 0;
    let rightBusiness = 0;

    // Recursively calculate left and right business
    if (userData.leftChild) {
        const leftData = await calculateTotalBusiness(userData.leftChild, date);
        leftBusiness += leftData.leftBusiness + leftData.rightBusiness + leftData.playedAmount;
    }

    if (userData.rightChild) {
        const rightData = await calculateTotalBusiness(userData.rightChild, date);
        rightBusiness += rightData.leftBusiness + rightData.rightBusiness + rightData.playedAmount;
    }

    return { leftBusiness, rightBusiness, playedAmount };
};

const updateBusinessForAllUsers = async () => {
    try {
        const today = new Date().toISOString().split("T")[0];
        const usersSnapshot = await db.ref("binaryUsers").once("value");
        if (!usersSnapshot.exists()) return;

        let updates = {};

        for (const [userId, userData] of Object.entries(usersSnapshot.val())) {
            const { leftBusiness, rightBusiness, playedAmount } = await calculateTotalBusiness(userId, today);

            // Store left and right business in dailyCalculations
            updates[`dailyCalculations/${today}/${userId}/totalLeftBusiness`] = leftBusiness;
            updates[`dailyCalculations/${today}/${userId}/totalRightBusiness`] = rightBusiness;
            updates[`dailyCalculations/${today}/${userId}/totalPlayedAmount`] = playedAmount;
        }

        await db.ref().update(updates);
        console.log("Left and Right Business Updated for all users.");
    } catch (error) {
        console.error("Error updating left and right business:", error);
    }
};

// Schedule the update to run at 11:55 PM daily
schedule.scheduleJob("43 12 * * *", updateBusinessForAllUsers); //11:55

// Bonus Step Levels
const BONUS_STEPS = [1000, 2500, 5000, 10000, 25000, 50000, 100000, 250000, 500000, 1000000, 2500000, 5000000, 10000000];

// Function to calculate bonuses for all users
const calculateBonuses = async () => {
    try {
        const today = new Date().toISOString().split("T")[0];
        const usersSnapshot = await db.ref("dailyCalculations/" + today).once("value");
        const usersRef = await db.ref("Users").once("value");

        const binaryUsersSnapshot = await db.ref("binaryUsers").once("value");
        const binaryUsers = binaryUsersSnapshot.exists() ? binaryUsersSnapshot.val() : {};

        if (!usersSnapshot.exists() || !usersRef.exists()) return;

        let updates = {};
        let usersData = usersRef.val();

        console.log(`Processing bonus calculations for ${today}`);

        for (const [userId, userData] of Object.entries(usersSnapshot.val())) {
            const binaryUserData = binaryUsers[userId] || {};
            const existingDataSnapshot = await db.ref(`dailyCalculations/${today}/${userId}`).once("value");
            const existingData = existingDataSnapshot.val() || {};
            let leftBusiness = existingData.totalLeftBusiness || 0;
            let rightBusiness = existingData.totalRightBusiness || 0;
            let todayPlayedAmount = userData.totalPlayedAmount || 0;

            // ADD PREVIOUS DAY'S CARRY FORWARDS TO TODAY'S BUSINESS
            const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().split("T")[0];
            const yesterdayCarrySnapshot = await db.ref(`binaryUsers/${userId}/carryForward/${yesterday}`).once("value");
            const yesterdayCarry = yesterdayCarrySnapshot.val() || {};
            const leftCarryForward = yesterdayCarry.left || 0;
            const rightCarryForward = yesterdayCarry.right || 0;

            // Add carry forwards to today's business
            leftBusiness += leftCarryForward;
            rightBusiness += rightCarryForward;

            // Get current eligible step (highest step ever achieved)
            let currentEligibleStep = binaryUserData.eligibleStep || 0;

            // Get yesterday's eligible amount to add with today's played amount
            const yesterdayDataSnapshot = await db.ref(`dailyCalculations/${yesterday}/${userId}`).once("value");
            const yesterdayData = yesterdayDataSnapshot.val() || {};
            
            // Use the correct field name from your data structure
            const yesterdayEligibleAmount = yesterdayData.eligibleAmount || yesterdayData.totalEligibleAmount || 0;

            // Calculate total eligible amount: yesterday's eligible + today's played
            let totalEligibleAmount = yesterdayEligibleAmount + todayPlayedAmount;

            // Find the highest step they're eligible for based on total eligible amount
            let newEligibleStep = currentEligibleStep; // Start with current step (never goes down)
            for (let step of BONUS_STEPS) {
                if (totalEligibleAmount >= step && step > currentEligibleStep) {
                    newEligibleStep = step;
                }
            }

            // Update eligible step ONLY if they achieved a higher one (never decrease)
            if (newEligibleStep > currentEligibleStep) {
                updates[`binaryUsers/${userId}/eligibleStep`] = newEligibleStep;
                currentEligibleStep = newEligibleStep;
            }
            
            // If no previous eligible step exists, set it based on total eligible amount
            if (currentEligibleStep === 0) {
                for (let step of BONUS_STEPS) {
                    if (totalEligibleAmount >= step) {
                        currentEligibleStep = step;
                    }
                }
                if (currentEligibleStep > 0) {
                    updates[`binaryUsers/${userId}/eligibleStep`] = currentEligibleStep;
                }
            }

            // BONUS CALCULATION START
            // Find the highest bonus step they can get based on:
            // 1. Their eligible step (highest step they've ever achieved)
            // 2. Their current left and right business (including carry forwards)
            let bonusStepMatched = 0;
            for (let step of BONUS_STEPS.slice().reverse()) {
                if (step <= currentEligibleStep) {
                    const leftValid = leftBusiness >= step;
                    const rightValid = rightBusiness >= step;
                    if (leftValid && rightValid) {
                        bonusStepMatched = step;
                        break;
                    }
                }
            }

            let bonusReceived = 0;
            let usedBusiness = 0;
            if (bonusStepMatched > 0) {
                bonusReceived = bonusStepMatched * 0.30;
                usedBusiness = bonusStepMatched;
            }

            // Deduct tax
            let gstDeducted = (bonusReceived * 18) / 100;
            let tdsDeducted = (bonusReceived * 5) / 100;
            let bonusAfterTax = bonusReceived - gstDeducted - tdsDeducted;

            // New carry forwards for business (after using for bonus)
            let newLeftCarry = leftBusiness - usedBusiness;
            let newRightCarry = rightBusiness - usedBusiness;

            // Ensure carry forwards don't go negative
            if (newLeftCarry < 0) newLeftCarry = 0;
            if (newRightCarry < 0) newRightCarry = 0;

            // Get previous total bonus to calculate cumulative total
            const previousTotalBonus = yesterdayData.totalBonusReceivedTillDate || 0;
            const newTotalBonusReceivedTillDate = previousTotalBonus + bonusAfterTax;

            // Update fields - now includes carry forward info
            updates[`dailyCalculations/${today}/${userId}`] = {
                date: today,
                totalLeftBusiness: existingData.totalLeftBusiness || 0, // Original business without carry forward
                totalRightBusiness: existingData.totalRightBusiness || 0, // Original business without carry forward
                leftCarryForward: leftCarryForward,
                rightCarryForward: rightCarryForward,
                finalLeftBusiness: leftBusiness, // Business after adding carry forward
                finalRightBusiness: rightBusiness, // Business after adding carry forward
                totalPlayedAmount: todayPlayedAmount,
                yesterdayEligibleAmount: yesterdayEligibleAmount,
                totalEligibleAmount: totalEligibleAmount,
                eligibleStep: currentEligibleStep,
                bonusStepMatched: bonusStepMatched,
                bonusReceived,
                gstDeducted,
                tdsDeducted,
                bonusAfterTax,
                totalBonusReceivedTillDate: newTotalBonusReceivedTillDate
            };

            // Store carry forwards for next day
            updates[`binaryUsers/${userId}/carryForward/${today}`] = {
                left: newLeftCarry,
                right: newRightCarry
            };

            // Find matching user in Users collection and add bonus to tokens
            let matchingUserId = null;
            Object.keys(usersData).forEach(userKey => {
                if (usersData[userKey]?.userIds?.myuserid === userId) {
                    matchingUserId = userKey;
                }
            });

            if (matchingUserId && bonusAfterTax > 0) {
                updates[`Users/${matchingUserId}/tokens`] = admin.database.ServerValue.increment(bonusAfterTax);
            }
        }

        await db.ref().update(updates);
        console.log("Bonuses calculated, taxes deducted, eligibility steps tracked, and carry forwards updated.");
    } catch (error) {
        console.error("Error calculating bonuses:", error);
    }
};

// Schedule the bonus calculation to run at 23:56 daily
schedule.scheduleJob("44 12 * * *", calculateBonuses);



//API to get total business and eligible remaining business(For User)
app.get("/user-business", async (req, res) => {
    try {
        const { userId } = req.query;
        if (!userId) {
            return res.status(400).json({ error: "User ID is required" });
        }

        const businessRef = db.ref(`dailyCalculations`);
        const snapshot = await businessRef.once("value");
        
        if (!snapshot.exists()) {
            return res.status(404).json({ error: "No business data found" });
        }

        let totalLeftBusiness = 0;
        let totalRightBusiness = 0;
        let eligibleLeftBusiness = 0;
        let eligibleRightBusiness = 0;
        
        snapshot.forEach((dateSnapshot) => {
            const userBusiness = dateSnapshot.child(userId).val();
            if (userBusiness) {
                totalLeftBusiness += userBusiness.totalLeftBusiness || 0;
                totalRightBusiness += userBusiness.totalRightBusiness || 0;
                eligibleLeftBusiness = userBusiness.carryForward?.left || eligibleLeftBusiness;
                eligibleRightBusiness = userBusiness.carryForward?.right || eligibleRightBusiness;
            }
        });
        
        return res.status(200).json({
            totalLeftBusiness,
            totalRightBusiness,
            eligibleLeftBusiness,
            eligibleRightBusiness
        });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

// Function to fetch full binary tree structure(For Admin)
const getBinaryTree = async () => {
    const usersSnapshot = await db.ref("binaryUsers").once("value");
    if (!usersSnapshot.exists()) return {};
    
    let users = usersSnapshot.val();
    let tree = {};
    
    for (let userId in users) {
        let user = users[userId];
        tree[userId] = {
            name: user.name || "Unknown",
            referralId: user.referralId || null,
            leftChild: user.leftChild || null,
            rightChild: user.rightChild || null,
            totalPlayed: 0,
            playedToday: 0,
            totalLeftBusiness: 0,
            totalRightBusiness: 0,
            todayLeftBusiness: 0,
            todayRightBusiness: 0,
            totalBonusReceived: 0,
            eligibleLeftBusiness: 0,
            eligibleRightBusiness: 0,
            // New fields from getUserDownline
            lastDayCarryForward: 0,
            totalForToday: 0,
            eligibleAmount: 0,
            bonusReceived: 0,
            gstDeducted: 0,
            tdsDeducted: 0,
            bonusAfterTax: 0,
            carryForwardForNextDay: 0,
            totalBonusReceivedTillDate: 0,
            totalBonusReceivedAfterTax: 0,
        };
    }
    
    return tree;
};

// Function to fetch business details with additional fields
const getBusinessDetails = async (tree) => {
    const dailySnapshot = await db.ref("dailyCalculations").once("value");
    if (!dailySnapshot.exists()) return;
    
    // Get today's and yesterday’s date
    const today = new Date().toISOString().split("T")[0];
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayDate = yesterday.toISOString().split("T")[0];
    
    dailySnapshot.forEach((dateSnapshot) => {
        const date = dateSnapshot.key;
        const isToday = date === today;
        const isYesterday = date === yesterdayDate;

        dateSnapshot.forEach((userSnapshot) => {
            const userId = userSnapshot.key;
            const userData = userSnapshot.val();
            
            if (tree[userId]) {
                // Update cumulative data
                tree[userId].totalPlayed += userData.totalPlayedAmount || 0;
                tree[userId].totalLeftBusiness += userData.totalLeftBusiness || 0;
                tree[userId].totalRightBusiness += userData.totalRightBusiness || 0;
                tree[userId].totalBonusReceived += userData.bonusGiven || 0;

                // Today's data
                if (isToday) {
                    tree[userId].playedToday = userData.totalPlayedAmount || 0;
                    tree[userId].todayLeftBusiness = userData.totalLeftBusiness || 0;
                    tree[userId].todayRightBusiness = userData.totalRightBusiness || 0;
                    
                    tree[userId].lastDayCarryForward = userData.lastDayCarryForward || 0;
                    tree[userId].totalForToday = userData.totalForToday || 0;
                    tree[userId].eligibleAmount = userData.eligibleAmount || 0;
                    tree[userId].bonusReceived = userData.bonusReceived || 0;
                    tree[userId].gstDeducted = userData.gstDeducted || 0;
                    tree[userId].tdsDeducted = userData.tdsDeducted || 0;
                    tree[userId].bonusAfterTax = userData.bonusAfterTax || 0;
                    tree[userId].carryForwardForNextDay = userData.carryForwardForNextDay || 0;
                    tree[userId].totalBonusReceivedTillDate = userData.totalBonusReceivedTillDate || 0;
                    tree[userId].totalBonusReceivedAfterTax = userData.totalBonusReceivedAfterTax || 0;
                }

                // Yesterday's data (Separate field for admin)
                if (isYesterday) {
                    tree[userId].playedYesterday = userData.totalPlayedAmount || 0;
                    tree[userId].yesterdayLeftBusiness = userData.totalLeftBusiness || 0;
                    tree[userId].yesterdayRightBusiness = userData.totalRightBusiness || 0;
                    
                    tree[userId].yesterdayBonusReceived = userData.bonusReceived || 0;
                    tree[userId].yesterdayGstDeducted = userData.gstDeducted || 0;
                    tree[userId].yesterdayTdsDeducted = userData.tdsDeducted || 0;
                    tree[userId].yesterdayBonusAfterTax = userData.bonusAfterTax || 0;
                    tree[userId].yesterdayCarryForward = userData.carryForwardForNextDay || 0;
                }

                tree[userId].eligibleLeftBusiness = userData.carryForward?.left || 0;
                tree[userId].eligibleRightBusiness = userData.carryForward?.right || 0;
            }
        });
    });
};


// Optional: Recursive function to build a hierarchical tree structure
const buildHierarchicalTree = (flatTree, rootId) => {
    const buildSubtree = (userId) => {
        if (!userId || !flatTree[userId]) return null;
        
        const user = flatTree[userId];
        const node = {
            userId,
            ...user,
            children: []
        };
        
        if (user.leftChild) {
            const leftSubtree = buildSubtree(user.leftChild);
            if (leftSubtree) node.children.push(leftSubtree);
        }
        
        if (user.rightChild) {
            const rightSubtree = buildSubtree(user.rightChild);
            if (rightSubtree) node.children.push(rightSubtree);
        }
        
        return node;
    };
    
    return buildSubtree(rootId);
};

// Admin API to fetch full binary tree with business details
app.get("/admin-binary-tree", async (req, res) => {
    try {
        const flatTree = await getBinaryTree();
        await getBusinessDetails(flatTree);
        
        const { hierarchical, rootId } = req.query;
        
        if (hierarchical === 'true' && rootId) {
            const hierarchicalTree = buildHierarchicalTree(flatTree, rootId);
            return res.status(200).json(hierarchicalTree || {});
        }
        
        return res.status(200).json(flatTree);
    } catch (error) {
        console.error("Error fetching binary tree:", error);
        return res.status(500).json({ error: error.message });
    }
});




//Binary strcture for user
// Recursive function to fetch full downline
const getUserDownline = async (userId) => {
    try {
        // Step 1: Check if user exists in binaryUsers
        const userRef = db.ref(`binaryUsers/${userId}`);
        const userSnapshot = await userRef.once("value");
        if (!userSnapshot.exists()) {
            console.log(`User ${userId} not found in binaryUsers`);
            return null;
        }

        const userData = userSnapshot.val();
        console.log(`Found user data for ${userId}:`, userData);

        // Step 2: Get all available dates from dailyCalculations
        const dailyCalcRef = db.ref("dailyCalculations");
        const dailyCalcSnapshot = await dailyCalcRef.once("value");
        
        if (!dailyCalcSnapshot.exists()) {
            console.log("No dailyCalculations data found");
            return null;
        }

        const dailyCalcData = dailyCalcSnapshot.val();
        const availableDates = Object.keys(dailyCalcData).sort(); // Sort dates in ascending order
        console.log("Available dates:", availableDates);

        // Step 3: Find the latest date (including today if available)
        const today = new Date().toISOString().split("T")[0];
        console.log("Today's date:", today);
        
        // First try to get today's data, then yesterday's
        let latestDate = null;
        
        // Check if today's data exists
        if (availableDates.includes(today)) {
            latestDate = today;
        } else {
            // Get the most recent date before today
            latestDate = availableDates
                .filter(date => date < today)
                .sort()
                .pop(); // Get the last (latest) date
        }

        console.log("Selected date for calculations:", latestDate);

        if (!latestDate) {
            console.log("No calculation data found for any date");
            // Return user data with zero earnings if no calculation data exists
            return {
                userId: userId,
                name: userData.name || "Unknown",
                totalPlayedAmount: 0,
                lastDayCarryForward: 0,
                totalForToday: 0,
                eligibleAmount: 0,
                bonusReceived: 0,
                gstDeducted: 0,
                tdsDeducted: 0,
                bonusAfterTax: 0,
                carryForwardForNextDay: 0,
                totalBonusReceivedTillDate: 0,
                totalBonusReceivedAfterTax: 0,
                children: []
            };
        }

        // Step 4: Fetch earnings for the selected date
        const earningsRef = db.ref(`dailyCalculations/${latestDate}/${userId}`);
        const earningsSnapshot = await earningsRef.once("value");
        const earningsData = earningsSnapshot.val() || {};
        
        console.log(`Earnings data for ${userId} on ${latestDate}:`, earningsData);

        // Step 5: Build user tree object
        let userTree = {
            userId: userId,
            name: userData.name || "Unknown",
            totalPlayedAmount: earningsData.totalPlayedAmount || 0,
            lastDayCarryForward: earningsData.lastDayCarryForward || 0,
            totalForToday: earningsData.totalForToday || 0,
            eligibleAmount: earningsData.eligibleAmount || 0,
            bonusReceived: earningsData.bonusReceived || 0,
            gstDeducted: earningsData.gstDeducted || 0,
            tdsDeducted: earningsData.tdsDeducted || 0,
            bonusAfterTax: earningsData.bonusAfterTax || 0,
            carryForwardForNextDay: earningsData.carryForwardForNextDay || 0,
            totalBonusReceivedTillDate: earningsData.totalBonusReceivedTillDate || 0,
            totalBonusReceivedAfterTax: earningsData.totalBonusReceivedAfterTax || 0,
            children: []
        };

        // Step 6: Recursively get children
        if (userData.leftChild) {
            console.log(`Fetching left child: ${userData.leftChild}`);
            const leftSubtree = await getUserDownline(userData.leftChild);
            if (leftSubtree) {
                leftSubtree.position = "left"; // Add position info
                userTree.children.push(leftSubtree);
            }
        }
        
        if (userData.rightChild) {
            console.log(`Fetching right child: ${userData.rightChild}`);
            const rightSubtree = await getUserDownline(userData.rightChild);
            if (rightSubtree) {
                rightSubtree.position = "right"; // Add position info
                userTree.children.push(rightSubtree);
            }
        }

        return userTree;
        
    } catch (error) {
        console.error(`Error in getUserDownline for ${userId}:`, error);
        return null;
    }
};

// API to fetch user's binary tree with latest available data
app.get("/user-downline", async (req, res) => {
    try {
        const { userId } = req.query;
        
        if (!userId) {
            return res.status(400).json({ 
                error: "User ID is required",
                message: "Please provide a userId parameter"
            });
        }

        console.log(`API Request: Fetching downline for user ${userId}`);
        
        const userTree = await getUserDownline(userId);
        
        if (!userTree) {
            return res.status(404).json({ 
                error: "User not found or no data available",
                message: `No data found for user ID: ${userId}`
            });
        }

        console.log(`API Response: Successfully fetched data for ${userId}`);
        return res.status(200).json(userTree);
        
    } catch (error) {
        console.error("API Error:", error);
        return res.status(500).json({ 
            error: "Internal server error",
            message: error.message 
        });
    }
});



//Frinds earning api
app.get('/latest', async (req, res) => {
    try {
      const { userId } = req.query;
      
      if (!userId) {
        return res.status(400).json({ success: false, message: 'User ID is required' });
      }
      
      // Reference to dailyCalculations
      const dailyCalculationsRef = db.ref('dailyCalculations');
      
      // Get all calculations for this user
      const userCalculationsSnapshot = await dailyCalculationsRef.orderByChild(`${userId}/date`).once('value');
      const userCalculations = userCalculationsSnapshot.val();
      
      if (!userCalculations) {
        return res.status(200).json({
          success: true,
          data: {
            bonusAfterTax: "N/A",
            bonusReceived: "N/A",
            carryForwardForNextDay: "N/A",
            date: "N/A",
            eligibleAmount: "N/A",
            gstDeducted: "N/A",
            lastDayCarryForward: "N/A",
            tdsDeducted: "N/A",
            totalBonusReceivedAfterTax: "N/A",
            totalBonusReceivedTillDate: "N/A",
            totalForToday: "N/A",
            totalPlayedAmount: "N/A"
          }
        });
      }
      
      // Find the most recent date
      let mostRecentDate = null;
      let mostRecentData = null;
      
      Object.keys(userCalculations).forEach(dateKey => {
        if (userCalculations[dateKey][userId]) {
          if (!mostRecentDate || dateKey > mostRecentDate) {
            mostRecentDate = dateKey;
            mostRecentData = userCalculations[dateKey][userId];
          }
        }
      });
      
      if (!mostRecentData) {
        return res.status(200).json({
          success: true,
          data: {
            bonusAfterTax: "N/A",
            bonusReceived: "N/A",
            carryForwardForNextDay: "N/A",
            date: "N/A",
            eligibleAmount: "N/A",
            gstDeducted: "N/A",
            lastDayCarryForward: "N/A",
            tdsDeducted: "N/A",
            totalBonusReceivedAfterTax: "N/A",
            totalBonusReceivedTillDate: "N/A",
            totalForToday: "N/A",
            totalPlayedAmount: "N/A"
          }
        });
      }
      
      // Make sure the date is included in the response
      if (!mostRecentData.date) {
        mostRecentData.date = mostRecentDate;
      }
      
      res.status(200).json({ success: true, data: mostRecentData });
      
    } catch (error) {
      console.error('Error fetching most recent daily calculation:', error);
      res.status(500).json({
        success: false,
        message: 'Server error',
        error: error.message
      });
    }
  });

  
//Api for user daily bonus show in frinds earning
app.get('/userDailyEarnings', async (req, res) => {
    try {
      const { userId } = req.query;
      
      if (!userId) {
        return res.status(400).json({ success: false, message: 'User ID is required' });
      }
      
      const dailyCalculationsRef = db.ref('dailyCalculations');
      const snapshot = await dailyCalculationsRef.once('value');
      const data = snapshot.val();
      
      if (!data) {
        return res.status(404).json({ success: false, message: 'No bonus history found' });
      }
      
      let userEarnings = [];
      let mostRecentDate = null;
      
      // First find the most recent date with data for this user
      Object.keys(data).forEach(date => {
        if (data[date][userId]) {
          if (!mostRecentDate || date > mostRecentDate) {
            mostRecentDate = date;
          }
        }
      });
      
      if (!mostRecentDate) {
        return res.status(404).json({ success: false, message: 'No earnings found for this user' });
      }
      
      // Then collect all entries up to and including the most recent date
      Object.keys(data).forEach(date => {
        if (date <= mostRecentDate && data[date][userId]) {
          const userData = data[date][userId];
          userEarnings.push({
            date,
            taxDeducted: (userData.tdsDeducted || 0) + (userData.gstDeducted || 0),
            bonusAfterTax: userData.bonusAfterTax || 0
          });
        }
      });
      
      // Sort by date to ensure chronological order
      userEarnings.sort((a, b) => new Date(a.date) - new Date(b.date));
      
      res.status(200).json({ success: true, data: userEarnings });
      
    } catch (error) {
      console.error('Error fetching user daily earnings:', error);
      res.status(500).json({ success: false, message: 'Server error', error: error.message });
    }
  });


app.get("/admin-binary-tree-by-date-range", async (req, res) => {
    try {
        // Get the base tree structure
        const flatTree = await getBinaryTree();
        
        // Get date range from query parameters with defaults
        const { startDate, endDate, hierarchical, rootId } = req.query;
        
        // Default to all dates if not specified
        const dailySnapshot = await db.ref("dailyCalculations").once("value");
        if (!dailySnapshot.exists()) {
            return res.status(200).json(flatTree);
        }
        
        // Get all available dates
        const availableDates = Object.keys(dailySnapshot.val());
        
        // Filter dates based on provided range
        let datesToProcess = availableDates;
        if (startDate && endDate) {
            datesToProcess = availableDates.filter(date => 
                date >= startDate && date <= endDate
            );
        } else if (startDate) {
            datesToProcess = availableDates.filter(date => date >= startDate);
        } else if (endDate) {
            datesToProcess = availableDates.filter(date => date <= endDate);
        }
        
        // Create a date-indexed result object
        const dateIndexedResults = {};
        
        // Process each date
        for (const date of datesToProcess) {
            // Create a copy of the flat tree for this date
            const dateTree = JSON.parse(JSON.stringify(flatTree));
            
            // Get snapshot for this specific date
            const dateSnapshot = dailySnapshot.child(date);
            
            // Process each user for this date
            dateSnapshot.forEach((userSnapshot) => {
                const userId = userSnapshot.key;
                const userData = userSnapshot.val();
                
                if (dateTree[userId]) {
                    // Update user data for this specific date
                    dateTree[userId].totalPlayed = userData.totalPlayedAmount || 0;
                    dateTree[userId].totalLeftBusiness = userData.totalLeftBusiness || 0;
                    dateTree[userId].totalRightBusiness = userData.totalRightBusiness || 0;
                    dateTree[userId].totalBonusReceived = userData.bonusGiven || 0;
                    
                    // Daily specific fields
                    dateTree[userId].lastDayCarryForward = userData.lastDayCarryForward || 0;
                    dateTree[userId].totalForToday = userData.totalForToday || 0;
                    dateTree[userId].eligibleAmount = userData.eligibleAmount || 0;
                    dateTree[userId].bonusReceived = userData.bonusReceived || 0;
                    dateTree[userId].gstDeducted = userData.gstDeducted || 0;
                    dateTree[userId].tdsDeducted = userData.tdsDeducted || 0;
                    dateTree[userId].bonusAfterTax = userData.bonusAfterTax || 0;
                    dateTree[userId].carryForwardForNextDay = userData.carryForwardForNextDay || 0;
                    dateTree[userId].totalBonusReceivedTillDate = userData.totalBonusReceivedTillDate || 0;
                    dateTree[userId].totalBonusReceivedAfterTax = userData.totalBonusReceivedAfterTax || 0;
                    
                    // Add carryforward data
                    dateTree[userId].eligibleLeftBusiness = userData.carryForward?.left || 0;
                    dateTree[userId].eligibleRightBusiness = userData.carryForward?.right || 0;
                }
            });
            
            // For hierarchical view
            if (hierarchical === 'true' && rootId) {
                dateIndexedResults[date] = buildHierarchicalTree(dateTree, rootId);
            } else {
                dateIndexedResults[date] = dateTree;
            }
        }
        
        return res.status(200).json(dateIndexedResults);
    } catch (error) {
        console.error("Error fetching binary tree by date range:", error);
        return res.status(500).json({ error: error.message });
    }
});





//Server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});