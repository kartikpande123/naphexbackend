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
const status = require("express-status-monitor");
const path = require("path")
const { v4: uuidv4 } = require('uuid');


const allowedOrigins = [
  'https://naphex.com',
  'https://www.naphex.com',
  'http://localhost:3000',
  'http://localhost:3200',
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true); // allow curl/postman
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
}));

app.options('*', cors()); // 👈 This must come after the above

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  next();
});


app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ limit: '20mb', extended: true }));
app.use(status())



// Multer for file uploads 
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 100 * 1024 * 1024 // 100MB file size limit
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
const bucket = admin.storage().bucket();


// Edumarc SMS API Configuration
const EDUMARC_API_URL = 'https://smsapi.edumarcsms.com/api/v1/sendsms';
const API_KEY = '0d9b7e18eb384af2975f47a75b62a433';
const SENDER_ID = 'NADENT';
const TEMPLATE_ID = '1707175077320499396';



app.get("/", (req,res)=>{
    res.send("Naphex Game Bakcend Is Running!")
})

//login api check kyc too
app.post('/api/login', async (req, res) => {
  const { phoneNo, password } = req.body;

  if (!phoneNo || !password) {
    return res.status(400).json({
      success: false,
      message: 'Phone number and password are required.'
    });
  }

  try {
    const formattedPhoneNo = phoneNo.startsWith('+91') ? phoneNo : `+91${phoneNo}`;
    const db = firebaseAdmin.database(); // ✅ using `db` variable as standard
    const usersRef = db.ref('/Users');

    const snapshot = await usersRef.once('value');
    const usersData = snapshot.val();

    if (!usersData) {
      return res.status(401).json({
        success: false,
        message: 'No users found in database.'
      });
    }

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

    // ✅ Check if user is blocked
    if (userData.status === 'blocked' || userData.blocked === true) {
      return res.status(403).json({
        success: false,
        message: 'Your account is blocked. Please contact support.'
      });
    }

    const isValidPassword = await bcrypt.compare(password, userData.password);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid password.'
      });
    }

    // --- ✅ KYC CHECK ---
    const isRootUser = userData.id === 'RootId';
    const kycStatus = userData?.kycStatus;

    if (!isRootUser) {
      if (!kycStatus) {
        return res.status(403).send('KYC status missing. Please complete your KYC to login.');
      }

      if (kycStatus === 'submitted') {
        return res.status(403).send('Your KYC verification is in process. Please wait or contact support.');
      }

      if (kycStatus !== 'accepted') {
        return res.status(403).send('KYC not accepted. Please contact support.');
      }
    }

    // ✅ Firebase Auth
    const userRecord = await firebaseAdmin.auth().getUserByPhoneNumber(formattedPhoneNo);
    const customToken = await firebaseAdmin.auth().createCustomToken(userRecord.uid);

    // ✅ Generate or reuse userIds
    const userids = {
      myuserid: userData.userIds?.myuserid || userData.userId || '',
      myrefrelid: userData.userIds?.myrefrelid || userData.referId || ''
    };

    if (!userids.myuserid || !userids.myrefrelid) {
      userids.myuserid = userids.myuserid || `USER${Math.random().toString(36).substr(2, 8).toUpperCase()}`;
      userids.myrefrelid = userids.myrefrelid || `REF${Math.random().toString(36).substr(2, 8).toUpperCase()}`;
      await usersRef.child(userKey).child('userIds').set(userids);
    }

    // ✅ Response
    const responseData = {
      success: true,
      message: 'Login successful',
      customToken,
      userData: {
        name: userData.name,
        phoneNo: userData.phoneNo,
        email: userData.email || '',
        tokens: userData.tokens,
        city: userData.city,
        state: userData.state,
        createdAt: userData.createdAt,
        loginTimestamp: new Date().toISOString(),
        userids: userids
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
app.post('/api/test-password', async (req, res) => {
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
app.post('/api/check-phone', async (req, res) => {
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
app.get('/api/user-profile/:phoneNo', (req, res) => {
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
app.post('/api/verify-otp', async (req, res) => {
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
app.post('/api/send-otp', async (req, res) => {
    const { phoneNo } = req.body;

    // ✅ Validate phone number
    if (!phoneNo || !/^\d{10}$/.test(phoneNo)) {
        return res.status(400).json({
            success: false,
            message: 'Valid 10-digit phone number is required.'
        });
    }

    try {
        // ✅ Generate 6-digit OTP
        const otp = crypto.randomInt(100000, 999999).toString();

        // ✅ Format message matching approved template
        const message = `Your OTP for login or password reset on https://www.naphex.com is: ${otp}. Do not share it with anyone. - NADENT`;

        const payload = {
            number: phoneNo, // ✅ send as string, not array
            message,
            senderId: SENDER_ID,
            templateId: TEMPLATE_ID
        };

        // ✅ Send SMS via Edumarc
        const response = await axios.post(EDUMARC_API_URL, payload, {
            headers: {
                'Content-Type': 'application/json',
                'apikey': API_KEY
            }
        });

        console.log('🟡 SMS API Full Response:', response.status, response.data);

        // ✅ Handle Edumarc response
        if (response.data && response.data.success === true) {
            return res.status(200).json({
                success: true,
                message: 'OTP sent successfully',
                transactionId: response.data.data.transactionId,
                debug: { otp } // ✅ Always return for testing
            });
        } else {
            throw new Error(response.data?.data?.msg || 'SMS API error');
        }

    } catch (error) {
        console.error('🔴 Error sending OTP:', error.response?.data || error.message);
        return res.status(500).json({
            success: false,
            message: 'Failed to send OTP. Try again later.',
            error: error.response?.data || error.message
        });
    }
});




/**
 * API to add user and their subcollection to Firebase.
 */

app.post('/api/add-user', async (req, res) => {
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
app.get('/api/health', (req, res) => {
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


app.post('/api/reset-password', async (req, res) => {
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
app.post("/api/deduct-tokens", async (req, res) => {
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
app.post('/api/store-game-action', async (req, res) => {
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
app.get('/api/api/users', (req, res) => {
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
cron.schedule('35 15 * * *', async () => {
    try {
        const bettedNumbersRef = admin.database().ref('/OpenCloseGameDetails/betted-numbers/session-1');
        await bettedNumbersRef.remove();
        console.log('Session 1 bets cleaned up at 5:30 PM');
    } catch (error) {
        console.error('Error cleaning session 1:', error);
    }
});

cron.schedule('58 23 * * *', async () => {
    try {
        const bettedNumbersRef = admin.database().ref('/OpenCloseGameDetails/betted-numbers/session-2');
        await bettedNumbersRef.remove();
        console.log('Session 2 bets cleaned up at 11:55 PM');
    } catch (error) {
        console.error('Error cleaning session 2:', error);
    }
});

app.post('/api/store-bet-numbers', async (req, res) => {
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
    return crypto.randomBytes(4).readUInt32BE(0);
  }

  // 🔹 UPDATED — replaced old names with your new Firebase keys
  _formatBetsData(firebaseBets) {
    return {
      openPanna: firebaseBets?.['3-fruits-start'] || {},
      closePanna: firebaseBets?.['3-fruits-end'] || {},
      openNumber: firebaseBets?.['1-fruits-start'] || {},
      closeNumber: firebaseBets?.['1-fruits-end'] || {},
      openClose: firebaseBets?.['2-fruits'] || {}
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
  const dbRef = admin.database();
  const betsRef = dbRef.ref(`/OpenCloseGameDetails/betted-numbers/${sessionNumber}`);
  const currentDate = new Date().toISOString().split("T")[0];
  const resultsRef = dbRef.ref(`/Results/${currentDate}`);

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

    let resultsToStore = { timestamp: new Date().toISOString() };

    if (type === "open") {
      const openResults = await generator.processOpenResults(firebaseBets, multipliers);
      resultsToStore[formattedSessionNumber] = {
        "open-number": String(openResults.openNumber),
        "open-pana": String(openResults.openPanna),
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
        "close-number": String(closeResults.closeNumber),
        "close-pana": String(closeResults.closePanna),
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
    console.log(`✅ Successfully stored ${type} results for ${sessionNumber}`);
  } catch (error) {
    console.error(`❌ Error generating ${type} results for ${sessionNumber}:`, error);
  }
}

// 🕒 Schedule Times
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
        .then(() => console.log(`🕒 Scheduled ${type} result done for ${session} at ${time}`))
        .catch(err => console.error(`Error in scheduled ${type} for ${session}:`, err));
    });

    console.log(`📅 Scheduled ${type} generation for ${session} at ${time} daily`);
  });
}

scheduleResultGeneration();


app.get('/api/users-with-openclose', async (req, res) => {
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
app.get('/api/fetch-results', async (req, res) => {
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


// MATCH RESULTS DEBUG API — session-aware, detailed logs
// MATCH RESULTS API — session-aware with winners collection
app.post('/api/match-results/new', async (req, res) => {
  try {
    const dbRef = firebaseAdmin.database();
    const resultsRef = dbRef.ref('/Results');
    const usersRef = dbRef.ref('/Users');
    const winnersRef = dbRef.ref('/Winners');

    const now = moment().tz('Asia/Kolkata');
    const today = now.format('YYYY-MM-DD');

    console.log(`🕒 Starting match-results API for date ${today}`);

    // Get today's results
    const resultsSnapshot = await resultsRef.child(today).once('value');
    const todayResults = resultsSnapshot.val();

    if (!todayResults) {
      console.log(`❌ No results found for today`);
      return res.status(404).json({ success: false, message: 'No results found for today' });
    }

    console.log("📊 Today's results:", JSON.stringify(todayResults, null, 2));

    // Get all users
    const usersSnapshot = await usersRef.once('value');
    const usersData = usersSnapshot.val();

    if (!usersData) {
      console.log(`❌ No users found`);
      return res.status(404).json({ success: false, message: 'No users found' });
    }

    // Map gameMode to result key
    const gameModeToResultKey = {
      "1-fruits-start": "open-number",
      "1-fruits-end": "close-number",
      "2-fruits": "open-close",
      "3-fruits-start": "open-pana",
      "3-fruits-end": "close-pana"
    };

    // ✅ Updated plain text winType (no brackets)
    const gameModeToWinType = {
      "1-fruits-start": "1 Fruits Start",
      "1-fruits-end": "1 Fruits End",
      "2-fruits": "2 Fruits",
      "3-fruits-start": "3 Fruits Start",
      "3-fruits-end": "3 Fruits End"
    };

    let totalWinners = 0;
    let totalAmountWon = 0;

    // Loop through all users
    for (const [userId, userData] of Object.entries(usersData)) {
      const userGamesRef = usersRef.child(`${userId}/game1/game-actions`);
      const gamesSnapshot = await userGamesRef.once('value');
      const gamesData = gamesSnapshot.val();
      if (!gamesData) continue;

      for (const [gameId, gameData] of Object.entries(gamesData)) {
        console.log(`\n➡️ Checking User ${userId}, gameId ${gameId}`);
        console.log("Game Data:", gameData);

        // Skip if not today's bet
        const betDate = gameData.timestamp
          ? moment(gameData.timestamp).tz('Asia/Kolkata').format('YYYY-MM-DD')
          : null;
        if (betDate != today) {
          console.log(`❌ Skipped: Different date (${betDate})`);
          continue;
        }

        // Match session from user's sessionNumber
        const sessionKey = `session${gameData.sessionNumber}`;
        const sessionResults = todayResults[sessionKey];
        if (!sessionResults) {
          console.log(`❌ Skipped: No results for user's session ${sessionKey}`);
          continue;
        }

        // Get result key and value
        const resultKey = gameModeToResultKey[gameData.gameMode];
        if (!resultKey) {
          console.log(`❌ Skipped: Unknown gameMode ${gameData.gameMode}`);
          continue;
        }

        const resultValue = sessionResults[resultKey];
        if (!resultValue) {
          console.log(`❌ Skipped: No result value for key ${resultKey}`);
          continue;
        }

        // Compare user's selected numbers with result
        const selectedStr = gameData.selectedNumbers.join(""); // user's selection
        const resultStr = resultValue.toString();              // result as string
        const isWin = selectedStr == resultStr;                // match check

        if (isWin) {
          const betAmount = parseFloat(gameData.betAmount) || 0;
          let amountWon = 0;

          // Payout multipliers
          if (
            gameData.gameMode === "1-fruits-start" ||
            gameData.gameMode === "1-fruits-end" ||
            gameData.gameMode === "3-fruits-start" ||
            gameData.gameMode === "3-fruits-end"
          ) {
            amountWon = betAmount * 10;
          } else if (gameData.gameMode === "2-fruits") {
            amountWon = betAmount * 100;
          }

          const winnerData = {
            userId: userId,
            phoneNo: userData.phone || userData.phoneNo || 'N/A',
            gameId: gameId,
            betAmount: betAmount,
            amountWon: amountWon,
            winType: gameModeToWinType[gameData.gameMode] || gameData.gameMode,
            date: today,
            session: sessionKey,
            selectedNumbers: selectedStr,
            resultNumbers: resultStr,
            timestamp: moment().tz('Asia/Kolkata').valueOf()
          };

          // Save to Winners
          await winnersRef.child(today).child(sessionKey).child(userId).child(gameId).set(winnerData);

          // Update user's tokens
          const currentTokens = parseFloat(userData.tokens || 0);
          await usersRef.child(userId).update({
            tokens: currentTokens + amountWon
          });

          totalWinners++;
          totalAmountWon += amountWon;

          console.log(`✅ WINNER! User ${userId}, gameId ${gameId} won ${amountWon}. Updated tokens: ${currentTokens + amountWon}`);
        } else {
          console.log(`❌ User ${userId}, gameId ${gameId} did NOT win. Selection: ${selectedStr}, Result: ${resultStr}`);
        }
      }
    }

    console.log(`\n🎉 Match results completed! Total winners: ${totalWinners}, Total amount won: ${totalAmountWon}`);

    res.status(200).json({
      success: true,
      message: 'Match results completed successfully',
      summary: {
        date: today,
        totalWinners: totalWinners,
        totalAmountWon: totalAmountWon
      }
    });

  } catch (error) {
    console.error('❌ Error in result matching:', error);
    res.status(500).json({ success: false, message: 'Failed to match results', error: error.message });
  }
});

cron.schedule(
  '55 23 * * *',
  async () => {
    try {
      // ✅ Define API base URL inside the cron
      const API_BASE_URL =
        process.env.NODE_ENV === 'production'
          ? 'https://naphex.com'
          : 'http://localhost:3200';

      console.log('🕒 Starting the match-results API call at 1:36 PM IST');

      const response = await axios.post(`${API_BASE_URL}/api/match-results/new`);

      console.log('✅ Match-results API called successfully:', response.data);
    } catch (error) {
      console.error(
        '❌ Error calling the match-results API:',
        error.response ? error.response.data : error.message
      );
    }
  },
  {
    timezone: 'Asia/Kolkata',
  }
);



//update game status token updated
app.post('/api/update-game-status', async (req, res) => {
  try {
    const dbRef = firebaseAdmin.database();
    const usersRef = dbRef.ref('/Users');
    const winnersRef = dbRef.ref('/Winners');

    const now = moment().tz('Asia/Kolkata');
    const today = now.format('YYYY-MM-DD');

    // ✅ Fetch today's winners (now deeply nested by session > user > game)
    const winnersSnapshot = await winnersRef.child(today).once('value');
    const winnersData = winnersSnapshot.val();

    if (!winnersData) {
      return res.status(404).json({
        success: false,
        message: `No winners found for date ${today}`,
      });
    }

    // ✅ Extract all winning game IDs from nested structure
    const winningGameIds = [];
    for (const [sessionKey, sessionUsers] of Object.entries(winnersData)) {
      for (const [userId, userGames] of Object.entries(sessionUsers)) {
        for (const [gameId, gameDetails] of Object.entries(userGames)) {
          winningGameIds.push(gameId);
        }
      }
    }

    console.log(`🎯 Found ${winningGameIds.length} winning games for ${today}`);

    // ✅ Fetch all users
    const usersSnapshot = await usersRef.once('value');
    const usersData = usersSnapshot.val();

    if (!usersData) {
      return res.status(404).json({
        success: false,
        message: 'No users found',
      });
    }

    let totalUpdated = 0;

    // ✅ Iterate through all users
    for (const [userId, userData] of Object.entries(usersData)) {
      const userGamesRef = usersRef.child(`${userId}/game1/game-actions`);
      const gamesSnapshot = await userGamesRef.once('value');
      const gamesData = gamesSnapshot.val();

      if (!gamesData) continue;

      // ✅ Iterate through all the user's games
      for (const [gameId, gameData] of Object.entries(gamesData)) {
        if (gameData.status !== 'pending') continue;

        if (winningGameIds.includes(gameId)) {
          // ✅ Mark as "won"
          await userGamesRef.child(gameId).update({ status: 'won' });

          // Optionally add tokens
          const betAmount = parseFloat(gameData.betAmount) || 0;
          await usersRef.child(`${userId}/tokens`).transaction((currentTokens) => {
            return (currentTokens || 0) + betAmount * 10; // Example payout
          });

          console.log(`✅ Game ${gameId} for ${userId} marked as WON`);
        } else {
          // ✅ Mark as "lost"
          await userGamesRef.child(gameId).update({ status: 'lost' });
          console.log(`❌ Game ${gameId} for ${userId} marked as LOST`);
        }

        totalUpdated++;
      }
    }

    // ✅ Send response
    res.status(200).json({
      success: true,
      message: `${totalUpdated} game statuses updated successfully.`,
      totalUpdated,
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
    const API_BASE_URL =
      process.env.NODE_ENV === 'production'
        ? 'https://naphex.com'
        : 'http://localhost:3200';

    console.log(`🚀 Running /update-game-status cron job at ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}`);
    console.log(`🌐 Using API_BASE_URL: ${API_BASE_URL}`);

    const response = await axios.post(`${API_BASE_URL}/api/update-game-status`);

    console.log('✅ Game status update result:', response.data);
  } catch (error) {
    console.error(
      '❌ Error running /update-game-status cron job:',
      error.response ? error.response.data : error.message
    );
  }
}, {
  timezone: 'Asia/Kolkata'
});
//add wins subcollection to user ds
app.post('/api/add-winner-to-wins', async (req, res) => {
  try {
    const dbRef = firebaseAdmin.database();
    const winnersRef = dbRef.ref('/Winners');
    const usersRef = dbRef.ref('/Users');

    // Fetch all winners
    const winnersSnapshot = await winnersRef.once('value');
    const winnersData = winnersSnapshot.val();

    if (!winnersData) {
      return res.status(404).json({
        success: false,
        message: 'No winners found in /Winners collection',
      });
    }

    let processedWinnersCount = 0;

    // Loop through structure: date → session → userId → gameId → winnerData
    for (const [date, sessions] of Object.entries(winnersData)) {
      for (const [sessionKey, users] of Object.entries(sessions)) {
        for (const [userId, userGames] of Object.entries(users)) {
          for (const [gameId, winner] of Object.entries(userGames)) {
            if (!winner || !userId || !gameId) continue;

            const {
              winType,
              betAmount,
              amountWon,
              phoneNo,
              resultNumbers,
              selectedNumbers,
              session,
              timestamp,
            } = winner;

            // Reference to user's wins subcollection
            const userWinsRef = usersRef.child(`${userId}/game1/wins`);
            const newWinRef = userWinsRef.push();

            // Prepare data
            const winData = {
              gameId,
              session: session || sessionKey,
              winType: winType || 'N/A',
              betAmount: betAmount || 0,
              amountWon: amountWon || 0,
              phoneNo: phoneNo || null,
              date: date,
              resultNumbers: resultNumbers || '',
              selectedNumbers: selectedNumbers || '',
              timestamp: timestamp || moment().tz('Asia/Kolkata').valueOf(),
            };

            // Save to user's wins
            await newWinRef.set(winData);

            processedWinnersCount++;
          }
        }
      }
    }

    res.status(200).json({
      success: true,
      message: `Winners added to users' wins successfully`,
      processedWinnersCount,
    });
  } catch (error) {
    console.error('❌ Error adding winners to wins subcollection:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to add winners to wins subcollection',
      error: error.message,
    });
  }
});


cron.schedule(
  '57 23 * * *',
  async () => {
    try {
      const API_BASE_URL =
        process.env.NODE_ENV === 'production'
          ? 'https://naphex.com'
          : 'http://localhost:3200';

      console.log(
        `🚀 Running /add-winner-to-wins cron job at ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}`
      );
      console.log(`🌐 Using API_BASE_URL: ${API_BASE_URL}`);

      const response = await axios.post(`${API_BASE_URL}/api/add-winner-to-wins`);

      console.log('✅ Winners → wins update result:', response.data);
    } catch (error) {
      console.error(
        '❌ Error running /add-winner-to-wins cron job:',
        error.response ? error.response.data : error.message
      );
    }
  },
  {
    scheduled: true,
    timezone: 'Asia/Kolkata',
  }
);




// API to fetch winners
app.get('/api/fetch-winners', async (req, res) => {
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


//Open Close Game Admin Profit
app.get('/api/updateGameDetails', async (req, res) => {
    try {
        let totalPlayerBetAmount = 0;
        let totalPlayerWinAmount = 0;

        // 1. Get the reference to the Firebase Realtime Database
        const db = firebaseAdmin.database();

        // 2. Fetch all users from 'Users' collection
        const usersSnapshot = await db.ref('Users').once('value');
        const usersData = usersSnapshot.val();

        if (!usersData) {
            return res.status(200).json({
                success: false,
                message: 'No users found in the Users collection'
            });
        }

        // 3. Loop through each user
        Object.keys(usersData).forEach(userId => {
            const userData = usersData[userId];

            // Calculate bet amounts
            if (userData?.game1?.['game-actions']) {
                const gameActions = userData.game1['game-actions'];
                Object.values(gameActions).forEach(action => {
                    totalPlayerBetAmount += parseFloat(action?.betAmount || 0);
                });
            }

            // Calculate win amounts
            if (userData?.game1?.wins) {
                const wins = userData.game1.wins;
                Object.values(wins).forEach(win => {
                    totalPlayerWinAmount += parseFloat(win?.amountWon || 0);
                });
            }
        });

        // 4. Calculate totalNetProfit (profit or loss)
        const totalNetProfit = totalPlayerBetAmount - totalPlayerWinAmount;

        // 5. Update the 'OpenCloseGameDetails' node with calculated values
        const gameDetailsRef = db.ref('OpenCloseGameDetails');
        const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
        await gameDetailsRef.child('totalPlayerBetAmount').set(totalPlayerBetAmount);
        await gameDetailsRef.child('totalPlayerWinAmount').set(totalPlayerWinAmount);
        await gameDetailsRef.child('dailyProfitLoss').child(today).set(totalNetProfit);

        // 6. Return calculated details as JSON
        return res.status(200).json({
            success: true,
            message: 'Game details updated successfully!',
            totalPlayerBetAmount,
            totalPlayerWinAmount,
            totalNetProfit
        });
    } catch (error) {
        console.error('Error updating game details:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal Server Error',
            error: error.message
        });
    }
});


cron.schedule(
  '58 23 * * *',
  async () => {
    try {
      const API_BASE_URL =
        process.env.NODE_ENV === 'production'
          ? 'https://naphex.com'      // Production URL
          : 'http://localhost:3200'; // Local URL

      console.log(
        `🚀 Running /updateGameDetails cron job at ${new Date().toLocaleString('en-IN', {
          timeZone: 'Asia/Kolkata'
        })}`
      );
      console.log(`🌐 Using API_BASE_URL: ${API_BASE_URL}`);

      const response = await axios.get(`${API_BASE_URL}/api/updateGameDetails`);

      console.log('✅ Game details updated successfully via cron job:', response.data);
    } catch (error) {
      console.error(
        '❌ Error running /updateGameDetails cron job:',
        error.response ? error.response.data : error.message
      );
    }
  },
  {
    scheduled: true,
    timezone: 'Asia/Kolkata',
  }
);

//for main component
app.get('/api/getOpenCloseProfitLoss', (req, res) => {
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
app.get('/api/gameDetailsStream', (req, res) => {
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
app.get('/api/get-winners', async (req, res) => {
  try {
    const db = admin.database();
    const winnersRef = db.ref('Winners');

    const snapshot = await winnersRef.once('value');
    const winnersData = snapshot.val();

    // Flatten nested structure into array
    const winnersList = [];

    for (const [date, sessions] of Object.entries(winnersData || {})) {
      for (const [sessionKey, users] of Object.entries(sessions || {})) {
        for (const [userId, userGames] of Object.entries(users || {})) {
          for (const [gameId, winner] of Object.entries(userGames || {})) {
            winnersList.push({
              date,
              session: sessionKey,
              userId,
              gameId,
              ...winner,
            });
          }
        }
      }
    }

    res.json({
      success: true,
      message: 'All winners fetched successfully',
      winners: winnersList,
      count: winnersList.length,
    });
  } catch (error) {
    console.error('Error fetching winners:', error);
    res.status(500).json({ error: true, message: 'Internal server error' });
  }
});


app.post('/api/mark-winner-claimed/:date/:session/:userId/:gameId', async (req, res) => {
  try {
    const { date, session, userId, gameId } = req.params;
    const db = admin.database();
    const winnerRef = db.ref(`Winners/${date}/${session}/${userId}/${gameId}`);

    const winnerSnapshot = await winnerRef.once('value');

    if (!winnerSnapshot.exists()) {
      return res.status(404).json({
        success: false,
        message: 'Winner not found',
      });
    }

    await winnerRef.update({
      popupShown: true,
      claimedAt: admin.database.ServerValue.TIMESTAMP,
    });

    res.json({
      success: true,
      message: 'Winner popup marked as shown',
    });
  } catch (error) {
    console.error('Error marking winner as claimed:', error);
    res.status(500).json({
      error: true,
      message: 'Internal server error',
    });
  }
});



app.get('/api/get-user-winners/:phoneNo', async (req, res) => {
  try {
    const { phoneNo } = req.params;
    const db = admin.database();
    const winnersRef = db.ref('Winners');

    // Fetch all winners
    const snapshot = await winnersRef.once('value');
    const winnersData = snapshot.val();

    if (!winnersData) {
      return res.json({
        success: true,
        message: 'No winners found for this user',
        winners: [],
        count: 0,
      });
    }

    const winnersList = [];

    // Loop through winners by date
    for (const [date, sessions] of Object.entries(winnersData)) {
      for (const [sessionKey, users] of Object.entries(sessions || {})) {
        for (const [userId, userGames] of Object.entries(users || {})) {
          for (const [gameId, winner] of Object.entries(userGames || {})) {
            // Match phone number and check if popupShown is false or undefined
            if (winner.phoneNo === phoneNo && !winner.popupShown) {
              winnersList.push({
                date,
                session: sessionKey,
                userId,
                gameId,
                amountWon: winner.amountWon,
                betAmount: winner.betAmount,
                resultNumbers: winner.resultNumbers,
                selectedNumbers: winner.selectedNumbers,
                timestamp: winner.timestamp,
                winType: winner.winType,
              });
            }
          }
        }
      }
    }

    res.json({
      success: true,
      message: 'User winners fetched successfully',
      winners: winnersList,
      count: winnersList.length,
    });

  } catch (error) {
    console.error('Error fetching user winners:', error);
    res.status(500).json({
      error: true,
      message: 'Internal server error'
    });
  }
});



//Game 2 action demo
app.post('/api/store-game2-action', async (req, res) => {
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
app.post('/api/help-request',
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

app.get('/api/help-requests', async (req, res) => {
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


app.patch('/api/help-requests/:id', async (req, res) => {
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
const uploadFileToStorage = async (file, fileName, folderPath) => {
    try {
        const fileUpload = bucket.file(`${folderPath}/${fileName}`);
        
        const blobStream = fileUpload.createWriteStream({
            metadata: {
                contentType: file.mimetype,
                metadata: {
                    firebaseStorageDownloadTokens: require('uuid').v4(),
                }
            }
        });

        return new Promise((resolve, reject) => {
            blobStream.on('error', (error) => {
                console.error('Upload error:', error);
                reject(error);
            });

            blobStream.on('finish', async () => {
                try {
                    // Make the file publicly accessible
                    await fileUpload.makePublic();
                    
                    // Get the public URL
                    const publicUrl = `https://storage.googleapis.com/${bucket.name}/${folderPath}/${fileName}`;
                    resolve(publicUrl);
                } catch (error) {
                    console.error('Error making file public:', error);
                    reject(error);
                }
            });

            blobStream.end(file.buffer);
        });
    } catch (error) {
        console.error('Storage upload error:', error);
        throw error;
    }
};

app.post("/api/registerUser", upload.fields([
    { name: 'aadharCard', maxCount: 1 },
    { name: 'panCard', maxCount: 1 },
    { name: 'bankPassbook', maxCount: 1 }, // optional
    { name: 'cancelledCheque', maxCount: 1 }, // new optional field
    { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
    const { userId, name, referralId, myrefrelid, phoneNo, email, password, city, state, panNumber } = req.body;

    // Validate required fields (added panNumber)
    if (!userId || !name || !myrefrelid || !phoneNo || !password || !city || !state || !panNumber) {
        return res.status(400).json({
            success: false,
            error: "Missing required fields: userId, name, myrefrelid, phoneNo, password, city, state, panNumber"
        });
    }

    // Validate mandatory KYC files (bankPassbook & cancelledCheque optional)
    if (!req.files || !req.files.aadharCard || !req.files.panCard || !req.files.selfie) {
        return res.status(400).json({
            success: false,
            error: 'Required KYC documents: aadharCard, panCard, selfie. (bankPassbook & cancelledCheque optional)'
        });
    }

    try {
        // ============ BINARY USER REGISTRATION LOGIC ============

        const binaryUsersRef = db.ref("binaryUsers");
        const usersSnapshot = await binaryUsersRef.once("value");

        let binaryUpdates = {};
        let referrerUserId = null;

        usersSnapshot.forEach((child) => {
            if (child.val().myrefrelid === referralId) {
                referrerUserId = child.key;
            }
        });

        if (!usersSnapshot.exists()) {
            binaryUpdates[`binaryUsers/${userId}`] = {
                name,
                referralId: null,
                leftChild: null,
                rightChild: null,
                myrefrelid,
                playedAmounts: {},
                carryForward: {},
                bonusReceived: {}
            };
        } else {
            if (!referrerUserId) {
                return res.status(400).json({ 
                    success: false,
                    error: "Invalid referral ID" 
                });
            }

            const referrerRef = db.ref(`binaryUsers/${referrerUserId}`);
            const referrerSnapshot = await referrerRef.once("value");

            if (!referrerSnapshot.exists()) {
                return res.status(400).json({ 
                    success: false,
                    error: "Invalid referral ID" 
                });
            }

            let referrerData = referrerSnapshot.val();

            if (!referrerData.leftChild) {
                binaryUpdates[`binaryUsers/${referrerUserId}/leftChild`] = userId;
            } else if (!referrerData.rightChild) {
                binaryUpdates[`binaryUsers/${referrerUserId}/rightChild`] = userId;
            } else {
                return res.status(400).json({ 
                    success: false,
                    error: "Both referral slots are occupied" 
                });
            }

            binaryUpdates[`binaryUsers/${userId}`] = {
                name,
                referralId: referrerUserId,
                leftChild: null,
                rightChild: null,
                myrefrelid,
                playedAmounts: {},
                carryForward: {},
                bonusReceived: {}
            };
        }

        await db.ref().update(binaryUpdates);

        // ============ REGULAR USER CREATION LOGIC ============

        const hashedPassword = await bcrypt.hash(password, 10);

        const userRecord = await firebaseAdmin.auth().createUser({
            phoneNumber: `+91${phoneNo}`,
            password: password,
            displayName: name,
            email: email || undefined,
        });

        const dbRef = firebaseAdmin.database();
        const usersRef = dbRef.ref('/Users');

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

        const nextUserNumber = highestNumber + 1;
        const userPath = `user-${nextUserNumber}`;
        const createdAt = new Date().toISOString();

        // Upload KYC documents
        const kycImages = {};
        const folderPath = `kyc-documents/${userPath}`;

        try {
            if (req.files.aadharCard && req.files.aadharCard[0]) {
                const aadharFile = req.files.aadharCard[0];
                const aadharFileName = `aadhar_${Date.now()}_${path.extname(aadharFile.originalname)}`;
                kycImages.aadharCardUrl = await uploadFileToStorage(aadharFile, aadharFileName, folderPath);
            }

            if (req.files.panCard && req.files.panCard[0]) {
                const panFile = req.files.panCard[0];
                const panFileName = `pan_${Date.now()}_${path.extname(panFile.originalname)}`;
                kycImages.panCardUrl = await uploadFileToStorage(panFile, panFileName, folderPath);
            }

            // Bank passbook optional
            if (req.files.bankPassbook && req.files.bankPassbook[0]) {
                const passbookFile = req.files.bankPassbook[0];
                const passbookFileName = `passbook_${Date.now()}_${path.extname(passbookFile.originalname)}`;
                kycImages.bankPassbookUrl = await uploadFileToStorage(passbookFile, passbookFileName, folderPath);
            }

            // Cancelled cheque optional
            if (req.files.cancelledCheque && req.files.cancelledCheque[0]) {
                const chequeFile = req.files.cancelledCheque[0];
                const chequeFileName = `cancelledCheque_${Date.now()}_${path.extname(chequeFile.originalname)}`;
                kycImages.cancelledChequeUrl = await uploadFileToStorage(chequeFile, chequeFileName, folderPath);
            }

            if (req.files.selfie && req.files.selfie[0]) {
                const selfieFile = req.files.selfie[0];
                const selfieFileName = `selfie_${Date.now()}_${path.extname(selfieFile.originalname)}`;
                kycImages.selfieUrl = await uploadFileToStorage(selfieFile, selfieFileName, folderPath);
            }
        } catch (uploadError) {
            console.error('Error uploading KYC documents:', uploadError);
            return res.status(500).json({
                success: false,
                message: 'Failed to upload KYC documents.',
                error: uploadError.message,
            });
        }

        const userData = {
            name,
            phoneNo,
            email: email || null,
            password: hashedPassword,
            referralId: referralId || null,
            tokens: 200,
            city,
            state,
            panNumber, // new field added
            createdAt,
            kycStatus: 'submitted',
            kycSubmittedAt: createdAt,
        };

        await dbRef.ref(`/Users/${userPath}`).set(userData);

        const userIdsData = {
            myuserid: userId,
            myrefrelid,
        };

        await dbRef.ref(`/Users/${userPath}/userIds`).set(userIdsData);

        const kycData = {
            aadharCardUrl: kycImages.aadharCardUrl || null,
            panCardUrl: kycImages.panCardUrl || null,
            bankPassbookUrl: kycImages.bankPassbookUrl || null,
            cancelledChequeUrl: kycImages.cancelledChequeUrl || null, // new optional field
            selfieUrl: kycImages.selfieUrl || null,
            status: 'submitted',
            submittedAt: createdAt,
            verifiedAt: null,
            verifiedBy: null,
            rejectionReason: null,
        };

        await dbRef.ref(`/Users/${userPath}/kyc`).set(kycData);

        const customToken = await firebaseAdmin.auth().createCustomToken(userRecord.uid);

        res.status(201).json({
            success: true,
            message: "User registered successfully (bank passbook & cancelled cheque optional)",
            binaryData: {
                userId,
                referralId: referrerUserId || null,
                message: "Binary user registered successfully"
            },
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
                panNumber,
                createdAt,
                kycStatus: 'submitted',
            },
            userIdsData,
            kycData: {
                status: 'submitted',
                submittedAt: createdAt,
                documentsUploaded: {
                    aadharCard: !!kycImages.aadharCardUrl,
                    panCard: !!kycImages.panCardUrl,
                    bankPassbook: !!kycImages.bankPassbookUrl,
                    cancelledCheque: !!kycImages.cancelledChequeUrl,
                    selfie: !!kycImages.selfieUrl,
                }
            }
        });

    } catch (error) {
        console.error('Error in registerUser:', error);
        if (error.message && error.message.includes('auth')) {
            try {
                await firebaseAdmin.auth().deleteUser(userRecord?.uid);
            } catch (cleanupError) {
                console.error('Error during cleanup:', cleanupError);
            }
        }

        res.status(500).json({
            success: false,
            message: 'Failed to register user.',
            error: error.message,
        });
    }
});



//Binary refrelid exist check api (signup)
app.get("/api/checkReferralSlots/:referralId", async (req, res) => {
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
app.post("/api/updatePlayedAmount", async (req, res) => {
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

schedule.scheduleJob("55 23 * * *", finalizeDailyAmounts); //11:55


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
schedule.scheduleJob("55 23 * * *", updateBusinessForAllUsers); //11:55

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
schedule.scheduleJob("56 23 * * *", calculateBonuses);



//API to get total business and eligible remaining business(For User)
app.get("/api/user-business", async (req, res) => {
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
app.get("/api/admin-binary-tree", async (req, res) => {
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
app.get("/api/user-downline", async (req, res) => {
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
app.get('/api/latest', async (req, res) => {
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
app.get('/api/userDailyEarnings', async (req, res) => {
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


app.get("/api/admin-binary-tree-by-date-range", async (req, res) => {
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


//User Accept Reject kyc related apis

// API 1: Accept KYC Request
app.post('/api/kyc/accept/:userIdentifier', async (req, res) => {
  try {
    const { userIdentifier } = req.params;
    
    if (!userIdentifier) {
      return res.status(400).json({ success: false, message: 'User identifier is required' });
    }

    // Initialize Firebase reference
    const usersRef = db.ref('Users');
    
    // Search for user by myuserid
    const snapshot = await usersRef.orderByChild('userIds/myuserid').equalTo(userIdentifier).once('value');
    
    if (!snapshot.exists()) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Get the user key (like 'user-3')
    const userKey = Object.keys(snapshot.val())[0];
    const userRef = usersRef.child(userKey);

    // Update KYC status
    await userRef.update({
      kycStatus: 'accepted',
      kycAcceptedAt: new Date().toISOString()
    });

    res.json({ 
      success: true,
      message: 'KYC accepted successfully',
      data: {
        userId: userIdentifier,
        firebaseKey: userKey,
        acceptedAt: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Error accepting KYC:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// API 2: Reject KYC Request
app.post('/api/kyc/reject/:userIdentifier', async (req, res) => {
  try {
    const { userIdentifier } = req.params;
    const { rejectionReason } = req.body;

    // 1. Validation
    if (!userIdentifier) {
      return res.status(400).json({ success: false, message: 'User identifier is required' });
    }
    if (!rejectionReason?.trim()) {
      return res.status(400).json({ success: false, message: 'Rejection reason is required' });
    }

    // 2. Locate user
    const usersRef = db.ref('Users');
    const snapshot = await usersRef.orderByChild('userIds/myuserid').equalTo(userIdentifier).once('value');
    if (!snapshot.exists()) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const userKey = Object.keys(snapshot.val())[0];
    const userRef = usersRef.child(userKey);
    const userData = snapshot.val()[userKey];
    const userIdsData = userData.userIds || {};
    const kycData = userData.kyc || {};
    const bucket = firebaseAdmin.storage().bucket();

    // 3. Delete KYC documents from Storage
    const deleteFile = async (url, label = '') => {
      try {
        if (!url || typeof url !== 'string') {
          console.log(`❌ Skipping ${label}: Invalid or empty URL`);
          return { success: true }; // continue
        }

        let filePath = '';

        // Firebase default hosted format
        if (url.includes('/o/')) {
          filePath = decodeURIComponent(url.split('/o/')[1].split('?')[0]);
        }

        // Custom hosted bucket format (e.g., Google Cloud Storage direct links)
        else if (url.includes('/naphex-game.firebasestorage.app/')) {
          const parts = url.split('/naphex-game.firebasestorage.app/');
          if (parts.length > 1) filePath = parts[1];
        }

        if (!filePath) {
          console.log(`❌ Unable to parse file path for ${label}`);
          return { success: false, label };
        }

        await bucket.file(filePath).delete();
        console.log(`✅ Deleted ${label}: ${filePath}`);
        return { success: true };
      } catch (err) {
        console.error(`❌ Error deleting ${label}:`, err.message);
        return { success: false, label, error: err.message };
      }
    };

    const deletionResults = await Promise.all([
      deleteFile(kycData.aadharCardUrl, 'aadharCardUrl'),
      deleteFile(kycData.panCardUrl, 'panCardUrl'),
      deleteFile(kycData.bankPassbookUrl, 'bankPassbookUrl')
    ]);

    const failedDeletions = deletionResults.filter(result => !result.success);
    if (failedDeletions.length > 0) {
      return res.status(500).json({
        success: false,
        message: 'Failed to delete KYC documents',
        failedFiles: failedDeletions
      });
    }

    // 4. Log to rejectedrequested (without KYC URLs)
    const rejectedRequestRef = db.ref('rejectedrequested').push();
    await rejectedRequestRef.set({
      userId: userIdentifier,
      userName: userData.name || 'N/A',
      phoneNo: userData.phoneNo || 'N/A',
      email: userData.email || 'N/A',
      rejectionReason: rejectionReason.trim(),
      rejectedAt: new Date().toISOString(),
      rejectedBy: 'admin',
      originalKycSubmittedAt: userData.kycSubmittedAt || null,
      firebaseKey: userKey
    });

    // 5. Delete Firebase Auth
    try {
      let authUser = null;
      if (userData.phoneNo) {
        try {
          authUser = await firebaseAdmin.auth().getUserByPhoneNumber(`+91${userData.phoneNo}`);
        } catch {}
      }
      if (!authUser && userData.email) {
        try {
          authUser = await firebaseAdmin.auth().getUserByEmail(userData.email);
        } catch {}
      }
      if (authUser) {
        await firebaseAdmin.auth().deleteUser(authUser.uid);
        console.log('✅ Deleted Firebase auth user:', authUser.uid);
      }
    } catch (authErr) {
      console.error('❌ Auth deletion error:', authErr.message);
    }

    // 6. Remove from binaryUsers
    if (userIdsData.myrefrelid) {
      const binaryUsersRef = db.ref('binaryUsers');
      const binarySnapshot = await binaryUsersRef.orderByChild('myrefrelid').equalTo(userIdsData.myrefrelid).once('value');

      if (binarySnapshot.exists()) {
        const binaryKey = Object.keys(binarySnapshot.val())[0];
        const binaryData = binarySnapshot.val()[binaryKey];

        if (binaryData.referralId) {
          const parentRef = db.ref(`binaryUsers/${binaryData.referralId}`);
          const parentSnap = await parentRef.once('value');
          const parentData = parentSnap.val();

          if (parentData) {
            const updates = {};
            if (parentData.leftChild === binaryKey) updates.leftChild = null;
            if (parentData.rightChild === binaryKey) updates.rightChild = null;

            if (Object.keys(updates).length) await parentRef.update(updates);
          }
        }

        await binaryUsersRef.child(binaryKey).remove();
        console.log('✅ Removed user from binaryUsers');
      }
    }

    // 7. Delete main user record
    await userRef.remove();
    console.log('✅ Removed user document from Users');

    // 8. Respond success
    res.json({
      success: true,
      message: 'KYC rejected and user completely removed.',
      data: {
        userId: userIdentifier,
        firebaseKey: userKey,
        rejectedRequestId: rejectedRequestRef.key,
        deletedAuthMethods: {
          phone: !!userData.phoneNo,
          email: !!userData.email
        },
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('❌ KYC rejection process error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process KYC rejection',
      error: error.message
    });
  }
});


app.get("/api/rejected-requests", async (req, res) => {
  try {
    const ref = db.ref("rejectedrequested");
    ref.once("value", (snapshot) => {
      const data = snapshot.val();
      if (!data) return res.status(404).json({ message: "No rejected requests found." });

      const formatted = Object.keys(data).map((key) => ({
        id: key,
        ...data[key],
      }));

      res.json(formatted);
    });
  } catch (error) {
    console.error("Error fetching rejected requests:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});



//Block Unblock Users
app.put('/api/users/:userId/status', async (req, res) => {
    try {
        const { userId } = req.params;
        const { status } = req.body;

        // Input validation
        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'User ID is required'
            });
        }

        if (!status || !['active', 'blocked'].includes(status)) {
            return res.status(400).json({
                success: false,
                message: 'Status must be either "active" or "blocked"'
            });
        }

        const usersRef = db.ref('/Users');

        // Get all users
        const snapshot = await usersRef.once('value');
        const users = snapshot.val();

        let matchedUserKey = null;

        // Find userKey where userIds.myuserid matches userId param
        for (const key in users) {
            const user = users[key];
            if (user?.userIds?.myuserid === userId) {
                matchedUserKey = key;
                break;
            }
        }

        if (!matchedUserKey) {
            return res.status(404).json({
                success: false,
                message: 'User not found with provided myuserid'
            });
        }

        const userRef = usersRef.child(matchedUserKey);

        const blocked = status === 'blocked';
        const updateData = {
            status: status,
            blocked: blocked,
            updatedAt: new Date().toISOString()
        };

        await userRef.update(updateData);

        console.log(`✅ Updated ${matchedUserKey} (myuserid: ${userId}) to status: ${status}`);

        res.status(200).json({
            success: true,
            message: `User ${status === 'blocked' ? 'blocked' : 'unblocked'} successfully`,
            data: {
                userKey: matchedUserKey,
                myuserid: userId,
                status,
                blocked,
                updatedAt: updateData.updatedAt
            }
        });

    } catch (error) {
        console.error('❌ Error updating user status:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while updating user status',
            error: error.message
        });
    }
});




//Payment gateway apis
// 🔒 Entry Fee (₹500) API
// Cashfree Configuration
const CASHFREE_CONFIG = {
  appId: process.env.CASHFREE_APP_ID,
  secretKey: process.env.CASHFREE_SECRET_KEY,
  baseUrl: 'https://sandbox.cashfree.com/pg', // Use 'https://api.cashfree.com/pg' for production
};

// Generate Cashfree signature for request authentication
function generateSignature(postData, timestamp) {
  const signatureData = postData + timestamp;
  return crypto
    .createHmac('sha256', CASHFREE_CONFIG.secretKey)
    .update(signatureData)
    .digest('base64');
}

// API 1: Create Order
app.post('/api/create-order', async (req, res) => {
  const { phoneNo, amount, currency = 'INR', orderNote = 'Payment for game tokens' } = req.body;

  if (!phoneNo || !amount || amount <= 0) {
    return res.status(400).json({ error: "Missing or invalid phoneNo or amount" });
  }

  try {
    const orderId = `ORDER_${phoneNo}_${Date.now()}`;
    const timestamp = Math.floor(Date.now() / 1000).toString();

    const orderData = {
      order_id: orderId,
      order_amount: amount,
      order_currency: currency,
      order_note: orderNote,
      customer_details: {
        customer_id: phoneNo,
        customer_phone: "9999999999",
        customer_email: "user@example.com"
      },
      order_meta: {
        return_url: `${process.env.API_BASE_URL}/payment-success`,
        notify_url: `${process.env.API_BASE_URL}/api/payment-webhook`
      }
    };

    // 🔄 Get user details from Firebase
    const userRef = db.ref(`users/${phoneNo}`);
    const userSnapshot = await userRef.once('value');
    const userData = userSnapshot.val();

    if (userData) {
      if (userData.phone) orderData.customer_details.customer_phone = userData.phone;
      if (userData.email) orderData.customer_details.customer_email = userData.email;
    }

    const postData = JSON.stringify(orderData);
    const signature = generateSignature(postData, timestamp);

    const headers = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'x-api-version': '2023-08-01',
      'x-client-id': CASHFREE_CONFIG.appId,
      'x-client-secret': CASHFREE_CONFIG.secretKey,
      'x-request-timestamp': timestamp,
      'x-request-signature': signature
    };

    const response = await axios.post(
      `${CASHFREE_CONFIG.baseUrl}/orders`,
      orderData,
      { headers }
    );

    const orderRef = db.ref(`orders/${orderId}`);
    await orderRef.set({
      userId: phoneNo,
      amount: amount,
      currency: currency,
      status: 'created',
      createdAt: admin.database.ServerValue.TIMESTAMP,
      cashfreeOrderId: response.data.order_id,
      paymentSessionId: response.data.payment_session_id
    });

    res.json({
      success: true,
      orderId: orderId,
      paymentSessionId: response.data.payment_session_id,
      orderToken: response.data.order_token,
      cashfreeOrderId: response.data.order_id
    });

  } catch (error) {
    console.error('Create order error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: "Failed to create order",
      details: error.response?.data?.message || error.message
    });
  }
});


// API 2: Verify Order
app.post('/api/verify-order', async (req, res) => {
  const { orderId } = req.body;

  if (!orderId) {
    return res.status(400).json({ error: "Missing orderId" });
  }

  try {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const postData = JSON.stringify({ order_id: orderId });
    const signature = generateSignature(postData, timestamp);

    const headers = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'x-api-version': '2023-08-01',
      'x-client-id': CASHFREE_CONFIG.appId,
      'x-client-secret': CASHFREE_CONFIG.secretKey,
      'x-request-timestamp': timestamp,
      'x-request-signature': signature
    };

    const response = await axios.get(
      `${CASHFREE_CONFIG.baseUrl}/orders/${orderId}`,
      { headers }
    );

    const orderStatus = response.data.order_status;
    const paymentDetails = response.data;

    const orderRef = db.ref(`orders/${orderId}`);
    const orderSnapshot = await orderRef.once('value');
    const orderData = orderSnapshot.val();

    if (!orderData) {
      return res.status(404).json({ error: "Order not found in database" });
    }

    await orderRef.update({
      status: orderStatus.toLowerCase(),
      verifiedAt: admin.database.ServerValue.TIMESTAMP,
      paymentDetails: paymentDetails
    });

    if (orderStatus === 'PAID') {
      const phoneNo = orderData.userId;
      const amount = orderData.amount;

      // You can add additional logic here for specific types of payments

      res.json({
        success: true,
        orderId: orderId,
        status: orderStatus,
        amount: amount,
        userId: phoneNo,
        paymentDetails: paymentDetails,
        message: "Payment verified successfully"
      });
    } else {
      res.json({
        success: false,
        orderId: orderId,
        status: orderStatus,
        message: `Payment status: ${orderStatus}`
      });
    }

  } catch (error) {
    console.error('Verify order error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: "Failed to verify order",
      details: error.response?.data?.message || error.message
    });
  }
});


app.post('/api/pay-entry-fee', async (req, res) => {
  const { phoneNo, paymentDetails, orderId } = req.body;

  if (!phoneNo || !paymentDetails || !orderId) {
    return res.status(400).json({ error: "Missing phoneNo, paymentDetails, or orderId" });
  }

  try {
    const usersSnap = await db.ref('Users').once('value');
    const users = usersSnap.val();

    let userKey = null;
    for (const [key, user] of Object.entries(users || {})) {
      if (user.phoneNo === phoneNo) {
        userKey = key;
        break;
      }
    }

    if (!userKey) {
      return res.status(404).json({ error: "User not found" });
    }

    const userRef = db.ref(`Users/${userKey}`);

    // Fixed entry fee
    const amountPaid = 500;

    // Calculate tax and credited amount
    const taxAmount = +(amountPaid * 0.28).toFixed(2); // 28% tax
    const creditedAmount = +(amountPaid - taxAmount).toFixed(2); // 72% amount

    // ===== 1. Update User Main Data (NO entryFeeTax object) =====
    await userRef.update({
      entryFee: "paid",
      entryFeePaidAt: admin.database.ServerValue.TIMESTAMP,
      entryFeeOrderId: orderId,
      entryFeeAmount: amountPaid
    });

    // ===== 2. Add to User's Orders Sub-Collection (NO creditedAmount here) =====
    await db.ref(`Users/${userKey}/orders/${orderId}`).set({
      type: "entry_fee",
      paymentDetails,
      amountPaid,
      taxAmount,
      taxRate: "28%",
      status: "paid",
      processedAt: admin.database.ServerValue.TIMESTAMP
    });

    // ===== 3. Update Main Orders Collection (with creditedAmount) =====
    await db.ref(`orders/${orderId}`).update({
      taxAmount,
      creditedAmount,
      taxRate: "28%",
      taxDate: admin.database.ServerValue.TIMESTAMP
    });

    res.json({
      success: true,
      message: "Entry fee recorded successfully with tax.",
      amountPaid,
      taxAmount,
      creditedAmount
    });

  } catch (err) {
    console.error("Entry fee error:", err);
    res.status(500).json({ error: "Failed to record entry fee." });
  }
});

app.post('/api/add-tokens', async (req, res) => {
  const { phoneNo, orderId, amount } = req.body;

  if (!phoneNo || !orderId || !amount) {
    return res.status(400).json({ error: "Missing phoneNo, orderId, or amount" });
  }

  try {
    const usersSnap = await db.ref('Users').once('value');
    const users = usersSnap.val();

    let userKey = null;
    let userData = null;

    for (const [key, user] of Object.entries(users || {})) {
      if (user.phoneNo === phoneNo) {
        userKey = key;
        userData = user;
        break;
      }
    }

    if (!userKey || !userData) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if this order is already processed in user's orders
    const userOrderRef = db.ref(`Users/${userKey}/orders/${orderId}`);
    const userOrderSnap = await userOrderRef.once('value');
    if (userOrderSnap.exists()) {
      return res.status(400).json({ error: "Order already processed" });
    }

    // Calculate tax and credited tokens
    const taxAmount = +(amount * 0.28).toFixed(2);
    const creditedTokens = +(amount - taxAmount).toFixed(2);

    const newTokenBalance = (userData.tokens || 0) + creditedTokens;

    // ===== 1. Update User's Token Balance =====
    await db.ref(`Users/${userKey}`).update({
      tokens: newTokenBalance,
      lastTokenAddition: {
        amountPaid: amount,
        taxAmount,
        creditedTokens,
        taxRate: "28%",
        orderId,
        timestamp: admin.database.ServerValue.TIMESTAMP
      }
    });

    // ===== 2. Save Order in User's Orders Sub-Collection =====
    await userOrderRef.set({
      type: "tokens",
      amountPaid: amount,
      taxAmount,
      creditedTokens,
      taxRate: "28%",
      status: "paid",
      processedAt: admin.database.ServerValue.TIMESTAMP
    });

    // ===== 3. Update Main Orders Collection with Tax Info =====
    await db.ref(`orders/${orderId}`).update({
      taxRate: "28%",
      taxAmount,
      creditedAmount: creditedTokens,
      taxDate: admin.database.ServerValue.TIMESTAMP,
      // Keep existing fields intact, just add tax info
      status: "paid"
    });

    res.json({
      success: true,
      tokens: newTokenBalance,
      tokensAdded: creditedTokens,
      taxAmount,
      message: "Tokens added successfully with tax calculation."
    });

  } catch (err) {
    console.error("Add tokens error:", err);
    res.status(500).json({ error: "Failed to add tokens." });
  }
});






//Apis for entry fees and add tokens manual

// API to submit entry fee payment (with screenshot upload)
app.post('/api/submit-order-id', upload.single('screenshot'), async (req, res) => {
  const { phoneNo, transactionId, amount } = req.body;
  const screenshotFile = req.file;

  if (!phoneNo || !amount) {
    return res.status(400).json({
      success: false,
      error: "Missing phoneNo or amount"
    });
  }

  if (!screenshotFile) {
    return res.status(400).json({
      success: false,
      error: "Payment screenshot is required"
    });
  }

  try {
    const usersSnap = await db.ref('Users').once('value');
    const users = usersSnap.val();

    let userKey = null;
    let userData = null;
    for (const [key, user] of Object.entries(users || {})) {
      if (user.phoneNo === phoneNo) {
        userKey = key;
        userData = user;
        break;
      }
    }

    if (!userKey) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    if (userData.entryFee === 'paid') {
      return res.json({ success: false, error: "Entry fee already paid and verified" });
    }

    if (userData.entryFee === 'pending') {
      return res.json({ success: false, error: "Entry fee verification already pending" });
    }

    // Upload screenshot to Firebase Storage
    const bucket = admin.storage().bucket();
    const timestamp = Date.now();
    const uniqueId = uuidv4();
    const fileName = `payment_screenshots/${phoneNo}_${timestamp}_${uniqueId}${path.extname(screenshotFile.originalname)}`;
    const file = bucket.file(fileName);

    await file.save(screenshotFile.buffer, {
      metadata: {
        contentType: screenshotFile.mimetype,
        metadata: {
          phoneNo,
          uploadedAt: new Date().toISOString()
        }
      }
    });

    await file.makePublic();
    const screenshotUrl = `https://storage.googleapis.com/${bucket.name}/${fileName}`;

    // Generate orderId (like old flow)
    const orderId = `ORD_${timestamp}_${uniqueId.substring(0, 8)}`;

    // Create entry fee request
    const requestData = {
      phoneNo,
      transactionId: transactionId || 'N/A',
      amount,
      userKey,
      userName: userData.name || 'N/A',
      userEmail: userData.email || 'N/A',
      screenshotUrl,
      screenshotFileName: fileName,
      status: 'pending',
      submittedAt: admin.database.ServerValue.TIMESTAMP,
      submittedDate: new Date().toISOString()
    };

    await db.ref(`entryFeesRequest/${orderId}`).set(requestData);

    await db.ref(`Users/${userKey}`).update({
      entryFee: 'pending',
      entryFeeOrderId: orderId,
      entryFeeAmount: amount,
      entryFeeScreenshotUrl: screenshotUrl,
      entryFeeSubmittedAt: admin.database.ServerValue.TIMESTAMP
    });

    res.json({
      success: true,
      message: "Payment details submitted successfully. Admin will verify soon.",
      orderId
    });

  } catch (err) {
    console.error("Submit Payment Details Error:", err);
    res.status(500).json({
      success: false,
      error: err.message || "Failed to submit payment details. Please try again."
    });
  }
});

// ✅ API to check entry fee status
app.post('/api/check-entry-fee', async (req, res) => {
  const { phoneNo } = req.body;

  if (!phoneNo) {
    return res.status(400).json({ success: false, error: "Missing phoneNo" });
  }

  try {
    const usersSnap = await db.ref('Users').once('value');
    const users = usersSnap.val();

    let userData = null;
    for (const [key, user] of Object.entries(users || {})) {
      if (user.phoneNo === phoneNo) {
        userData = user;
        break;
      }
    }

    if (!userData) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    res.json({
      success: true,
      entryFee: userData.entryFee || 'unpaid'
    });

  } catch (err) {
    console.error("Check Entry Fee Error:", err);
    res.status(500).json({ success: false, error: "Failed to check entry fee status" });
  }
});

// ✅ Admin endpoint for approval/rejection (creates same DS as old orders)
// ✅ Admin endpoint for approval/rejection using existing order ID
app.post('/api/admin/verify-entry-fee', async (req, res) => {
  const { orderId, userKey, phoneNo, approved, adminNote } = req.body;
  
  if (!orderId || !userKey || approved === undefined) {
    return res.status(400).json({
      success: false,
      error: "Missing required fields: orderId, userKey, or approved status"
    });
  }
  
  try {
    // Get user data
    const userSnap = await db.ref(`Users/${userKey}`).once('value');
    const userData = userSnap.val();
    
    if (!userData) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    
    // Verify this order ID matches the user's pending request
    if (userData.entryFeeOrderId !== orderId) {
      return res.status(400).json({ 
        success: false, 
        error: "Order ID mismatch. This request may have been already processed." 
      });
    }
    
    const amount = parseFloat(userData.entryFeeAmount || 500);
    const screenshotUrl = userData.entryFeeScreenshotUrl;
    const transactionId = userData.entryFeeTransactionId;
    
    if (approved) {
      // APPROVE CASE
      const taxAmount = +(amount * 0.28).toFixed(2);
      const creditedAmount = +(amount - taxAmount).toFixed(2);
      
      const userRef = db.ref(`Users/${userKey}`);
      
      // 1️⃣ Update main user data
      await userRef.update({
        entryFee: "paid",
        entryFeePaidAt: admin.database.ServerValue.TIMESTAMP,
        entryFeeOrderId: orderId, // Keep the same order ID
        entryFeeAmount: amount,
        entryFeeAdminNote: adminNote || 'Payment verified and approved',
        // Clear pending submission timestamp
        entryFeeSubmittedAt: null
      });
      
      // 2️⃣ Add to user orders subcollection
      await db.ref(`Users/${userKey}/orders/${orderId}`).set({
        type: "entry_fee",
        paymentDetails: {
          method: "manual_verification",
          verifiedBy: "admin",
          transactionId: transactionId || 'N/A'
        },
        amountPaid: amount,
        taxAmount,
        taxRate: "28%",
        creditedAmount,
        status: "paid",
        processedAt: admin.database.ServerValue.TIMESTAMP,
        createdAt: admin.database.ServerValue.TIMESTAMP
      });
      
      // 3️⃣ Add to main orders collection
      await db.ref(`orders/${orderId}`).set({
        phoneNo: phoneNo || userData.phoneNo,
        userKey,
        type: "entry_fee",
        orderId,
        amountPaid: amount,
        taxAmount,
        creditedAmount,
        taxRate: "28%",
        status: "paid",
        verifiedBy: "admin",
        transactionId: transactionId || 'N/A',
        screenshotUrl,
        createdAt: admin.database.ServerValue.TIMESTAMP,
        processedAt: admin.database.ServerValue.TIMESTAMP,
        adminNote: adminNote || 'Payment verified and approved'
      });
      
      // 4️⃣ Create/Update entryFeesRequest record (for history)
      await db.ref(`entryFeesRequest/${orderId}`).set({
        phoneNo: phoneNo || userData.phoneNo,
        userKey,
        amount,
        transactionId: transactionId || 'N/A',
        screenshotFileName: screenshotUrl ? screenshotUrl.split('/').pop() : null,
        status: 'approved',
        approvedAt: admin.database.ServerValue.TIMESTAMP,
        approvedDate: new Date().toISOString(),
        adminNote: adminNote || 'Payment verified and approved',
        taxAmount,
        creditedAmount,
        taxRate: "28%"
      });
      
      res.json({
        success: true,
        message: `Payment approved successfully! Order ID: ${orderId}`,
        orderId,
        amountPaid: amount,
        taxAmount,
        creditedAmount
      });
      
    } else {
     // REJECT CASE
      
      // Delete screenshot from storage if it exists
      if (screenshotUrl) {
        try {
          const bucket = admin.storage().bucket();
          // Extract filename from URL
          const urlParts = screenshotUrl.split('/');
          const encodedFilename = urlParts[urlParts.length - 1];
          const filename = decodeURIComponent(encodedFilename.split('?')[0]);
          
          // Try to delete from payment_screenshots folder
          const filePath = filename.includes('payment_screenshots/') 
            ? filename 
            : `payment_screenshots/${filename}`;
          
          const file = bucket.file(filePath);
          const [exists] = await file.exists();
          
          if (exists) {
            await file.delete();
            console.log('Screenshot deleted:', filePath);
          }
        } catch (err) {
          console.error('Error deleting screenshot:', err);
          // Continue even if deletion fails
        }
      }
      
      // Clear user's pending entry fee data
      await db.ref(`Users/${userKey}`).update({
        entryFee: "unpaid",
        entryFeeOrderId: null,
        entryFeeAmount: null,
        entryFeeSubmittedAt: null,
        entryFeeScreenshotUrl: null,
        entryFeeTransactionId: null,
        entryFeeAdminNote: adminNote || 'Payment verification failed'
      });
      
      // Create/Update entryFeesRequest record as rejected (for history)
      await db.ref(`entryFeesRequest/${orderId}`).set({
        phoneNo: phoneNo || userData.phoneNo,
        userKey,
        amount,
        transactionId: transactionId || 'N/A',
        status: 'rejected',
        rejectedAt: admin.database.ServerValue.TIMESTAMP,
        rejectedDate: new Date().toISOString(),
        adminNote: adminNote || 'Payment verification failed'
      });
      
      res.json({
        success: true,
        message: "Payment rejected and data cleared successfully."
      });
    }
    
  } catch (err) {
    console.error("Verify Entry Fee Error:", err);
    res.status(500).json({
      success: false,
      error: "Failed to verify entry fee. Please try again.",
      details: err.message
    });
  }
});





// API endpoint to submit token request with screenshot upload
app.post('/api/submit-token-request', upload.single('screenshot'), async (req, res) => {
  const { 
    phoneNo, 
    transactionId, 
    requestedTokens, 
    netTokens, 
    amountPaid, 
    gstAmount 
  } = req.body;
  
  const screenshotFile = req.file;

  if (!phoneNo || !requestedTokens || !netTokens || !amountPaid) {
    return res.status(400).json({ 
      success: false, 
      error: "Missing required fields" 
    });
  }

  if (!screenshotFile) {
    return res.status(400).json({
      success: false,
      error: "Payment screenshot is required"
    });
  }

  try {
    // Find user by phone number
    const usersSnap = await db.ref('Users').once('value');
    const users = usersSnap.val();

    let userKey = null;
    let userData = null;
    for (const [key, user] of Object.entries(users || {})) {
      if (user.phoneNo === phoneNo) {
        userKey = key;
        userData = user;
        break;
      }
    }

    if (!userKey) {
      return res.status(404).json({ 
        success: false, 
        error: "User not found" 
      });
    }

    // Upload screenshot to Firebase Storage
    const bucket = admin.storage().bucket();
    const timestamp = Date.now();
    const uniqueId = uuidv4();
    const fileName = `token_payment_screenshots/${phoneNo}_${timestamp}_${uniqueId}${path.extname(screenshotFile.originalname)}`;
    const file = bucket.file(fileName);

    await file.save(screenshotFile.buffer, {
      metadata: {
        contentType: screenshotFile.mimetype,
        metadata: {
          phoneNo,
          uploadedAt: new Date().toISOString(),
          type: 'token_payment'
        }
      }
    });

    await file.makePublic();
    const screenshotUrl = `https://storage.googleapis.com/${bucket.name}/${fileName}`;

    // Generate unique request ID
    const requestId = `TOK_${timestamp}_${uniqueId.substring(0, 8)}`;

    // Create token request data
    const requestData = {
      phoneNo,
      transactionId: transactionId || 'N/A',
      requestedTokens: parseInt(requestedTokens),
      netTokens: parseFloat(netTokens),
      amountPaid: parseFloat(amountPaid),
      gstAmount: parseFloat(gstAmount || 0),
      userKey,
      userName: userData.name || 'N/A',
      userEmail: userData.email || 'N/A',
      currentTokens: userData.tokens || 0,
      screenshotUrl,
      screenshotFileName: fileName,
      status: 'pending', // pending, approved, rejected
      submittedAt: admin.database.ServerValue.TIMESTAMP,
      submittedDate: new Date().toISOString(),
      type: 'token_purchase'
    };

    // Store in tokenRequests collection
    await db.ref(`tokenRequests/${requestId}`).set(requestData);

    // Also store reference in user's token request history
    await db.ref(`Users/${userKey}/tokenRequestHistory/${requestId}`).set({
      transactionId: transactionId || 'N/A',
      requestedTokens: parseInt(requestedTokens),
      netTokens: parseFloat(netTokens),
      amountPaid: parseFloat(amountPaid),
      screenshotUrl,
      status: 'pending',
      submittedAt: admin.database.ServerValue.TIMESTAMP,
      submittedDate: new Date().toISOString(),
      type: 'token_purchase'
    });

    res.json({
      success: true,
      message: "Token request submitted successfully. Admin team will update tokens within 4 to 24 hours. Please check request status in previous requests page.",
      requestId
    });

  } catch (err) {
    console.error("Submit Token Request Error:", err);
    res.status(500).json({ 
      success: false, 
      error: "Failed to submit token request. Please try again." 
    });
  }
});




// ✅ Normal Admin API to approve and process token requests
app.post('/api/admin/update-tokens', async (req, res) => {
  try {
    console.log('Received request body:', req.body);

    const { userId, requestId, tokensToAdd, paymentId, amountPaid, requestedTokens, netTokens, gstAmount, gatewayFee } = req.body;

    if (!userId || !requestId || !tokensToAdd || !paymentId) {
      console.error('Missing fields:', { userId, requestId, tokensToAdd, paymentId });
      return res.status(400).json({
        success: false,
        error: "Missing required fields: userId, requestId, tokensToAdd, or paymentId"
      });
    }

    // ===== 1. Generate unique order ID =====
    const orderId = `ORD_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // ===== 2. Fetch token request =====
    const requestRef = db.ref(`tokenRequests/${requestId}`);
    const requestSnap = await requestRef.once('value');
    if (!requestSnap.exists()) {
      return res.status(404).json({ success: false, error: "Token request not found" });
    }
    const requestData = requestSnap.val();

    // Verify request status
    if (requestData.status !== 'pending') {
      return res.status(400).json({
        success: false,
        error: `Request already ${requestData.status}`
      });
    }

    // ===== 3. Fetch user =====
    const userRef = db.ref(`Users/${userId}`);
    const userSnap = await userRef.once('value');
    if (!userSnap.exists()) {
      return res.status(404).json({ success: false, error: "User not found" });
    }
    const userData = userSnap.val();

    // Check duplicate payment
    const userOrderRef = db.ref(`Users/${userId}/orders/${orderId}`);
    const userOrderSnap = await userOrderRef.once('value');
    if (userOrderSnap.exists()) {
      return res.status(400).json({ success: false, error: "Order already processed for this user" });
    }

    // ===== 4. Compute tokens and tax =====
    const paidAmount = parseFloat(amountPaid || requestData.amountPaid);
    const taxAmount = +(paidAmount * 0.28).toFixed(2);
    const creditedTokens = parseFloat(tokensToAdd);
    const newTokenBalance = (userData.tokens || 0) + creditedTokens;

    // ===== 5. Update user's token balance =====
    await userRef.update({
      tokens: newTokenBalance,
      lastTokenAddition: {
        amountPaid: paidAmount,
        taxAmount,
        creditedTokens,
        taxRate: "28%",
        orderId: orderId,
        requestId,
        timestamp: admin.database.ServerValue.TIMESTAMP
      }
    });

    // ===== 6. Save order inside user orders =====
    await userOrderRef.set({
      orderId: orderId,
      type: "tokens",
      amountPaid: paidAmount,
      taxAmount,
      creditedTokens,
      taxRate: "28%",
      requestedTokens: requestedTokens || requestData.requestedTokens,
      netTokens: netTokens || requestData.netTokens,
      gstAmount: gstAmount || requestData.gstAmount || 0,
      gatewayFee: gatewayFee || requestData.gatewayFee || 0,
      status: "paid",
      processedAt: admin.database.ServerValue.TIMESTAMP,
      approvedBy: "admin",
      requestId: requestId,
      paymentId: paymentId,
      userId: userId,
      userName: userData.name || 'N/A',
      userPhone: userData.phoneNo || 'N/A',
      userEmail: userData.email || 'N/A'
    });

    // ===== 7. Save in main orders collection =====
    await db.ref(`orders/${orderId}`).set({
      orderId: orderId,
      userId,
      phoneNo: userData.phoneNo,
      userName: userData.name || 'N/A',
      userEmail: userData.email || 'N/A',
      type: "tokens",
      amountPaid: paidAmount,
      taxRate: "28%",
      taxAmount,
      creditedTokens: creditedTokens,
      requestedTokens: requestedTokens || requestData.requestedTokens,
      netTokens: netTokens || requestData.netTokens,
      gstAmount: gstAmount || requestData.gstAmount || 0,
      gatewayFee: gatewayFee || requestData.gatewayFee || 0,
      status: "paid",
      processedAt: admin.database.ServerValue.TIMESTAMP,
      approvedBy: "admin",
      requestId: requestId,
      paymentId: paymentId,
      screenshotUrl: requestData.screenshotUrl || null,
      submittedAt: requestData.submittedAt || admin.database.ServerValue.TIMESTAMP
    });

    // ===== 8. Update token request status =====
    await requestRef.update({
      status: 'approved',
      approvedAt: admin.database.ServerValue.TIMESTAMP,
      approvedDate: new Date().toISOString(),
      tokensAdded: creditedTokens,
      taxAmount,
      processedBy: "admin",
      orderId: orderId
    });

    // ===== 9. Update user's token request history =====
    await db.ref(`Users/${userId}/tokenRequestHistory/${requestId}`).update({
      status: 'approved',
      approvedAt: admin.database.ServerValue.TIMESTAMP,
      approvedDate: new Date().toISOString(),
      tokensAdded: creditedTokens,
      taxAmount,
      orderId: orderId
    });

    // ===== 10. Final Response =====
    return res.status(200).json({
      success: true,
      message: "Tokens updated successfully",
      data: {
        tokens: newTokenBalance,
        tokensAdded: creditedTokens,
        taxAmount,
        orderId: orderId,
        requestId
      }
    });

  } catch (err) {
    console.error("Admin Update Tokens Error:", err);
    return res.status(500).json({
      success: false,
      error: "Failed to update tokens. Please try again."
    });
  }
});

// API to reject a token request
app.post('/api/admin/reject-token-request', async (req, res) => {
  const { userId, requestId, reason } = req.body;

  if (!userId || !requestId) {
    return res.status(400).json({ 
      success: false, 
      error: "Missing required fields: userId or requestId" 
    });
  }

  try {
    // Get the token request details
    const requestRef = db.ref(`tokenRequests/${requestId}`);
    const requestSnap = await requestRef.once('value');
    
    if (!requestSnap.exists()) {
      return res.status(404).json({ 
        success: false, 
        error: "Token request not found" 
      });
    }

    const requestData = requestSnap.val();

    // Verify the request is still pending
    if (requestData.status !== 'pending') {
      return res.status(400).json({ 
        success: false, 
        error: `Request already ${requestData.status}` 
      });
    }

    // Update Token Request Status to 'rejected'
    await requestRef.update({
      status: 'rejected',
      rejectedAt: admin.database.ServerValue.TIMESTAMP,
      rejectedDate: new Date().toISOString(),
      rejectionReason: reason || 'No reason provided',
      processedBy: "admin"
    });

    // Update User's Token Request History
    await db.ref(`Users/${userId}/tokenRequestHistory/${requestId}`).update({
      status: 'rejected',
      rejectedAt: admin.database.ServerValue.TIMESTAMP,
      rejectedDate: new Date().toISOString(),
      rejectionReason: reason || 'No reason provided'
    });

    res.json({
      success: true,
      message: "Token request rejected successfully"
    });

  } catch (err) {
    console.error("Reject Token Request Error:", err);
    res.status(500).json({ 
      success: false, 
      error: "Failed to reject token request. Please try again." 
    });
  }
});



// ✅ GET API to fetch all token requests
app.get("/api/get-add-token-requests", async (req, res) => {
  try {
    // Correct Firebase reference
    const ref = db.ref("tokenRequests");

    // Fetch data
    const snapshot = await ref.once("value");

    if (!snapshot.exists()) {
      return res.status(404).json({
        success: false,
        message: "No token requests found",
      });
    }

    const data = snapshot.val();

    // Convert to array
    const formattedData = Object.entries(data).map(([key, value]) => ({
      id: key,
      ...value,
    }));

    res.status(200).json({
      success: true,
      total: formattedData.length,
      requests: formattedData,
    });
  } catch (error) {
    console.error("Error fetching token requests:", error);
    res.status(500).json({
      success: false,
      error: "Internal Server Error",
    });
  }
});



// user bank details api
 app.post('/api/banking/add', async (req, res) => {
    const { phoneNo, bankAccountNo, ifsc, upiId } = req.body;

    if (!phoneNo) {
      return res.status(400).json({ error: "Missing phoneNo" });
    }

    if ((!bankAccountNo || !ifsc) && !upiId) {
      return res.status(400).json({ error: "Provide either bankAccountNo+ifsc or upiId" });
    }

    try {
      const usersSnap = await db.ref("Users").once("value");
      const users = usersSnap.val();

      let userKey = null;
      for (const [key, user] of Object.entries(users || {})) {
        if (user.phoneNo === phoneNo) {
          userKey = key;
          break;
        }
      }

      if (!userKey) {
        return res.status(404).json({ error: "User not found" });
      }

      // Save data
      const bankingRef = db.ref(`Users/${userKey}/bankingDetails`);
      const bankingId = bankingRef.push().key; // unique id

      const bankingData = {
        bankAccountNo: bankAccountNo || null,
        ifsc: ifsc || null,
        upiId: upiId || null,
        createdAt: admin.database.ServerValue.TIMESTAMP
      };

      await bankingRef.child(bankingId).set(bankingData);

      res.json({ success: true, bankingId, message: "Banking details added successfully" });
    } catch (err) {
      console.error("Add banking error:", err);
      res.status(500).json({ error: "Failed to add banking details" });
    }
  });

 /**
 * Edit Banking Details
 * req.body = { phoneNo, bankingId, bankAccountNo?, ifsc?, upiId? }
 */
app.put('/api/banking/edit', async (req, res) => {
  const { phoneNo, bankingId, bankAccountNo, ifsc, upiId } = req.body;

  if (!phoneNo || !bankingId) {
    return res.status(400).json({ error: "Missing phoneNo or bankingId" });
  }

  try {
    const usersSnap = await db.ref("Users").once("value");
    const users = usersSnap.val();

    let userKey = null;
    for (const [key, user] of Object.entries(users || {})) {
      if (user.phoneNo === phoneNo) {
        userKey = key;
        break;
      }
    }

    if (!userKey) {
      return res.status(404).json({ error: "User not found" });
    }

    const bankingRef = db.ref(`Users/${userKey}/bankingDetails/${bankingId}`);
    const bankingSnap = await bankingRef.once("value");

    if (!bankingSnap.exists()) {
      return res.status(404).json({ error: "Banking record not found" });
    }

    const updates = {};
    if (bankAccountNo) updates.bankAccountNo = bankAccountNo;
    if (ifsc) updates.ifsc = ifsc;
    if (upiId) updates.upiId = upiId;

    // ✅ Flagging as unverified
    updates.status = "unverified";
    updates.updatedAt = admin.database.ServerValue.TIMESTAMP;

    await bankingRef.update(updates);

    res.json({ success: true, message: "Banking details updated and marked as unverified" });
  } catch (err) {
    console.error("Edit banking error:", err);
    res.status(500).json({ error: "Failed to edit banking details" });
  }
});


  app.delete('/api/banking/delete', async (req, res) => {
    const { phoneNo, bankingId } = req.body;

    if (!phoneNo || !bankingId) {
      return res.status(400).json({ error: "Missing phoneNo or bankingId" });
    }

    try {
      const usersSnap = await db.ref("Users").once("value");
      const users = usersSnap.val();

      let userKey = null;
      for (const [key, user] of Object.entries(users || {})) {
        if (user.phoneNo === phoneNo) {
          userKey = key;
          break;
        }
      }

      if (!userKey) {
        return res.status(404).json({ error: "User not found" });
      }

      const bankingRef = db.ref(`Users/${userKey}/bankingDetails/${bankingId}`);
      const bankingSnap = await bankingRef.once("value");

      if (!bankingSnap.exists()) {
        return res.status(404).json({ error: "Banking record not found" });
      }

      await bankingRef.remove();

      res.json({ success: true, message: "Banking details deleted successfully" });
    } catch (err) {
      console.error("Delete banking error:", err);
      res.status(500).json({ error: "Failed to delete banking details" });
    }
  });


  
// API endpoint to verify banking details
app.post('/api/verify-banking-detail', async (req, res) => {
  const { userId, detailId, type } = req.body;

  if (!userId || !detailId || !type) {
    return res.status(400).json({ error: "Missing userId, detailId, or type" });
  }

  try {
    // Find user by userId (assuming userId is the Firebase key or a field)
    const usersSnap = await db.ref("Users").once("value");
    const users = usersSnap.val();

    let userKey = null;
    for (const [key, user] of Object.entries(users || {})) {
      if (key === userId || user.userId === userId) {
        userKey = key;
        break;
      }
    }

    if (!userKey) {
      return res.status(404).json({ error: "User not found" });
    }

    const bankingRef = db.ref(`Users/${userKey}/bankingDetails/${detailId}`);
    const bankingSnap = await bankingRef.once("value");

    if (!bankingSnap.exists()) {
      return res.status(404).json({ error: "Banking record not found" });
    }

    // Update status to verified
    const updates = {
      status: "verified",
      verifiedAt: admin.database.ServerValue.TIMESTAMP,
      verifiedBy: "admin",
      updatedAt: admin.database.ServerValue.TIMESTAMP
    };

    await bankingRef.update(updates);

    res.json({ 
      success: true, 
      message: `${type} details verified successfully`,
      data: {
        userId,
        detailId,
        type,
        status: "verified"
      }
    });

  } catch (err) {
    console.error("Banking verification error:", err);
    res.status(500).json({ 
      success: false, 
      error: "Failed to verify banking details",
      message: err.message 
    });
  }
});



// Withdraw API
app.post("/api/request-withdrawal", async (req, res) => {
  try {
    const { phoneNo, tokens, method } = req.body;

    if (!phoneNo || !tokens || !method) {
      return res.status(400).json({ error: "phoneNo, tokens, and method are required" });
    }

    // 🔹 Find user by phoneNo
    const usersSnap = await db.ref("Users").once("value");
    const users = usersSnap.val();

    let userKey = null;
    let userData = null;

    for (const [key, user] of Object.entries(users || {})) {
      if (user.phoneNo === phoneNo) {
        userKey = key;
        userData = user;
        break;
      }
    }

    if (!userKey) {
      return res.status(404).json({ error: "User not found" });
    }

    const currentTokens = userData.tokens || 0;

    if (tokens > currentTokens) {
      return res.status(400).json({ error: "Insufficient tokens" });
    }

    // 🔹 Calculate tax (30%) and final withdrawal
    const tax = Math.floor(tokens * 0.3);
    const amountAfterTax = tokens - tax;

    // 🔹 Deduct tokens from user balance
    await db.ref(`Users/${userKey}`).update({
      tokens: currentTokens - tokens,
    });

    // 🔹 Find selected banking/upi details
    let selectedMethodDetails = null;

    if (userData.bankingDetails) {
      for (const [id, detail] of Object.entries(userData.bankingDetails)) {
        const isBank =
          detail.bankAccountNo && method.includes(detail.bankAccountNo);
        const isUpi = detail.upiId && method.includes(detail.upiId);

        if (isBank || isUpi) {
          selectedMethodDetails = {
            bankAccountNo: detail.bankAccountNo || null,
            ifsc: detail.ifsc || null,
            upiId: detail.upiId || null,
            status: detail.status || "unverified",
          };
          break;
        }
      }
    }

    // 🔹 Create withdrawal request inside user node
    const withdrawalsRef = db.ref(`Users/${userKey}/withdrawals`);
    const withdrawalId = withdrawalsRef.push().key;

    const withdrawalData = {
      requestedTokens: tokens,
      tax: tax,
      finalTokens: amountAfterTax,
      method: selectedMethodDetails || { raw: method }, // full bank/upi info
      status: "pending", // admin updates later
      createdAt: admin.database.ServerValue.TIMESTAMP,
    };

    await withdrawalsRef.child(withdrawalId).set(withdrawalData);

    res.json({
      success: true,
      message: "Withdrawal request submitted successfully",
      withdrawalId,
      withdrawal: withdrawalData,
    });
  } catch (error) {
    console.error("Error requesting withdrawal:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin API
app.patch("/api/withdrawals/:userId/:withdrawalId", async (req, res) => {
  try {
    const { userId, withdrawalId } = req.params;
    const { status } = req.body; // expected: "approved" or "rejected"

    if (!status || !["approved", "rejected"].includes(status)) {
      return res.status(400).json({ success: false, error: "Invalid status" });
    }

    const withdrawalRef = db.ref(`Users/${userId}/withdrawals/${withdrawalId}`);
    const withdrawalSnap = await withdrawalRef.once("value");

    if (!withdrawalSnap.exists()) {
      return res.status(404).json({ success: false, error: "Withdrawal not found" });
    }

    const withdrawal = withdrawalSnap.val();

    if (withdrawal.status !== "pending") {
      return res.status(400).json({ success: false, error: "Already processed" });
    }

    // ✅ If rejected, refund tokens to user
    if (status === "rejected") {
      const userRef = db.ref(`Users/${userId}`);
      const userSnap = await userRef.once("value");

      if (!userSnap.exists()) {
        return res.status(404).json({ success: false, error: "User not found" });
      }

      const userData = userSnap.val();
      const currentTokens = userData.tokens || 0;
      const refundTokens = withdrawal.requestedTokens || 0;

      await userRef.update({
        tokens: currentTokens + refundTokens,
      });
    }

    // ✅ Update withdrawal status
    await withdrawalRef.update({
      status: status,
      updatedAt: admin.database.ServerValue.TIMESTAMP,
    });

    return res.json({
      success: true,
      message: `Withdrawal ${status} successfully`,
      withdrawalId,
      status,
    });
  } catch (error) {
    console.error("Error updating withdrawal:", error);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});


app.get('/api/user-profile/json/:phoneNo', async (req, res) => {
    try {
        const { phoneNo } = req.params;
        console.log(`\nFetching user data for phone number: ${phoneNo}`);

        // Reference to the Users node
        const usersRef = admin.database().ref('Users');

        // Fetch data once
        const snapshot = await usersRef.once('value');
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
            console.log('\nUser Details Found:');
            console.log('User ID:', foundUserId);

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

            // Return JSON response instead of SSE
            res.json({
                success: true,
                tokens: userData.tokens || 0,
                userData: userData
            });
        } else {
            console.log('User not found for phone number:', phoneNo);
            res.json({
                success: false,
                message: 'User not found'
            });
        }
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching user data'
        });
    }
});



//root user creation api 
// app.post("/api/createRootUser", async (req, res) => {
//   try {
//     const { name, phoneNo, password, city, state, email } = req.body;

//     if (!name || !phoneNo || !password || !city || !state) {
//       return res.status(400).json({
//         success: false,
//         error: "Missing required fields: name, phoneNo, password, city, state"
//       });
//     }

//     // Generate IDs
//     const userId = "USER" + Math.random().toString(36).substring(2, 12).toUpperCase();
//     const myrefrelid = "REFI" + Math.random().toString(36).substring(2, 10).toUpperCase();

//     // Hash password
//     const hashedPassword = await bcrypt.hash(password, 10);

//     // Create user in Firebase Authentication
//     const userRecord = await firebaseAdmin.auth().createUser({
//       phoneNumber: `+91${phoneNo}`,
//       password: password,
//       displayName: name,
//       email: email || undefined,
//     });

//     const createdAt = new Date().toISOString();
//     const updatedAt = createdAt;

//     // Save in /Users
//     const dbRef = firebaseAdmin.database();
//     const userPath = "user-1";

//     const userData = {
//       id: "RootId",
//       name,
//       phoneNo,
//       email: email || null,
//       password: hashedPassword,
//       city,
//       state,
//       tokens: 200,
//       status: "active",
//       blocked: false,
//       createdAt,
//       updatedAt
//     };

//     await dbRef.ref(`/Users/${userPath}`).set(userData);

//     const userIdsData = {
//       myuserid: userId,
//       myrefrelid: myrefrelid
//     };
//     await dbRef.ref(`/Users/${userPath}/userIds`).set(userIdsData);

//     // Save in /binaryUsers
//     const binaryData = {
//       name,
//       myrefrelid,
//       leftChild: null,
//       rightChild: null,
//       Root: "RootId",
//       carryForward: {},
//     };
//     await dbRef.ref(`/binaryUsers/${userId}`).set(binaryData);

//     // Optional custom token
//     const customToken = await firebaseAdmin.auth().createCustomToken(userRecord.uid);

//     res.status(201).json({
//       success: true,
//       message: "Root user created successfully (with Firebase Auth entry)",
//       authUid: userRecord.uid,
//       customToken,
//       userData: {
//         userPath,
//         ...userData,
//         userIds: userIdsData
//       },
//       binaryData: {
//         userId,
//         ...binaryData
//       }
//     });

//   } catch (error) {
//     console.error("Error creating root user:", error);
//     res.status(500).json({
//       success: false,
//       error: error.message
//     });
//   }
// });



//APis for deleting user
// API: Delete a user completely (Admin triggered)
// app.delete('/api/admin/delete-user/:userIdentifier', async (req, res) => {
//   try {
//     const { userIdentifier } = req.params;

//     if (!userIdentifier) {
//       return res.status(400).json({ success: false, message: 'User identifier is required' });
//     }

//     const usersRef = db.ref('Users');
//     const snapshot = await usersRef.orderByChild('userIds/myuserid').equalTo(userIdentifier).once('value');

//     if (!snapshot.exists()) {
//       return res.status(404).json({ success: false, message: 'User not found' });
//     }

//     const userKey = Object.keys(snapshot.val())[0];
//     const userRef = usersRef.child(userKey);
//     const userData = snapshot.val()[userKey];
//     const userIdsData = userData.userIds || {};
//     const kycData = userData.kyc || {};
//     const bucket = firebaseAdmin.storage().bucket();

//     // 🔹 1. Delete KYC Documents
//     const deleteFile = async (url, label) => {
//       try {
//         if (!url) return;
//         let filePath = '';

//         if (url.includes('/o/')) {
//           filePath = decodeURIComponent(url.split('/o/')[1].split('?')[0]);
//         } else if (url.includes('/naphex-game.firebasestorage.app/')) {
//           const parts = url.split('/naphex-game.firebasestorage.app/');
//           if (parts.length > 1) filePath = parts[1];
//         }

//         if (filePath) {
//           await bucket.file(filePath).delete();
//           console.log(`✅ Deleted ${label}: ${filePath}`);
//         }
//       } catch (err) {
//         console.error(`❌ Error deleting ${label}:`, err.message);
//       }
//     };

//     await Promise.all([
//       deleteFile(kycData.aadharCardUrl, 'aadharCardUrl'),
//       deleteFile(kycData.panCardUrl, 'panCardUrl'),
//       deleteFile(kycData.bankPassbookUrl, 'bankPassbookUrl'),
//       deleteFile(kycData.selfieUrl, 'selfieUrl'),
//     ]);

//     // 🔹 2. Remove user from binaryUsers
//     if (userIdsData.myrefrelid) {
//       const binaryUsersRef = db.ref('binaryUsers');
//       const binarySnapshot = await binaryUsersRef.orderByChild('myrefrelid').equalTo(userIdsData.myrefrelid).once('value');

//       if (binarySnapshot.exists()) {
//         const binaryKey = Object.keys(binarySnapshot.val())[0];
//         const binaryData = binarySnapshot.val()[binaryKey];

//         if (binaryData.referralId) {
//           const parentRef = db.ref(`binaryUsers/${binaryData.referralId}`);
//           const parentSnap = await parentRef.once('value');
//           const parentData = parentSnap.val();

//           if (parentData) {
//             const updates = {};
//             if (parentData.leftChild === binaryKey) updates.leftChild = null;
//             if (parentData.rightChild === binaryKey) updates.rightChild = null;
//             if (Object.keys(updates).length) await parentRef.update(updates);
//           }
//         }

//         await binaryUsersRef.child(binaryKey).remove();
//         console.log('✅ Removed user from binaryUsers');
//       }
//     }

//     // 🔹 3. Delete Auth account
//     try {
//       let authUser = null;
//       if (userData.phoneNo) {
//         try {
//           authUser = await firebaseAdmin.auth().getUserByPhoneNumber(`+91${userData.phoneNo}`);
//         } catch {}
//       }
//       if (!authUser && userData.email) {
//         try {
//           authUser = await firebaseAdmin.auth().getUserByEmail(userData.email);
//         } catch {}
//       }

//       if (authUser) {
//         await firebaseAdmin.auth().deleteUser(authUser.uid);
//         console.log(`✅ Deleted Firebase Auth user: ${authUser.uid}`);
//       }
//     } catch (err) {
//       console.error('❌ Firebase Auth deletion error:', err.message);
//     }

//     // 🔹 4. Delete User Node
//     await userRef.remove();
//     console.log(`✅ Removed user data from Users: ${userKey}`);

//     // 🔹 5. (Optional) Log in deletedusers
//     const deletedLogRef = db.ref('deletedusers').push();
//     await deletedLogRef.set({
//       userId: userIdentifier,
//       name: userData.name || 'N/A',
//       phoneNo: userData.phoneNo || 'N/A',
//       email: userData.email || 'N/A',
//       deletedAt: new Date().toISOString(),
//       deletedBy: 'admin',
//     });

//     return res.json({
//       success: true,
//       message: `User ${userIdentifier} deleted successfully.`,
//       data: {
//         userKey,
//         deletedAt: new Date().toISOString(),
//       },
//     });
//   } catch (error) {
//     console.error('❌ Delete user error:', error);
//     return res.status(500).json({
//       success: false,
//       message: 'Failed to delete user completely',
//       error: error.message,
//     });
//   }
// });


//Api add user bank details from bank details component (Bank passbook image and cancelled check image)

// Add this API endpoint to your backend server

app.post("/api/banking/upload-documents", upload.fields([
    { name: 'passbookPhoto', maxCount: 1 },
    { name: 'cancelledChequePhoto', maxCount: 1 }
]), async (req, res) => {
    const { phoneNo } = req.body;

    // Validate required fields
    if (!phoneNo) {
        return res.status(400).json({
            success: false,
            error: "Phone number is required"
        });
    }

    // Validate that at least one file is uploaded
    if (!req.files || (!req.files.passbookPhoto && !req.files.cancelledChequePhoto)) {
        return res.status(400).json({
            success: false,
            error: 'At least one document (passbook or cancelled cheque) is required'
        });
    }

    try {
        const dbRef = firebaseAdmin.database();
        const usersRef = dbRef.ref('/Users');

        // Find user by phone number
        const snapshot = await usersRef.orderByChild('phoneNo').equalTo(phoneNo).once('value');
        
        if (!snapshot.exists()) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        let userPath = null;
        snapshot.forEach((childSnapshot) => {
            userPath = childSnapshot.key;
        });

        if (!userPath) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        // Upload documents to storage
        const documentUrls = {};
        const folderPath = `kyc-documents/${userPath}`;

        try {
            // Upload bank passbook if provided
            if (req.files.passbookPhoto && req.files.passbookPhoto[0]) {
                const passbookFile = req.files.passbookPhoto[0];
                const passbookFileName = `passbook_ingame_${Date.now()}_${path.extname(passbookFile.originalname)}`;
                documentUrls.bankPassbookUrlByInGame = await uploadFileToStorage(passbookFile, passbookFileName, folderPath);
            }

            // Upload cancelled cheque if provided
            if (req.files.cancelledChequePhoto && req.files.cancelledChequePhoto[0]) {
                const chequeFile = req.files.cancelledChequePhoto[0];
                const chequeFileName = `cancelledCheque_ingame_${Date.now()}_${path.extname(chequeFile.originalname)}`;
                documentUrls.cancelledChequeUrlByInGame = await uploadFileToStorage(chequeFile, chequeFileName, folderPath);
            }
        } catch (uploadError) {
            console.error('Error uploading bank documents:', uploadError);
            return res.status(500).json({
                success: false,
                message: 'Failed to upload bank documents.',
                error: uploadError.message,
            });
        }

        // Get existing KYC data
        const kycRef = dbRef.ref(`/Users/${userPath}/kyc`);
        const kycSnapshot = await kycRef.once('value');
        const existingKyc = kycSnapshot.val() || {};

        // Update KYC with new document URLs
        const updatedAt = new Date().toISOString();
        const kycUpdates = {
            ...documentUrls,
            bankDocumentsUploadedAt: updatedAt,
        };

        await kycRef.update(kycUpdates);

        res.status(200).json({
            success: true,
            message: "Bank documents uploaded successfully",
            data: {
                userPath,
                documentsUploaded: {
                    bankPassbook: !!documentUrls.bankPassbookUrlByInGame,
                    cancelledCheque: !!documentUrls.cancelledChequeUrlByInGame,
                },
                urls: documentUrls,
                uploadedAt: updatedAt
            }
        });

    } catch (error) {
        console.error('Error uploading bank documents:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to upload bank documents.',
            error: error.message,
        });
    }
});

//Admin apis to accept reject kyc images from in game

// API endpoint to verify or reject KYC bank images
app.post("/api/verify-kyc-bank-images", async (req, res) => {
    const { userId, action } = req.body;

    // Validate required fields
    if (!userId || !action) {
        return res.status(400).json({
            success: false,
            error: "userId and action are required"
        });
    }

    // Validate action value
    if (action !== 'verify' && action !== 'reject') {
        return res.status(400).json({
            success: false,
            error: "Action must be either 'verify' or 'reject'"
        });
    }

    try {
        const dbRef = firebaseAdmin.database();
        const userKycRef = dbRef.ref(`/Users/${userId}/kyc`);

        // Get existing KYC data
        const kycSnapshot = await userKycRef.once('value');
        const kycData = kycSnapshot.val();

        if (!kycData) {
            return res.status(404).json({
                success: false,
                error: 'KYC data not found for this user'
            });
        }

        // Check if bank documents exist
        if (!kycData.bankPassbookUrlByInGame && !kycData.cancelledChequeUrlByInGame) {
            return res.status(404).json({
                success: false,
                error: 'No bank documents found to verify/reject'
            });
        }

        if (action === 'verify') {
            // Accept the KYC documents
            const updatedAt = new Date().toISOString();
            
            await userKycRef.update({
                bankDocumentsStatus: 'verified',
                kycDetailsByInGame: 'accepted',
                bankDocumentsVerifiedAt: updatedAt
            });

            return res.status(200).json({
                success: true,
                message: 'KYC bank images verified successfully',
                data: {
                    userId,
                    status: 'verified',
                    verifiedAt: updatedAt
                }
            });

        } else if (action === 'reject') {
            // Reject and delete the documents
            
            // Helper function to delete file from storage using full URL
            const deleteFileFromStorage = async (fileUrl) => {
                if (!fileUrl) return;
                
                try {
                    const bucket = firebaseAdmin.storage().bucket();
                    
                    // Extract the file path from the full URL
                    // Example URL: https://storage.googleapis.com/naphex-game.firebasestorage.app/kyc-documents/user-1/passbook_ingame_1762156827148_.png
                    
                    let filePath = '';
                    
                    if (fileUrl.includes('storage.googleapis.com')) {
                        // Split by the domain and get everything after it
                        const urlParts = fileUrl.split('storage.googleapis.com/')[1];
                        if (urlParts) {
                            // Remove bucket name and get the path
                            const pathParts = urlParts.split('/');
                            // Skip the bucket name (first part) and join the rest
                            filePath = pathParts.slice(1).join('/');
                        }
                    } else if (fileUrl.includes('firebasestorage.googleapis.com')) {
                        // Alternative Firebase Storage URL format
                        const match = fileUrl.match(/\/o\/(.+?)\?/);
                        if (match && match[1]) {
                            filePath = decodeURIComponent(match[1]);
                        }
                    }
                    
                    if (!filePath) {
                        console.error('Could not extract file path from URL:', fileUrl);
                        return;
                    }
                    
                    console.log(`Attempting to delete file: ${filePath}`);
                    
                    const file = bucket.file(filePath);
                    const [exists] = await file.exists();
                    
                    if (exists) {
                        await file.delete();
                        console.log(`Successfully deleted file: ${filePath}`);
                    } else {
                        console.log(`File does not exist: ${filePath}`);
                    }
                } catch (error) {
                    console.error('Error deleting file from storage:', error);
                    // Don't throw error, continue with database update
                }
            };

            // Delete both documents from storage if they exist
            if (kycData.bankPassbookUrlByInGame) {
                await deleteFileFromStorage(kycData.bankPassbookUrlByInGame);
            }
            
            if (kycData.cancelledChequeUrlByInGame) {
                await deleteFileFromStorage(kycData.cancelledChequeUrlByInGame);
            }

            // Remove the document URLs and status from database
            const updatedAt = new Date().toISOString();
            
            await userKycRef.update({
                bankPassbookUrlByInGame: null,
                cancelledChequeUrlByInGame: null,
                bankDocumentsStatus: 'rejected',
                kycDetailsByInGame: 'rejected',
                bankDocumentsRejectedAt: updatedAt,
                bankDocumentsUploadedAt: null
            });

            return res.status(200).json({
                success: true,
                message: 'KYC bank images rejected and deleted successfully',
                data: {
                    userId,
                    status: 'rejected',
                    rejectedAt: updatedAt
                }
            });
        }

    } catch (error) {
        console.error('Error processing KYC bank images:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to process KYC bank images',
            error: error.message
        });
    }
});


//Server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});