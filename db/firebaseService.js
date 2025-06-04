const firebaseAdmin = require('firebase-admin');
const path = require('path');
require('dotenv').config();

// Use the service account file path from environment variables
const serviceAccountPath = path.resolve(process.env.FIREBASE_SERVICE_ACCOUNT);
const serviceAccount = require(serviceAccountPath);

const firebaseApp = firebaseAdmin.initializeApp({
    credential: firebaseAdmin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DB_URL,
});

// Initialize Firestore
const firestore = firebaseAdmin.firestore();

/**
 * Add a user to the "Users" node in Firebase Realtime Database and add a subcollection "userids".
 * Also stores user data in Firestore under "Users" collection.
 * @param {Object} userData - User data including name, phoneNo, email, password, referralId.
 * @param {Object} idsData - Data for the subcollection including myuserid and myrefrelid.
 * @returns {Object} Response with success message and user ID.
 */
const addUserToDatabase = async (userData, idsData) => {
    try {
        // Reference to the "Users" node in Firebase Realtime Database
        const usersRef = firebaseAdmin.database().ref('Users');

        // Get the current number of users
        const snapshot = await usersRef.once('value');
        const userCount = snapshot.numChildren();

        // Generate user ID like user-1, user-2, etc.
        const userId = `user-${userCount + 1}`;

        // Add the user data under the custom user ID in Realtime Database
        await usersRef.child(userId).set(userData);

        // Add the subcollection "userids" with provided data in Realtime Database
        const subCollectionRef = usersRef.child(`${userId}/userids`);
        await subCollectionRef.set(idsData);

        // Store user data in Firestore under "Users" collection
        await firestore.collection('Users').doc(userId).set(userData);

        // Store subcollection "userids" in Firestore
        await firestore.collection('Users').doc(userId).collection('userids').doc('idsData').set(idsData);

        return {
            success: true,
            message: 'User added successfully to Firebase Realtime Database and Firestore',
            userId: userId,
        };
    } catch (error) {
        console.error('Error adding user:', error);
        throw {
            success: false,
            message: error.message,
            error: error,
        };
    }
};

module.exports = {
    addUserToDatabase,
    firebaseAdmin,
    firestore,
};
