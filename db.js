const { MongoClient } = require('mongodb');
require('dotenv').config();

const client = new MongoClient(process.env.MONGO_URI);
let dbConnection;

module.exports = {
    connectToServer: async function () {
        try {
            await client.connect();
            dbConnection = client.db('AlumniDirectory'); // Database er nam
            console.log('Successfully connected to Native MongoDB.');
        } catch (err) {
            console.error('MongoDB connection error:', err);
            process.exit(1);
        }
    },
    getDb: function () {
        return dbConnection;
    }
};