const { MongoClient } = require('mongodb');
require('dotenv').config();

const client = new MongoClient(process.env.MONGO_URI);
let dbConnection;

module.exports = {
    connectToServer: async function () {
        if (dbConnection) return; 
        try {
            await client.connect();
            dbConnection = client.db('AlumniDirectory');
            console.log('Successfully connected to Native MongoDB.');
        } catch (err) {
            console.error('MongoDB connection error:', err);
            throw err;
        }
    },
    getDb: function () {
        return dbConnection;
    }
};