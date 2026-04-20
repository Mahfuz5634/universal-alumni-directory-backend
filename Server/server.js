const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { ObjectId } = require('mongodb');
const { connectToServer, getDb } = require('./db');
const { verifyToken, verifyAdmin } = require('./authMiddleware');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());


// 1. AUTHENTICATION APIs
// Register API (Alumni, Student ba Admin er jonno)
app.post('/api/auth/register', async (req, res) => {
    const db = getDb();
    const { name, email, password, role, university_id, graduation_year, student_roll_no } = req.body;

    try {
        // Password hashing
        const password_hash = await bcrypt.hash(password, 10);
        const newUser = {
            name, email, password_hash, university_id: new ObjectId(university_id),
            created_at: new Date()
        };

        let result;
        // Role onujayi specific collection e data insert kora 
        if (role === 'alumni') {
            newUser.graduation_year = graduation_year;
            newUser.is_verified = false;
            result = await db.collection('alumni').insertOne(newUser);
        } else if (role === 'student') {
            newUser.student_roll_no = student_roll_no;
            newUser.is_verified = false;
            result = await db.collection('running_students').insertOne(newUser);
        } else if (role === 'admin') {
            newUser.role = 'admin';
            result = await db.collection('admins').insertOne(newUser);
        } else {
            return res.status(400).json({ error: 'Invalid role' });
        }

        res.status(201).json({ message: 'User registered successfully', id: result.insertedId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Login API 
app.post('/api/auth/login', async (req, res) => {
    const db = getDb();
    const { email, password, role } = req.body; // role (alumni/student/admin) select kore login korbe

    try {
        let collectionName = role === 'student' ? 'running_students' : (role === 'admin' ? 'admins' : 'alumni');
        const user = await db.collection(collectionName).findOne({ email });

        if (!user) return res.status(404).json({ error: 'User not found' });

        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) return res.status(401).json({ error: 'Invalid password' });

        // JWT token generate kora 
        const token = jwt.sign(
            { id: user._id, email: user.email, role, university_id: user.university_id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(200).json({ message: 'Login successful', token, user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// 2. ALUMNI PROFILE APIs 

// Get Profile Details
app.get('/api/alumni/profile/:id', verifyToken, async (req, res) => {
    const db = getDb();
    try {
        const profile = await db.collection('alumni').findOne({ _id: new ObjectId(req.params.id) });
        res.status(200).json(profile);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update Profile 
app.put('/api/alumni/profile/:id', verifyToken, async (req, res) => {
    const db = getDb();
    const updateData = req.body; 
    // Delete password_hash from update body for security
    delete updateData.password_hash; 
    delete updateData.is_verified; // Alumni nije nije verified status change korte parbe na

    try {
        const result = await db.collection('alumni').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: updateData }
        );
        res.status(200).json({ message: 'Profile updated successfully', result });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// 3. DIRECTORY & SEARCH APIs 
// Get Directory (Filter & Search combined) 
app.get('/api/directory', verifyToken, async (req, res) => {
    const db = getDb();
    const { name, department, graduation_year, company, location, university_id } = req.query;
    let query = { is_verified: true }; // Shudhu verified alumni dekhabe

    // Dynamic Query Builder
    if (name) query.name = { $regex: name, $options: 'i' };
    if (department) query.department = { $regex: department, $options: 'i' };
    if (company) query.company = { $regex: company, $options: 'i' };
    if (location) query.location = { $regex: location, $options: 'i' };
    if (graduation_year) query.graduation_year = parseInt(graduation_year);
    if (university_id) query.university_id = new ObjectId(university_id);

    try {
        const alumniList = await db.collection('alumni').find(query).toArray();
        res.status(200).json(alumniList);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// 4. ADMIN APIs 

// Admin: Verify Alumni Profile 
app.put('/api/admin/verify/:id', verifyToken, verifyAdmin, async (req, res) => {
    const db = getDb();
    try {
        const result = await db.collection('alumni').updateOne(
            { _id: new ObjectId(req.params.id) },
            { 
                $set: { 
                    is_verified: true, 
                    verified_by: new ObjectId(req.user.id) // Admin er ID db image onujayi 
                } 
            }
        );
        res.status(200).json({ message: 'Alumni verified successfully', result });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Admin: Delete/Remove Alumni 
app.delete('/api/admin/delete/:id', verifyToken, verifyAdmin, async (req, res) => {
    const db = getDb();
    try {
        const result = await db.collection('alumni').deleteOne({ _id: new ObjectId(req.params.id) });
        res.status(200).json({ message: 'Alumni record deleted successfully', result });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// 5. UNIVERSITY APIs 

// Add University (Admin Only)
app.post('/api/universities', verifyToken, verifyAdmin, async (req, res) => {
    const db = getDb();
    const { name, location } = req.body;
    try {
        const result = await db.collection('universities').insertOne({
            name, location, created_at: new Date()
        });
        res.status(201).json({ message: 'University added', id: result.insertedId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Admin: Get all alumni (Verified + Unverified) for their specific university
app.get('/api/admin/alumni', verifyToken, verifyAdmin, async (req, res) => {
    const db = getDb();
    try {
        const query = { university_id: new ObjectId(req.user.university_id) };
        
        // সব অ্যালামনাই (verified এবং unverified) বের করে আনবে
        const alumniList = await db.collection('alumni').find(query).toArray();
        res.status(200).json(alumniList);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get verified alumni by specific University ID
app.get('/api/universities/:id/alumni', verifyToken, async (req, res) => {
    const db = getDb();
    try {
        const query = { 
            university_id: new ObjectId(req.params.id),
            is_verified: true // সাধারণ ইউজাররা শুধু verified অ্যালামনাইদের দেখতে পারবে
        };
        
        const alumniList = await db.collection('alumni').find(query).toArray();
        res.status(200).json(alumniList);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// Get all universities 
app.get('/api/universities', async (req, res) => {
    const db = getDb();
    try {
        const universities = await db.collection('universities').find({}).toArray();
        res.status(200).json(universities);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// SERVER INITIALIZATION
const PORT = process.env.PORT || 5000;

connectToServer().then(() => {
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
});