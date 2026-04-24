const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { ObjectId } = require("mongodb");
const { connectToServer, getDb } = require("../DB connection/db");
const {
  verifyToken,
  verifySystemAdmin,
  verifyUniAdmin,
} = require("../Auth/authMiddleware");
require("dotenv").config();

const app = express();
const corsOptions = {
  origin: [
    'https://universal-alumni-directory-frontend.vercel.app', 
    'http://localhost:5173' 
  ],
  credentials: true, 
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
};

app.use(cors(corsOptions))
app.use(express.json());

// 1. AUTHENTICATION APIs
app.post("/api/auth/register", async (req, res) => {
  const db = getDb();
  const {
    name,
    email,
    password,
    role,
    university_id,
    graduation_year,
    department,
    student_roll_no,
    company,
    position,
    linkedin_id,
    github_id,
    contact_number,
  } = req.body;

  if (role === "admin" || role === "uni_admin") {
    return res
      .status(403)
      .json({ error: "Admins must be created by System Admin" });
  }

  try {
    const password_hash = await bcrypt.hash(password, 10);
    const newUser = {
      name,
      email,
      password_hash,
      university_id: new ObjectId(university_id),
      department,
      contact_number,
      created_at: new Date(),
    };

    let result;

    if (role === "alumni") {
      Object.assign(newUser, {
        role: "alumni",
        graduation_year: parseInt(graduation_year),
        student_roll_no,
        company,
        position,
        linkedin_id,
        github_id,
        is_verified: false,
      });
      result = await db.collection("alumni").insertOne(newUser);
    } else if (role === "student") {
      Object.assign(newUser, {
        role: "student",
        graduation_year: parseInt(graduation_year),
        is_verified: true,
      });
      result = await db.collection("running_students").insertOne(newUser);
    } else {
      return res.status(400).json({ error: "Invalid role" });
    }

    res
      .status(201)
      .json({ message: "User registered successfully", id: result.insertedId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const db = getDb();
  const { email, password, role } = req.body;

  try {
    let collectionName = "alumni";
    if (role === "student") collectionName = "running_students";
    if (role === "admin" || role === "uni_admin") collectionName = "admins";

    const user = await db.collection(collectionName).findOne({ email, role });

    if (!user)
      return res.status(404).json({ error: "User not found or role mismatch" });

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid)
      return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign(
      {
        id: user._id,
        email: user.email,
        role: user.role,
        university_id: user.university_id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" },
    );

    delete user.password_hash;
    res.status(200).json({ message: "Login successful", token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. DIRECTORY & SEARCH APIs
app.get("/api/directory", verifyToken, async (req, res) => {
  const db = getDb();
  const { department, graduation_year, company, university_id } = req.query;
  const userRole = req.user.role;
  const userUniId = req.user.university_id;

  let query = {};

  if (userRole === "student" || userRole === "alumni") {
    query.is_verified = true;
    query.university_id = new ObjectId(userUniId);
  } else if (userRole === "uni_admin") {
    query.university_id = new ObjectId(userUniId);
  } else if (userRole === "admin") {
    if (university_id) query.university_id = new ObjectId(university_id);
  }

  if (department) query.department = { $regex: department, $options: "i" };
  if (company) query.company = { $regex: company, $options: "i" };
  if (graduation_year) query.graduation_year = parseInt(graduation_year);

  try {
    const alumniList = await db.collection("alumni").find(query).toArray();
    res.status(200).json(alumniList);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. SYSTEM ADMIN APIs
// Add University
app.post(
  "/api/universities",
  verifyToken,
  verifySystemAdmin,
  async (req, res) => {
    const db = getDb();
    const { name, location } = req.body;
    try {
      const result = await db
        .collection("universities")
        .insertOne({ name, location, created_at: new Date() });
      res
        .status(201)
        .json({ message: "University added", id: result.insertedId });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// Edit University
app.put(
  "/api/universities/:id",
  verifyToken,
  verifySystemAdmin,
  async (req, res) => {
    const db = getDb();
    try {
      const result = await db
        .collection("universities")
        .updateOne({ _id: new ObjectId(req.params.id) }, { $set: req.body });
      res.status(200).json({ message: "University updated", result });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// Delete University
app.delete(
  "/api/universities/:id",
  verifyToken,
  verifySystemAdmin,
  async (req, res) => {
    const db = getDb();
    try {
      const result = await db
        .collection("universities")
        .deleteOne({ _id: new ObjectId(req.params.id) });
      res.status(200).json({ message: "University deleted", result });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// Create University Admin
app.post(
  "/api/admin/system/create-uni-admin",
  verifyToken,
  verifySystemAdmin,
  async (req, res) => {
    const db = getDb();
    const { name, email, password, university_id } = req.body;
    try {
      const password_hash = await bcrypt.hash(password, 10);
      const newUniAdmin = {
        name,
        email,
        password_hash,
        role: "uni_admin",
        university_id: new ObjectId(university_id),
        created_at: new Date(),
      };
      const result = await db.collection("admins").insertOne(newUniAdmin);
      res.status(201).json({
        message: "University Admin created successfully",
        id: result.insertedId,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// Edit/Change Uni Admin details
app.put(
  "/api/admin/system/uni-admin/:id",
  verifyToken,
  verifySystemAdmin,
  async (req, res) => {
    const db = getDb();
    const updateData = req.body;
    if (updateData.password)
      updateData.password_hash = await bcrypt.hash(updateData.password, 10);
    delete updateData.password;

    try {
      const result = await db
        .collection("admins")
        .updateOne(
          { _id: new ObjectId(req.params.id), role: "uni_admin" },
          { $set: updateData },
        );
      res.status(200).json({ message: "Uni Admin updated", result });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// System Admin: View ALL Alumni (Any University)
app.get(
  "/api/admin/system/all-alumni",
  verifyToken,
  verifySystemAdmin,
  async (req, res) => {
    const db = getDb();
    try {
      const alumniList = await db.collection("alumni").find({}).toArray();
      res.status(200).json(alumniList);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// System Admin: Delete ANY Alumni
app.delete(
  "/api/admin/system/alumni/:id",
  verifyToken,
  verifySystemAdmin,
  async (req, res) => {
    const db = getDb();
    try {
      const result = await db
        .collection("alumni")
        .deleteOne({ _id: new ObjectId(req.params.id) });
      res
        .status(200)
        .json({ message: "Alumni deleted by System Admin", result });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// 4. UNIVERSITY ADMIN APIs
// Verify Alumni
app.put(
  "/api/admin/uni/verify/:alumni_id",
  verifyToken,
  verifyUniAdmin,
  async (req, res) => {
    const db = getDb();
    try {
      const alumniId = new ObjectId(req.params.alumni_id);
      const alumni = await db.collection("alumni").findOne({ _id: alumniId });

      if (!alumni) return res.status(404).json({ error: "Alumni not found" });
      if (alumni.university_id.toString() !== req.user.university_id) {
        return res.status(403).json({
          error: "You can only verify alumni from your own university",
        });
      }

      const result = await db.collection("alumni").updateOne(
        { _id: alumniId },
        {
          $set: { is_verified: true, verified_by: new ObjectId(req.user.id) },
        },
      );
      res.status(200).json({ message: "Alumni verified", result });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// System Admin: View list of ALL University Admins
app.get(
  "/api/admin/system/all-uni-admins",
  verifyToken,
  verifySystemAdmin,
  async (req, res) => {
    const db = getDb();
    try {
      const uniAdmins = await db
        .collection("admins")
        .find({ role: "uni_admin" })
        .project({ password_hash: 0 })
        .toArray();

      res.status(200).json(uniAdmins);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// University Admin: View all students of their OWN university
app.get(
  "/api/admin/uni/all-students",
  verifyToken,
  verifyUniAdmin,
  async (req, res) => {
    const db = getDb();
    try {
      // Shudhu oi admin er university_id er sathe match kora student-der khujbe
      const query = { university_id: new ObjectId(req.user.university_id) };

      const studentsList = await db
        .collection("running_students")
        .find(query)
        .project({ password_hash: 0 }) // Password_hash bad diye data nibe
        .toArray();

      res.status(200).json(studentsList);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// Unverify Alumni (Reject / Revoke verification)
app.put(
  "/api/admin/uni/unverify/:alumni_id",
  verifyToken,
  verifyUniAdmin,
  async (req, res) => {
    const db = getDb();
    try {
      const alumniId = new ObjectId(req.params.alumni_id);
      const alumni = await db.collection("alumni").findOne({ _id: alumniId });

      if (!alumni) return res.status(404).json({ error: "Alumni not found" });
      if (alumni.university_id.toString() !== req.user.university_id) {
        return res.status(403).json({ error: "Access denied" });
      }

      const result = await db
        .collection("alumni")
        .updateOne(
          { _id: alumniId },
          { $set: { is_verified: false, verified_by: null } },
        );
      res.status(200).json({ message: "Alumni unverified", result });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// Delete Alumni (Own University)
app.delete(
  "/api/admin/uni/alumni/:alumni_id",
  verifyToken,
  verifyUniAdmin,
  async (req, res) => {
    const db = getDb();
    try {
      const alumniId = new ObjectId(req.params.alumni_id);
      const alumni = await db.collection("alumni").findOne({ _id: alumniId });

      if (
        !alumni ||
        alumni.university_id.toString() !== req.user.university_id
      ) {
        return res
          .status(403)
          .json({ error: "Alumni not found in your university" });
      }

      const result = await db.collection("alumni").deleteOne({ _id: alumniId });
      res.status(200).json({ message: "Alumni deleted successfully", result });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// Delete Student (Own University)
app.delete(
  "/api/admin/uni/student/:student_id",
  verifyToken,
  verifyUniAdmin,
  async (req, res) => {
    const db = getDb();
    try {
      const studentId = new ObjectId(req.params.student_id);
      const student = await db
        .collection("running_students")
        .findOne({ _id: studentId });

      if (
        !student ||
        student.university_id.toString() !== req.user.university_id
      ) {
        return res
          .status(403)
          .json({ error: "Student not found in your university" });
      }

      const result = await db
        .collection("running_students")
        .deleteOne({ _id: studentId });
      res.status(200).json({ message: "Student deleted successfully", result });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// 5. GENERAL APIs
app.get("/api/universities", async (req, res) => {
  const db = getDb();
  try {
    const universities = await db.collection("universities").find({}).toArray();
    res.status(200).json(universities);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/alumni/profile/:id", verifyToken, async (req, res) => {
  const db = getDb();
  try {
    const profile = await db
      .collection("alumni")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (profile) delete profile.password_hash;
    res.status(200).json(profile);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/alumni/profile/:id", verifyToken, async (req, res) => {
  const db = getDb();
  const updateData = req.body;
  delete updateData.password_hash;
  delete updateData.is_verified;
  delete updateData.role;

  try {
    const result = await db
      .collection("alumni")
      .updateOne({ _id: new ObjectId(req.params.id) }, { $set: updateData });
    res.status(200).json({ message: "Profile updated successfully", result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/', (req, res) => {
  res.send('Alumni Directory Backend Server is Running Perfectly!');
});

//const PORT = process.env.PORT || 5000;



