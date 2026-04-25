# Universal Alumni Platform Project for course: Software Development ( CSE-416 )
## Project Developers:
### Name: MD. Mahfuz (ID:0432310005101057)
### Name: Hrithik Saha (ID:0432310005101071)

# Universal Alumni Platform — Backend

This is the backend service for a universal alumni networking platform that supports multiple user roles, university-wise administration, and secure alumni verification.

Built with Node.js, Express.js, MongoDB, and JWT authentication, the backend handles user registration, login, role-based authorization, university management, and alumni verification workflows.

## Project Overview

The backend powers a system where:

- Students and alumni can create accounts and log in based on their role
- University admins can be created for specific universities
- University admins can verify alumni from their own university
- Super admins have full access across the platform
- Alumni profiles can store public professional links such as LinkedIn and GitHub
- Running students can access verified alumni information for networking

## Features

- JWT-based authentication
- Role-based authorization
- User registration and login
- University-wise admin account creation
- Alumni profile management
- Alumni verification by university admins
- Super admin access control
- Secure REST API architecture
- MongoDB database integration
- Scalable backend structure

## Tech Stack

- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** MongoDB
- **Authentication:** JWT
- **Hosting:** Vercel
- **Password Security:** bcrypt
- **API Style:** REST API

## Getting Started

### Prerequisites

  Make sure the following are installed:
  
  - Node.js
  - npm
  - MongoDB
  ### Installation

### Clone the repository:

  git clone https://github.com/Mahfuz5634/universal-alumni-directory-backend
  cd your-backend-repo

### Install dependencies:

  npm install
  Environment Variables

### Create a .env file in the root directory and add the following:

  PORT=5000
  MONGO_URI=your_mongodb_connection_string
  JWT_SECRET=your_jwt_secret_key
  CLIENT_URL=http://localhost:3000

### Adjust these values according to your local setup or production environment.

### Running the Server

  Start the development server:
  
  npm run dev
  
  Or run the server normally:
  
  npm start
  API Structure

### The backend is organized around role-based and university-based operations such as:

  Authentication routes
  User profile routes
  Alumni verification routes
  University management routes
  Admin management routes
  Super admin routes
### Example API Endpoints
  ```md
  POST   /api/auth/register  
  POST   /api/auth/login  
  GET    /api/users/profile  
  GET    /api/alumni  
  PATCH  /api/alumni/verify/:id  
  POST   /api/university/create  
  GET    /api/admin/university/:id  
```
### Authentication Flow
```md
  User registers as a student, alumni, university admin, or super admin
  User logs in with valid credentials
  JWT token is issued after successful authentication
  Protected routes verify the token
  Role-based middleware controls access to each route
  Authorization Levels
  Running Student: Can view alumni profiles and contact links
  Alumni: Can manage personal profile and professional information
  University Admin: Can verify alumni of their own university
  Super Admin: Can manage all universities, admins, and users
  ```
### Database Model:
```md
  User
  University
  Alumni Profile
  Verification Request
  Role / Permission data
  Security Features
  Password hashing with bcrypt
  JWT authentication
  Protected routes with middleware
  Role-based access control
  Validation for sensitive operations
  Deployment
```
This backend is deployed on Vercel.
Before deployment, make sure your environment variables are properly configured.

### Future Enhancements:
```md
  Email verification
  Forgot password flow
  Advanced admin analytics
  Search and filtering APIs
  Notification system
  Alumni event management
  Real-time messaging support
```
