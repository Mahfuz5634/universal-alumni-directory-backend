const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'A token is required for authentication' });

    try {
        const decoded = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET);
        req.user = decoded;
    } catch (err) {
        return res.status(401).json({ error: 'Invalid Token' });
    }
    return next();
};

const verifyAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};
const verifySystemAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied. System Admin only.' });
    }
    next();
};

const verifyUniAdmin = (req, res, next) => {
    if (req.user.role !== 'uni_admin') {
        return res.status(403).json({ error: 'Access denied. University Admin only.' });
    }
    next();
};



module.exports = { verifyToken, verifyAdmin, verifySystemAdmin, verifyUniAdmin };