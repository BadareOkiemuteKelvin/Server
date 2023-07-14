const asyncHandler = require("express-async-handler");
const jwt = require("jsonwebtoken");
const db = require('../Database/db');

const loginStatus = asyncHandler(async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json(false)
    }
    // verified token
    const verified = jwt.verify(token, process.env.JWT_SECTRET);
    if (verified) {
        return res.json(true)
    } else {
        return res.json(false)
    }
});
module.exports = loginStatus;