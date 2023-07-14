const asyncHandler = require("express-async-handler");
const db = require('../../Database/db');

// Get All USERS
const getAllUsers = asyncHandler(async (req, res) => {
    const user = 'SELECT * FROM glopilot.users';
    db.query(user, (err, data) => {
        if (err) {
            res.status(500).json({
                message: "Something went wrong "
            });
        }
        res.status(200).json(data);
    })


})

module.exports = getAllUsers;