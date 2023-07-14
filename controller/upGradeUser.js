const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const parser = require("ua-parser-js");
const Cryptr = require('cryptr');
const cryptr = new Cryptr(process.env.CRYPTER_KEY);
const sendEmail = require("../utils/sendEmail");

const { generateToken, hashToken } = require("../utils");

const db = require('../Database/db');


// Upgrade USERS Change users role
const upgradeUser = asyncHandler(async (req, res) => {
    const { role, id } = req.body;

    const q = 'UPDATE * SET `role` =? WHERE id = ?';
    const values = [
        role,
        id
    ]
    db.query(q, [values], async (err, user) => {
        console.log(user);
        console.log(q);
        console.log(values);
        if (err) {
            return res.status(500).json({
                message: "Something went wrong"
            })
        }
        if (!user) {
            res.status(404).json({
                message: "User not found"
            });
        }
        user.role = role;

        const result = ' INSERT INTO glopilot.users ( `role`, `id` ) VALUES (?)';
        const VALUES = [
            role,
            id
        ]
        db.query(result, (req, res) => {

        })

        res.status(200).json({
            message: `User role updated to ${role}`
        });
    });
})

// const user = await User.findById(id);


module.exports = upgradeUser;