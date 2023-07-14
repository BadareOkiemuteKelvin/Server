const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const parser = require("ua-parser-js");

const { generateToken, hashToken } = require("../../utils");

const db = require('../../Database/db');



// Register USER
const register = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    // validation
    if (!name || !email || !password) {
        res.status(400)
        throw new Error("Please fill in all the require fields.");
    }
    if (password.length < 6) {
        res.status(400)
        throw new Error("Password must not less than 6 characters.");
    }
    const q = 'SELECT * FROM glopilot.users WHERE email = ?';
    // check if the user exists
    db.query(q, [email], async (err, userExists) => {
        if (err) return console.log(err);
        if (userExists[0]) return res.json({ status: "error", error: "User exist already login instead" })

        // hashed password,
        //  const salt = bcrypt.genSaltSync(10);

        //const hashPassword = await bcrypt.hash(password, 10)
        // Get UserAgent
        const ua = parser(req.headers['user-agent']);
        const userAgent = [ua.ua]
        console.log("hashhhhhh", password);
        // Create new user 
        db.query('INSERT INTO glopilot.users SET name =?, email =?, password =?, userAgent=?', [name, email, password, userAgent], (err, data) => {
            if (err) throw err;
            // Generate Token 
            console.log(data);
            const token = generateToken(data.id);
            console.log(data);
            // Send HTTP 
            res.cookie("token", token, {
                path: "/",
                httpOnly: true,
                expires: new Date(Date.now() + 1000 * 86400), // 1 day
                sameSite: "none",
            })


            if (data) {
                const { id, name, email, number, bio, photo, role, isVerified } = data;

                res.status(201).json({
                    id,
                    name,
                    email,
                    number,
                    bio,
                    photo,
                    role,
                    isVerified,
                    token
                })

            } else {
                res.status(400)
                throw new Error("Invalid user input");
            }

            return console.log(data);
        })


    })



});


module.exports = register;