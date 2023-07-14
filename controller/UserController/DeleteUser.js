const asyncHandler = require("express-async-handler");
const db = require('../../Database/db');

// Delete USERS
const deleteUser = asyncHandler(async (req, res) => {
    const user = req.params.id;
    const q = 'DELETE FROM `glopilot`.`users` WHERE id = ?'

    db.query(q, [user], (err, data) => {
        if (!user) {
            res.status(400)
            throw new Error("user not found");
        }
        if (err) {
            res.status(400)
            throw new Error("user delete not successfully");

        }
        res.status(200).json({
            message: "user delete successfully"
        });

    })


});

module.exports = deleteUser;