let userSchema = require('../models/users');
let roleSchema = require('../models/roles');
let bcrypt = require('bcrypt');
let jwt = require('jsonwebtoken');
let constants = require('../Utils/constants');

module.exports = {
    // Lấy user theo ID (bao gồm thông tin role)
    getUserById: async function(id) {
        return await userSchema.findById(id).populate("role");
    },

    // Tạo user mới
    createUser: async function(username, password, email, role) {
        let roleCheck = await roleSchema.findOne({ roleName: role });

        if (!roleCheck) {
            throw new Error("Role không tồn tại");
        }

        let hashedPassword = bcrypt.hashSync(password, 10);
        let newUser = new userSchema({
            username: username,
            password: hashedPassword,
            email: email,
            role: roleCheck._id,
        });

        await newUser.save();
        return newUser;
    },

    // Kiểm tra đăng nhập
    checkLogin: async function(username, password) {
        if (!username || !password) {
            throw new Error("Username hoặc password không được để trống");
        }

        let user = await userSchema.findOne({ username: username }).populate("role");

        if (!user || !bcrypt.compareSync(password, user.password)) {
            throw new Error("Username hoặc password không chính xác");
        }

        return jwt.sign({
            id: user._id,
            role: user.role.roleName,
            expired: new Date(Date.now() + 30 * 60 * 1000) // Token hết hạn sau 30 phút
        }, constants.SECRET_KEY);
    },

    // Cập nhật mật khẩu người dùng
    updatePassword: async function(userId, newPassword) {
        let hashedPassword = bcrypt.hashSync(newPassword, 10);
        return await userSchema.findByIdAndUpdate(userId, { password: hashedPassword }, { new: true });
    }
};
