var express = require('express');
var router = express.Router();
let userController = require('../controllers/users');
const { check_authentication } = require('../Utils/check_auth');
const bcrypt = require('bcrypt');

// Reset password về "123456" (Chỉ dành cho Admin)
router.get('/resetPassword/:id', check_authentication, async function(req, res, next) {
    try {
        let user = req.user;  // Lấy thông tin user từ middleware check_authentication

        if (user.role.roleName !== 'admin') {
            return res.status(403).send({
                success: false,
                message: "Only admin can reset passwords!"
            });
        }

        let userId = req.params.id;
        let newPassword = bcrypt.hashSync("123456", 10);
        
        let result = await userController.updatePassword(userId, newPassword);
        
        res.status(200).send({
            success: true,
            message: "Password has been reset successfully!",
            data: result
        });

    } catch (error) {
        next(error);
    }
});

// Change password (User đã đăng nhập mới đổi được mật khẩu)
router.post('/changePassword', check_authentication, async function(req, res, next) {
    try {
        let { currentPassword, newPassword } = req.body;
        let user = await userController.getUserById(req.user._id);

        if (!bcrypt.compareSync(currentPassword, user.password)) {
            return res.status(400).send({
                success: false,
                message: "Current password is incorrect!"
            });
        }

        let hashedNewPassword = bcrypt.hashSync(newPassword, 10);
        let result = await userController.updatePassword(req.user._id, hashedNewPassword);

        res.status(200).send({
            success: true,
            message: "Password changed successfully!",
            data: result
        });

    } catch (error) {
        next(error);
    }
});

module.exports = router;
