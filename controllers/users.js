let userModel = require('../schemas/users')
let bcrypt = require('bcrypt')
module.exports = {
    CreateAnUser: async function (username, password, email, role,
        avatarUrl, fullName, status, loginCount
    ) {
        let newUser = new userModel({
            username: username,
            password: password,
            email: email,
            role: role,
            avatarUrl: avatarUrl,
            fullName: fullName,
            status: status,
            loginCount: loginCount
        })
        await newUser.save();
        return newUser;
    },
    QueryByUserNameAndPassword: async function (username, password) {
        let getUser = await userModel.findOne({ username: username });
        if (!getUser) {
            return false;
        }
        let isMatch = await bcrypt.compare(password, getUser.password);
        if (!isMatch) {
            return false;
        }
        return getUser;
    },
    FindUserById: async function (id) {
        return await userModel.findOne({
            _id: id,
            isDeleted: false
        }).populate('role')
    },
    ChangePassword: async function (userId, oldPassword, newPassword) {
        let user = await userModel.findOne({ _id: userId, isDeleted: false });
        if (!user) {
            throw new Error("User khong ton tai");
        }
        let isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
            throw new Error("Mat khau cu khong dung");
        }
        // Hash new password manually and use updateOne to bypass pre-save double-hash
        let salt = bcrypt.genSaltSync(10);
        let hashedPassword = bcrypt.hashSync(newPassword, salt);
        await userModel.updateOne({ _id: userId }, { password: hashedPassword });
        return true;
    }
}