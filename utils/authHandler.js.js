let jwt = require('jsonwebtoken')
let userController = require('../controllers/users')
module.exports = {
    checkLogin: async function (req, res, next) {
        try {
            let token
            if (req.cookies.token) {
                token = req.cookies.token
            } else {
                token = req.headers.authorization;
                if (!token || !token.startsWith("Bearer")) {
                    return res.status(403).send({ message: "ban chua dang nhap" })
                }
                token = token.split(' ')[1];
            }
            let result = jwt.verify(token, 'secret');
            if (result && result.exp * 1000 > Date.now()) {
                req.userId = result.id;
                next();
            } else {
                res.status(403).send({ message: "ban chua dang nhap" })
            }
        } catch (error) {
            res.status(403).send({ message: "token khong hop le hoac da het han" })
        }
    },
    checkRole: function (...requiredRole) {
        return async function (req, res, next) {
            let userId = req.userId;
            let user = await userController.FindUserById(userId);
            if (!user) {
                return res.status(403).send({ message: "user khong ton tai" });
            }
            let currentRole = user.role.name;
            if (requiredRole.includes(currentRole)) {
                next();
            } else {
                res.status(403).send({ message: "ban khong co quyen" });
            }
        }
    }
}