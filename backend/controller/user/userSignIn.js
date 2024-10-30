const bcrypt = require('bcryptjs')
const userModel = require('../../models/userModel')
const jwt = require('jsonwebtoken');

async function userSignInController(req,res){
    try {
        const { email, password } = req.body;
    
        if (!email) {
          throw new Error("Entrer un email valide");
        }
        if (!password) {
          throw new Error("Entrer  un mot de passe valide");
        }
    
        const user = await userModel.findOne({ email });
        if (!user) {
          throw new Error("Utilisateur non trouvé");
        }
    
        const checkPassword = await bcrypt.compare(password, user.password);
    
        if (checkPassword) {
          const tokenData = {
            _id: user._id,
            email: user.email,
          };
          const token = jwt.sign(tokenData, process.env.TOKEN_SECRET_KEY, {
            expiresIn: 60 * 60 * 8,
          });
          const tokenOption = {
            httpOnly: true,
            secure: true,
          };
          res.cookie("token", token, tokenOption).json({
            message: "Connexion réussie",
            data: token,
            success: true,
            error: false,
          });
        } else {
          throw new Error("Verifiez votre mot de passe ");
        }
      } catch (error) {
        res.json({
          message: error.message || error,
          error: true,
          success: false,
        });
      }


}

module.exports = userSignInController