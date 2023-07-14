//we are going to import two functions from jsonwebtokens,sign and verify
require("dotenv").config
const {sign,verify} = require("jsonwebtoken")

//this function lets us create a token and send it to the users browser
// atoken is basically an object with information and it's secure because it is encrypted 
const createTokens =(user) =>{ 
    const accessToken = sign({username:user.username,id:user.id}, process.env.JWT_SECRET)

    return accessToken
}

const validateToken = (req, res, next) => {
  const accessToken = req.cookies["access-token"];

  if (!accessToken)
    return res.status(400).json({ error: "User not Authenticated!" });

  try {
    const validToken = verify(accessToken, process.env.JWT_SECRET);
    if (validToken) {
      req.authenticated = true;
      return next();
    }
  } catch (err) {
    return res.status(400).json({ error: err });
  }
};


module.exports ={createTokens,validateToken } 