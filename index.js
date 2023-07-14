const express = require("express")
require("dotenv").config()
const db =require("./models")
const {user} = require("./models")

const cookieParser = require("cookie-parser")
const jsonwebtoken = require("jsonwebtoken")
const app = express();
const bcrypt = require("bcrypt")
const {createTokens,validateToken} = require("./JWT")

app.use(express.json());
app.use(cookieParser())
app.use(express.urlencoded({ extended: true }));

app.post("/register",(req,res)=>{
    const {username, password } = req.body;
    bcrypt.hash(password, 10).then((hash)=>{
     user.create({
        username:username ,
        password :hash 
     }).then(()=>{
        res.json("registered successfully");
     }).catch((err)=>{
        if(err){
            res.status(400).json({error:err})
        }
     })
    })
     
})

app.post("/login", async(req,res)=>{
    const {username , password}= req.body
  const userperson = await user.findOne({where:{username:username}})

  if(!userperson) res.status(400).json({error:"User doesn't exist"})

  const dbPassword = userperson.password
  bcrypt.compare(password, dbPassword).then((match)=>{
    if(!match){
       res.status(400).json({error:"wrong password username combination"})
    }else{

        const accessToken = createTokens(userperson)//basically what we are doing here is creating a jwt token
        
        res.cookie("access-token", accessToken, {
            maxAge : 60*60*24*30,
            httpOnly:true
        })
        
        res.json("Logged in");
    }
  });
  
})

app.get("/profile", validateToken,(req,res)=>{
    res.json("profile")
})

const APP_PORT = process.env.PORT || 4000

db.sequelize.sync().then(()=>{
 app.listen(APP_PORT, () => {
   console.log(`server running on port ${APP_PORT}`);
 });
})

