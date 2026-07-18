import userModel from "../models/user.model.js"
import crypto from "crypto";
import config from "../config/config.js"
import sessionModel from "../models/session.model.js";
import jwt from "jsonwebtoken";

 
async function register(req,res){
    try{
        const { username , email, password} = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({
                message: "All fields are required"
            });
        }
        const normalizedEmail = email.toLowerCase();
        const isAlreadyRegistered = await userModel.findOne({
        $or:[
            {username},
            {email:normalizedEmail}
        ]
        })
        if(isAlreadyRegistered){
            return res.status(409).json({
                message:"username or email already exist"
            })
        }
        const hashedPassword = crypto.createHash("sha256").update(password).digest("hex")
        const user = await userModel.create({
            username,
            email: normalizedEmail,
            password:hashedPassword
        })
        const refreshToken = jwt.sign({
            id:user._id,
        },config.JWT_SECRET,
        {

            expiresIn:"7d"
        })
        console.log("Register Refresh Token:", refreshToken);
        const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex")
        console.log("Register Hash:", refreshTokenHash);
        const session = await sessionModel.create({
            user:user._id,
            refreshTokenHash,
            ip:req.ip,
            userAgent:req.headers["user-agent"]
        })
        const accessToken = jwt.sign(
        {
           id: user._id,
           sessionId:session._id
        },
        config.JWT_SECRET,
        {
            expiresIn: "15m",
        });
        res.cookie("refreshToken",refreshToken,{
            httpOnly:true,
            secure:true,
            sameSite:"strict",
            maxAge: 7*24*60*60*1000
        })
        return res.status(201).json({
         message: "User registered successfully",
         accessToken,
        user: {
            id: user._id,
            username: user.username,
            email: user.email
            }
        });
    }catch(error){
        return res.status(500).json({
            message:error.message
        })
    }

}


async function login(req,res){
    const {email,password} = req.body;

    const user = await userModel.findOne({email})

    if(!user){
        return res.status(401).json({
            message:"invalid credential"
        })
    }
    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");
    const isPasswordValid = hashedPassword === user.password
    if(!isPasswordValid){
        return res.status(401).json({
            message:"Invalid email or password"
        })
    }
    const refreshToken = jwt.sign({
        id:user._id
    },config.JWT_SECRET,
    {
        expiresIn:"7d"
    })
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    const session = await sessionModel.create({
        user:user._id,
        refreshTokenHash,
        ip:req.ip,
        userAgent:req.headers["user-agent"]
    })
    const accessToken = jwt.sign({
        id:user._id,
        sessionId:session._id
    },config.JWT_SECRET,
    {
        expiresIn:"15m"
    })
    res.cookie("refreshToken",refreshToken,{
        httpOnly:true,
        secure:true,
        sameSite:"strict",
        maxAge:7 * 24 * 60 * 60 *1000
    })
    res.status(200).json({
        message:"Logged in successfully",
        user:{
            username:user.username,
            email:user.email,
        },
        accessToken,
    })
}

async function getMe(req,res){
    try{
        const token = req.headers.authorization?.split(" ")[1]; //Authorization header se JWT token nikalti hai.
        if(!token){
            return res.status(401).json({
                message:"Token not found"
            })
        }
        const decoded = jwt.verify(token,config.JWT_SECRET);
        const user = await userModel.findById(decoded.id)
        res.status(200).json({
            message:"user fetched succesfully",
            user:{
                username:user.username,
                email:user.email
            }
        })
    }catch(error){
        return res.status(401).json({
            message:"invalid or expired token"
        })
    }
}

async function refreshToken(req,res){
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken){
        return res.status(401).json({
            message:"Refresh token not found"
        })
    }
    const decoded = jwt.verify(refreshToken,config.JWT_SECRET)
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
    const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked:false
    })
    if(!session){
        return res.status(401).json({
            message:"Invalid refresh token"
        })
    }
    const accessToken = jwt.sign({
    id:decoded.id
    },config.JWT_SECRET,
    {
        expiresIn:"15m"
    }
    )
    const newRefreshToken = jwt.sign({ //agr kisi ne by mistake refresh token acess kr liya to 7 din tk accesss token generate kr lega, isliye hm access token k baad refresh token bhi change kr diye
        id:decoded.id,
    },config.JWT_SECRET,
    {
        expiresIn:"7d"
    })
    const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");
    session.refreshTokenHash = newRefreshTokenHash;
    await session.save();


    res.cookie("refreshToken",newRefreshToken,{
        httpOnly:true,
        secure:true,
        sameSite:"strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
    })
    res.status(200).json({
        message:"access token refresh successfully",
        accessToken,
    })
} 


async function logout (req,res){
    const refreshToken = req.cookies.refreshToken;
    console.log("Cookie:", refreshToken);
    if(!refreshToken){
        return res.status(400).json({
            message:"Refresh token not found"
        })
    }

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    console.log("Hash:", refreshTokenHash);

    const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked:false
    })
    console.log("Session:", session);
    if(!session){
        return res.status(400).json({
            message:"Invalid refresh token"
        })
    }
    session.revoked = true;
    await session.save();
    res.clearCookie("refreshToken")

    res.status(200).json({
        message:"Logged out successfully"
    })

}

async function logoutall(req,res){
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken){
        return res.status(400).json({
            message:"Refresh token not found"
        })
    }
     const decoded = jwt.verify(refreshToken,config.JWT_SECRET)

     await sessionModel.updateMany({
        user:decoded.id,
        revoked:false
     },{
        revoked:true
     })
     res.clearCookie("refreshToken")

     res.status(200).json({
        message:"Logged out from all devices successfully"
     })





}


export { register,getMe,refreshToken,logout ,login,logoutall};