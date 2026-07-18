import {Router} from "express";
import {register,getMe, refreshToken,logout,logoutall,login} from "../controllers/auth.controller.js"


const authRouter = Router();


authRouter.post("/register", register)

authRouter.get("/get-me",getMe)

authRouter.get("/refresh-token",refreshToken)


authRouter.get("/logout",logout)

authRouter.get("/logout-all",logoutall)
authRouter.post("/login",login)
export default authRouter;