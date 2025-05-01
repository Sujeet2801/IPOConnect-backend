import { Router } from "express";
import { forgotPasswordRequest, loginUser, logoutUser, registerUser, resendVerificationEmail, verifyEmail } from "../controllers/user.controllers.js";
import { validate } from "../middlewares/validator.middleware.js";
import { userRegistrationValidator } from "../validators/index.js";

const router = Router();

router.route("/register").post(userRegistrationValidator(), validate, registerUser)
router.route("/verify/:token").get(verifyEmail)
router.route("/login").post(loginUser)
router.route("/logout").get(logoutUser)
router.route("/resendVerificationEmail").post(resendVerificationEmail)
router.route("/reset-password/:token").post(forgotPasswordRequest)

export default router;