import { Router, type Request, type Response } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import type { User, UserPayload, CustomRequest } from "../libs/types.ts";

// import database
import { users, reset_users } from "../db/db.ts";

const router = Router();

// GET /api/v2/users
router.get("/", (req: Request, res: Response) => {

    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            success: false,
            message: "Authorization header is required"
        })
    }

    console.log(authHeader);
    const token = authHeader.split(" ")[1];

    if (token === null) {
        return res.status(401).json({
            success: false,
            message: "token is required"
        })
    }

    const jwt_secret = process.env.JWT_SECRET || "this_is_my_secret";
    jwt.verify(token, jwt_secret, (err, payload) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: "Invalid or expired token"
            })
        }

        //find payload
        const user_payload = payload as UserPayload;
        const user = users.find((u) => u.username === user_payload.username)

        if (!user || user.role !== "ADMIN") {
            return res.status(401).json({
                success: false,
                message: "Unauthorized user"
            })
        }
    })

    try {
        // return all users
        return res.json({
            success: true,
            data: users,
        });
    } catch (err) {
        return res.status(200).json({
            success: false,
            message: "Something is wrong, please try again",
            error: err,
        });
    }
});

// POST /api/v2/users/login
router.post("/login", (req: Request, res: Response) => {
    // 1. get username and password from body
    const { username, password } = req.body;
    const user = users.find((u) => u.username === username && u.password === password);

    // 2. check if user exists (search with username & password in DB)
    if (!user) {
        return res.status(404).json({
            success: false,
            message: "Invalid username or password"
        })
    }

    // 3. create JWT token (with user info object as payload) using JWT_SECRET_KEY
    const jwt_secret = process.env.jwt_secret || "this_is_my_secret";
    const token = jwt.sign(
        {
            //app payload
            username: user.username,
            studentId: user.studentId,
            role: user.role
        },
        jwt_secret,
        { expiresIn: "30m" }
    )
    //    (optional: save the token as part of User data)

    // 4. send HTTP response with JWT token
    return res.status(200).json({
        success: true,
        message: "Login successful",
        token: token
    })
    return res.status(500).json({
        success: false,
        message: "POST /api/v2/users/login has not been implemented yet",
    });
});

// POST /api/v2/users/logout
router.post("/logout", (req: Request, res: Response) => {
    // 1. check Request if "authorization" header exists
    //    and container "Bearer ...JWT-Token..."

    // 2. extract the "...JWT-Token..." if available

    // 3. verify token using JWT_SECRET_KEY and get payload (username, studentId and role)

    // 4. check if user exists (search with username)

    // 5. proceed with logout process and return HTTP response
    //    (optional: remove the token from User data)

    return res.status(500).json({
        success: false,
        message: "POST /api/v2/users/logout has not been implemented yet",
    });
});

// POST /api/v2/users/reset
router.post("/reset", (req: Request, res: Response) => {
    try {
        reset_users();
        return res.status(200).json({
            success: true,
            message: "User database has been reset",
        });
    } catch (err) {
        return res.status(500).json({
            success: false,
            message: "Something is wrong, please try again",
            error: err,
        });
    }
});
export default router;