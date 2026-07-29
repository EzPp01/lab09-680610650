import { Router, type Request, type Response } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import type { User, UserPayload, CustomRequest, Enrollment } from "../libs/types.ts";

// import database
import { users, reset_users, enrollments, students, courses } from "../db/db.ts";

const router = Router();

// GET /api/v2/users
router.get("/", (req: Request, res: Response) => {
    const authHeader = req.headers["authorization"];

    //check auth
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            success: false,
            message: "Authorization header is required",
        });
    }

    console.log(authHeader);
    const token = authHeader.split(" ")[1];
    //check token
    if (token === null) {
        return res.status(401).json({
            success: false,
            message: "token is required",
        });
    }

    const jwt_secret = process.env.JWT_SECRET || "this_is_my_secret";
    jwt.verify(token, jwt_secret, (err, payload) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: "Invalid or expired token",
            });
        }

        //find payload
        const user_payload = payload as UserPayload;
        const user = users.find((u) => u.username === user_payload.username);

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized user",
            });
        }
        //admin see all user
        if (user.role === "ADMIN") {
            try {
                // return all users
                return res.json({
                    success: true,
                    data: enrollments,
                });
            } catch (err) {
                return res.status(500).json({
                    success: false,
                    message: "Something is wrong, please try again",
                    error: err,
                });
            }
        }
        //student see only youself
        if (user.role === "STUDENT") {
            const findstudent = enrollments.filter((e) => e.studentId === user.studentId)
            return res.status(200).json({
                success: true,
                data: findstudent
            })
        }
    })
});

// POST /api/v2/enrollments
router.post("/", (req: Request, res: Response) => {
    const authHeader = req.headers["authorization"];

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            success: false,
            message: "Authorization header is required",
        });
    }

    const token = authHeader.split(" ")[1];
    const jwt_secret = process.env.JWT_SECRET || "this_is_my_secret";

    jwt.verify(token, jwt_secret, (err, payload) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: "Invalid or expired token",
            });
        }

        const user_payload = payload as UserPayload;
        const user = users.find((u) => u.username === user_payload.username);

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized user",
            });
        }

        if (user.role === "ADMIN") {
            return res.status(403).json({
                success: false,
                message: "Only Student can access this API route",
            });
        }

        const { courseId } = req.body;

        const course = courses.find((c) => c.courseId === courseId);

        if (!course) {
            return res.status(404).json({
                success: false,
                message: "Course not found",
            });
        }

        const duplicate = enrollments.find(
            (e) => e.studentId === user.studentId && e.courseId === courseId
        );

        if (duplicate) {
            return res.status(400).json({
                success: false,
                message: "Already enrolled",
            });
        }

        enrollments.push({
            studentId: user.studentId!,
            courseId,
        });

        return res.status(201).json({
            success: true,
            message: "Enroll successful",
        });
    });
});

router.delete("/", (req: Request, res: Response) => {
    const authHeader = req.headers["authorization"];

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            success: false,
            message: "Authorization header is required",
        });
    }

    const token = authHeader.split(" ")[1];
    const jwt_secret = process.env.JWT_SECRET || "this_is_my_secret";

    jwt.verify(token, jwt_secret, (err, payload) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: "Invalid or expired token",
            });
        }

        const user_payload = payload as UserPayload;
        const user = users.find((u) => u.username === user_payload.username);

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized user",
            });
        }

        // ไม่อนุญาตให้ ADMIN ถอนรายวิชา
        if (user.role === "ADMIN") {
            return res.status(403).json({
                success: false,
                message: "Only Student can access this API route",
            });
        }

        const { courseId } = req.body;
        const studentId = user.studentId;

        if (!courseId) {
            return res.status(400).json({
                success: false,
                message: "Course Id is required",
            });
        }

        if (courseId.length !== 6) {
            return res.status(400).json({
                success: false,
                message: "Course Id must contain 6 characters",
            });
        }

        const findIndex = enrollments.findIndex(
            (e) =>
                e.courseId === courseId &&
                e.studentId === studentId
        );

        if (findIndex === -1) {
            return res.status(404).json({
                success: false,
                message: "Enrollment not found",
            });
        }

        enrollments.splice(findIndex, 1);

        const student = students.find(
            (s) => s.studentId === studentId
        );

        if (student?.courses) {
            const courseIndex = student.courses.findIndex(
                (c) => c === courseId
            );

            if (courseIndex !== -1) {
                student.courses.splice(courseIndex, 1);
            }
        }

        return res.status(200).json({
            success: true,
            message: "You have been dropped from this course.",
        });
    });
});
export default router;