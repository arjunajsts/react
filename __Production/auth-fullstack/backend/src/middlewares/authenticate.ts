import { AppErrorCode } from "@/constants/appErrorCode.js";
import { OK, UNAUTHORIZED } from "@/constants/http.js";
import { SessionModel } from "@/models/session.model.js";
import { appAssert } from "@/utils/appAssert.js";
import { clearAuthCookies } from "@/utils/cookies.js";
import { verifyToken } from "@/utils/jwt.js";
import type { RequestHandler } from "express";
import type mongoose from "mongoose";

export const authenticate: RequestHandler = async (req, res, next) => {
  const accessToken = req.cookies.accessToken as string | undefined;
  appAssert(
    accessToken,
    UNAUTHORIZED,
    "Not authorized",
    AppErrorCode.InvalidAccessToken
  );

  const { error, payload } = verifyToken(accessToken);
  appAssert(
    payload,
    UNAUTHORIZED,
    error === "jwt expired" ? "Token expired" : "Invalid token",
    AppErrorCode.InvalidAccessToken
  );

  // add userId & sessionId to req handler
  req.userId = payload.userId as mongoose.Types.ObjectId;
  req.sessionId = payload.sessionId as mongoose.Types.ObjectId;
 
  next();
};
