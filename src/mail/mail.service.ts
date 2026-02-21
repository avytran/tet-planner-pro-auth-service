// mail.service.ts
import { Injectable } from "@nestjs/common";
import * as nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

@Injectable()
export class MailService {
  private transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD,
      },
    });
  }

  async sendResetPasswordEmail(email: string, resetLink: string) {
    await this.transporter.sendMail({
      from: "Lucky Money Support Team",
      to: email,
      subject: "Reset your password",
      html: `
        <h3>Password Reset</h3>
        <p>You requested to reset your password.</p>
        <p>Click the link below (valid for 10 minutes):</p>
        <a href="${resetLink}">${resetLink}</a>
        <br/><br/>
        <p>If you did not request this, please ignore this email.</p>
      `,
    });
  }
}