// utils/mailer.ts

import ResetPasswordEmail from "@/emails/reset-password-email";
import VerificationCodeEmail from "@/emails/VerificationCodeEmail";
import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY!);
const FROM = process.env.MAIL_FROM || "Your App <no-reply@yourdomain.com>";

export async function sendResetEmailResend(args: {
  to: string;
  name?: string;
  resetUrl: string;
}) {
  const { to, name, resetUrl } = args;
  const { error } = await resend.emails.send({
    from: FROM,
    to,
    subject: "Reset your password",
    react: ResetPasswordEmail({ name, resetUrl }),
    // tip: avoid click/open tracking for security emails
  });
  if (error) throw error;
}


export async function sendVerifyEmailResend(args: {
  to: string;
  name?: string;
  code: string; // 6 digit
}) {
  const { to, name, code } = args;
  const { data, error } = await resend.emails.send({
    from: FROM,
    to,
    subject: "Verify your email with Goldkach",
    react: VerificationCodeEmail({ name, code }),
  });
  if (error) throw error;
  console.log("Verification email id:", data?.id, "to:", to);
  return { ok: true as const, id: data?.id };
}