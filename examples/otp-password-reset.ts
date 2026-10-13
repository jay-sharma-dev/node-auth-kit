/**
 * Example: flexible OTP delivery for password reset.
 *
 * Plug in YOUR SMTP or SMS gateway by implementing OtpDelivery.
 * jay-auth-kit generates/verifies OTPs — it does not call providers directly.
 */
import "dotenv/config";
import { createAuth, createChannelDelivery, type OtpDelivery } from "../src/index";

// --- SMTP adapter (Nodemailer / Resend / SES / etc.) ---
const smtpDelivery: OtpDelivery = {
  async send({ to, code, purpose, expiresAt }) {
    // Example with fetch + Resend, or replace with nodemailer:
    // await transporter.sendMail({
    //   to,
    //   subject: "Password reset code",
    //   text: `Your ${purpose} code is ${code}. Expires at ${expiresAt.toISOString()}`,
    // });
    console.log(`[SMTP] to=${to} purpose=${purpose} code=${code} expires=${expiresAt.toISOString()}`);
  },
};

// --- SMS adapter (Twilio / MSG91 / SNS / etc.) ---
const smsDelivery: OtpDelivery = {
  async send({ to, code, purpose, expiresAt }) {
    // Example:
    // await twilio.messages.create({
    //   to,
    //   from: process.env.TWILIO_FROM,
    //   body: `Your ${purpose} code is ${code}`,
    // });
    console.log(`[SMS] to=${to} purpose=${purpose} code=${code} expires=${expiresAt.toISOString()}`);
  },
};

const delivery = createChannelDelivery({
  email: smtpDelivery,
  sms: smsDelivery,
});

const auth = createAuth({ delivery });

async function demoEmailReset() {
  // 1) User requests reset via email
  const requested = await auth.passwordReset!.requestReset({
    to: "user@example.com",
    channel: "email",
    meta: { locale: "en" },
  });

  // Persist requested.challenge in your DB (hashed OTP + expiry + attempts)
  console.log("store challenge:", {
    destination: requested.challenge.destination,
    expiresAt: requested.expiresAt,
  });

  // 2) User submits OTP + new password (use the code printed by the adapter above)
  // In real apps the code comes from the request body — never from logs.
}

async function demoSmsReset() {
  await auth.passwordReset!.requestReset({
    to: "+15551234567",
    channel: "sms",
  });
}

await demoEmailReset();
await demoSmsReset();
