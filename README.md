# Balaji Ludo backend starter

This is a starter project, not a production-ready real-money gaming platform.

## Features
- SMS OTP flow using Twilio Verify (real SMS only after credentials are configured)
- OTP-verified phone account creation and 12-hour JWT session
- Deposit information endpoint for the provided UPI ID
- Withdrawal form API with a server-side maximum of 2 requests per user per local calendar day
- Bank holder name, account number and IFSC encrypted at rest using AES-256-GCM
- Withdrawal requests are `pending` for manual review; this code does not transfer money or credit deposits automatically

## Run locally
1. Install Node.js 20+.
2. Copy `.env.example` to `.env`.
3. Set `JWT_SECRET` to a random string of 32+ characters.
4. Set `BANK_ENCRYPTION_KEY` to 64 hexadecimal characters (32 random bytes).
   Generate one with: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
5. Create a Twilio Verify service and fill `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_VERIFY_SERVICE_SID`.
6. Run `npm install`, then `npm start`.
7. Open `http://localhost:3000`.

Phone numbers must be in E.164 format, e.g. `+919876543210`.

## Important production work still required
- Review legality and licensing for your jurisdiction before enabling real-money play.
- Use HTTPS, secure secrets management, backups, logging/monitoring, admin authentication and audit logs.
- Add account recovery, fraud controls, KYC only if legally required, rate limits and abuse monitoring.
- Integrate a compliant payment provider and verify payments server-to-server. Never credit a wallet based on a screenshot or client-side claim.
- Review data-protection obligations before collecting bank details; consider using a regulated payout provider/tokenization instead of storing bank account data.
- Add an authenticated admin workflow to approve/reject pending withdrawals and reconcile payout status.
- Configure timezone explicitly in production; the sample daily count uses the server's local date.
- Do not use fake OTPs or client-side-only withdrawal limits for real accounts.

The provided QR image is saved at `public/qr.png`. The starter UI currently shows the UPI ID; wire this image into `public/index.html` if you want it displayed.
