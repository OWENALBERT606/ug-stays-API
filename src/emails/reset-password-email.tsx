

// emails/ResetPasswordEmail.tsx
import * as React from "react";
import {
  Html,
  Head,
  Preview,
  Body,
  Container,
  Section,
  Text,
  Button,
  Hr,
  Link,
  Img,
} from "@react-email/components";

type Props = {
  name?: string;
  resetUrl: string; // must be absolute: https://yourapp.com/reset-password?token=...&uid=...
};

export default function ResetPasswordEmail({ name = "there", resetUrl }: Props) {
  const year = new Date().getFullYear();

  return (
    <Html>
      <Head />
      <Preview>Reset your Goldkach password (link expires in 30 minutes)</Preview>
      <Body
        style={{
          margin: 0,
          fontFamily: 'system-ui, -apple-system, Segoe UI, Roboto, "Helvetica Neue", Arial, sans-serif',
          backgroundColor: "#f8f9fb",
          color: "#111",
        }}
      >
        <Container
          style={{
            maxWidth: 560,
            margin: "24px auto",
            background: "#fff",
            border: "1px solid #eee",
            borderRadius: 12,
            padding: 24,
          }}
        >
              <Section style={{ textAlign: "center", marginBottom: 16 }}>
            <Link href="goldkach.co.ug" target="_blank" rel="noopener noreferrer">
              <Img
                src="https://ylhpxhcgr4.ufs.sh/f/ZVlDsNdibGfFjOMmT0owa03UxsE9D4Q16iJb7PSqYeAZTyFV?expires=1760582229143&signature=hmac-sha256%3D2fcbc9a2f7b1993ffc36cb97f27843431e61fd20198a8b3ccfc3b03576970ecf"   // ensure this path is correct and accessible
                alt="Goldkach"
                width={120}          // set intrinsic dimensions for better rendering
                height={120}         // optional but recommended
                style={{ display: "block", margin: "0 auto" }}
              />
            </Link>
          </Section>
          <Text style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>Reset your password</Text>
          <Text style={{ color: "#555", marginTop: 8 }}>
            Hi {name}, click the button below to set a new password. This link expires in 30 minutes.
          </Text>

          <Section style={{ margin: "20px 0" }}>
            <Button
              href={resetUrl}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                display: "inline-block",
                background: "#111",
                color: "#fff",
                padding: "12px 16px",
                borderRadius: 8,
                textDecoration: "none",
                fontWeight: 600,
              }}
            >
              Reset password
            </Button>
          </Section>

          {/* Fallback link if buttons/images are blocked */}
          <Text style={{ color: "#777", fontSize: 12 }}>
            If the button doesn’t work, copy and paste this link into your browser:
            <br />
            <a
              href={resetUrl}
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: "#0a66c2", wordBreak: "break-all" }}
            >
              {resetUrl}
            </a>
          </Text>

          <Hr style={{ borderColor: "#eee", margin: "16px 0" }} />

          <Text style={{ color: "#888", fontSize: 12, marginTop: 0 }}>
            If you didn’t request this, you can safely ignore this email.
          </Text>

          <Text style={{ color: "#aaa", fontSize: 12, marginTop: 8 }}>
            © {year} Goldkach
          </Text>
        </Container>
      </Body>
    </Html>
  );
}
