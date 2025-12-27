// import * as React from "react";
// import { Html, Body, Container, Text, Hr, Link, Img, Section } from "@react-email/components";

// export default function VerificationCodeEmail({
//   name = "there",
//   code,
// }: { name?: string; code: string }) {
//   return (
//     <Html>
//       <Body style={{ fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif" }}>
//         <Container style={{ maxWidth: 560, margin: "24px auto", padding: 24, border: "1px solid #eee", borderRadius: 12 }}>
//                      <Section style={{ textAlign: "center", marginBottom: 16 }}>
//             <Link href="goldkach.co.ug" target="_blank" rel="noopener noreferrer">
//               <Img
//                 src="https://ylhpxhcgr4.ufs.sh/f/ZVlDsNdibGfFjOMmT0owa03UxsE9D4Q16iJb7PSqYeAZTyFV?expires=1760582229143&signature=hmac-sha256%3D2fcbc9a2f7b1993ffc36cb97f27843431e61fd20198a8b3ccfc3b03576970ecf"   // ensure this path is correct and accessible
//                 alt="Goldkach"
//                 width={120}          // set intrinsic dimensions for better rendering
//                 height={120}         // optional but recommended
//                 style={{ display: "block", margin: "0 auto" }}
//               />
//             </Link>
//           </Section>
//           <Text style={{ fontSize: 20, fontWeight: 600, marginBottom: 8 }}>Verify your email</Text>
//           <Text style={{ color: "#555" }}>
//             Hi {name}, here is your 6-digit verification code:
//           </Text>
//           <Text style={{ fontSize: 28, letterSpacing: 4, margin: "12px 0", fontWeight: 700 }}>
//             {code}
//           </Text>
//           <Text style={{ color: "#777", fontSize: 12 }}>
//             If you didn’t create an account, you can ignore this email.
//           </Text>
//           <Hr />
//           <Text style={{ color: "#aaa", fontSize: 12 }}>© {new Date().getFullYear()} Goldkach</Text>
//         </Container>
//       </Body>
//     </Html>
//   );
// }


import * as React from "react";
import { Html, Body, Container, Text, Hr, Link, Img, Section } from "@react-email/components";

export default function VerificationCodeEmail({
  name = "there",
  code,
}: { name?: string; code: string }) {
  return (
    <Html>
      <Body style={{ fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, sans-serif" }}>
        <Container style={{ maxWidth: 560, margin: "24px auto", padding: 24, border: "1px solid #eee", borderRadius: 12 }}>
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
          <Text style={{ fontSize: 20, fontWeight: 600, marginBottom: 8 }}>Verify your email</Text>
          <Text style={{ color: "#555" }}>
            Hi {name}, here is your 6-digit verification code:
          </Text>
          <Text style={{ fontSize: 28, letterSpacing: 4, margin: "12px 0", fontWeight: 700 }}>
            {code}
          </Text>
          <Text style={{ color: "#777", fontSize: 12 }}>
            If you didn’t create an account, you can ignore this email.
          </Text>
          <Hr />
          <Text style={{ color: "#aaa", fontSize: 12 }}>© {new Date().getFullYear()} Goldkach</Text>
        </Container>
      </Body>
    </Html>
  );
}
