module github.com/CruGlobal/cru-iap

// 1.25 for crypto/ecdsa.ParseUncompressedPublicKey (which validates the point is
// on the curve, unlike the deprecated elliptic.Unmarshal) and log/slog's
// DiscardHandler. wormhole, the only consumer as of 2026-07, is on 1.25.8.
go 1.25

// No requires, deliberately. See cruiap/verifier.go for why this package is
// stdlib-only where the Ruby, TypeScript and Python siblings each lean on their
// ecosystem's JWT library.
