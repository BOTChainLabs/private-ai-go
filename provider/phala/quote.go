package phala

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"

	nearai "github.com/nearai/inference-sdk/go"

	"github.com/BOTChainLabs/private-ai-go/internal/tdx"
)

// QuoteResult is what the SDK needs from a verified TDX quote.
type QuoteResult struct {
	TCBStatus    string
	DebugEnabled bool
	ReportData   []byte
	MRTD         []byte
	MRConfigID   []byte
	RTMR0        []byte
	RTMR1        []byte
	RTMR2        []byte
	RTMR3        []byte
}

// QuoteVerifier verifies a hex-encoded TDX quote against Intel's root of
// trust and returns its measurements.
type QuoteVerifier func(ctx context.Context, hexQuote string) (QuoteResult, error)

// DefaultQuoteVerifier checks the quote with DCAP against Intel's production
// root (the verifier shipped in NEAR's Go SDK, with collateral from Phala's
// PCCS) and then reads every measurement from the authenticated quote bytes.
func DefaultQuoteVerifier() QuoteVerifier {
	verify := nearai.CreateTDXQuoteVerifier("")
	return func(ctx context.Context, hexQuote string) (QuoteResult, error) {
		r, err := verify(ctx, hexQuote)
		if err != nil {
			return QuoteResult{}, err
		}
		raw, err := hex.DecodeString(hexQuote)
		if err != nil {
			return QuoteResult{}, err
		}
		td, err := parseTDReport(raw)
		if err != nil {
			return QuoteResult{}, err
		}
		// The verifier read the same fields; disagreement means a parser bug.
		if !bytes.Equal(td.ReportData, r.ReportData) || !bytes.Equal(td.RTMR3, r.RTMR3) || !bytes.Equal(td.MRConfigID, r.MRConfigID) {
			return QuoteResult{}, errors.New("quote fields disagree with the DCAP verifier")
		}
		td.TCBStatus, td.DebugEnabled = r.TCBStatus, r.DebugEnabled
		return td, nil
	}
}

// parseTDReport reads the measurements of an accepted quote.
func parseTDReport(q []byte) (QuoteResult, error) {
	m, err := tdx.ParseQuote(q)
	if err != nil {
		return QuoteResult{}, err
	}
	return QuoteResult{
		MRTD: m.MRTD, MRConfigID: m.MRConfigID,
		RTMR0: m.RTMR0, RTMR1: m.RTMR1, RTMR2: m.RTMR2, RTMR3: m.RTMR3,
		ReportData: m.ReportData,
	}, nil
}

func (q QuoteResult) measurements() tdx.Measurements {
	return tdx.Measurements{MRTD: q.MRTD, MRConfigID: q.MRConfigID, RTMR0: q.RTMR0, RTMR1: q.RTMR1, RTMR2: q.RTMR2, RTMR3: q.RTMR3, ReportData: q.ReportData}
}
