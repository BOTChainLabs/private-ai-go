package phala

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCrossCheckWithOfficialVerifier compares this implementation with
// Phala's official TypeScript verifier on identical inputs. Produce the
// inputs with tools/crosscheck (see its README), then run:
//
//	PRIVATEAI_CROSSCHECK_DIR=<workdir> go test ./provider/phala -run CrossCheck -v
func TestCrossCheckWithOfficialVerifier(t *testing.T) {
	dir := os.Getenv("PRIVATEAI_CROSSCHECK_DIR")
	if dir == "" {
		t.Skip("set PRIVATEAI_CROSSCHECK_DIR to a tools/crosscheck workdir")
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var ts struct {
		Report struct {
			Nonce, KeysetDigest, ReportData, ComposeHash, QuoteStatus string
			BindingOk, ComposeOk, QuoteOk                             bool
		}
		Receipts []struct {
			Name, Receipt, Request, Response, Established string
			Keyset                                        struct {
				ReceiptSigningKeys []KeyEntry `json:"receipt_signing_keys"`
			}
			Ok bool
		}
	}
	if err := json.Unmarshal(read("ts-result.json"), &ts); err != nil {
		t.Fatal(err)
	}

	t.Run("report", func(t *testing.T) {
		var rep Report
		if err := json.Unmarshal(read("report.json"), &rep); err != nil {
			t.Fatal(err)
		}
		nonce := strings.TrimSpace(string(read("nonce.txt")))
		digest, err := KeysetDigest(rep.Attestation.WorkloadKeyset)
		if err != nil || digest != ts.Report.KeysetDigest {
			t.Fatalf("keyset digest: go %s, ts %s (%v)", digest, ts.Report.KeysetDigest, err)
		}
		rd := ExpectedReportData(digest, &nonce)
		if hex.EncodeToString(rd[:]) != ts.Report.ReportData {
			t.Fatalf("report_data: go %x, ts %s", rd, ts.Report.ReportData)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		v := &Verifier{Quote: DefaultQuoteVerifier(), Workload: ProductionWorkload()}
		id, err := v.VerifyReport(ctx, &rep, nonce, "inference.phala.com", time.Now())
		tsOK := ts.Report.BindingOk && ts.Report.ComposeOk && ts.Report.QuoteOk
		if (err == nil) != tsOK {
			t.Fatalf("verdict differs: go err=%v, ts binding=%v compose=%v quote=%v", err, ts.Report.BindingOk, ts.Report.ComposeOk, ts.Report.QuoteOk)
		}
		if err == nil && (id.ComposeHash != ts.Report.ComposeHash || id.TCBStatus != ts.Report.QuoteStatus) {
			t.Fatalf("go compose %s tcb %s; ts compose %s tcb %s", id.ComposeHash, id.TCBStatus, ts.Report.ComposeHash, ts.Report.QuoteStatus)
		}
		t.Logf("agree: digest %s, compose %s, TCB %s", digest, ts.Report.ComposeHash, ts.Report.QuoteStatus)
	})

	for _, c := range ts.Receipts {
		t.Run("receipt/"+c.Name, func(t *testing.T) {
			id := &Identity{
				KeysetDigest: c.Established,
				Keyset:       Keyset{ReceiptSigningKeys: c.Keyset.ReceiptSigningKeys},
				Serving:      "aggregator",
			}
			_, err := VerifyReceipt([]byte(c.Receipt), id, []byte(c.Request), []byte(c.Response))
			if (err == nil) != c.Ok {
				t.Fatalf("verdict differs: go err=%v, ts ok=%v", err, c.Ok)
			}
		})
	}
}
