// Command demo sends one verified inference and prints the answer with its
// verification evidence.
//
//	PHALA_API_KEY=... go run ./examples/demo "Say hi"
//	NEARAI_API_KEY=... go run ./examples/demo -provider near -stream "Say hi"
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	privateai "github.com/BOTChainLabs/private-ai-go"
)

var defaults = map[privateai.ProviderID]struct{ model, keyEnv string }{
	privateai.Phala: {"z-ai/glm-5.3", "PHALA_API_KEY"},
	privateai.NEAR:  {"z-ai/glm-5.3-flash", "NEARAI_API_KEY"},
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	provider := flag.String("provider", "phala", "phala or near")
	model := flag.String("model", "", "model id (default depends on the provider)")
	stream := flag.Bool("stream", false, "stream the answer")
	flag.Parse()

	id := privateai.ProviderID(*provider)
	d, ok := defaults[id]
	if !ok {
		return fmt.Errorf("unknown provider %q", *provider)
	}
	if *model == "" {
		*model = d.model
	}
	key := os.Getenv(d.keyEnv)
	if key == "" {
		return fmt.Errorf("set %s", d.keyEnv)
	}
	prompt := "Say hi in one short sentence."
	if flag.NArg() > 0 {
		prompt = strings.Join(flag.Args(), " ")
	}

	client, err := privateai.New(privateai.Config{
		Providers: map[privateai.ProviderID]privateai.ProviderConfig{id: {APIKey: key}},
		Models:    []privateai.ModelEntry{{Provider: id, Model: *model}},
	})
	if err != nil {
		return err
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	req := privateai.InferRequest{
		Provider: id,
		Model:    *model,
		Messages: []privateai.Message{{Role: "user", Content: prompt}},
	}

	var v *privateai.Verification
	var usage privateai.Usage
	if *stream {
		v, usage, err = runStream(ctx, client, req)
	} else {
		var res *privateai.InferResult
		if res, err = client.Infer(ctx, req); err == nil {
			fmt.Println(res.Content)
			v, usage = &res.Verification, res.Usage
		}
	}
	if err != nil {
		var e *privateai.Error
		if errors.As(err, &e) && e.Verification != nil {
			return fmt.Errorf("%w\nverification: %s %v", err, e.Verification.Status, e.Verification.Reasons)
		}
		return err
	}

	fmt.Println()
	fmt.Printf("status:   %s\n", v.Status)
	fmt.Printf("route:    %s\n", v.Route)
	fmt.Printf("tcb:      %s\n", v.Evidence.TCBStatus)
	fmt.Printf("compose:  %s\n", v.Evidence.ComposeHash)
	fmt.Printf("receipt:  %s\n", v.Evidence.ReceiptID)
	fmt.Printf("tokens:   %d\n", usage.TotalTokens)
	return nil
}

// runStream prints the answer as it arrives, then verifies it. The printed
// text only counts as verified once Verify returns without error.
func runStream(ctx context.Context, client *privateai.Client, req privateai.InferRequest) (*privateai.Verification, privateai.Usage, error) {
	st, err := client.Stream(ctx, req)
	if err != nil {
		return nil, privateai.Usage{}, err
	}
	defer st.Close()
	for {
		c, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, privateai.Usage{}, err
		}
		fmt.Print(c.Content)
	}
	fmt.Println()
	v, err := st.Verify(ctx)
	return v, st.Usage(), err
}
