package privateai_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	privateai "github.com/BOTChainLabs/private-ai-go"
)

func Example() {
	client, err := privateai.New(privateai.Config{
		Providers: map[privateai.ProviderID]privateai.ProviderConfig{
			privateai.Phala: {APIKey: os.Getenv("PHALA_API_KEY")},
		},
		Models: []privateai.ModelEntry{{Provider: privateai.Phala, Model: "z-ai/glm-5.3"}},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer client.Close()

	res, err := client.Infer(context.Background(), privateai.InferRequest{
		Provider: privateai.Phala,
		Model:    "z-ai/glm-5.3",
		Messages: []privateai.Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		var e *privateai.Error
		if errors.As(err, &e) {
			fmt.Println("refused:", e.Code)
		}
		return
	}
	// A nil error means the result passed attestation and signature checks.
	fmt.Println(res.Content, res.Verification.Status)
}

func ExampleClient_Stream() {
	client, err := privateai.New(privateai.Config{
		Providers: map[privateai.ProviderID]privateai.ProviderConfig{
			privateai.NEAR: {APIKey: os.Getenv("NEARAI_API_KEY")},
		},
		Models: []privateai.ModelEntry{{Provider: privateai.NEAR, Model: "z-ai/glm-5.3-flash"}},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer client.Close()

	ctx := context.Background()
	st, err := client.Stream(ctx, privateai.InferRequest{
		Provider: privateai.NEAR,
		Model:    "z-ai/glm-5.3-flash",
		Messages: []privateai.Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer st.Close()

	var sb strings.Builder
	for {
		c, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fmt.Println(err)
			return
		}
		sb.WriteString(c.Content) // not trustworthy yet
	}
	// Only after Verify succeeds is the streamed text verified.
	if _, err := st.Verify(ctx); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(sb.String())
}
