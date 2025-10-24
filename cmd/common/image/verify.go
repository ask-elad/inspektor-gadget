package image

import (
	"context"
	"fmt"
	"os"

	"github.com/distribution/reference"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/cosign"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/notation"
)

type verifyOpts struct {
	imageRef string

	publicKeys []string
	notationCerts     []string
	notationPolicyDoc string
}

func NewVerifyCmd() *cobra.Command {
	opts := &verifyOpts{}

	cmd := &cobra.Command{
		Use:          "verify IMAGE",
		Short:        "Verify the signature of a gadget image",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.imageRef = args[0]
			return runVerify(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringArrayVar(&opts.publicKeys, "public-keys", nil,
		"Public keys for Cosign signature verification")

	cmd.Flags().StringArrayVar(&opts.notationCerts, "notation-certificates", nil,
		"X.509 certificates for Notation signature verification")
	cmd.Flags().StringVar(&opts.notationPolicyDoc, "notation-policy-document", "",
		"Path to Notation trust policy document")

	return cmd
}

func runVerify(ctx context.Context, opts *verifyOpts) error {

	if len(opts.publicKeys) == 0 && len(opts.notationCerts) == 0 {
		return fmt.Errorf("at least one verification method must be provided (--public-keys or --notation-certificates)")
	}

	if len(opts.notationCerts) > 0 && opts.notationPolicyDoc == "" {
		return fmt.Errorf("--notation-policy-document is required when using --notation-certificates")
	}

	if opts.notationPolicyDoc != "" && len(opts.notationCerts) == 0 {
		return fmt.Errorf("--notation-certificates is required when using --notation-policy-document")
	}

	verifierOpts, err := buildVerifierOptions(opts)
	if err != nil {
		return fmt.Errorf("building verifier options: %w", err)
	}

	verifier, err := signature.NewSignatureVerifier(verifierOpts)
	if err != nil {
		return fmt.Errorf("creating signature verifier: %w", err)
	}

	_, err = reference.ParseNormalizedNamed(opts.imageRef)
	if err != nil {
		return fmt.Errorf("parsing image reference: %w", err)
	}

	imgOpts := &oci.ImageOptions{
		AuthOptions: oci.AuthOptions{
			AuthFile: oci.DefaultAuthFile,
		},
		VerifyOptions: oci.VerifyOptions{
			VerifySignature: true,
			Verifier:        verifier,
		},
	}

	if err := oci.EnsureImage(ctx, opts.imageRef, imgOpts, oci.PullImageMissing); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	fmt.Printf("✓ Signature verification passed for %s\n", opts.imageRef)
	return nil
}

func buildVerifierOptions(opts *verifyOpts) (signature.VerifierOptions, error) {
	verifierOpts := signature.VerifierOptions{}

	if len(opts.publicKeys) > 0 {
		publicKeyContents := make([]string, len(opts.publicKeys))
		for i, keyPath := range opts.publicKeys {
			content, err := os.ReadFile(keyPath)
			if err != nil {
				return verifierOpts, fmt.Errorf("reading public key file %q: %w", keyPath, err)
			}
			publicKeyContents[i] = string(content)
		}
		verifierOpts.CosignVerifierOpts = cosign.VerifierOptions{
			PublicKeys: publicKeyContents,
		}
	}

	if len(opts.notationCerts) > 0 {
		certContents := make([]string, len(opts.notationCerts))
		for i, certPath := range opts.notationCerts {
			content, err := os.ReadFile(certPath)
			if err != nil {
				return verifierOpts, fmt.Errorf("reading certificate file %q: %w", certPath, err)
			}
			certContents[i] = string(content)
		}

		policyContent, err := os.ReadFile(opts.notationPolicyDoc)
		if err != nil {
			return verifierOpts, fmt.Errorf("reading policy document %q: %w", opts.notationPolicyDoc, err)
		}

		verifierOpts.NotationVerifierOpts = notation.VerifierOptions{
			Certificates:   certContents,
			PolicyDocument: string(policyContent),
		}
	}

	return verifierOpts, nil
}
