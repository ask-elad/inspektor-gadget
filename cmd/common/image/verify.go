package image

import (
	"context"
	"fmt"

	"github.com/distribution/reference"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/cosign"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/notation"
)

func NewVerifyCmd() *cobra.Command {
	var publicKey []string
	var certificates []string
	var policy string

	cmd := &cobra.Command{
		Use:   "verify [image]",
		Short: "Verify the signature of a single gadget image",

		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			imageRef := args[0]

			verifier, err := signature.NewSignatureVerifier(signature.VerifierOptions{
				CosignVerifierOpts: cosign.VerifierOptions{
					PublicKeys: publicKey,
				},
				NotationVerifierOpts: notation.VerifierOptions{
					Certificates:   certificates,
					PolicyDocument: policy,
				},
			})
			if err != nil {
				return fmt.Errorf("initializing verifier: %w", err)
			}

			fmt.Printf("Verifying image: %s\n", imageRef)

			ref, err := reference.ParseNormalizedNamed(imageRef)
			if err != nil {
				return fmt.Errorf("invalid image reference: %w", err)
			}

			repo, err := remote.NewRepository(reference.FamiliarName(ref))
			if err != nil {
				return fmt.Errorf("failed to create repository: %w", err)
			}

			if err := verifier.Verify(ctx, repo, repo, ref); err != nil {
				return fmt.Errorf("verification failed: %w", err)
			}

			fmt.Println("Image verified successfully!")
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&publicKey, "public-keys", nil, "Inline Cosign public key (use --public-key=\"$(cat your-key.pub)\")")
	cmd.Flags().StringSliceVar(&certificates, "notation-certificates", nil, "Certificates for Notation verification")
	cmd.Flags().StringVar(&policy, "notation-policy-document", "", "Trust policy JSON for Notation verification")

	return cmd
}
