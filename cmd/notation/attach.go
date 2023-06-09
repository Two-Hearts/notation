package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation/cmd/notation/internal/experimental"
	"github.com/notaryproject/notation/internal/cmd"
	"github.com/notaryproject/notation/internal/envelope"
	"github.com/spf13/cobra"
)

type attachOpts struct {
	cmd.LoggingFlagOpts
	SecureFlagOpts
	signatureMediaType     string
	reference              string
	signatureEnvelopePaths []string
	allowReferrersAPI      bool
	inputType              inputType
}

func attachCommand(opts *attachOpts) *cobra.Command {
	if opts == nil {
		opts = &attachOpts{
			inputType: inputTypeRegistry, // remote registry by default
		}
	}
	longMessage := `Attach signature envelope to target artifact

Example - Attach a signature envelope to OCI artifact with the default JWS envelope:
  notation attach <registry>/<repository>@<digest> <signature_envelope_path>

Example - Attach a signature envelope to OCI artifact with the COSE envelope:
  notation attach --signature-format cose <registry>/<repository>@<digest> <signature_envelope_path>

Example - Attach a signature envelope to OCI artifact identified by a tag (Notation will resolve tag to digest)
  notation attach <registry>/<repository>:<tag> <signature_envelope_path>
`
	experimentalExamples := `
Example - [Experimental] Attach a signature envelope to OCI artifact and store signature using the Referrers API. If it's not supported (returns 404), fallback to the Referrers tag schema
  notation attach --allow-referrers-api <registry>/<repository>@<digest> <signature_envelope_path>
`

	command := &cobra.Command{
		Use:   "attach [flags] <reference> <signature_envelope_path>...",
		Short: "Attach signature envelopes to target artifact",
		Long:  longMessage,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return errors.New("attach requires reference and at least one signature envelope path")
			}
			opts.reference = args[0]
			opts.signatureEnvelopePaths = args[1:]
			return nil
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return experimental.CheckFlagsAndWarn(cmd, "allow-referrers-api")
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttach(cmd, opts)
		},
	}
	opts.LoggingFlagOpts.ApplyFlags(command.Flags())
	opts.SecureFlagOpts.ApplyFlags(command.Flags())
	cmd.SetPflagSignatureFormat(command.Flags(), &opts.signatureMediaType)
	cmd.SetPflagReferrersAPI(command.Flags(), &opts.allowReferrersAPI, fmt.Sprintf(cmd.PflagReferrersUsageFormat, "attach"))
	experimental.HideFlags(command, experimentalExamples, []string{"allow-referrers-api"})
	return command
}

func runAttach(command *cobra.Command, cmdOpts *attachOpts) error {
	// set log level
	ctx := cmdOpts.LoggingFlagOpts.SetLoggerLevel(command.Context())

	// initialize
	repo, err := getRepository(ctx, cmdOpts.inputType, cmdOpts.reference, &cmdOpts.SecureFlagOpts, cmdOpts.allowReferrersAPI)
	if err != nil {
		return err
	}
	signatureMediaType, err := envelope.GetEnvelopeMediaType(cmdOpts.signatureMediaType)
	if err != nil {
		return err
	}

	// attach signatures one by one
	succeededAttach := 0
	for _, sigEnvPath := range cmdOpts.signatureEnvelopePaths {
		fmt.Printf("attaching signature at: %s\n", sigEnvPath)
		sigEnv, err := os.ReadFile(sigEnvPath) // just pass the file name
		if err != nil {
			fmt.Println("failed to attach:", err)
			continue
		}
		attachOpts := notation.AttachOptions{
			SignatureEnvelope:  sigEnv,
			SignatureMediaType: signatureMediaType,
			ArtifactReference:  cmdOpts.reference,
		}
		sigManifestDesc, err := notation.Attach(ctx, repo, attachOpts)
		if err != nil {
			fmt.Println("failed to attach:", err)
			continue
		}
		fmt.Printf("successfully attached signature with signature manifest descriptor: %+v\n", sigManifestDesc)
		succeededAttach++
	}
	fmt.Printf("Attached %d out of %d signatures\n", succeededAttach, len(cmdOpts.signatureEnvelopePaths))
	return nil
}
