// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/log"
	notationregistry "github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation/cmd/notation/internal/experimental"
	"github.com/notaryproject/notation/internal/cmd"
	"github.com/notaryproject/notation/internal/envelope"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
)

const referrersTagSchemaDeleteError = "failed to delete dangling referrers index"

type signOpts struct {
	cmd.LoggingFlagOpts
	cmd.SignerFlagOpts
	SecureFlagOpts
	expiry            time.Duration
	pluginConfig      []string
	userMetadata      []string
	reference         string
	allowReferrersAPI bool
	ociLayout         bool
	inputType         inputType
	filePath          string
	fileMediaType     string
}

func signCommand(opts *signOpts) *cobra.Command {
	if opts == nil {
		opts = &signOpts{
			inputType: inputTypeRegistry, // remote registry by default
		}
	}
	longMessage := `Sign artifacts

Note: a signing key must be specified. This can be done temporarily by specifying a key ID, or a new key can be configured using the command "notation key add"

Example - Sign an OCI artifact using the default signing key, with the default JWS envelope, and use OCI image manifest to store the signature:
  notation sign <registry>/<repository>@<digest>

Example - Sign an OCI artifact using the default signing key, with the COSE envelope:
  notation sign --signature-format cose <registry>/<repository>@<digest> 

Example - Sign an OCI artifact with a specified plugin and signing key stored in KMS 
  notation sign --plugin <plugin_name> --id <remote_key_id> <registry>/<repository>@<digest>

Example - Sign an OCI artifact using a specified key
  notation sign --key <key_name> <registry>/<repository>@<digest>

Example - Sign an OCI artifact identified by a tag (Notation will resolve tag to digest)
  notation sign <registry>/<repository>:<tag>

Example - Sign an OCI artifact stored in a registry and specify the signature expiry duration, for example 24 hours
  notation sign --expiry 24h <registry>/<repository>@<digest>
`
	experimentalExamples := `
Example - [Experimental] Sign an OCI artifact and store signature using the Referrers API. If it's not supported (returns 404), fallback to the Referrers tag schema
  notation sign --allow-referrers-api <registry>/<repository>@<digest>

Example - [Experimental] Sign an OCI artifact referenced in an OCI layout
  notation sign --oci-layout "<oci_layout_path>@<digest>"

Example - [Experimental] Sign an OCI artifact identified by a tag and referenced in an OCI layout
  notation sign --oci-layout "<oci_layout_path>:<tag>"
`

	command := &cobra.Command{
		Use:   "sign [flags] <reference>",
		Short: "Sign artifacts",
		Long:  longMessage,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("missing reference")
			}
			opts.reference = args[0]
			return nil
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if opts.ociLayout {
				opts.inputType = inputTypeOCILayout
			}
			return experimental.CheckFlagsAndWarn(cmd, "allow-referrers-api", "oci-layout")
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSign(cmd, opts)
		},
	}
	opts.LoggingFlagOpts.ApplyFlags(command.Flags())
	opts.SignerFlagOpts.ApplyFlagsToCommand(command)
	opts.SecureFlagOpts.ApplyFlags(command.Flags())
	cmd.SetPflagExpiry(command.Flags(), &opts.expiry)
	cmd.SetPflagPluginConfig(command.Flags(), &opts.pluginConfig)
	cmd.SetPflagUserMetadata(command.Flags(), &opts.userMetadata, cmd.PflagUserMetadataSignUsage)
	cmd.SetPflagReferrersAPI(command.Flags(), &opts.allowReferrersAPI, fmt.Sprintf(cmd.PflagReferrersUsageFormat, "sign"))
	command.Flags().BoolVar(&opts.ociLayout, "oci-layout", false, "[Experimental] sign the artifact stored as OCI image layout")
	command.MarkFlagsMutuallyExclusive("oci-layout", "allow-referrers-api")
	experimental.HideFlags(command, experimentalExamples, []string{"allow-referrers-api", "oci-layout"})
	command.Flags().StringVar(&opts.filePath, "file", "", "file path of the target file to be signed")
	command.Flags().StringVar(&opts.fileMediaType, "file-artifact-type", "", "artifact type of the target file to be signed")
	return command
}

func runSign(command *cobra.Command, cmdOpts *signOpts) error {
	// set log level
	ctx := cmdOpts.LoggingFlagOpts.SetLoggerLevel(command.Context())

	// initialize
	signer, err := cmd.GetSigner(ctx, &cmdOpts.SignerFlagOpts)
	if err != nil {
		return err
	}
	signOpts, err := prepareSigningOpts(ctx, cmdOpts)
	if err != nil {
		return err
	}
	if cmdOpts.filePath != "" {
		return signFile(ctx, cmdOpts, signer, signOpts)
	}
	if cmdOpts.allowReferrersAPI {
		fmt.Fprintln(os.Stderr, "Warning: using the Referrers API to store signature. On success, must set the `--allow-referrers-api` flag to list, inspect, and verify the signature.")
	}
	sigRepo, err := getRepository(ctx, cmdOpts.inputType, cmdOpts.reference, &cmdOpts.SecureFlagOpts, cmdOpts.allowReferrersAPI)
	if err != nil {
		return err
	}
	manifestDesc, resolvedRef, err := resolveReference(ctx, cmdOpts.inputType, cmdOpts.reference, sigRepo, func(ref string, manifestDesc ocispec.Descriptor) {
		fmt.Fprintf(os.Stderr, "Warning: Always sign the artifact using digest(@sha256:...) rather than a tag(:%s) because tags are mutable and a tag reference can point to a different artifact than the one signed.\n", ref)
	})
	if err != nil {
		return err
	}
	signOpts.ArtifactReference = manifestDesc.Digest.String()

	// core process
	_, err = notation.Sign(ctx, signer, sigRepo, signOpts)
	if err != nil {
		var errorPushSignatureFailed notation.ErrorPushSignatureFailed
		if errors.As(err, &errorPushSignatureFailed) && strings.Contains(err.Error(), referrersTagSchemaDeleteError) {
			fmt.Fprintln(os.Stderr, "Warning: Removal of outdated referrers index from remote registry failed. Garbage collection may be required.")
			// write out
			fmt.Println("Successfully signed", resolvedRef)
			return nil
		}
		return err
	}
	fmt.Println("Successfully signed", resolvedRef)
	return nil
}

func prepareSigningOpts(ctx context.Context, opts *signOpts) (notation.SignOptions, error) {
	mediaType, err := envelope.GetEnvelopeMediaType(opts.SignerFlagOpts.SignatureFormat)
	if err != nil {
		return notation.SignOptions{}, err
	}
	pluginConfig, err := cmd.ParseFlagMap(opts.pluginConfig, cmd.PflagPluginConfig.Name)
	if err != nil {
		return notation.SignOptions{}, err
	}
	userMetadata, err := cmd.ParseFlagMap(opts.userMetadata, cmd.PflagUserMetadata.Name)
	if err != nil {
		return notation.SignOptions{}, err
	}
	signOpts := notation.SignOptions{
		SignerSignOptions: notation.SignerSignOptions{
			SignatureMediaType: mediaType,
			ExpiryDuration:     opts.expiry,
			PluginConfig:       pluginConfig,
		},
		UserMetadata: userMetadata,
	}
	return signOpts, nil
}

func signFile(ctx context.Context, cmdOpts *signOpts, signer notation.Signer, signOpts notation.SignOptions) error {
	store, err := file.New("")
	if err != nil {
		return err
	}
	defer store.Close()

	fileDesc, err := store.Add(ctx, cmdOpts.filePath, cmdOpts.fileMediaType, "")
	if err != nil {
		return err
	}
	fmt.Printf("file descriptor: %+v\n", fileDesc)
	opts := oras.PackOptions{
		PackImageManifest: true,
	}
	manifestDescriptor, err := oras.Pack(ctx, store, cmdOpts.fileMediaType, []ocispec.Descriptor{fileDesc}, opts)
	if err != nil {
		return err
	}
	fmt.Printf("manifestDescriptor: %+v\n", manifestDescriptor)
	ref := manifestDescriptor.Digest.String()
	if err := store.Tag(ctx, manifestDescriptor, ref); err != nil {
		return err
	}
	signOpts.ArtifactReference = ref

	// core process
	_, err = notation.Sign(ctx, signer, notationregistry.NewRepository(store), signOpts)
	if err != nil {
		var errorPushSignatureFailed notation.ErrorPushSignatureFailed
		if errors.As(err, &errorPushSignatureFailed) && strings.Contains(err.Error(), referrersTagSchemaDeleteError) {
			fmt.Fprintln(os.Stderr, "Warning: Removal of outdated referrers index from remote registry failed. Garbage collection may be required.")
			// write out
			fmt.Println("Successfully signed", cmdOpts.filePath)
			return nil
		}
		return err
	}
	fmt.Println("Successfully signed", cmdOpts.filePath)
	sigRepo, err := getOrasRemoteRepository(ctx, &cmdOpts.SecureFlagOpts, cmdOpts.reference, cmdOpts.allowReferrersAPI)
	if err != nil {
		return err
	}
	tagName := "latest"
	desc, err := oras.ExtendedCopy(ctx, store, ref, sigRepo, tagName, oras.DefaultExtendedCopyOptions)
	if err != nil {
		return err
	}
	fmt.Printf("ExtendedCopy desc: %+v\n", desc)
	return nil
}

func getOrasRemoteRepository(ctx context.Context, opts *SecureFlagOpts, reference string, allowReferrersAPI bool) (*remote.Repository, error) {
	logger := log.GetLogger(ctx)
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return nil, err
	}

	// generate notation repository
	remoteRepo, err := getRepositoryClient(ctx, opts, ref)
	if err != nil {
		return nil, err
	}

	if !experimental.IsDisabled() && allowReferrersAPI {
		logger.Info("Trying to use the referrers API")
	} else {
		logger.Info("Using the referrers tag schema")
		if err := remoteRepo.SetReferrersCapability(false); err != nil {
			return nil, err
		}
	}
	return remoteRepo, nil
}
